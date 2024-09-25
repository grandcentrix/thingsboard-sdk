#include "coap_client.h"

#include <stdio.h>
#include <zephyr/net/socket.h>
#include <zephyr/random/random.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(coap_client, CONFIG_THINGSBOARD_LOG_LEVEL);

#define APP_COAP_VERSION 1
#define APP_RECEIVE_INTERVAL K_MSEC(100)

static int coap_socket;

static uint16_t next_token;

static struct sockaddr_storage server;

#define SLAB_SIZE (sizeof(struct coap_client_request) + CONFIG_COAP_CLIENT_MSG_LEN)
#define SLAB_ALIGN (__alignof__ (struct coap_client_request))

/* Use +1 to always allow receive to allocate a block */
K_MEM_SLAB_DEFINE(coap_msg_slab, SLAB_SIZE, CONFIG_COAP_CLIENT_NUM_MSGS+1, SLAB_ALIGN);

static sys_dlist_t requests;

#define COAP_FOR_EACH_REQUEST_SAFE(r, rs) SYS_DLIST_FOR_EACH_CONTAINER_SAFE(&requests, (r), (rs), node)
#define COAP_FOR_EACH_REQUEST(r) SYS_DLIST_FOR_EACH_CONTAINER(&requests, (r), node)

static void on_work(struct k_work* work);
K_WORK_DELAYABLE_DEFINE(work_coap, on_work);

static enum coap_client_state {
	COAP_CLIENT_DISCONNECTED,
	COAP_CLIENT_ACTIVE,
	COAP_CLIENT_ERROR
} c_state;

static void (*active_cb)(void);

#define STATE(s) case COAP_CLIENT_ ## s: return #s
static const char *state_str(enum coap_client_state state)
{
	switch (state) {
	STATE(DISCONNECTED);
	STATE(ACTIVE);
	STATE(ERROR);
	}

	return "INVALID STATE";
}
#undef STATE

static void client_state_set(enum coap_client_state state) {
	if (c_state == state) {
		return;
	}

	LOG_INF("CoAP client changed from state %s to %s", state_str(c_state), state_str(state));

	c_state = state;

	if (c_state == COAP_CLIENT_ACTIVE && active_cb) {
		active_cb();
	}
}

static void coap_client_request_free(struct coap_client_request *req) {
	void *block = req;
	if (sys_dnode_is_linked(&req->node)) {
		sys_dlist_remove(&req->node);
	}
	k_mem_slab_free(&coap_msg_slab, block);
}

struct coap_client_request *coap_client_request_alloc(uint8_t type, uint8_t code) {
	void *block = NULL;
	uint8_t *data;
	uint16_t datalen;
	struct coap_client_request *req;
	int err;

	err = k_mem_slab_alloc(&coap_msg_slab, &block, K_NO_WAIT);
	if (err < 0) {
		LOG_ERR("Could not allocate memory for request, error (%d): %s", err, strerror(-err));
		return NULL;
	}

	req = (struct coap_client_request *)block;
	*req = (struct coap_client_request){0};
	data = (uint8_t*)block + sizeof(*req);
	datalen = SLAB_SIZE - sizeof(*req);

	req->confirmable = type == COAP_TYPE_CON;

	next_token++;
	req->tkl = sizeof(next_token);
	memcpy(req->token, &next_token, req->tkl);

	req->id = coap_next_id();
	err = coap_packet_init(&req->pkt, data, datalen, APP_COAP_VERSION, type, req->tkl, req->token, code, req->id);
	if (err < 0) {
		coap_client_request_free(req);
		return NULL;
	}

	sys_dlist_append(&requests, &req->node);

	return req;
}

int coap_client_request_observe(struct coap_client_request *req) {
	int err;

	req->observation = true;
	err = coap_append_option_int(&req->pkt, COAP_OPTION_OBSERVE, 0);
	if (err < 0) {
		return err;
	}

	return 0;
}

static int send_raw(void *buf, size_t len) {
	if (sendto(coap_socket, buf, len, 0, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) < 0) {
		LOG_ERR("Failed to send, error (%d): %s", errno, strerror(errno));
		return -errno;
	}

	return 0;
}

static int client_send_request(struct coap_client_request *req) {
	int err;

	LOG_INF("Sending %s request %p (message id %d), %u retries left",
		req->confirmable ? "confirmable" : "non-confirmable", req, req->id, req->retries);

	err = send_raw(req->pkt.data, req->pkt.offset);
	if (err < 0) {
		LOG_ERR("Error sending request %p", req);
	}

	return err;
}

/**
 * Find the next request to expire. If there are no
 * requests, returns NULL. Otherwise, int64_t pointed to
 * by next_expiry will contain the time the returned
 * request expires.
 */
static struct coap_client_request *coap_request_next_to_expire(int64_t *next_expiry)
{
	struct coap_client_request *found = NULL, *p;
	int64_t expiry, min_expiry = 0;

	COAP_FOR_EACH_REQUEST(p) {
		if (!p->t0) {
			continue;
		}

		expiry = p->t0 + p->timeout;

		if (!found || (int32_t)(expiry - min_expiry) < 0) {
			min_expiry = expiry;
			found = p;
		}
	}

	*next_expiry = min_expiry;

	return found;
}

int coap_client_send(struct coap_client_request *req, coap_reply_handler_t reply) {
	LOG_HEXDUMP_DBG(req->pkt.data, req->pkt.offset, "sending coap packet");
	int err;

	req->reply_handler = reply;
	req->t0 = k_uptime_get();

	if (req->reply_handler || req->confirmable) {
		req->retries = CONFIG_COAP_NUM_RETRIES;
	}

	err = k_work_reschedule(&work_coap, K_NO_WAIT);
	if (err < 0) {
		return err;
	}

	return 0;
}

int coap_client_make_request(const uint8_t** uri, const void *payload, size_t plen, uint8_t type, uint8_t code, coap_reply_handler_t reply) {
	int err;
	struct coap_client_request *req;

	req = coap_client_request_alloc(type, code);
	if (!req) {
		return -ENOMEM;
	}

	err = coap_packet_append_uri_path(&req->pkt, uri);
	if (err < 0) {
		LOG_ERR("Could not append URI path, error (%d): %s", err, strerror(-err));
		goto cleanup;
	}

	if (payload && plen) {
		err = coap_packet_append_payload_marker(&req->pkt);
		if (err) {
			LOG_ERR("Could not append payload marker, error (%d): %s", err, strerror(-err));
			goto cleanup;
		}

		err = coap_packet_append_payload(&req->pkt, payload, plen);
		if (err < 0) {
			LOG_ERR("Failed to append payload, error (%d): %s", err, strerror(-err));
			goto cleanup;
		}
	}

	return coap_client_send(req, reply);

cleanup:
	coap_client_request_free(req);
	return err;
}

static int client_ack_message(struct coap_packet *response) {
	struct coap_packet ack;
	uint8_t ack_buf[4];
	uint16_t msg_id;
	int err;

	msg_id = coap_header_get_id(response);
	err = coap_packet_init(&ack, ack_buf, sizeof(ack_buf),
			APP_COAP_VERSION, COAP_TYPE_ACK,
			0, NULL,
			0, msg_id);
	if (err) {
		LOG_ERR("Could not initialize ack, error (%d): %s", err, strerror(-err));
		return err;
	}

	return send_raw(ack.data, ack.offset);
}

static int client_reset_message(struct coap_packet *response) {
	struct coap_packet reset;
	uint8_t buf[4];
	uint16_t msg_id;
	int err;

	msg_id = coap_header_get_id(response);
	err = coap_packet_init(&reset, buf, sizeof(buf),
			APP_COAP_VERSION, COAP_TYPE_RESET,
			0, NULL,
			0, msg_id);
	if (err) {
		LOG_ERR("Could not initialize reset, error (%d): %s", err, strerror(-err));
		return err;
	}

	return send_raw(reset.data, reset.offset);
}

static void decode_response_code(int code, int *class, int *detail) {
	*class = (code >> 5);
	*detail = code & 0x1f;
}

static void response_code_to_str(int code, char str[5]) {
	int class, detail;
	decode_response_code(code, &class, &detail);
	sprintf(str, "%1d.%02d", class, detail);
}

static char* message_type_strings[] = {"Confirmable", "Non-confirmable", "Acknowledgement", "Reset"};

static char* message_type_to_str(uint8_t type) {
	if (type < ARRAY_SIZE(message_type_strings)) {
		return message_type_strings[type];
	}
	return "unknown";
}


static int client_handle_get_response(uint8_t *buf, int received, struct sockaddr *from)
{
	int err;
	struct coap_packet response;
	struct coap_client_request *r, *rs;
	uint8_t code;
	char code_str[5];
	uint8_t type;
	uint16_t id;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl;

	err = coap_packet_parse(&response, buf, received, NULL, 0);
	if (err < 0) {
		LOG_ERR("Malformed response received, error (%d): %s", err, strerror(-err));
		return err;
	}

	code = coap_header_get_code(&response);
	type = coap_header_get_type(&response);
	id = coap_header_get_id(&response);
	tkl = coap_header_get_token(&response, token);


	response_code_to_str(code, code_str);
	LOG_INF("Received CoAP message: type %s, code %s, message id %d", message_type_to_str(type), code_str, id);

	if (type == COAP_TYPE_ACK && code == COAP_CODE_EMPTY) {
		/*
		 * This is an empty ACK message. It is matched
		 * to the original request by the message ID.
		 * RFC7252 5.3.2
		 */
		COAP_FOR_EACH_REQUEST_SAFE(r, rs) {
			if (r->confirmable && !r->confirmed && r->id == id) {
				r->confirmed = true;
				LOG_DBG("Received acknowledgement for request %p (message id %d)", r, r->id);
				if (r->reply_handler) {
					/*
					 * We expect a reply -
					 * Let's extend the timeout of this request
					 * since we got something.
					 * The spec doesn't really define how
					 * to handle the case of getting an ACK
					 * but never an actual response. Clients should
					 * give the server "reasonable" time to create
					 * the response, whatever that means.
					 * RFC7252 5.2.2, Implementation Notes
					 */
					r->t0 = k_uptime_get();
					r->retries = CONFIG_COAP_NUM_RETRIES;
				} else {
					coap_client_request_free(r);
				}
				return 0;
			}
		}
		/*
		 * If the ACK does not match any message, it is
		 * silently ignored. RFC7252 4.2
		 */
		return 0;
	}

	/*
	 * Handle responses (piggybacked and non-piggybacked)
	 */
	COAP_FOR_EACH_REQUEST_SAFE(r, rs) {
		if (!memcmp(r->token, token, tkl)) {
			LOG_DBG("Received response for request %p (message id %d)", r, r->id);
			if (r->reply_handler) {
				r->reply_handler(r, &response);
			}

			if (!r->observation) {
				/* Request done */
				coap_client_request_free(r);
			} else {
				/*
				 * This stops the handler for pending requests
				 * from re-sending this request
				 */
				r->t0 = 0;
			}

			if(type == COAP_TYPE_CON) {
				return client_ack_message(&response);
			}
			return 0;
		}
	}

	LOG_HEXDUMP_WRN(buf, received, "Received unexpected CoAP message");

	return client_reset_message(&response);
}

static void receive(void *buf, size_t len) {

	int err;
	int received;
	struct sockaddr src = {0};
	socklen_t socklen = sizeof(src);

	received = zsock_recvfrom(coap_socket, buf, len, MSG_DONTWAIT, (struct sockaddr*)&src, &socklen);
	if (received < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		LOG_ERR("Socket error (%d): %s", errno, strerror(errno));
		return;
	}

	if (received == 0) {
		LOG_ERR("Empty datagram");
		return;
	}

	#ifdef CONFIG_THINGSBOARD_LOG_LEVEL_DBG
	char src_ip[NET_IPV4_ADDR_LEN];
	char *res;
	res = zsock_inet_ntop(src.sa_family, &src, src_ip, sizeof(src_ip));
	LOG_DBG("Received from %s", res);
	#endif

	LOG_HEXDUMP_DBG(buf, received, "Received");

	err = client_handle_get_response(buf, received, &src);
	if (err < 0) {
		LOG_ERR("Failed to handle response");
		return;
	}
}

static int server_resolve(void)
{
	int err;
	struct addrinfo *result;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM
	};
	char ipv4_addr[NET_IPV4_ADDR_LEN];

	err = getaddrinfo(CONFIG_COAP_SERVER_HOSTNAME, NULL, &hints, &result);
	if (err != 0) {
		LOG_ERR("ERROR: getaddrinfo failed, error %d: (%s)", err, strerror(-errno));
		return -EIO;
	}

	if (result == NULL) {
		LOG_ERR("ERROR: Address not found");
		return -ENOENT;
	}

	/* IPv4 Address. */
	struct sockaddr_in *server4 = ((struct sockaddr_in *)&server);

	server4->sin_addr.s_addr =
		((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr;
	server4->sin_family = AF_INET;
	server4->sin_port = htons(CONFIG_COAP_SERVER_PORT);

	inet_ntop(AF_INET, &server4->sin_addr.s_addr, ipv4_addr,
		  sizeof(ipv4_addr));
	LOG_INF("IPv4 Address found %s", ipv4_addr);

	/* Free the address. */
	freeaddrinfo(result);

	return 0;
}

static int udp_setup(void) {
	int err;
	struct sockaddr_in src = {0};

	/* Randomize token. */
	next_token = sys_rand32_get();

	src.sin_family = AF_INET;
	src.sin_addr.s_addr = INADDR_ANY;
	src.sin_port = htons(0);

	coap_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (coap_socket < 0) {
		LOG_ERR("Failed to create CoAP socket,error (%d): %s", errno, strerror(errno));
		return -errno;
	}

	/*
	 * Do not use connect!
	 * For some networking reason, the source address of the responses
	 * might not match the server address, in which case a connected
	 * socket can just drop the messages.
	 */
	err = bind(coap_socket, (struct sockaddr *)&src, sizeof(src));
	if (err < 0) {
		LOG_ERR("bind failed, error (%d): %s", errno, strerror(errno));
		err = -errno;
		/* Ignore possible errors, there is nothing we can do */
		zsock_close(coap_socket);
		return err;
	}

	client_state_set(COAP_CLIENT_ACTIVE);

	return 0;
}

static int udp_teardown(void) {
	int err;
	struct coap_client_request *r, *rs;

	err = zsock_close(coap_socket);
	if (err) {
		LOG_ERR("Failed to close socket, error (%d): %s", err, strerror(err));
		return err;
	}

	COAP_FOR_EACH_REQUEST_SAFE(r, rs) {
		coap_client_request_free(r);
	}

	client_state_set(COAP_CLIENT_DISCONNECTED);

	return 0;
}

/**
 * Check all pending requests.
 */
static int client_cycle_requests(void) {
	struct coap_client_request *req;
	int64_t next_expiry;
	int64_t next_sched = INT64_MAX;
	int64_t now = k_uptime_get();
	int err;

	while ((req = coap_request_next_to_expire(&next_expiry))) {
		if (next_expiry > now) {
			/* This isn't expired yet */
			if (next_expiry < next_sched) {
				next_sched = next_expiry;
			}
			break;
		}

		if (!req->timeout) {
			/* First attempt at sending */
			if (!req->retries) {
				/* This is a fire-and-forget request */
				err = client_send_request(req);
				if (err < 0) {
					return err;
				}
				coap_client_request_free(req);
				continue;
			}

			req->timeout = CONFIG_COAP_INIT_ACK_TIMEOUT_MS;
		} else {
			if (!req->retries) {
				LOG_ERR("Request %p has timed out", req);
				return -ENETRESET;
			}

			req->t0 += req->timeout;
			req->timeout = req->timeout << 1;
			req->retries--;

			LOG_INF("Retrying request %p", req);
		}

		err = client_send_request(req);
		if (err < 0) {
			return err;
		}
	}

	if (next_sched != INT64_MAX) {
		err = k_work_reschedule(&work_coap, K_MSEC(next_sched - now));
		if (err < 0) {
			return err;
		}
	}

	return 0;
}

static int client_active(void) {
	static uint8_t rx_buf[CONFIG_COAP_CLIENT_MSG_LEN];
	receive(rx_buf, sizeof(rx_buf));

	return client_cycle_requests();
}

static void on_work(struct k_work* work) {
	ARG_UNUSED(work);

	int err;

	switch (c_state) {
	case COAP_CLIENT_ACTIVE:
		err = client_active();
		break;
	case COAP_CLIENT_DISCONNECTED:
		err = udp_setup();
		break;
	case COAP_CLIENT_ERROR:
		err = udp_teardown();
		if (err < 0) {
			/* If even this fails, better abort */
			LOG_ERR("CoAP client fatally failed");
			return;
		}
		break;
	default:
		err = -EINVAL;
		break;
	}

	if (err) {
		client_state_set(COAP_CLIENT_ERROR);
	}

	err = k_work_schedule(&work_coap, APP_RECEIVE_INTERVAL);
	if (err < 0) {
		LOG_ERR("Failed to schedule receiver, error (%d): %s", err, strerror(-err));
	}
}

#if CONFIG_COAP_CLIENT_STAT_INTERVAL_SECONDS > 0
static void statistics(struct k_work *work) {
	uint32_t mem_free;

	mem_free = k_mem_slab_num_free_get(&coap_msg_slab);

	LOG_INF("CoAP stats: free: %u requests", mem_free);

	k_work_schedule(k_work_delayable_from_work(work),
			K_SECONDS(CONFIG_COAP_CLIENT_STAT_INTERVAL_SECONDS));
}
K_WORK_DELAYABLE_DEFINE(stat_work, statistics);
#endif

int coap_client_init(void (*cb)(void))
{
	int err;

	active_cb = cb;

	if (requests.head) {
		return -EALREADY;
	}

	sys_dlist_init(&requests);

	err = server_resolve();
	if (err != 0) {
		LOG_ERR("Failed to resolve server name");
		return err;
	}

	err = k_work_schedule(&work_coap, APP_RECEIVE_INTERVAL);
	if (err < 0) {
		LOG_ERR("Failed to schedule receiver, error (%d): %s", err, strerror(-err));
		return -1;
	}

#if CONFIG_COAP_CLIENT_STAT_INTERVAL_SECONDS > 0
	err = k_work_schedule(&stat_work, K_SECONDS(CONFIG_COAP_CLIENT_STAT_INTERVAL_SECONDS));
	if (err < 0) {
		LOG_ERR("Failed to schedule statistics, error (%d): %s", err, strerror(-err));
		return err;
	}
#endif

	return 0;
}

int coap_packet_append_uri_path(struct coap_packet *pkt, const uint8_t **uri)
{
	int err;

	while (*uri) {
		err = coap_packet_append_option(pkt, COAP_OPTION_URI_PATH,
						*uri,
						strlen(*uri));
		if (err < 0) {
			return err;
		}
		uri++;
	}

	return 0;
}

int coap_packet_append_uri_query_s(struct coap_packet *pkt, const char *fmt, const char *s) {
	char query[50];
	int err;

	err = snprintf(query, sizeof(query), fmt, s);
	if (err < 0 || err >= sizeof(query)) {
		LOG_ERR("Could not format \"%s\"", fmt);
		return -ENOMEM;
	}
	return coap_packet_append_option(pkt, COAP_OPTION_URI_QUERY, query, err);
}

int coap_packet_append_uri_query_d(struct coap_packet *pkt, const char *fmt, int d) {
	char query[20];
	int err;

	err = snprintf(query, sizeof(query), fmt, d);
	if (err < 0 || err >= sizeof(query)) {
		LOG_ERR("Could not format \"%s\"", fmt);
		return -ENOMEM;
	}

	return coap_packet_append_option(pkt, COAP_OPTION_URI_QUERY, query, err);
}
