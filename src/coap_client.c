#include "coap_client.h"

#include <net/socket.h>
#include <random/rand32.h>
#include <stdio.h>

#include <logging/log.h>
LOG_MODULE_REGISTER(coap_client);

#define APP_COAP_VERSION 1
#define APP_RECEIVE_INTERVAL K_MSEC(100)

static int coap_socket;

static uint16_t next_token;

static struct sockaddr_storage server;

struct coap_reply replies[CONFIG_COAP_CLIENT_NUM_MSGS];
struct coap_pending pendings[CONFIG_COAP_CLIENT_NUM_MSGS];

/* Use +1 to always allow receive to allocate a block */
K_MEM_SLAB_DEFINE(coap_msg_slab, CONFIG_COAP_CLIENT_MSG_LEN, CONFIG_COAP_CLIENT_NUM_MSGS+1, 1);

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

	LOG_INF("CoAP client changed from state %s to %s", log_strdup(state_str(c_state)), log_strdup(state_str(state)));

	c_state = state;

	if (c_state == COAP_CLIENT_ACTIVE && active_cb) {
		active_cb();
	}
}

static void *coap_client_buf(size_t *len) {
	void *block = NULL;
	int err;

	err = k_mem_slab_alloc(&coap_msg_slab, &block, K_NO_WAIT);
	if (err < 0) {
		return NULL;
	}

	*len = CONFIG_COAP_CLIENT_MSG_LEN;

	return block;
}

static void coap_client_buf_free(void *buf) {
	void *block = buf;
	k_mem_slab_free(&coap_msg_slab, &block);
}

int coap_client_packet_init(struct coap_packet *cpkt, uint8_t type, uint8_t code) {
	int err;
	size_t len;
	void *buf;

	buf = coap_client_buf(&len);
	if (!buf) {
		LOG_ERR("No more buffers");
		return -ENOMEM;
	}

	next_token++;
	err = coap_packet_init(cpkt, buf, len,
						   APP_COAP_VERSION, type,
						   sizeof(next_token), (uint8_t *)&next_token,
						   code, coap_next_id());
	if (err < 0) {
		coap_client_buf_free(buf);
		return err;
	}

	return 0;
}

static int send_raw(void *buf, size_t len) {
	if (sendto(coap_socket, buf, len, 0, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) < 0) {
		LOG_ERR("Failed to send: %d", errno);
		return -errno;
	}

	return 0;
}

static int client_send_pending(struct coap_pending *p) {
	if (!coap_pending_cycle(p)) {
		LOG_WRN("Pending terminally expired: %p", (void*)p);
		return -ENETRESET;
	}

	LOG_DBG("Sending pending %p, retries %u", (void*)p, p->retries);

	return send_raw(p->data, p->len);
}

static int coap_make_request(struct coap_packet *pkt, coap_reply_t replyf) {
	struct coap_pending *pending = NULL;
	struct coap_reply *reply = NULL;
	int err;

	if (coap_header_get_type(pkt) != COAP_TYPE_CON) {
		/*
		 * For some stupid reason, responses to non-con-requests
		 * are not required to carry the same msg id as the request,
		 * and the pending structs only carry the msg id to match
		 * responses, and also manage the memory. Reply structs have
		 * no concept of expiry or anything, so they can't be cleaned
		 * up on their own. Hence, we need a pending struct to track
		 * the whereabouts of our outgoing message, which only works if
		 * they are of type CON.
		 */
		err = -EINVAL;
		goto cleanup_buf;
	}

	pending = coap_pending_next_unused(pendings, ARRAY_SIZE(pendings));
	if (!pending) {
		LOG_ERR("No pending struct available to track responses");
		err = -ENOMEM;
		goto cleanup_buf;
	}

	reply = coap_reply_next_unused(replies, ARRAY_SIZE(replies));
	if (!reply) {
		LOG_ERR("No reply struct available to track responses");
		err = -ENOMEM;
		goto cleanup_p;
	}

	err = coap_pending_init(pending, pkt, (struct sockaddr*)&server, CONFIG_COAP_NUM_RETRIES);
	if (err) {
		goto cleanup_r;
	}

	coap_reply_init(reply, pkt);
	reply->reply = replyf;

	err = client_send_pending(pending);
	if (err == 0) {
		return 0;
	}

cleanup_r:
	coap_reply_clear(reply);
cleanup_p:
	coap_pending_clear(pending);
cleanup_buf:
	coap_client_buf_free(pkt->data);

	return err;
}

int coap_client_send(struct coap_packet *pkt, coap_reply_t replyf) {
	int err;

	LOG_HEXDUMP_DBG(pkt->data, pkt->offset, "sending coap packet");

	if (replyf) {
		return coap_make_request(pkt, replyf);
	}

	err = send_raw(pkt->data, pkt->offset);

	coap_client_buf_free(pkt->data);

	return err;
}

int coap_client_make_request(const uint8_t** uri, const void *payload, size_t plen, uint8_t type, uint8_t code, coap_reply_t reply) {
	int err;
	struct coap_packet request;

	err = coap_client_packet_init(&request, type, code);
	if (err < 0) {
		LOG_ERR("Could not create request");
		return err;
	}

	err = coap_packet_append_uri_path(&request, uri);
	if (err < 0) {
		LOG_ERR("Could not append URI path");
		goto cleanup;
	}

	if (payload && plen) {
		err = coap_packet_append_payload_marker(&request);
		if (err) {
			LOG_ERR("Could not append payload marker");
			goto cleanup;
		}

		err = coap_packet_append_payload(&request, payload, strlen(payload));
		if (err < 0) {
			LOG_ERR("Failed to append payload, %d", err);
			goto cleanup;
		}
	}

	return coap_client_send(&request, reply);

cleanup:
	coap_client_buf_free(request.data);
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
		LOG_ERR("Could not initialize ack");
		return err;
	}

	return send_raw(ack.data, ack.offset);
}

static int client_handle_get_response(uint8_t *buf, int received, struct sockaddr *from)
{
	int err;
	struct coap_packet response;
	struct coap_reply *reply;
	struct coap_pending *pending;
	uint8_t code;
	uint8_t type;

	err = coap_packet_parse(&response, buf, received, NULL, 0);
	if (err < 0) {
		LOG_ERR("Malformed response received: %d", err);
		return err;
	}

	code = coap_header_get_code(&response);
	type = coap_header_get_type(&response);

	pending = coap_pending_received(&response, pendings, ARRAY_SIZE(pendings));
	if (pending) {
		coap_client_buf_free(pending->data);
		coap_pending_clear(pending);
	}

	if (code != 0) {
		/* It's not obvious from the function's name but this calls the reply's handler */
		reply = coap_response_received(&response, from, replies, ARRAY_SIZE(replies));

		if (!reply && !pending) {
			LOG_HEXDUMP_WRN(buf, received, "Received unexpected CoAP message");
		}

		if(reply && type == COAP_TYPE_CON) {
			return client_ack_message(&response);
		}
	}

	return 0;
}

static void receive(void *buf, size_t len) {
	int err;
	int received;
	struct sockaddr src = {0};
	socklen_t socklen = sizeof(src);
	char src_ip[NET_IPV4_ADDR_LEN];
	char *res;

	received = zsock_recvfrom(coap_socket, buf, len, MSG_DONTWAIT, (struct sockaddr*)&src, &socklen);
	if (received < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		LOG_ERR("Socket error");
		return;
	}

	if (received == 0) {
		LOG_ERR("Empty datagram");
		return;
	}

	if (Z_LOG_CONST_LEVEL_CHECK(LOG_LEVEL_DBG)) {
		res = zsock_inet_ntop(src.sa_family, &src, src_ip, sizeof(src_ip));
		LOG_DBG("Received from %s", log_strdup(res));
	}

	LOG_HEXDUMP_DBG(buf, received, "Received");

	err = client_handle_get_response(buf, received, &src);
	if (err < 0) {
		LOG_ERR("Invalid response, exit...");
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
		LOG_ERR("ERROR: getaddrinfo failed %d", err);
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
	LOG_INF("IPv4 Address found %s", log_strdup(ipv4_addr));

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
		LOG_ERR("Failed to create CoAP socket: %d.\n", errno);
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
		LOG_ERR("bind failed : %d", errno);
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
	struct coap_pending *p;
	struct coap_reply *r;
	int i;

	err = zsock_close(coap_socket);
	if (err) {
		LOG_ERR("Failed to close socket: %d", err);
		return err;
	}

	for (i = 0, p = pendings; i < ARRAY_SIZE(pendings); i++, p++) {
		if (p->data) {
			coap_client_buf_free(p->data);
		}
		coap_pending_clear(p);
	}

	for (i = 0, r = replies; i < ARRAY_SIZE(replies); i++, r++) {
		coap_reply_clear(r);
	}

	client_state_set(COAP_CLIENT_DISCONNECTED);

	return 0;
}

static void on_work(struct k_work* work);
K_WORK_DELAYABLE_DEFINE(work_coap, on_work);

static int client_cycle_pendings(void) {
	struct coap_pending *p;
	uint32_t expiry;
	uint32_t now = k_uptime_get_32();

	p = coap_pending_next_to_expire(pendings, ARRAY_SIZE(pendings));
	if (!p) {
		return 0;
	}

	expiry = p->t0 + p->timeout;

	// Overflow aware way to put (now > expiry)
	if ((int32_t)(expiry - now) < 0) {
		LOG_INF("Pending %p expired", (void*)p);
		return client_send_pending(p);
	}

	return 0;
}

static int client_active(void) {
	size_t len;
	static uint8_t rx_buf[CONFIG_COAP_CLIENT_MSG_LEN];

	receive(rx_buf, sizeof(rx_buf));

	return client_cycle_pendings();
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
		break;
	default:
		err = -EINVAL;
		break;
	}

	if (err) {
		client_state_set(COAP_CLIENT_ERROR);
	}

	if (k_work_schedule(&work_coap, APP_RECEIVE_INTERVAL) < 0) {
		LOG_ERR("Failed to schedule receiver!");
	}
}

static void statistics(struct k_work *work);

K_WORK_DELAYABLE_DEFINE(stat_work, statistics);

static void statistics(struct k_work *work) {
	uint32_t mem_free;
	uint32_t p_free = 0;
	uint32_t r_free = 0;
	struct coap_pending *p;
	struct coap_reply *r;
	int i;

	ARG_UNUSED(work);

	mem_free = k_mem_slab_num_free_get(&coap_msg_slab);

	for (i = 0, p = pendings; i < ARRAY_SIZE(pendings); i++, p++) {
		if (!p->timeout) {
			p_free++;
		}
	}

	for (i = 0, r = replies; i < ARRAY_SIZE(replies); i++, r++) {
		if (!r->reply) {
			r_free++;
		}
	}

	LOG_INF("CoAP stats: free: %u mem blocks, %u pendings, %u replies", mem_free, p_free, r_free);

	k_work_schedule(&stat_work, K_SECONDS(30));
}


int coap_client_init(void (*cb)(void))
{
	int err;

	active_cb = cb;

	err = server_resolve();
	if (err != 0) {
		LOG_ERR("Failed to resolve server name");
		return err;
	}

	if (k_work_schedule(&work_coap, APP_RECEIVE_INTERVAL) < 0) {
		LOG_ERR("Failed to schedule receiver!");
		return -1;
	}

	if (k_work_schedule(&stat_work, K_SECONDS(30)) < 0) {
		LOG_ERR("Failed to schedule stats!");
		return -1;
	}

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
			LOG_ERR("Failed to encode CoAP option, %d", err);
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
		LOG_ERR("Could not format \"%s\"", log_strdup(fmt));
		return -ENOMEM;
	}
	return coap_packet_append_option(pkt, COAP_OPTION_URI_QUERY, query, err);
}

int coap_packet_append_uri_query_d(struct coap_packet *pkt, const char *fmt, int d) {
	char query[20];
	int err;

	err = snprintf(query, sizeof(query), fmt, d);
	if (err < 0 || err >= sizeof(query)) {
		LOG_ERR("Could not format \"%s\"", log_strdup(fmt));
		return -ENOMEM;
	}

	return coap_packet_append_option(pkt, COAP_OPTION_URI_QUERY, query, err);
}
