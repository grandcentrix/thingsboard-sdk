#include <thingsboard.h>
#include <zephyr/ztest.h>

#include <zephyr/sys/reboot.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(coap_test);

#define MOCK_ANY_PORT        0
#define MOCK_UDP_BUFFER_SIZE 128
#define NUM_COAP_OPTIONS     10

#define STACKSIZE 2048
#ifndef CONFIG_THINGSBOARD_TEST_FAILURE
static K_THREAD_STACK_DEFINE(udp_stack, STACKSIZE);
static struct k_thread udp_thread;
#endif // CONFIG_THINGSBOARD_TEST_FAILURE
static bool keep_running;
K_SEM_DEFINE(time_request_sem, 1, 1);

#define COAP_ATTRIBUTES_PATH ((const char *const[]){"api", "v1", "+", "attributes", NULL})
#define COAP_RPC_PATH        ((const char *const[]){"api", "v1", "+", "rpc", NULL})

#define COAP_TEST_TIME 12345678

static void attr_write_callback(struct thingsboard_attr *attr)
{
}

static const struct tb_fw_id fw_id = {
	.fw_title = "tb_test",
	.fw_version = "1",
	.device_name = "123456789",
};

void mock_udp_server_thread(void *p1, void *p2, void *p3)
{
	int ret;
	int server_sock;
	struct sockaddr_in server_addr;
	struct sockaddr addr;
	ssize_t received;
	socklen_t addrlen;

	struct coap_packet packet, response;
	struct coap_option options[NUM_COAP_OPTIONS];

	char server_buffer[MOCK_UDP_BUFFER_SIZE];
	char coap_buffer[MOCK_UDP_BUFFER_SIZE];

	server_sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	zassert_true(server_sock >= 0, "socket open failed");

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(CONFIG_COAP_SERVER_PORT);
	ret = zsock_inet_pton(AF_INET, CONFIG_COAP_SERVER_HOSTNAME, &server_addr.sin_addr);
	zassert_equal(ret, 1, "inet_pton failed");

	ret = zsock_bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
	zassert_equal(ret, 0, "bind failed");
	addrlen = sizeof(addr);
	while (keep_running) {
		received = zsock_recvfrom(server_sock, server_buffer, sizeof(server_buffer), 0,
					  &addr, &addrlen);
		if (received == 0) {
			continue;
		}
		LOG_HEXDUMP_INF(server_buffer, received, "received:");
		ret = coap_packet_parse(&packet, server_buffer, received, options,
					NUM_COAP_OPTIONS);
		zassert_equal(ret, 0, "Received something different from a coap package.");
		uint16_t id, token_len;
		uint8_t token[COAP_TOKEN_MAX_LEN];
		id = coap_header_get_id(&packet);
		token_len = coap_header_get_token(&packet, token);
		ret = coap_packet_init(&response, coap_buffer, sizeof(coap_buffer), COAP_VERSION_1,
				       COAP_TYPE_CON, token_len, token, COAP_RESPONSE_CODE_CONTENT,
				       id);
		if (coap_uri_path_match(COAP_ATTRIBUTES_PATH, options, NUM_COAP_OPTIONS)) {
			LOG_INF("Attributes package!");
		} else if (coap_uri_path_match(COAP_RPC_PATH, options, NUM_COAP_OPTIONS)) {
			LOG_INF("Time package!");
			ret = coap_packet_append_payload_marker(&response);
			zassert_equal(ret, 0, "could not append payload marker");
			char *payload = STRINGIFY(COAP_TEST_TIME);
			ret = coap_packet_append_payload(&response, payload, strlen(payload));
			zassert_equal(ret, 0, "could not append payload");
			ret = zsock_sendto(server_sock, response.data, response.offset, 0, &addr,
					   addrlen);
			zassert_equal(ret, response.offset, "Could not send all data");
			LOG_INF("Responded to time package");
			k_sem_give(&time_request_sem);
		}
	}

	ret = zsock_close(server_sock);
	zassert_equal(ret, 0, "close failed");
}

#ifdef CONFIG_THINGSBOARD_TEST_FAILURE
ZTEST(thingsboard, test_thingsboard_failure)
{
	/* since we have no server, there should be no time response. */
	int ret = thingsboard_init(attr_write_callback, &fw_id);
	zassert_equal(ret, -EAGAIN, "Unexpected return value %d", ret);

	/* can't init twice and expect a success value! */
	ret = thingsboard_init(attr_write_callback, &fw_id);
	zassert_equal(ret, -EALREADY, "Unexpected return value %d", ret);
}
#else  // CONFIG_THINGSBOARD_TEST_FAILURE
ZTEST(thingsboard, test_thingsboard_init)
{
	int ret;
	keep_running = true;
	k_thread_create(&udp_thread, udp_stack, K_THREAD_STACK_SIZEOF(udp_stack),
			mock_udp_server_thread, NULL, NULL, NULL, K_PRIO_COOP(3), 0, K_NO_WAIT);

	ret = thingsboard_init(attr_write_callback, &fw_id);
	zassert_equal(ret, 0, "Unexpected return value %d", ret);

	time_t tb_ms = thingsboard_time_msec();
	zassert_true(tb_ms >= COAP_TEST_TIME, "Time is less then what we provided!");
	uint64_t now_ms = k_uptime_get();
	zassert_true(tb_ms <= COAP_TEST_TIME + now_ms, "Time is higher then what we expect!");

	// reset the time semaphore to a taken state.
	k_sem_take(&time_request_sem, K_NO_WAIT);
	// Wait for next time request.
	ret = k_sem_take(&time_request_sem,
			 K_SECONDS((CONFIG_THINGSBOARD_TIME_REFRESH_INTERVAL_SECONDS + 1)));
	zassert_equal(ret, 0, "Did not receive a time request in time.");
	keep_running = false;
}
#endif // CONFIG_THINGSBOARD_TEST_FAILURE

ZTEST_SUITE(thingsboard, NULL, NULL, NULL, NULL, NULL);
