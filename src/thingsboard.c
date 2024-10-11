#include "thingsboard.h"

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <thingsboard_attr_parser.h>

#include "coap_client.h"
#include "tb_fota.h"
#include "provision.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(thingsboard_client, CONFIG_THINGSBOARD_LOG_LEVEL);

static struct {
	int64_t tb_time;      // actual Unix timestamp in ms
	int64_t own_time;     // uptime when receiving timestamp in ms
	int64_t last_request; // uptime when time was last requested in ms
} tb_time;

K_SEM_DEFINE(time_sem, 0, 1);

static attr_write_callback_t attribute_cb;

static void client_request_time(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(work_time, client_request_time);

static const char *access_token;

static int client_handle_attribute_notification(struct coap_client_request *req,
						struct coap_packet *response)
{
	LOG_INF("%s", __func__);

	uint8_t *payload;
	uint16_t payload_len;
	struct thingsboard_attr attr = {0};
	int err;

	LOG_INF("%s", __func__);

	payload = (uint8_t *)coap_packet_get_payload(response, &payload_len);
	if (!payload_len) {
		LOG_WRN("Received empty attributes");
		return payload_len;
	}
	LOG_HEXDUMP_DBG(payload, payload_len, "Received attributes");

	err = thingsboard_attr_from_json(payload, payload_len, &attr);
	if (err < 0) {
		LOG_ERR("Parsing attributes failed");
		return err;
	}

#ifdef CONFIG_THINGSBOARD_FOTA
	thingsboard_check_fw_attributes(&attr);
#endif

	if (attribute_cb) {
		attribute_cb(&attr);
	}
	return 0;
}

/**
 * Parse an int64_t from a non-zero-terminated buffer.
 *
 * The value is expected to be a valid (and current) timestamp.
 * Hence, the only error case that is handled is that the buffer
 * does not actually consist of digits. No attempt is made to validate
 * the resulting number.
 *
 * Limitations:
 * - It does not actually handle negative values
 * - It does not take care of integer overflows
 * - The buffer must only contain valid digits
 */
static int timestamp_from_buf(int64_t *value, const void *buf, size_t sz)
{
	int64_t result = 0;
	size_t i;
	const char *next;

	for (i = 0, next = buf; i < sz; i++, next++) {
		if (*next < '0' || *next > '9') {
			LOG_WRN("Buffer contains non-digits: %c", *next);
			return -EBADMSG;
		}
		result = result * 10 + (*next - '0');
	}

	*value = result;
	return 0;
}

static int client_handle_time_response(struct coap_client_request *req,
				       struct coap_packet *response)
{
	int64_t ts = 0;
	const uint8_t *payload;
	uint16_t payload_len;
	int err;

	LOG_INF("%s", __func__);

	payload = coap_packet_get_payload(response, &payload_len);
	if (!payload_len) {
		LOG_WRN("Received empty timestamp");
		return payload_len;
	}

	err = timestamp_from_buf(&ts, payload, payload_len);
	if (err) {
		LOG_ERR("Parsing of time response failed");
		return err;
	}

	tb_time.tb_time = ts;
	tb_time.own_time = k_uptime_get();
	LOG_DBG("Timestamp updated: %lld", ts);

	/* schedule a refresh request for later. */
	k_work_reschedule(&work_time, K_SECONDS(CONFIG_THINGSBOARD_TIME_REFRESH_INTERVAL_SECONDS));

	k_sem_give(&time_sem);
	return 0;
}

static int client_subscribe_to_attributes(void)
{
	int err;
	struct coap_client_request *request;

	request = coap_client_request_alloc(COAP_TYPE_CON, COAP_METHOD_GET);
	if (!request) {
		return -ENOMEM;
	}

	err = coap_client_request_observe(request);
	if (err < 0) {
		return err;
	}

	const uint8_t *uri[] = {"api", "v1", access_token, "attributes", NULL};
	err = coap_packet_append_uri_path(&request->pkt, uri);
	if (err < 0) {
		return err;
	}

	err = coap_client_send(request, client_handle_attribute_notification);
	if (err < 0) {
		return err;
	}

	LOG_INF("Attributes subscription request sent");

	return 0;
}

static void client_request_time(struct k_work *work)
{
	int err;

	static const char *payload = "{\"method\": \"getCurrentTime\", \"params\": {}}";
	const uint8_t *uri[] = {"api", "v1", access_token, "rpc", NULL};

	err = coap_client_make_request(uri, payload, strlen(payload), COAP_TYPE_CON,
				       COAP_METHOD_POST, client_handle_time_response);
	if (err) {
		LOG_ERR("Failed to request time");
	}

	tb_time.last_request = k_uptime_get();

	// Fallback to ask for time, if we don't receive a response.
	k_work_reschedule(k_work_delayable_from_work(work), K_SECONDS(10));
}

int thingsboard_send_telemetry(const void *payload, size_t sz)
{
	int err;

	const uint8_t *uri[] = {"api", "v1", access_token, "telemetry", NULL};
	err = coap_client_make_request(uri, payload, sz, COAP_TYPE_CON, COAP_METHOD_POST, NULL);
	if (err) {
		LOG_ERR("Failed to send telemetry");
		return err;
	}

	return 0;
}

static void start_client(void);

static const struct tb_fw_id *current_fw;

static void prov_callback(const char *token)
{
	LOG_INF("Device provisioned");
	access_token = token;

#ifdef CONFIG_THINGSBOARD_FOTA
	thingsboard_fota_init(access_token, current_fw);

	if (confirm_fw_update() != 0) {
		LOG_ERR("Failed to confirm FW update");
	}
#endif

	start_client();
}

static void start_client(void)
{
	int err;

	LOG_INF("%s", __func__);

	if (!access_token) {
		LOG_INF("No access token in storage. Requesting provisioning.");

		err = thingsboard_provision_device(current_fw->device_name, prov_callback);
		if (err) {
			LOG_ERR("Could not provision device");
			return;
		}

		return;
	}

	if (client_subscribe_to_attributes() != 0) {
		LOG_ERR("Failed to observe attributes");
	}

	if (k_work_reschedule(&work_time, K_NO_WAIT) < 0) {
		LOG_ERR("Failed to schedule time worker!");
	}
}

int thingsboard_init(attr_write_callback_t cb, const struct tb_fw_id *fw_id)
{
	attribute_cb = cb;
	int ret;

	current_fw = fw_id;

	ret = coap_client_init(start_client);
	if (ret != 0) {
		LOG_ERR("Failed to initialize CoAP client (%d)", ret);
		return ret;
	}

	LOG_INF("Waiting for Timestamp...");
	ret = k_sem_take(&time_sem, K_SECONDS(10));
	if (ret < 0) {
		LOG_ERR("Failed to wait for timestamp: %d", ret);
		return ret;
	}

	return 0;
}

time_t thingsboard_time(void)
{
	return thingsboard_time_msec() / MSEC_PER_SEC;
}

time_t thingsboard_time_msec(void)
{
	time_t result = (time_t)((k_uptime_get() - tb_time.own_time) + tb_time.tb_time);
	return result;
}
