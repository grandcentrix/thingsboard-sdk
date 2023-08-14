#include "thingsboard.h"

#include <string.h>

#include <kernel.h>
#include <net/coap.h>
#include <thingsboard_attr_parser.h>
#include <modem/at_cmd_parser.h>
#include <modem/at_params.h>
#include <modem/lte_lc.h>
#include <modem/modem_info.h>

#include "coap_client.h"
#include "tb_fota.h"
#include "provision.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(thingsboard_client);

static struct {
	int64_t tb_time; // actual Unix timestamp in ms
	int64_t own_time; // uptime when receiving timestamp in ms
	int64_t last_request; // uptime when time was last requested in ms
} tb_time;

K_SEM_DEFINE(time_sem, 0, 1);

static attr_write_callback_t attribute_cb;

#define TIME_RETRY_INTERVAL 10000U
#define TIME_REFRESH_INTERVAL 3600000U

static void time_worker(struct k_work *work);

K_WORK_DELAYABLE_DEFINE(work_time, time_worker);

static const char *access_token;

static bool provisioned;
static bool initialized;

static void client_handle_attribute_notification(struct coap_client_request *req, struct coap_packet *response)
{
	LOG_INF("%s", __func__);

	uint8_t *payload;
	uint16_t payload_len;
	struct thingsboard_attr attr = {0};
	int err;

	LOG_INF("%s", __func__);

	payload = (uint8_t*)coap_packet_get_payload(response, &payload_len);
	if (!payload_len) {
		LOG_WRN("Received empty attributes");
		return;
	}
	LOG_HEXDUMP_DBG(payload, payload_len, "Received attributes");

	err = thingsboard_attr_from_json(payload, payload_len, &attr);
	if (err < 0) {
		LOG_ERR("Parsing attributes failed");
		return;
	}

	thingsboard_check_fw_attributes(&attr);

	if (attribute_cb) {
		attribute_cb(&attr);
	}
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
static int timestamp_from_buf(int64_t *value, const void *buf, size_t sz) {
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

static void client_handle_time_response(struct coap_client_request *req, struct coap_packet *response)
{
	int64_t ts = 0;
	const uint8_t *payload;
	uint16_t payload_len;
	int err;

	LOG_INF("%s", __func__);

	payload = coap_packet_get_payload(response, &payload_len);
	if (!payload_len) {
		LOG_WRN("Received empty timestamp");
		return;
	}

	err = timestamp_from_buf(&ts, payload, payload_len);
	if (err) {
		LOG_ERR("Parsing of time response failed");
		return;
	}

	tb_time.tb_time = ts;
	tb_time.own_time = k_uptime_get();

	k_sem_give(&time_sem);
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

static int client_request_time(void) {
	int err;

	static const char *payload = "{\"method\": \"getCurrentTime\", \"params\": {}}";
	const uint8_t *uri[] = {"api", "v1", access_token, "rpc", NULL};

	err = coap_client_make_request(uri, payload, strlen(payload), COAP_TYPE_CON, COAP_METHOD_POST, client_handle_time_response);
	if (err) {
		LOG_ERR("Failed to request time");
		return err;
	}

	tb_time.last_request = k_uptime_get();

	return 0;
}

static void time_worker(struct k_work *work) {
	ARG_UNUSED(work);

	int64_t since_last_request = k_uptime_get() - tb_time.last_request;

	// Request is due
	if ((!tb_time.last_request) ||
		(since_last_request >= TIME_REFRESH_INTERVAL) ||
		(tb_time.last_request > tb_time.own_time
			&& since_last_request >= TIME_RETRY_INTERVAL)) {
		client_request_time();
	}

	k_work_schedule(&work_time, K_MSEC(TIME_RETRY_INTERVAL));
}

static void modem_configure(void)
{
#if defined(CONFIG_LTE_LINK_CONTROL)
	if (IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT)) {
		/* Do nothing, modem is already turned on
		 * and connected.
		 */
	} else {
		int err;

		LOG_INF("LTE Link Connecting ...");
		err = lte_lc_init_and_connect();
		__ASSERT(err == 0, "LTE link could not be established.");
		LOG_INF("LTE Link Connected!");
	}
#endif /* defined(CONFIG_LTE_LINK_CONTROL) */
}

int thingsboard_send_telemetry(const void *payload, size_t sz) {
	int err;

	const uint8_t *uri[] = {"api", "v1", access_token, "telemetry", NULL};
	err = coap_client_make_request(uri, payload, sz, COAP_TYPE_CON, COAP_METHOD_POST, NULL);
	if (err) {
		LOG_ERR("Failed to send telemetry");
		return err;
	}

	return 0;
}

static void print_modem_info(void) {
	char info_name[50];
	char modem_info[50];

	enum modem_info infos[] = {
		MODEM_INFO_FW_VERSION,
		MODEM_INFO_UICC,
		MODEM_INFO_IMSI,
		MODEM_INFO_ICCID,
		MODEM_INFO_APN,
		MODEM_INFO_IP_ADDRESS
	};

	int ret;

	for (size_t i = 0; i < ARRAY_SIZE(infos); i++) {
		ret = modem_info_string_get(infos[i],
						modem_info,
						sizeof(modem_info));
		if (ret < 0) {
			return;
		}
		ret = modem_info_name_get(infos[i],
						info_name);
		if (ret < 0 || ret > sizeof(info_name)) {
			return;
		}
		info_name[ret] = '\0';
		LOG_INF("Value of %s is %s", log_strdup(info_name), log_strdup(modem_info));
	}
}

static void start_client(void) {
	if (client_subscribe_to_attributes() != 0) {
		LOG_ERR("Failed to observe attributes");
	}

	if (client_request_time() != 0) {
		LOG_ERR("Failed to request time");
	}

	if (k_work_schedule(&work_time, K_NO_WAIT) < 0) {
		LOG_ERR("Failed to schedule time worker!");
	}
}

static const struct tb_fw_id *current_fw;

static void prov_callback(const char *token) {
	LOG_INF("Device provisioned");
	access_token = token;
	provisioned = true;

	thingsboard_fota_init(access_token, current_fw);

	if (confirm_fw_update() != 0) {
		LOG_ERR("Failed to confirm FW update");
	}

	start_client();
}

void coap_client_setup_cb(void) {
	LOG_INF("%s", __func__);
	char name[30];
	int err;

	if (!initialized) {
		err = modem_info_string_get(MODEM_INFO_ICCID, name, sizeof(name));
		if (err < 0) {
			LOG_ERR("Could not fetch ICCID");
			return;
		}

		err = thingsboard_provision_device(name, prov_callback);
		if (err) {
			LOG_ERR("Could not provision device");
			return;
		}

		initialized = true;
	}

	if (provisioned) {
		start_client();
	}
}

int thingsboard_init(attr_write_callback_t cb, const struct tb_fw_id *fw_id) {
	attribute_cb = cb;
	int ret;

	current_fw = fw_id;

	modem_configure();

	print_modem_info();

	if (coap_client_init(coap_client_setup_cb) != 0) {
		LOG_ERR("Failed to initialize CoAP client");
		return -1;
	}

	LOG_INF("Waiting for Timestamp...");
	ret = k_sem_take(&time_sem, K_SECONDS(10));
	if (ret < 0) {
		LOG_ERR("Failed to wait for timestamp: %d", ret);
	}

	return 0;
}

time_t thingsboard_time(void) {
	return thingsboard_time_msec() / MSEC_PER_SEC;
}

time_t thingsboard_time_msec(void) {
	time_t result = (time_t) ((k_uptime_get() - tb_time.own_time) + tb_time.tb_time);
	return result;
}
