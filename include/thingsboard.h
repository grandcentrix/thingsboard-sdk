#ifndef THINGSBOARD_H
#define THINGSBOARD_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

struct thingsboard_attr;

/**
 * This callback will be called when new shared attributes are
 * received from the Thingsboard server.
 * For information on how the struct thingsboard_attr is defined,
 * see top-level CMakeLists.txt and scripts/gen_json_parser.py.
 */
typedef void (*attr_write_callback_t)(struct thingsboard_attr *attr);

/**
 * Return the current time in seconds.
 * Time is initially retreived from Thingsboard, given that your
 * rule chain supports it.
 * You can import the file root_rule_chain.json on your Thingsboard
 * instance to create a rule chain with the required D2C function.
 */
time_t thingsboard_time(void);

/**
 * Same as thingsboard_time, but the return value is not truncated to
 * seconds. Please be aware that no special care is taken to guarantee
 * the accuracy of the time. Due to network latency, the time will
 * be off in the order of multiple seconds.
 */
time_t thingsboard_time_msec(void);

/**
 * Send telemetry.
 * See https://thingsboard.io/docs/user-guide/telemetry/ for details.
 * If you provide your own timestamp, be aware that Thingsboard expects
 * timestamps with millisecond-precision as provided by thingsboard_time_msec.
 */
int thingsboard_send_telemetry(const void *payload, size_t sz);

/**
 * This callback will be called when the response for an RPC call
 * was received from the Thingsboard server.
 */
typedef void (*rpc_callback_t)(const uint8_t *data, size_t len);

/**
 * Send RPC call.
 * 'method' is required, a callback in case the call returns data, too.
 * Parameters are an optional string in JSON format as the variadic arguments
 * See https://thingsboard.io/docs/reference/coap-api/#client-side-rpc for details.
 */
int thingsboard_rpc(const char *method, rpc_callback_t cb, const char *params);

struct tb_fw_id {
	/** Title of your firmware, e.g. <project>-prod. This
	 * must match to what you configure on your thingsboard
	 * FOTA page.
	 */
	const char *fw_title;

	/** Version of your firmware, e.g. 8b5ca79. This
	 * must match to what you configure on your thingsboard
	 * FOTA page.
	 */
	const char *fw_version;

	/** Name of your device. for example the ICCID of the SIM-Card. */
	const char *device_name;
};

/**
 * Initialize the Thingsboard library.
 *
 * This function should only be called once. The pointer to the current FW id
 * is stored internally, the memory is not copied. Do not change the contents
 * later.
 */
int thingsboard_init(attr_write_callback_t attr_cb, const struct tb_fw_id *fw_id);

#endif
