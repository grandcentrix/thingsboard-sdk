#include <thingsboard.h>
#include <thingsboard_attr_parser.h>

#include <modem/lte_lc.h>
#include <modem/nrf_modem_lib.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <string.h>

LOG_MODULE_REGISTER(main);

static struct tb_fw_id fw_id = {
	.fw_title = "attributes-sample", .fw_version = "v1.0.0", .device_name = "sample-device"};

void attr_write_callback(struct thingsboard_attr *attr)
{
	if (attr->foo_parsed) {
		LOG_INF("Received value for attribute 'foo' from server: '%s'", attr->foo);
	}
}

int main(void)
{
	int err = 0;

	LOG_INF("Initializing modem library");
	err = nrf_modem_lib_init();
	if (err) {
		LOG_ERR("Failed to initialize the modem library, error (%d): %s", err,
			strerror(-err));
		return err;
	}

	err = lte_lc_func_mode_set(LTE_LC_FUNC_MODE_ACTIVATE_LTE);
	if (err) {
		LOG_ERR("Failed to activate LTE");
		return err;
	}

	LOG_INF("Connecting to LTE network");
	err = lte_lc_connect();
	if (err) {
		LOG_ERR("Could not establish LTE connection, error (%d): %s", err, strerror(-err));
		return err;
	}
	LOG_INF("LTE connection established");

	LOG_INF("Connecting to Thingsboards");
	err = thingsboard_init(&attr_write_callback, &fw_id);
	if (err) {
		LOG_ERR("Could not initialize thingsboard connection, error (%d) :%s", err,
			strerror(-err));
		return err;
	}
}
