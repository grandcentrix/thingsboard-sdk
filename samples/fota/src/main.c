#include <thingsboard.h>

#include <modem/lte_lc.h>
#include <modem/nrf_modem_lib.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <string.h>

LOG_MODULE_REGISTER(main);

static struct tb_fw_id fw_id = {.fw_title = "thingsboard-sdk-fota-sample",
				.fw_version = "1",
				.device_name = "sample-device"};

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
	err = thingsboard_init(NULL, &fw_id);
	if (err) {
		LOG_ERR("Could not initialize thingsboard connection, error (%d) :%s", err,
			strerror(-err));
		return err;
	}
}
