#include <thingsboard.h>
#include <zephyr/ztest.h>

#include <zephyr/sys/reboot.h>

static void attr_write_callback(struct thingsboard_attr *attr) {

}

static const struct tb_fw_id fw_id = {
	.fw_title = "tb_test",
	.fw_version = "1",
	.device_name = "123456789",
};

ZTEST_SUITE(tb_compile, NULL, NULL, NULL, NULL, NULL);

ZTEST(tb_compile, test_thingsboard_init) {
    int ret = thingsboard_init(attr_write_callback, &fw_id);
    zassert_equal(ret, 0, "Unexpected return value %d", ret);
}
