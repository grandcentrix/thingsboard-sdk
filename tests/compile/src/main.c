#include <thingsboard.h>
#include <zephyr/ztest.h>

#include <modem/modem_info.h>
#include <zephyr/sys/reboot.h>

void sys_reboot(int type)
{
    while(1) {}
}

int modem_info_string_get(enum modem_info info, char *buf,
			  const size_t buf_size) {
    return 0;
}

int modem_info_name_get(enum modem_info info, char *name) {
    return 0;
}

static void attr_write_callback(struct thingsboard_attr *attr) {

}

static const struct tb_fw_id fw_id = {
    .fw_title = "tb_test",
    .fw_version = "1"
};

ZTEST_SUITE(tb_compile, NULL, NULL, NULL, NULL, NULL);

ZTEST(tb_compile, test_thingsboard_init) {
    int ret = thingsboard_init(attr_write_callback, &fw_id);
    zassert_equal(ret, 0, "Unexpected return value %d", ret);
}
