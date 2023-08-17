#include <thingsboard.h>
#include <ztest.h>

#include <modem/modem_info.h>
#include <sys/reboot.h>

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

static void test_thingsboard_init(void) {
    int ret = thingsboard_init(attr_write_callback, &fw_id);
    zassert_equal(ret, 0, "Unexpected return value %d", ret);
}

void test_main(void)
{
	ztest_test_suite(tb_compile,
        ztest_unit_test(test_thingsboard_init)
    );

	ztest_run_test_suite(tb_compile);
}
