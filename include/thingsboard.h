#ifndef THINGSBOARD_H
#define THINGSBOARD_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

struct thingsboard_attr;

typedef void (*attr_write_callback)(struct thingsboard_attr *attr);

time_t thingsboard_time(void);

time_t thingsboard_time_msec(void);

int thingsboard_send_telemetry(const void *payload, size_t sz);

int thingsboard_start_fw_update(void);

struct tb_fw_id {
	const char *fw_title;
	const char *fw_version;
};

int thingsboard_init(attr_write_callback attr_cb, const struct tb_fw_id *fw_id);

//void thingsboard_connect(void);

#endif
