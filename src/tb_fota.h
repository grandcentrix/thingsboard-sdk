#ifndef TB_FOTA_H
#define TB_FOTA_H

#include <thingsboard.h>

int confirm_fw_update(void);

struct thingsboard_attr;

void thingsboard_check_fw_attributes(struct thingsboard_attr *attr);

void thingsboard_fota_init(const char *access_token, const struct tb_fw_id *current_fw);

#endif /* TB_FOTA_H */
