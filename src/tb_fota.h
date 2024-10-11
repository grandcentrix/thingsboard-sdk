#ifndef TB_FOTA_H
#define TB_FOTA_H

#include <thingsboard.h>

/**
 * Should be called as soon as CoAP connectivity works.
 * This confirms the image in MCUboot and sends the current
 * version as given by struct tb_fw_id (on init) to Thingsboard,
 * if the image has not already been confirmed.
 */
int confirm_fw_update(void);

struct thingsboard_attr;

/**
 * Call this function when attributes have been received to check
 * for the relevant FOTA attributes. If all data is available,
 * it also attempts to start an update.
 */
void thingsboard_check_fw_attributes(struct thingsboard_attr *attr);

/**
 * Initialize the FOTA system. The system only stores the pointers internally
 * and does not copy the memory, so changing the pointed-to memory later is
 * an error and undefined behavior may happen.
 */
void thingsboard_fota_init(const char *access_token, const struct tb_fw_id *current_fw);

#endif /* TB_FOTA_H */
