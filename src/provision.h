#ifndef PROVISION_H
#define PROVISION_H

/**
 * Callback that will be called with the token as soon as
 * provisioning has been completed successfully.
 */
typedef void (*token_callback)(const char *token);

#ifdef CONFIG_THINGSBOARD_USE_PROVISIONING

/**
 * Provision the device.
 */
int thingsboard_provision_device(const char *device_name, token_callback cb);

#else

/**
 * Provision the device.
 * @note This is a dummy implementation that calls the callback
 * immediately.
 */
static int thingsboard_provision_device(const char *device_name, token_callback cb)
{
	static char *token = CONFIG_THINGSBOARD_ACCESS_TOKEN;

	cb(token);

	return 0;
}

#endif /* CONFIG_THINGSBOARD_USE_PROVISIONING */

#endif /* PROVISION_H */
