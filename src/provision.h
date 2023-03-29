#ifndef PROVISION_H
#define PROVISION_H

typedef void (*token_callback)(const char *token);

#ifdef CONFIG_THINGSBOARD_USE_PROVISIONING

int thingsboard_provision_device(const char *device_name, token_callback cb);

#else

static int thingsboard_provision_device(const char *device_name, token_callback cb) {
    static char* token = CONFIG_THINGSBOARD_ACCESS_TOKEN;

    cb(token);

    return 0;
}

#endif

#endif /* PROVISION_H */
