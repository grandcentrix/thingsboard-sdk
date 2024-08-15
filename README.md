# thingsboard-sdk
This module is an SDK to interface a Zephyr-based project with an instance of https://thingsboard.io using a cellular connection. Internally, CoAP is used to interface with the server.

This module uses RPC calls to fetch the current time stamp from the server. You have to implement this RPC call in your rule chain for this to work. An example implementation can be found when you import `root_rule_chain.json` into your Thingsboard tenant.

## Installation
This is a Zephyr module, so just include it into your project's west.yml. It comes with the correct nRF SDK version included, so you need to use `import:true`.

#### **`west.yml`**
```yml
manifest:
  remotes:
    - name: gcx
      url-base: ssh://git@github.com/GCX-EMBEDDED
  projects:
    - name: thingsboard-sdk
      remote: gcx
      revision: v2.7.0
      path: modules/thingsboard
      import: true
  self:
    path: my-project
```

This is the minimal manifest that you need to use in your project.

### Requirements
Besides the typical Zephyr toolchain, this module comes with its own build-time Python requirements. Install with pip:
```sh
pip install -r thingsboard/scripts/requirements.txt
```

## Functionality
Please make sure to have read and understood https://thingsboard.io/docs/.

### Initialization
To initialize the module, you need two things:
- A callback to be notified when attributes change
- A descriptor of your current firmware version according to thingsboard semantics

```c
static struct tb_fw_id fw_id;

static void handle_attr_update(struct thingsboard_attr *attr) {
    /* Handle attribute changes */
}

int main() {
    fw_id.fw_title = "my-app";
    fw_id.fw_version = fw_version_str;

    thingsboard_init(handle_attr_update, &fw_id);
}
```

### Connecting
The module takes care of modem enabling, socket creating and connecting to the server automatically. You just have to configure URL and port of the Thingsboard CoAP server, using `config COAP_CLIENT_NUM_MSGS` and `config COAP_CLIENT_MSG_LEN`. CoAP reliability can be fine-tuned using `config COAP_NUM_RETRIES` and the Zephyr-internal `config COAP_INIT_ACK_TIMEOUT_MS`. Using NB-IoT, 15000 is a good starting value for the latter.

### Sending telemetry to cloud
```c
/**
 * Send telemetry.
 * See https://thingsboard.io/docs/user-guide/telemetry/ for details.
 * If you provide your own timestamp, be aware that Thingsboard expects
 * timestamps with millisecond-precision as provided by thingsboard_time_msec.
*/
int thingsboard_send_telemetry(const void *payload, size_t sz);
```
As outlined in the [official Thingsboard documentation](https://thingsboard.io/docs/user-guide/telemetry/), by default, their telemetry endpoint expects a JSON string with values:
```json
{
  "temperature": 42.2,
  "humidity": 70
}
```

You can also configure your device profile to expect protobuf or custom content encodings.

You can include your own timestamp using the syntax documented by Thingsboard:
```json
{
  "ts": 1527863043000,
  "values": {
    "temperature": 42.2,
    "humidity": 70
  }
}
```
If you don't, Thingsboard simply uses its own current time on reception. This feature is useful for example if you want to collect data over time and upload later at once. You can then also use Thingsboard's rule chain to split an array into single messages, so that you only have to send one long message.

### Sending configuration to device
To configure devices, Thingsboard has the concept of attributes, namely [shared attributes](https://thingsboard.io/docs/user-guide/attributes/#shared-attributes).
These attributes are one big JSON object with keys. Some of the keys are pre-defined by other functionality (e.g. this mechanism is also used for Thingsboard's FOTA component), but you can also define and use any of your own.

Parsing JSON on an embedded device can be a huge pain. Zephyr comes with its own JSON library where the schema of the expected JSON has to be defined with macros.
One challenge here is to split the attributes sent by the server into the parts that the individual subsystems need - e.g. FOTA, and your application. The first approach was to just copy the JSON and have it parsed by every consumer individually, but this induces a huge overhead and feels clumsy.

To solve all of these problems, this library comes with a generator for Zephyr JSON schemas, fed with _actual_ JSON schema files.

The plural here is key: The generator is able to merge multiple files into one JSON schema. This allows you to define attributes used in your app separately from those that are needed by the library itself. To add your own JSON schema files into the pool, do like the following in your app's CMakeLists.txt:

```cmake
set_property(
    TARGET thingsboard
    APPEND
    PROPERTY JSON_SCHEMAS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/profile.jsonschema
)
```

There is also an [example directory](scripts/example) that you can look at. Note how both fields from `scripts/example/example.jsonschema` and `scripts/example/extra.jsonschema` end up in the same struct in `scripts/example/output/example_parser.h`:
#### **`example.jsonschema`**
```json
{
    "type": "object",
    "properties": {
        "status": { "type": "string" },
        "credentialsType": { "type": "string" },
        "credentialsValue": { "type": "string" }
    }
}
```

#### **`extra.jsonschema`**
```json
{
    "type": "object",
    "properties": {
        "extra_value": { "type": "string" }
    }
}
```

#### **`example_parser.h`**
```c
struct example {
	bool status_parsed;
	bool credentialsType_parsed;
	bool credentialsValue_parsed;
	bool extra_value_parsed;
	char *status;
	char *credentialsType;
	char *credentialsValue;
	char *extra_value;
};
```

Also, note how for all fields, beside the actual value, there is a bool with `<name>_parsed`. This bool denotes if the field was present in the attribute struct received from the cloud server. If this field is false, you should not try to interpret the values in the actual field value, the contents are undefined.

### RPC calls - device to cloud
This functionality is implemented, but not exposed in a general fashion. The module uses this functionality to get the current time from the server.

### RPC calls - cloud to device
This functionality is not implemented. One would need to observe the respective CoAP endpoint and take action depending on the received payload.

### Device provisioning
The provisioning functionality is fully implemented. Using it is straight forward using the Kconfig options:
```
config THINGSBOARD_USE_PROVISIONING
    bool "Provision devices"

config THINGSBOARD_PROVISIONING_KEY
    string "Provisioning key"

config THINGSBOARD_PROVISIONING_SECRET
    string "Provisioning secret"
```
Please refer to the Thingsboard documentation for further information. Please note that the received access token is stored persistently in flash. If you erase your device completely, it will be lost forever. You can not reprovision a device without also deleting it on the server. During development, it might be helpful not to use provisioning, but to manually create devices and using the access token, utilizing `config THINGSBOARD_ACCESS_TOKEN`.

### Firmware update
Firmware update is fully implemented. Using the Thingsboard-provided mechanisms, the library will pull a new firmware image and reboot the device.
