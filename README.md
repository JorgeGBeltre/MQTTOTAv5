# MQTTOTAv5

**Secure Over-The-Air firmware updates for ESP32 over MQTT 5.0**

[![Arduino Library](https://img.shields.io/badge/Arduino-Library-teal)](https://github.com/JorgeGBeltre/MQTTOTAv5)
[![Platform](https://img.shields.io/badge/platform-ESP32-blue)](https://www.espressif.com/en/products/socs/esp32)
[![MQTT 5.0](https://img.shields.io/badge/MQTT-5.0-orange)](https://mqtt.org)

---

**MQTTOTAv5** is an SDK that revolutionizes firmware management for ESP32-based IoT devices. By leveraging the full power of the MQTT 5.0 protocol, it provides a seamless, secure, and scalable solution for Over-The-Air updates in distributed IoT ecosystems. Whether you're managing a handful of devices or thousands across global deployments, MQTTOTAv5 ensures reliable firmware delivery with enterprise-level security, incremental hash verification, HMAC authentication, and robust error handling — all without blocking your application's main loop.

## Table of Contents

- [Features](#features)
- [Dependencies](#dependencies)
- [Quick Start](#quick-start)
  - [1. Install libraries](#1-install-libraries)
  - [2. Basic sketch](#2-basic-sketch)
  - [3. Backend Implementation](#3-backend-implementation)
- [Public API](#public-api)
  - [Initialization](#initialization)
  - [Security](#security)
  - [Callbacks](#callbacks)
  - [Main loop](#main-loop)
  - [Status (all const)](#status-all-const)
  - [Control](#control)
  - [Diagnostics](#diagnostics)
- [OTAv5State values](#otav5state-values)
- [MQTT 5.0 Message Format](#mqtt-50-message-format)
  - [Incoming OTA message (broker → device)](#incoming-ota-message-broker--device)
  - [Outgoing device messages](#outgoing-device-messages)
- [Configuration Macros](#configuration-macros)
- [Examples](#examples)
- [Security Architecture](#security-architecture)
- [Changelog](#changelog)
- [Broker Compatibility](#broker-compatibility)
- [License](#license)
- [Contact](#contact)
- [Support](#support)

---

## Features

| Feature | Description |
|---|---|
| **Transport** | `ESP32_MQTTv5` — native MQTT 5.0, no PubSubClient |
| **SHA-256** | Full firmware hash via `mbedtls` (no extra deps) |
| **Incremental hash** | SHA-256 updated per chunk — no temporary full buffer |
| **HMAC-SHA256** | Obligatory signature in production; disable for dev |
| **User Properties** | `sha256`, `hmac_sig`, `target_model` in MQTT 5.0 headers |
| **Chunked OTA** | Arbitrary firmware size, direct `esp_ota_ops.h` API |
| **Non-blocking** | No `delay()` — restart timer handled in `handle()` |
| **Rollback** | `esp_ota_mark_app_valid_cancel_rollback()` on boot |
| **AUTH flow** | `onAuthRequired()` callback for broker challenge-response |
| **Will Message** | 30 s delay + `content_type: application/json` |
| **Topic separation** | `Subscription Identifier` filters OTA vs. app topics |
| **Correlation Data** | Links each chunk to its ACK |
| **Response Topic** | Broker knows where to route ACK responses |
| **Message Expiry** | Stale OTA messages discarded automatically |

---

## Dependencies

- [ESP32_MQTTv5](https://github.com/JorgeGBeltre/ESP32_MQTTv5)
- [ArduinoJson](https://arduinojson.org/) ≥ 6.x
- ESP32 core ≥ 2.0 (Arduino-ESP32)
- `mbedtls` — bundled with ESP32 core, no installation needed

---

## Quick Start

### 1. Install libraries

In Arduino IDE: `Sketch → Include Library → Add .ZIP Library` for both `ESP32_MQTTv5` and `MQTTOTAv5`.

### 2. Basic sketch

```cpp
#include "ESP32_MQTTv5.h"
#include "MQTTOTAv5.h"

ESP32_MQTTv5 mqtt;
MQTTOTAv5    ota;

void setup() {
    // ... WiFi connect ...

    mqtt.begin("192.168.1.100", 1883);
    mqtt.onConnect([]() {
        ota.begin(mqtt, "my-device", "1.0.0");
        ota.requireSignature(false); // dev only
    });
    mqtt.connect("esp32-client");

    ota.onSuccess([](const String& ver) {
        Serial.printf("Updated to %s!\n", ver.c_str());
    });
}

void loop() {
    mqtt.loop();
    ota.handle(); // required
}
```

### 3. Backend Implementation

To use MQTTOTA in your project, you'll need an MQTT/MQTTS/MQTTv5.0 server to manage OTA updates. You can implement your own backend using our reference repository:

**MQTT/MQTTS/MQTTv5.0 Broker support OTA Updates**
- **Repository:** [github.com/Ruben890/Mqtt-Broker](https://github.com/Ruben890/Mqtt-Broker)
- **Description:** Complete backend for managing broker via MQTT/MQTTS/MQTTv5.0
- **Features:**
  - Configurable MQTT/MQTTS/MQTTv5.0 server
  - IoT device management
  - Firmware update delivery
  - OTA progress tracking
  - Error handling and retry mechanisms

**Steps to use the backend:**
1. Clone the backend repository
2. Configure the MQTT broker according to your needs
3. Implement the update delivery logic
4. Connect your ESP32 devices to the broker
5. Manage OTA updates from a centralized interface

**Example workflow:**
```javascript
// From your backend
1. Prepare firmware in base64 format
2. Publish MQTT/MQTTS/MQTT5 message to target device
3. Monitor progress via callbacks
4. Confirm successful completion
5. Log results in database
```

---

## Public API

### Initialization

```cpp
void begin(ESP32_MQTTv5& mqtt,
           const String& deviceName,
           const String& firmwareVersion,
           const String& otaTopic = "");  // default: "ota/<deviceName>"
```

Registers `onMessage` and `onAuth` handlers on the `mqtt` object and subscribes to the OTA topic. **Must be called after** `mqtt.connect()` returns (best inside `mqtt.onConnect()`).

---

### Security

```cpp
void setSecurityKey(const char* key);    // HMAC-SHA256 shared key
void requireSignature(bool required);    // default: true (production)
```

> **Warning**: `requireSignature(false)` should only be used during development. In production, pass `--key` to the Python publisher and call `setSecurityKey()` on the device. Without a valid HMAC, the OTA is rejected.

---

### Callbacks

```cpp
void onProgress(OTAv5ProgressCb cb);    // (int pct, String version)
void onError(OTAv5ErrorCb cb);          // (String error, String version)
void onSuccess(OTAv5SuccessCb cb);      // (String version)
void onStateChange(OTAv5StateCb cb);    // (uint8_t state)
void onAuthRequired(OTAv5AuthCb cb);    // (String method, String data)
```

---

### Main loop

```cpp
void handle();  // call every loop() iteration
```

Handles OTA timeout and the non-blocking restart timer after a successful update.

---

### Status (all `const`)

```cpp
bool            isUpdateInProgress() const;
bool            isValidating()        const;
bool            isWriting()           const;
OTAv5State      getCurrentState()     const;
String          getCurrentVersion()   const;
String          getDeviceID()         const;
int             getProgress()         const;
OTAv5Statistics getStatistics()       const;
size_t          getFreeOTASpace()     const;
```

---

### Control

```cpp
void abortUpdate();
void setAutoReset(bool enable = true);
void setMaxRetries(int maxRetries);
void enableVersionCheck(bool enable = true);
void enableRollbackProtection(bool enable = true);
```

---

### Diagnostics

```cpp
void   printDiagnostics() const;     // detailed Serial output
String getBootPartitionInfo() const;
static void   logMemoryStatus();
static size_t getFreeHeap();
static bool   checkMemory(size_t requiredBytes);
```

---

## OTAv5State values

| Value | Name | Description |
|---|---|---|
| 0 | `OTAV5_IDLE` | No OTA in progress |
| 1 | `OTAV5_AUTHENTICATING` | AUTH challenge in progress |
| 2 | `OTAV5_RECEIVING` | First chunk / single payload received |
| 3 | `OTAV5_DECODING` | Base64 decoding |
| 4 | `OTAV5_VALIDATING` | SHA-256 / HMAC verification |
| 5 | `OTAV5_WRITING` | Writing to OTA partition |
| 6 | `OTAV5_COMPLETING` | `esp_ota_end` + set boot partition |
| 7 | `OTAV5_SUCCESS` | OTA succeeded, pending restart |
| 8 | `OTAV5_ERROR` | OTA failed |
| 9 | `OTAV5_ABORTED` | Aborted by user or timeout |

---

## MQTT 5.0 Message Format

### Incoming OTA message (broker → device)

**Topic:** `ota/<device>`  
**QoS:** 1

#### MQTT 5.0 User Properties (preferred metadata transport)

| Key | Value | Example |
|---|---|---|
| `firmware_version` | Target version | `"1.0.1"` |
| `sha256` | Hex SHA-256 of full firmware | `"a3f4..."` (64 chars) |
| `hmac_sig` | Hex HMAC-SHA256 (full firmware) | `"9c1b..."` (64 chars) |
| `target_model` | Model filter (empty = any) | `"sensors-v2"` |

#### MQTT 5.0 Properties

| Property | Purpose |
|---|---|
| `Correlation Data` | Chunk ID for ACK correlation (e.g. `"1.0.1-3"`) |
| `Response Topic` | Where to send ACK (e.g. `"ota/my-device/ack"`) |
| `Message Expiry Interval` | Discard stale messages (e.g. 600 s) |
| `Content-Type` | `"application/json"` |
| `Payload Format Indicator` | `1` (UTF-8) |

#### JSON Payload

```json
{
  "firmware_version": "1.0.1",
  "base64":           "<Base64-encoded firmware chunk>",
  "part_index":       1,
  "total_parts":      12
}
```

> For single-chunk OTA: `part_index=1`, `total_parts=1`.
> For v1 compatibility also accepted: `Base64Part`, `PartIndex`, `TotalParts`, `FirmwareVersion`, `EventType: "UpdateFirmwareDevice"`.

---

### Outgoing device messages

| Topic | Content |
|---|---|
| `ota/<device>/progress` | `{ "device", "version", "progress", "bytes" }` |
| `ota/<device>/error` | `{ "device", "version", "error", "ts" }` |
| `ota/<device>/success` | `{ "device", "version", "success", "bytes", "ts" }` |
| `ota/<device>/state` | `{ "device", "state", "name", "ts" }` |
| `ota/<device>/ack` | `{ "device", "ok", "msg", "ts" }` + Correlation Data |
| `ota/<device>/status` | Will message: `{ "device", "version", "status":"offline" }` |

---

## Configuration Macros

Override any of these **before** `#include "MQTTOTAv5.h"`:

```cpp
#define MQTTOTAV5_JSON_SIZE       4096      // StaticJsonDocument size
#define MQTTOTAV5_CHUNK_SIZE      8192      // OTA write chunk size
#define MQTTOTAV5_TIMEOUT_MS      420000UL  // 7-minute OTA timeout
#define MQTTOTAV5_MIN_MEMORY      45000     // Min free heap before OTA
#define MQTTOTAV5_MAX_RETRIES     3         // Chunk retry limit
#define MQTTOTAV5_RESTART_DELAY_MS 3000UL  // Non-blocking post-OTA restart delay
#define MQTTOTAV5_SUB_ID          0x0A     // Subscription Identifier
#define MQTTOTAV5_MSG_EXPIRY_S    600      // Message Expiry for subscriptions
```

---

## Examples

| Sketch | Description |
|---|---|
| `BasicOTAv5` | Plain TCP, Mosquitto local, no signature |
| `SecureOTAv5` | TLS + SHA-256 + HMAC, EMQX / Mosquitto TLS |
| `ChunkedOTAv5` | Large firmware, incremental hash, ACK stats |

---

## Security Architecture

```
Device                         Broker / Backend
──────                         ────────────────
begin()                        
  └─ subscribe("ota/device")
     + Subscription ID 0x0A

                               publish("ota/device")
                                 User Properties:
                                   sha256:    hex(sha256(firmware))
                                   hmac_sig:  hex(HMAC-SHA256(key, firmware))
                                 Correlation Data: "1.0.1-1"
                                 Response Topic: "ota/device/ack"

_onMQTTMessage()
  ├─ Filter Subscription ID
  ├─ Parse User Properties
  ├─ Version check
  ├─ Memory check
  ├─ esp_ota_begin()
  ├─ Per chunk:
  │    ├─ Base64 decode
  │    ├─ mbedtls_sha256_update()
  │    └─ esp_ota_write()
  ├─ mbedtls_sha256_finish() → compare sha256
  ├─ esp_ota_end()  (IDF validates internally)
  └─ esp_ota_set_boot_partition()

handle() → non-blocking restart
  └─ esp_ota_mark_app_valid_cancel_rollback() on next boot
```

---

## Changelog

### v1.0.0
- Initial release with full MQTT 5.0 feature set
- SHA-256 incremental verification
- HMAC-SHA256 signature enforcement
- Non-blocking restart timer
- Rollback protection
- `getFreeOTASpace()` implemented correctly
- `StaticJsonDocument` throughout (no heap fragmentation)

---

---

##  Broker Compatibility

Tested with:
- [Mosquitto](https://mosquitto.org/) 2.0+ (with MQTT 5.0 enabled)
- [EMQX](https://www.emqx.com/) 5.0+
- [HiveMQ Cloud](https://www.hivemq.com/) (MQTT 5.0 plan)
- [AWS IoT Core](https://aws.amazon.com/iot-core/) (via custom authentication)

If you encounter issues, please open an issue with broker version and configuration.

---

##  License

This library is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

## Contact

Author: **Jorge Gaspar Beltre Rivera**  
Project: **MQTTOTAv5 - For OTA Updates via MQTTv5/MQTTSv5**

 [![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/JorgeGBeltre)
 [![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/jorge-gaspar-beltre-rivera/)
 [![Email](https://img.shields.io/badge/Email-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:Jorgegaspar3021@gmail.com)

---

##  Support

This project is developed independently.

Even a small contribution helps me dedicate more time to development, testing, and releasing new features.

 [![Buy Me a Coffee](https://img.shields.io/badge/Buy_Me_a_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://www.paypal.com/donate/?hosted_button_id=2VLA8BWT967LU)