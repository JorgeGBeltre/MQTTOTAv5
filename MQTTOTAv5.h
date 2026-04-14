#ifndef MQTTOTAV5_H
#define MQTTOTAV5_H

/**
 * @file MQTTOTAv5.h
 * @brief MQTTOTAv5 — Over-The-Air firmware update library for ESP32 using
 * MQTT 5.0
 *
 * Features:
 *  - Native MQTT 5.0 via ESP32_MQTTv5
 *  - SHA-256 firmware verification (mbedtls)
 *  - HMAC-SHA256 signature verification
 *  - Metadata via MQTT 5.0 User Properties (sha256, hmac_sig, target_model)
 *  - Chunked OTA with incremental SHA-256 hashing
 *  - Message Expiry Interval, Correlation Data, Response Topic, Subscription
 * Identifier
 *  - Enhanced AUTH flow support
 *  - Will Message with delay + content_type: application/json
 *  - Non-blocking restart timer
 *  - Automatic rollback if boot confirmation fails
 *
 * @author Jorge Gaspar Beltre Rivera
 * @version 1.0.0
 */

#include "ESP32_MQTTv5.h"
#include "esp_app_format.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

// Configuration macros  (override before including this header)

#ifndef MQTTOTAV5_JSON_SIZE
#define MQTTOTAV5_JSON_SIZE 4096 ///< StaticJsonDocument size (bytes)
#endif

#ifndef MQTTOTAV5_CHUNK_SIZE
#define MQTTOTAV5_CHUNK_SIZE 8192 ///< Write chunk to OTA partition (bytes)
#endif

#ifndef MQTTOTAV5_TIMEOUT_MS
#define MQTTOTAV5_TIMEOUT_MS 420000UL ///< OTA total timeout (7 min)
#endif

#ifndef MQTTOTAV5_MIN_MEMORY
#define MQTTOTAV5_MIN_MEMORY 45000 ///< Minimum free heap before starting OTA
#endif

#ifndef MQTTOTAV5_MAX_RETRIES
#define MQTTOTAV5_MAX_RETRIES 3 ///< Max chunk retries before aborting
#endif

#ifndef MQTTOTAV5_RESTART_DELAY_MS
#define MQTTOTAV5_RESTART_DELAY_MS 3000UL ///< Non-blocking delay before restart
#endif

#ifndef MQTTOTAV5_SUB_ID
#define MQTTOTAV5_SUB_ID 0x0A ///< MQTT Subscription Identifier for OTA topic
#endif

#ifndef MQTTOTAV5_MSG_EXPIRY_S
#define MQTTOTAV5_MSG_EXPIRY_S 600 ///< Message Expiry Interval: 10 min
#endif

// SHA-256 digest size

#define MQTTOTAV5_SHA256_SIZE 32

// Callback typedefs

typedef std::function<void(int progress, const String &version)>
    OTAv5ProgressCb;
typedef std::function<void(const String &error, const String &version)>
    OTAv5ErrorCb;
typedef std::function<void(const String &version)> OTAv5SuccessCb;
typedef std::function<void(uint8_t state)> OTAv5StateCb;
typedef std::function<void(const String &method, const String &data)>
    OTAv5AuthCb;

// OTA States

enum OTAv5State : uint8_t {
  OTAV5_IDLE = 0,           ///< No OTA in progress
  OTAV5_AUTHENTICATING = 1, ///< AUTH challenge-response flow
  OTAV5_RECEIVING = 2,      ///< Receiving first chunk / single payload
  OTAV5_DECODING = 3,       ///< Decoding Base64 payload
  OTAV5_VALIDATING = 4,     ///< Verifying SHA-256 / HMAC
  OTAV5_WRITING = 5,        ///< Writing to OTA partition
  OTAV5_COMPLETING = 6,     ///< esp_ota_end + set boot partition
  OTAV5_SUCCESS = 7,        ///< OTA succeeded, pending restart
  OTAV5_ERROR = 8,          ///< OTA failed
  OTAV5_ABORTED = 9         ///< Aborted by user or timeout
};

// Internal structures

/** Metadata extracted from MQTT 5.0 User Properties */
struct OTAv5MessageMeta {
  String firmwareVersion; ///< Target firmware version
  String sha256Hex;       ///< Expected SHA-256 (hex string, 64 chars)
  String hmacSig;         ///< Expected HMAC-SHA256 (hex string, 64 chars)
  String targetModel;     ///< Target device model (empty = any)
  String correlationId;   ///< Correlation Data from MQTT properties
  String responseTopic;   ///< Response Topic from MQTT properties
  bool hasExpiry = false;
  uint32_t expiry = 0;
};

/** State of a chunked OTA transfer */
struct OTAv5Context {
  bool inProgress = false;
  OTAv5State state = OTAV5_IDLE;

  // Transfer metadata
  String firmwareVersion;
  String expectedSha256;
  String expectedHmac;

  // Chunked transfer state
  int currentPart = 0;
  int totalParts = 0;
  size_t receivedBytes = 0;

  // ESP-IDF OTA handles
  esp_ota_handle_t update_handle = 0;
  const esp_partition_t *update_partition = nullptr;

  // Timing
  unsigned long startTime = 0;

  // Retry
  int retryCount = 0;
  int maxRetries = MQTTOTAV5_MAX_RETRIES;

  // Incremental SHA-256 context for chunked hash
  mbedtls_sha256_context sha256_ctx;
  bool sha256_active = false;

  // Incremental HMAC-SHA256 context
  mbedtls_md_context_t hmacCtx;
  bool hmac_active = false;

  // Non-blocking restart
  bool pendingRestart = false;
  unsigned long restartAt = 0;

  // Last received MQTT 5.0 properties
  MQTTProperties lastMsgProps;
};

/** Per-chunk data parsed from an OTA MQTT message */
struct OTAv5ChunkData {
  String firmwareVersion;
  String base64Part;
  int partIndex = 0;
  int totalParts = 0;
  bool isError = false;
  String errorMessage;

  // From MQTT User Properties
  String sha256Hex;
  String hmacSig;
  String targetModel;
  String correlationId;
  String responseTopic;
};

/** Runtime OTA statistics */
struct OTAv5Statistics {
  unsigned long startTime = 0;
  unsigned long endTime = 0;
  size_t totalBytes = 0;
  size_t receivedBytes = 0;
  int chunkCount = 0;
  int errorCount = 0;
  OTAv5State lastState = OTAV5_IDLE;
  String lastError;
  float avgSpeedBps = 0.0f; ///< bytes/second average
};

class MQTTOTAv5 {
public:
  MQTTOTAv5();
  ~MQTTOTAv5();

  void begin(ESP32_MQTTv5 &mqtt, const String &device, const String &version,
             const String &otaTopic = "");

  void setSecurityKey(const char *key);

  void requireSignature(bool required = true);

  void onProgress(OTAv5ProgressCb cb);
  void onError(OTAv5ErrorCb cb);
  void onSuccess(OTAv5SuccessCb cb);
  void onStateChange(OTAv5StateCb cb);

  void onAuthRequired(OTAv5AuthCb cb);
  void handle();

  void abortUpdate();

  bool isUpdateInProgress() const;
  bool isValidating() const;
  bool isWriting() const;
  OTAv5State getCurrentState() const;
  String getCurrentVersion() const;
  String getDeviceID() const;
  int getProgress() const;
  OTAv5Statistics getStatistics() const;
  size_t getFreeOTASpace() const;

  void printDiagnostics() const;
  String getBootPartitionInfo() const;

  static bool checkMemory(size_t requiredBytes);
  static size_t getFreeHeap();
  static void logMemoryStatus();

  void setAutoReset(bool enable = true);
  void setMaxRetries(int maxRetries);
  void enableVersionCheck(bool enable = true);
  void enableRollbackProtection(bool enable = true);

private:
  ESP32_MQTTv5 *_mqtt = nullptr;

  String _deviceName;
  String _firmwareVersion;
  String _deviceID;
  String _otaTopic;
  String _ackTopic;    ///< ota/<device>/ack
  String _statusTopic; ///< ota/<device>/status

  uint8_t _hmacKey[64];
  size_t _hmacKeyLen = 0;
  bool _requireSig = true;

  OTAv5Context _ctx;
  OTAv5Statistics _stats;
  int _currentProgress = 0;

  bool _autoReset = true;
  bool _versionCheck = true;
  bool _rollbackProtection = true;
  int _maxRetries = MQTTOTAV5_MAX_RETRIES;

  OTAv5ProgressCb _progressCb = nullptr;
  OTAv5ErrorCb _errorCb = nullptr;
  OTAv5SuccessCb _successCb = nullptr;
  OTAv5StateCb _stateCb = nullptr;
  OTAv5AuthCb _authCb = nullptr;

  void _onMQTTMessage(const MQTTMessage &msg);
  void _onMQTTAuth(MQTTReasonCode reason, const MQTTProperties &props);

  bool _parseMetaFromProps(const MQTTProperties &props, OTAv5MessageMeta &meta);
  bool _parseChunkFromJson(const String &payload, const OTAv5MessageMeta &meta,
                           OTAv5ChunkData &chunk);

  void _processOTAMessage(const MQTTMessage &msg);
  bool _startChunkedOTA(const OTAv5ChunkData &chunk);
  bool _processChunkData(const OTAv5ChunkData &chunk);
  void _completeChunkedOTA(const OTAv5ChunkData &chunk);
  void _cleanupChunkedOTA(bool abort = true);

  static String _sha256Hex(const uint8_t *data, size_t len);
  String _hmacSha256Hex(const uint8_t *data, size_t len) const;
  bool _verifySha256Final(const String &expectedHex);
  bool _verifyHmac(const uint8_t *data, size_t len,
                   const String &expectedHex) const;
  bool _verifyHmacFinal(const String &expectedHex);
  static bool _verifyImageHeader(const uint8_t *data, size_t len);

  bool _checkVersionDiff(const String &newVer) const;
  bool _validatePartition() const;
  void _setState(OTAv5State state);
  void _updateStats(size_t bytes = 0, bool isError = false);
  String _generateDeviceID() const;
  String _stateName(OTAv5State s) const;

  void _publishProgress(int pct, const String &ver,
                        const String &responseTopic = "");
  void _publishError(const String &err, const String &ver = "",
                     const String &responseTopic = "");
  void _publishSuccess(const String &ver, const String &responseTopic = "");
  void _publishStateChange(OTAv5State state);
  void _publishAck(const String &corrId, bool ok, const String &msg = "");

  void _setupWillMessage();

  static size_t _base64DecodedSize(const char *src, size_t srcLen);
  static ssize_t _base64Decode(const char *src, size_t srcLen, uint8_t *dst,
                               size_t dstBuf);
};

inline bool MQTTOTAv5::isUpdateInProgress() const { return _ctx.inProgress; }
inline bool MQTTOTAv5::isValidating() const {
  return _ctx.state == OTAV5_VALIDATING;
}
inline bool MQTTOTAv5::isWriting() const { return _ctx.state == OTAV5_WRITING; }
inline OTAv5State MQTTOTAv5::getCurrentState() const { return _ctx.state; }
inline String MQTTOTAv5::getCurrentVersion() const { return _firmwareVersion; }
inline String MQTTOTAv5::getDeviceID() const { return _deviceID; }
inline int MQTTOTAv5::getProgress() const { return _currentProgress; }
inline OTAv5Statistics MQTTOTAv5::getStatistics() const { return _stats; }
inline void MQTTOTAv5::setAutoReset(bool enable) { _autoReset = enable; }
inline void MQTTOTAv5::enableVersionCheck(bool enable) {
  _versionCheck = enable;
}
inline void MQTTOTAv5::enableRollbackProtection(bool enable) {
  _rollbackProtection = enable;
}
inline void MQTTOTAv5::setMaxRetries(int n) {
  _maxRetries = (n > 0) ? n : MQTTOTAV5_MAX_RETRIES;
}
inline void MQTTOTAv5::onProgress(OTAv5ProgressCb cb) { _progressCb = cb; }
inline void MQTTOTAv5::onError(OTAv5ErrorCb cb) { _errorCb = cb; }
inline void MQTTOTAv5::onSuccess(OTAv5SuccessCb cb) { _successCb = cb; }
inline void MQTTOTAv5::onStateChange(OTAv5StateCb cb) { _stateCb = cb; }
inline void MQTTOTAv5::onAuthRequired(OTAv5AuthCb cb) { _authCb = cb; }

#endif // MQTTOTAV5_H
