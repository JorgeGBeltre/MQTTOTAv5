/**
 * @file MQTTOTAv5.cpp
 * @brief Implementation of MQTTOTAv5 — OTA over MQTT 5.0 for ESP32
 *
 * Architecture:
 *  - begin() registers onMessage + onAuth callbacks on the ESP32_MQTTv5
 * instance.
 *  - _onMQTTMessage() filters by Subscription Identifier and dispatches to
 * _processOTAMessage().
 *  - Chunked flow: _startChunkedOTA → _processChunkData (incremental SHA-256) →
 * _completeChunkedOTA
 *  - Security: SHA-256 verified with mbedtls before esp_ota_end(); HMAC-SHA256
 * verified from User Properties.
 *  - Non-blocking restart: pendingRestart flag polled in handle().
 *  - Rollback: esp_ota_mark_app_valid_cancel_rollback() called on successful
 * boot detection.
 */

#include "MQTTOTAv5.h"

static int8_t _b64Val(char c) {
  if (c >= 'A' && c <= 'Z')
    return (int8_t)(c - 'A');
  if (c >= 'a' && c <= 'z')
    return (int8_t)(c - 'a' + 26);
  if (c >= '0' && c <= '9')
    return (int8_t)(c - '0' + 52);
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

size_t MQTTOTAv5::_base64DecodedSize(const char *src, size_t srcLen) {
  if (srcLen == 0)
    return 0;
  // Strip whitespace for estimation
  size_t padding = 0;
  // Walk backward
  for (size_t i = srcLen;
       i > 0 && (src[i - 1] == '=' || src[i - 1] == '\n' || src[i - 1] == '\r');
       --i) {
    if (src[i - 1] == '=')
      padding++;
  }
  return (srcLen / 4) * 3 - padding;
}

// Returns: number of decoded bytes, or -1 on error
ssize_t MQTTOTAv5::_base64Decode(const char *src, size_t srcLen, uint8_t *dst,
                                 size_t dstBuf) {
  size_t out = 0;
  uint32_t acc = 0;
  int bits = 0;

  for (size_t i = 0; i < srcLen; ++i) {
    char c = src[i];
    if (c == '\n' || c == '\r' || c == ' ')
      continue; // skip whitespace
    if (c == '=')
      break;

    int8_t v = _b64Val(c);
    if (v < 0)
      return -1; // invalid character

    acc = (acc << 6) | (uint8_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (out >= dstBuf)
        return -1; // buffer overflow
      dst[out++] = (uint8_t)((acc >> bits) & 0xFF);
    }
  }
  return (ssize_t)out;
}

// Constructor / Destructor

MQTTOTAv5::MQTTOTAv5() {
  memset(_hmacKey, 0, sizeof(_hmacKey));
  mbedtls_sha256_init(&_ctx.sha256_ctx);
  mbedtls_md_init(&_ctx.hmacCtx); // BUG-01: pre-init so free() is always safe
  _deviceID = _generateDeviceID();
}

MQTTOTAv5::~MQTTOTAv5() { _cleanupChunkedOTA(true); }

// begin()

void MQTTOTAv5::begin(ESP32_MQTTv5 &mqtt, const String &device,
                      const String &version, const String &otaTopic) {
  _mqtt = &mqtt;
  _deviceName = device;
  _firmwareVersion = version;
  _deviceID = _generateDeviceID();

  // Build topics
  if (otaTopic.isEmpty()) {
    _otaTopic = "ota/" + _deviceName;
  } else {
    _otaTopic = otaTopic;
  }
  _ackTopic = _otaTopic + "/ack";
  _statusTopic = _otaTopic + "/status";

  _setupWillMessage();

  Serial.println("[MQTTOTAv5] NOTE: overrides existing onMessage callback.");
  Serial.println(
      "[MQTTOTAv5] Register other topic handlers via onMessage AFTER begin().");
  _mqtt->onMessageRaw([this](const String &topic, const uint8_t *payload,
                             size_t len, uint8_t qos, bool retain,
                             const MQTTProperties &props) {
    _ctx.lastMsgProps = props;
    MQTTMessage msg;
    msg.topic = topic;
    msg.payload = String((const char *)payload, len);
    msg.qos = qos;
    msg.retain = retain;
    msg.hasSubscriptionIdentifier = false; // use topic filter in _onMQTTMessage
    this->_onMQTTMessage(msg);
  });

  // Register AUTH callback
  _mqtt->onAuth([this](MQTTReasonCode reason, const MQTTProperties &props) {
    this->_onMQTTAuth(reason, props);
  });

  // Subscribe to OTA topic with Subscription Identifier and Message Expiry
  _mqtt->subscribe(_otaTopic, 1, false, false, 0, MQTTOTAV5_SUB_ID);

  if (_rollbackProtection) {
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running && running->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_0 &&
        running->subtype <= ESP_PARTITION_SUBTYPE_APP_OTA_MAX) {
      esp_ota_mark_app_valid_cancel_rollback();
      Serial.println("[MQTTOTAv5] Boot confirmed — rollback cancelled");
    }
  }

  Serial.println("[MQTTOTAv5] Initialized");
  Serial.printf("  Device   : %s\n", _deviceName.c_str());
  Serial.printf("  Version  : %s\n", _firmwareVersion.c_str());
  Serial.printf("  DeviceID : %s\n", _deviceID.c_str());
  Serial.printf("  OTA Topic: %s\n", _otaTopic.c_str());
  Serial.printf("  Signature: %s\n", _requireSig ? "REQUIRED" : "optional");
}

// Security configuration

void MQTTOTAv5::setSecurityKey(const char *key) {
  if (!key)
    return;
  _hmacKeyLen = strlen(key);
  if (_hmacKeyLen > sizeof(_hmacKey))
    _hmacKeyLen = sizeof(_hmacKey);
  memcpy(_hmacKey, key, _hmacKeyLen);
  Serial.printf("[MQTTOTAv5] Security key set (%zu bytes)\n", _hmacKeyLen);
}

void MQTTOTAv5::requireSignature(bool required) {
  _requireSig = required;
  Serial.printf("[MQTTOTAv5] Signature requirement: %s\n",
                required ? "ON" : "OFF");
}

// handle() — call every loop iteration

void MQTTOTAv5::handle() {
  if (!_ctx.inProgress) {
    if (_ctx.pendingRestart) {
      unsigned long now = millis();

      if (now >= _ctx.restartAt || (now + 10000UL < _ctx.restartAt)) {
        Serial.println("[MQTTOTAv5] Restarting...");
        ESP.restart();
      }
    }
    return;
  }

  // Timeout check
  if (millis() - _ctx.startTime > MQTTOTAV5_TIMEOUT_MS) {
    Serial.println("[MQTTOTAv5] OTA timeout — aborting");
    _publishError("OTA timeout", _ctx.firmwareVersion);
    _cleanupChunkedOTA(true);
    _setState(OTAV5_ERROR);
  }
}

// Will Message setup

void MQTTOTAv5::_setupWillMessage() {
  if (!_mqtt)
    return;

  // Build JSON will payload
  StaticJsonDocument<256> doc;
  doc["device"] = _deviceID;
  doc["version"] = _firmwareVersion;
  doc["status"] = "offline";

  String payload;
  serializeJson(doc, payload);

  MQTTProperties willProps;
  willProps.setWillDelay(30);
  willProps.setContentType("application/json");
  willProps.setPayloadFormat(1); // UTF-8 JSON

  _mqtt->setWill(_statusTopic, payload, 0, true, &willProps);
}

// MQTT callbacks

void MQTTOTAv5::_onMQTTMessage(const MQTTMessage &msg) {

  bool forUs = (msg.topic == _otaTopic);
  if (!forUs && msg.hasSubscriptionIdentifier) {
    forUs = (msg.subscriptionIdentifier == MQTTOTAV5_SUB_ID);
  }
  if (!forUs)
    return;

  _processOTAMessage(msg);
}

void MQTTOTAv5::_onMQTTAuth(MQTTReasonCode reason,
                            const MQTTProperties &props) {
  String method = props.getString(AUTHENTICATION_METHOD);
  String data = props.getString(AUTHENTICATION_DATA);

  Serial.printf("[MQTTOTAv5] AUTH received — method=%s reason=0x%02X\n",
                method.c_str(), (uint8_t)reason);

  _setState(OTAV5_AUTHENTICATING);

  if (_authCb) {
    _authCb(method, data);
  }
}

// Metadata parsing from MQTT 5.0 User Properties

bool MQTTOTAv5::_parseMetaFromProps(const MQTTProperties &props,
                                    OTAv5MessageMeta &meta) {
  meta.firmwareVersion = props.getUserProperty("firmware_version");
  meta.sha256Hex = props.getUserProperty("sha256");
  meta.hmacSig = props.getUserProperty("hmac_sig");
  meta.targetModel = props.getUserProperty("target_model");
  meta.correlationId = props.getString(CORRELATION_DATA);
  meta.responseTopic = props.getString(RESPONSE_TOPIC);
  meta.expiry = props.getUint32(MESSAGE_EXPIRY_INTERVAL, 0);
  meta.hasExpiry = (meta.expiry > 0);

  // Target model check
  if (!meta.targetModel.isEmpty() && meta.targetModel != _deviceName) {
    Serial.printf("[MQTTOTAv5] Ignoring OTA for model=%s (we are %s)\n",
                  meta.targetModel.c_str(), _deviceName.c_str());
    return false;
  }

  return true;
}

// Chunk parsing from JSON payload

bool MQTTOTAv5::_parseChunkFromJson(const String &payload,
                                    const OTAv5MessageMeta &meta,
                                    OTAv5ChunkData &chunk) {
  StaticJsonDocument<MQTTOTAV5_JSON_SIZE> doc;
  DeserializationError err = deserializeJson(doc, payload);
  if (err) {
    Serial.printf("[MQTTOTAv5] JSON parse error: %s\n", err.c_str());
    return false;
  }

  // Accept legacy "EventType" key or bare chunk object
  if (doc.containsKey("EventType") &&
      doc["EventType"] != "UpdateFirmwareDevice") {
    return false; // Not an OTA message
  }

  JsonObjectConst details = doc.containsKey("Details")
                                ? doc["Details"].as<JsonObjectConst>()
                                : doc.as<JsonObjectConst>();

  // firmware_version: prefer User Property, fallback to JSON
  chunk.firmwareVersion =
      meta.firmwareVersion.isEmpty()
          ? details["firmware_version"] | details["FirmwareVersion"] | ""
          : meta.firmwareVersion;

  // base64 data: try both keys
  const char *b64 =
      details["base64"] | details["Base64Part"] | details["Base64"] | "";
  chunk.base64Part = String(b64);

  chunk.partIndex = details["part_index"] | details["PartIndex"] | 1;
  chunk.totalParts = details["total_parts"] | details["TotalParts"] | 1;
  chunk.isError = details["error"] | details["IsError"] | false;
  chunk.errorMessage = details["error_msg"] | details["ErrorMessage"] | "";

  // Security from User Properties (preferred) or JSON fallback
  chunk.sha256Hex = meta.sha256Hex.isEmpty() ? String(details["sha256"] | "")
                                             : meta.sha256Hex;
  chunk.hmacSig =
      meta.hmacSig.isEmpty() ? String(details["hmac_sig"] | "") : meta.hmacSig;
  chunk.targetModel = meta.targetModel;
  chunk.correlationId = meta.correlationId;
  chunk.responseTopic = meta.responseTopic;

  if (chunk.firmwareVersion.isEmpty()) {
    Serial.println("[MQTTOTAv5] Missing firmware_version in message");
    return false;
  }

  return true;
}

// Main OTA message dispatcher

void MQTTOTAv5::_processOTAMessage(const MQTTMessage &msg) {
  if (_ctx.inProgress) {
    Serial.println("[MQTTOTAv5] OTA in progress — ignoring new message");
    return;
  }

  if (ESP.getFreeHeap() < (uint32_t)MQTTOTAV5_MIN_MEMORY) {
    Serial.printf("[MQTTOTAv5] Insufficient memory (%u free, need %d)\n",
                  ESP.getFreeHeap(), MQTTOTAV5_MIN_MEMORY);
    _publishError("Insufficient memory");
    return;
  }

  OTAv5MessageMeta meta;
  if (!_parseMetaFromProps(_ctx.lastMsgProps, meta))
    return;

  // Parse chunk from JSON payload
  OTAv5ChunkData chunk;
  if (!_parseChunkFromJson(msg.payload, meta, chunk))
    return;

  // Error flag from sender
  if (chunk.isError) {
    Serial.printf("[MQTTOTAv5] Sender reported error: %s\n",
                  chunk.errorMessage.c_str());
    _publishError(chunk.errorMessage, chunk.firmwareVersion,
                  chunk.responseTopic);
    return;
  }

  // Version check
  if (_versionCheck && !_checkVersionDiff(chunk.firmwareVersion)) {
    Serial.printf("[MQTTOTAv5] Version unchanged (%s) — skipping\n",
                  chunk.firmwareVersion.c_str());
    _publishError("Version unchanged", chunk.firmwareVersion,
                  chunk.responseTopic);
    return;
  }

  if (chunk.partIndex == 1) {

    if (!_startChunkedOTA(chunk))
      return;
  } else {
    // Mid-stream chunk: verify version consistency, then sequence order
    if (!_ctx.inProgress) {
      Serial.println(
          "[MQTTOTAv5] Chunk received but no OTA is active — ignoring");
      return;
    }
    if (chunk.firmwareVersion != _ctx.firmwareVersion) {
      Serial.printf(
          "[MQTTOTAv5] Version mismatch in chunk stream: expected %s got %s\n",
          _ctx.firmwareVersion.c_str(), chunk.firmwareVersion.c_str());
      _publishError("Version mismatch in chunk stream", chunk.firmwareVersion,
                    chunk.responseTopic);
      _cleanupChunkedOTA(true);
      return;
    }
    if (chunk.partIndex != _ctx.currentPart + 1) {
      Serial.printf("[MQTTOTAv5] Out-of-order chunk: expected %d got %d\n",
                    _ctx.currentPart + 1, chunk.partIndex);
      _publishError("Chunk out of order", chunk.firmwareVersion,
                    chunk.responseTopic);
      _cleanupChunkedOTA(true);
      return;
    }
  }

  // Process data
  if (!_processChunkData(chunk)) {
    _cleanupChunkedOTA(true);
    return;
  }

  _ctx.currentPart = chunk.partIndex;
  _currentProgress = (chunk.partIndex * 100) / chunk.totalParts;

  _publishProgress(_currentProgress, chunk.firmwareVersion,
                   chunk.responseTopic);
  _publishAck(chunk.correlationId, true,
              String(chunk.partIndex) + "/" + String(chunk.totalParts));

  Serial.printf("[MQTTOTAv5] Chunk %d/%d — %d%% — heap=%u\n", chunk.partIndex,
                chunk.totalParts, _currentProgress, ESP.getFreeHeap());

  // Last chunk
  if (chunk.partIndex == chunk.totalParts) {
    _completeChunkedOTA(chunk);
  }
}

// Start chunked OTA

bool MQTTOTAv5::_startChunkedOTA(const OTAv5ChunkData &chunk) {
  Serial.printf("[MQTTOTAv5] Starting chunked OTA — version=%s parts=%d\n",
                chunk.firmwareVersion.c_str(), chunk.totalParts);

  _setState(OTAV5_RECEIVING);

  // Find next OTA partition
  _ctx.update_partition = esp_ota_get_next_update_partition(nullptr);
  if (!_ctx.update_partition) {
    _publishError("No OTA partition found", chunk.firmwareVersion,
                  chunk.responseTopic);
    _setState(OTAV5_ERROR);
    return false;
  }

  // Validate partition before writing
  if (!_validatePartition()) {
    _publishError("Invalid OTA partition", chunk.firmwareVersion,
                  chunk.responseTopic);
    _setState(OTAV5_ERROR);
    return false;
  }

  // Begin OTA
  esp_err_t err = esp_ota_begin(
      _ctx.update_partition, OTA_WITH_SEQUENTIAL_WRITES, &_ctx.update_handle);
  if (err != ESP_OK) {
    String msg = String("esp_ota_begin failed: ") + esp_err_to_name(err);
    _publishError(msg, chunk.firmwareVersion, chunk.responseTopic);
    _setState(OTAV5_ERROR);
    return false;
  }

  // Init incremental SHA-256
  mbedtls_sha256_init(&_ctx.sha256_ctx);
  mbedtls_sha256_starts(&_ctx.sha256_ctx, 0); // 0 = SHA-256 (not SHA-224)
  _ctx.sha256_active = true;

  _ctx.hmac_active = false;
  if (_hmacKeyLen > 0) {
    const mbedtls_md_info_t *mdInfo =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_init(&_ctx.hmacCtx);
    if (mbedtls_md_setup(&_ctx.hmacCtx, mdInfo, 1) == 0) { // 1 = HMAC mode
      mbedtls_md_hmac_starts(&_ctx.hmacCtx, _hmacKey, _hmacKeyLen);
      _ctx.hmac_active = true;
    } else {
      Serial.println("[MQTTOTAv5] WARN: HMAC context setup failed");
      mbedtls_md_free(&_ctx.hmacCtx);
    }
  }

  // Init context
  _ctx.inProgress = true;
  _ctx.firmwareVersion = chunk.firmwareVersion;
  _ctx.expectedSha256 = chunk.sha256Hex;
  _ctx.expectedHmac = chunk.hmacSig;
  _ctx.currentPart = 0;
  _ctx.totalParts = chunk.totalParts;
  _ctx.startTime = millis();
  _ctx.receivedBytes = 0;
  _ctx.retryCount = 0;
  _ctx.maxRetries = _maxRetries;
  _ctx.pendingRestart = false;

  _stats.startTime = millis();
  _stats.chunkCount = 0;
  _stats.receivedBytes = 0;
  _stats.totalBytes = 0;
  _stats.errorCount = 0;

  _publishProgress(0, chunk.firmwareVersion, chunk.responseTopic);
  return true;
}

// Process chunk data

bool MQTTOTAv5::_processChunkData(const OTAv5ChunkData &chunk) {
  _setState(OTAV5_DECODING);

  if (!_ctx.inProgress || _ctx.update_handle == 0) {
    _publishError("OTA handle invalid", chunk.firmwareVersion,
                  chunk.responseTopic);
    return false;
  }

  const char *b64src = chunk.base64Part.c_str();
  size_t b64len = chunk.base64Part.length();

  // Allocate decode buffer
  size_t maxDecoded = _base64DecodedSize(b64src, b64len) + 4;
  uint8_t *buf = (uint8_t *)malloc(maxDecoded);
  if (!buf) {
    _publishError("Out of memory decoding chunk", chunk.firmwareVersion,
                  chunk.responseTopic);
    return false;
  }

  ssize_t decoded = _base64Decode(b64src, b64len, buf, maxDecoded);
  if (decoded <= 0) {
    free(buf);
    _publishError("Base64 decode error", chunk.firmwareVersion,
                  chunk.responseTopic);
    return false;
  }

  // Verify image header on first chunk
  if (chunk.partIndex == 1) {
    _setState(OTAV5_VALIDATING);
    if (!_verifyImageHeader(buf, (size_t)decoded)) {
      free(buf);
      _publishError("Invalid firmware image header", chunk.firmwareVersion,
                    chunk.responseTopic);
      return false;
    }
  }

  // Update incremental SHA-256
  if (_ctx.sha256_active) {
    mbedtls_sha256_update(&_ctx.sha256_ctx, buf, (size_t)decoded);
  }

  if (_ctx.hmac_active) {
    mbedtls_md_hmac_update(&_ctx.hmacCtx, buf, (size_t)decoded);
  }

  _setState(OTAV5_WRITING);

  // Write to partition
  esp_err_t err = esp_ota_write(_ctx.update_handle, buf, (size_t)decoded);
  free(buf);

  if (err != ESP_OK) {
    String msg = String("esp_ota_write failed: ") + esp_err_to_name(err);
    _publishError(msg, chunk.firmwareVersion, chunk.responseTopic);
    return false;
  }

  _ctx.receivedBytes += (size_t)decoded;
  _stats.receivedBytes = _ctx.receivedBytes;
  _stats.chunkCount++;

  unsigned long elapsed = millis() - _ctx.startTime;
  if (elapsed > 0) {
    _stats.avgSpeedBps = (_ctx.receivedBytes * 1000.0f) / (float)elapsed;
  }

  return true;
}

// Complete chunked OTA

void MQTTOTAv5::_completeChunkedOTA(const OTAv5ChunkData &chunk) {
  Serial.printf("[MQTTOTAv5] Completing OTA — %zu bytes written\n",
                _ctx.receivedBytes);
  _setState(OTAV5_COMPLETING);

  // minimum firmware size
  if (_ctx.receivedBytes < 1024) {
    _publishError("Firmware too small", chunk.firmwareVersion,
                  chunk.responseTopic);
    _cleanupChunkedOTA(true);
    return;
  }

  _publishProgress(90, chunk.firmwareVersion, chunk.responseTopic);

  _setState(OTAV5_VALIDATING);

  if (!_ctx.expectedSha256.isEmpty()) {
    if (!_verifySha256Final(_ctx.expectedSha256)) {
      _publishError("SHA-256 mismatch — firmware rejected",
                    chunk.firmwareVersion, chunk.responseTopic);
      _cleanupChunkedOTA(true);
      _setState(OTAV5_ERROR);
      return;
    }
    Serial.println("[MQTTOTAv5] SHA-256 OK");
  } else if (_requireSig) {
    _publishError("No sha256 provided — rejected in production mode",
                  chunk.firmwareVersion, chunk.responseTopic);
    _cleanupChunkedOTA(true);
    _setState(OTAV5_ERROR);
    return;
  }

  if (!_ctx.expectedHmac.isEmpty() && _hmacKeyLen > 0) {
    if (!_verifyHmacFinal(_ctx.expectedHmac)) {
      _publishError("HMAC mismatch — firmware rejected", chunk.firmwareVersion,
                    chunk.responseTopic);
      _cleanupChunkedOTA(true);
      _setState(OTAV5_ERROR);
      return;
    }
    Serial.println("[MQTTOTAv5] HMAC OK");
  } else if (_requireSig && _hmacKeyLen > 0) {
    _publishError("No hmac_sig provided — rejected in production mode",
                  chunk.firmwareVersion, chunk.responseTopic);
    _cleanupChunkedOTA(true);
    _setState(OTAV5_ERROR);
    return;
  }

  esp_err_t err = esp_ota_end(_ctx.update_handle);
  _ctx.update_handle = 0;

  if (err != ESP_OK) {
    String msg = String("esp_ota_end failed: ") + esp_err_to_name(err);
    if (err == ESP_ERR_OTA_VALIDATE_FAILED)
      msg += " (image validation)";
    _publishError(msg, chunk.firmwareVersion, chunk.responseTopic);
    _cleanupChunkedOTA(false);
    _setState(OTAV5_ERROR);
    return;
  }

  _publishProgress(95, chunk.firmwareVersion, chunk.responseTopic);

  err = esp_ota_set_boot_partition(_ctx.update_partition);
  if (err != ESP_OK) {
    String msg =
        String("esp_ota_set_boot_partition failed: ") + esp_err_to_name(err);
    _publishError(msg, chunk.firmwareVersion, chunk.responseTopic);
    _cleanupChunkedOTA(false);
    _setState(OTAV5_ERROR);
    return;
  }

  _publishProgress(100, chunk.firmwareVersion, chunk.responseTopic);
  _setState(OTAV5_SUCCESS);
  _publishSuccess(chunk.firmwareVersion, chunk.responseTopic);

  _stats.endTime = millis();
  _stats.lastState = OTAV5_SUCCESS;

  _ctx.inProgress = false;
  if (_ctx.sha256_active) {
    mbedtls_sha256_free(&_ctx.sha256_ctx);
    _ctx.sha256_active = false;
  }

  if (_ctx.hmac_active) {
    mbedtls_md_free(&_ctx.hmacCtx);
    _ctx.hmac_active = false;
  }

  Serial.printf("[MQTTOTAv5] OTA SUCCESS — %s in %.1f s (%.1f KB/s)\n",
                chunk.firmwareVersion.c_str(),
                (millis() - _ctx.startTime) / 1000.0f,
                _stats.avgSpeedBps / 1024.0f);

  // Schedule non-blocking restart
  if (_autoReset) {
    _ctx.pendingRestart = true;
    _ctx.restartAt = millis() + MQTTOTAV5_RESTART_DELAY_MS;
    Serial.printf("[MQTTOTAv5] Restarting in %lu ms\n",
                  MQTTOTAV5_RESTART_DELAY_MS);
  }
}

// Cleanup / abort

void MQTTOTAv5::_cleanupChunkedOTA(bool abort) {
  if (_ctx.update_handle != 0) {
    if (abort) {
      esp_ota_abort(_ctx.update_handle);
    }
    _ctx.update_handle = 0;
  }

  if (_ctx.sha256_active) {
    mbedtls_sha256_free(&_ctx.sha256_ctx);
    _ctx.sha256_active = false;
  }

  if (_ctx.hmac_active) {
    mbedtls_md_free(&_ctx.hmacCtx);
    _ctx.hmac_active = false;
  }

  _ctx.inProgress = false;
  _ctx.currentPart = 0;
  _ctx.totalParts = 0;
  _ctx.receivedBytes = 0;
  _ctx.startTime = 0;
  _ctx.update_partition = nullptr;
  _ctx.retryCount = 0;
  _currentProgress = 0;

  _ctx.state = OTAV5_IDLE;
}

void MQTTOTAv5::abortUpdate() {
  if (_ctx.inProgress) {
    _publishError("Aborted by user", _ctx.firmwareVersion);
    _cleanupChunkedOTA(true);
    _setState(OTAV5_ABORTED);
    Serial.println("[MQTTOTAv5] Update aborted by user");
  }
}

// Security: SHA-256

String MQTTOTAv5::_sha256Hex(const uint8_t *data, size_t len) {
  uint8_t digest[MQTTOTAV5_SHA256_SIZE];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);

  char hex[MQTTOTAV5_SHA256_SIZE * 2 + 1];
  for (int i = 0; i < MQTTOTAV5_SHA256_SIZE; ++i) {
    snprintf(&hex[i * 2], 3, "%02x", digest[i]);
  }
  return String(hex);
}

bool MQTTOTAv5::_verifySha256Final(const String &expectedHex) {
  if (!_ctx.sha256_active)
    return false;

  uint8_t digest[MQTTOTAV5_SHA256_SIZE];
  mbedtls_sha256_finish(&_ctx.sha256_ctx, digest);
  // sha256_active stays true until we free it; finish is safe to call

  char hex[MQTTOTAV5_SHA256_SIZE * 2 + 1];
  for (int i = 0; i < MQTTOTAV5_SHA256_SIZE; ++i) {
    snprintf(&hex[i * 2], 3, "%02x", digest[i]);
  }

  bool ok = (expectedHex.equalsIgnoreCase(String(hex)));
  if (!ok) {
    Serial.printf(
        "[MQTTOTAv5] SHA-256 MISMATCH\n  expected: %s\n  computed: %s\n",
        expectedHex.c_str(), hex);
  }
  return ok;
}

// Security: HMAC-SHA256

String MQTTOTAv5::_hmacSha256Hex(const uint8_t *data, size_t len) const {
  uint8_t digest[MQTTOTAV5_SHA256_SIZE];

  const mbedtls_md_info_t *mdInfo =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(mdInfo, _hmacKey, _hmacKeyLen, data, len, digest);

  char hex[MQTTOTAV5_SHA256_SIZE * 2 + 1];
  for (int i = 0; i < MQTTOTAV5_SHA256_SIZE; ++i) {
    snprintf(&hex[i * 2], 3, "%02x", digest[i]);
  }
  return String(hex);
}

bool MQTTOTAv5::_verifyHmac(const uint8_t *data, size_t len,
                            const String &expectedHex) const {
  if (_hmacKeyLen == 0)
    return false;
  String computed = _hmacSha256Hex(data, len);
  bool ok = computed.equalsIgnoreCase(expectedHex);
  if (!ok) {
    Serial.printf("[MQTTOTAv5] HMAC mismatch\n  expected: %s\n  computed: %s\n",
                  expectedHex.c_str(), computed.c_str());
  }
  return ok;
}

bool MQTTOTAv5::_verifyHmacFinal(const String &expectedHex) {
  if (!_ctx.hmac_active)
    return false;

  uint8_t digest[MQTTOTAV5_SHA256_SIZE];
  mbedtls_md_hmac_finish(&_ctx.hmacCtx, digest);

  char hex[MQTTOTAV5_SHA256_SIZE * 2 + 1];
  for (int i = 0; i < MQTTOTAV5_SHA256_SIZE; ++i) {
    snprintf(&hex[i * 2], 3, "%02x", digest[i]);
  }

  bool ok = expectedHex.equalsIgnoreCase(String(hex));
  if (!ok) {
    Serial.printf("[MQTTOTAv5] HMAC MISMATCH\n  expected: %s\n  computed: %s\n",
                  expectedHex.c_str(), hex);
  }
  return ok;
}

// Image header verification

bool MQTTOTAv5::_verifyImageHeader(const uint8_t *data, size_t len) {
  const size_t minLen = sizeof(esp_image_header_t) +
                        sizeof(esp_image_segment_header_t) +
                        sizeof(esp_app_desc_t);
  if (len < minLen) {
    Serial.printf("[MQTTOTAv5] First chunk too small: %zu < %zu\n", len,
                  minLen);
    return false;
  }

  const esp_image_header_t *imgHdr = (const esp_image_header_t *)data;
  if (imgHdr->magic != ESP_IMAGE_HEADER_MAGIC) {
    Serial.printf("[MQTTOTAv5] Bad magic: 0x%02X (expected 0x%02X)\n",
                  imgHdr->magic, ESP_IMAGE_HEADER_MAGIC);
    return false;
  }
  if (imgHdr->segment_count == 0) {
    Serial.println("[MQTTOTAv5] Zero segments in image header");
    return false;
  }

  // Log the embedded app description
  esp_app_desc_t appDesc;
  memcpy(&appDesc,
         data + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t),
         sizeof(esp_app_desc_t));
  Serial.printf("[MQTTOTAv5] Image version: %s  IDF: %s\n", appDesc.version,
                appDesc.idf_ver);

  return true;
}

// Partition validation

bool MQTTOTAv5::_validatePartition() const {
  if (!_ctx.update_partition)
    return false;
  if (_ctx.update_partition->type != ESP_PARTITION_TYPE_APP) {
    Serial.println("[MQTTOTAv5] Partition type is not APP");
    return false;
  }
  if (_ctx.update_partition->size < 65536) {
    Serial.printf("[MQTTOTAv5] Partition too small: %u bytes\n",
                  _ctx.update_partition->size);
    return false;
  }
  Serial.printf("[MQTTOTAv5] Partition OK: %s @ 0x%08X (%u bytes)\n",
                _ctx.update_partition->label, _ctx.update_partition->address,
                _ctx.update_partition->size);
  return true;
}

// getFreeOTASpace

size_t MQTTOTAv5::getFreeOTASpace() const {
  const esp_partition_t *part = esp_ota_get_next_update_partition(nullptr);
  if (!part)
    return 0;
  return (size_t)part->size;
}

// Version check

bool MQTTOTAv5::_checkVersionDiff(const String &newVer) const {
  return (newVer != _firmwareVersion && !newVer.isEmpty());
}

// State management

void MQTTOTAv5::_setState(OTAv5State s) {
  if (_ctx.state == s)
    return;
  _ctx.state = s;
  _stats.lastState = s;
  _publishStateChange(s);
}

void MQTTOTAv5::_updateStats(size_t bytes, bool isError) {
  if (bytes > 0) {
    _stats.totalBytes += bytes;
    _stats.receivedBytes += bytes;
    // BUG-05: chunkCount is managed exclusively in _processChunkData
  }
  if (isError)
    _stats.errorCount++;
}

// MQTT publishing helpers

void MQTTOTAv5::_publishProgress(int pct, const String &ver,
                                 const String &responseTopic) {
  _currentProgress = pct;
  if (_progressCb)
    _progressCb(pct, ver);

  if (!_mqtt || !_mqtt->connected())
    return;
  if (pct % 10 != 0 && pct != 100)
    return; // throttle

  StaticJsonDocument<256> doc;
  doc["device"] = _deviceID;
  doc["version"] = ver;
  doc["progress"] = pct;
  doc["bytes"] = _ctx.receivedBytes;

  String payload;
  serializeJson(doc, payload);

  MQTTProperties props;
  props.setContentType("application/json");
  props.setPayloadFormat(1);
  if (!responseTopic.isEmpty())
    props.setResponseTopic(responseTopic);

  String topic =
      responseTopic.isEmpty() ? (_otaTopic + "/progress") : responseTopic;
  _mqtt->publish(topic, payload, 0, false, &props);
}

void MQTTOTAv5::_publishError(const String &err, const String &ver,
                              const String &responseTopic) {
  _stats.errorCount++;
  if (_errorCb)
    _errorCb(err, ver.isEmpty() ? _firmwareVersion : ver);

  Serial.printf("[MQTTOTAv5] ERROR: %s\n", err.c_str());

  if (!_mqtt || !_mqtt->connected())
    return;

  StaticJsonDocument<256> doc;
  doc["device"] = _deviceID;
  doc["version"] = ver.isEmpty() ? _firmwareVersion : ver;
  doc["error"] = err;
  doc["ts"] = millis();

  String payload;
  serializeJson(doc, payload);

  MQTTProperties props;
  props.setContentType("application/json");
  props.setPayloadFormat(1);

  String topic =
      responseTopic.isEmpty() ? (_otaTopic + "/error") : responseTopic;
  _mqtt->publish(topic, payload, 0, false, &props);
}

void MQTTOTAv5::_publishSuccess(const String &ver,
                                const String &responseTopic) {
  if (_successCb)
    _successCb(ver);

  if (!_mqtt || !_mqtt->connected())
    return;

  StaticJsonDocument<256> doc;
  doc["device"] = _deviceID;
  doc["version"] = ver;
  doc["success"] = true;
  doc["bytes"] = _ctx.receivedBytes;
  doc["ts"] = millis();

  String payload;
  serializeJson(doc, payload);

  MQTTProperties props;
  props.setContentType("application/json");
  props.setPayloadFormat(1);

  String topic =
      responseTopic.isEmpty() ? (_otaTopic + "/success") : responseTopic;
  _mqtt->publish(topic, payload, 0, false, &props);
}

void MQTTOTAv5::_publishStateChange(OTAv5State state) {
  if (_stateCb)
    _stateCb((uint8_t)state);

  Serial.printf("[MQTTOTAv5] State → %s\n", _stateName(state).c_str());

  if (!_mqtt || !_mqtt->connected())
    return;

  StaticJsonDocument<256> doc;
  doc["device"] = _deviceID;
  doc["state"] = (uint8_t)state;
  doc["name"] = _stateName(state);
  doc["ts"] = millis();

  String payload;
  serializeJson(doc, payload);

  MQTTProperties props;
  props.setContentType("application/json");
  props.setPayloadFormat(1);

  _mqtt->publish(_otaTopic + "/state", payload, 0, false, &props);
}

void MQTTOTAv5::_publishAck(const String &corrId, bool ok, const String &msg) {
  if (!_mqtt || !_mqtt->connected() || corrId.isEmpty())
    return;

  StaticJsonDocument<256> doc;
  doc["device"] = _deviceID;
  doc["ok"] = ok;
  doc["msg"] = msg;
  doc["ts"] = millis();

  String payload;
  serializeJson(doc, payload);

  MQTTProperties props;
  props.setContentType("application/json");
  props.setPayloadFormat(1);
  props.setCorrelationData(corrId);

  _mqtt->publish(_ackTopic, payload, 0, false, &props);
}

// Memory utilities

bool MQTTOTAv5::checkMemory(size_t requiredBytes) {
  size_t freeHeap = ESP.getFreeHeap();
  bool ok = freeHeap >= (requiredBytes + MQTTOTAV5_MIN_MEMORY);
  if (!ok) {
    Serial.printf("[MQTTOTAv5] Low memory: %u free, need %zu\n", freeHeap,
                  requiredBytes + MQTTOTAV5_MIN_MEMORY);
  }
  return ok;
}

size_t MQTTOTAv5::getFreeHeap() { return ESP.getFreeHeap(); }

void MQTTOTAv5::logMemoryStatus() {
  Serial.printf("[MQTTOTAv5] Heap — free=%u  minFree=%u  maxAlloc=%u\n",
                ESP.getFreeHeap(), ESP.getMinFreeHeap(), ESP.getMaxAllocHeap());
}

// Diagnostics

void MQTTOTAv5::printDiagnostics() const {
  Serial.println("=== MQTTOTAv5 Diagnostics ===");
  Serial.printf("  DeviceID  : %s\n", _deviceID.c_str());
  Serial.printf("  Device    : %s\n", _deviceName.c_str());
  Serial.printf("  Version   : %s\n", _firmwareVersion.c_str());
  Serial.printf("  OTA Topic : %s\n", _otaTopic.c_str());
  Serial.printf("  Signature : %s\n", _requireSig ? "required" : "optional");
  Serial.printf("  State     : %s\n", _stateName(_ctx.state).c_str());
  Serial.printf("  Progress  : %d%%\n", _currentProgress);
  Serial.printf("  Received  : %zu bytes\n", _ctx.receivedBytes);

  logMemoryStatus();

  const esp_partition_t *running = esp_ota_get_running_partition();
  if (running) {
    Serial.printf("  Running   : %s @ 0x%08X\n", running->label,
                  running->address);
  }
  if (_ctx.update_partition) {
    Serial.printf("  OTA Part  : %s @ 0x%08X (%u bytes)\n",
                  _ctx.update_partition->label, _ctx.update_partition->address,
                  _ctx.update_partition->size);
  }

  Serial.printf("  Stats — chunks=%d errors=%d speed=%.1f KB/s\n",
                _stats.chunkCount, _stats.errorCount,
                _stats.avgSpeedBps / 1024.0f);
  Serial.println("=============================");
}

String MQTTOTAv5::getBootPartitionInfo() const {
  const esp_partition_t *boot = esp_ota_get_boot_partition();
  if (!boot)
    return "unknown";
  char buf[128];
  snprintf(buf, sizeof(buf), "label=%s addr=0x%08X size=%u", boot->label,
           boot->address, boot->size);
  return String(buf);
}

// Helpers

String MQTTOTAv5::_generateDeviceID() const {
  uint64_t mac = ESP.getEfuseMac();
  char buf[17];
  snprintf(buf, sizeof(buf), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  return String(buf);
}

String MQTTOTAv5::_stateName(OTAv5State s) const {
  switch (s) {
  case OTAV5_IDLE:
    return "IDLE";
  case OTAV5_AUTHENTICATING:
    return "AUTHENTICATING";
  case OTAV5_RECEIVING:
    return "RECEIVING";
  case OTAV5_DECODING:
    return "DECODING";
  case OTAV5_VALIDATING:
    return "VALIDATING";
  case OTAV5_WRITING:
    return "WRITING";
  case OTAV5_COMPLETING:
    return "COMPLETING";
  case OTAV5_SUCCESS:
    return "SUCCESS";
  case OTAV5_ERROR:
    return "ERROR";
  case OTAV5_ABORTED:
    return "ABORTED";
  default:
    return "UNKNOWN";
  }
}
