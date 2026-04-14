#include "ESP32_MQTTv5.h"
#include "MQTTOTAv5.h"
#include <WiFi.h>

const char *WIFI_SSID = "your-ssid";
const char *WIFI_PASS = "your-password";

const char *MQTT_HOST = "[IP_ADDRESS]";
const uint16_t MQTT_PORT = 1883;
const char *MQTT_CLIENT = "esp32-chunked-ota";
const char *DEVICE_NAME = "my-chunked-device";
const char *FW_VERSION = "3.0.0";
const char *HMAC_KEY = "chunked-secret";

ESP32_MQTTv5 mqtt;
MQTTOTAv5 ota;

unsigned long _otaStartMs = 0;

void connectWiFi() {
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print('.');
  }
  Serial.printf("\nWiFi OK: %s\n", WiFi.localIP().toString().c_str());
}

void connectMQTT() {
  mqtt.begin(MQTT_HOST, MQTT_PORT);
  mqtt.setKeepAlive(120); // longer keepalive for chunked transfer
  mqtt.setCleanStart(true);
  mqtt.setAutoReconnect(true, 2000, 30000);
  mqtt.setBufferSize(8192); // large buffer for base64-encoded chunks

  mqtt.onConnect([]() {
    Serial.println("MQTT: connected");

    ota.begin(mqtt, DEVICE_NAME, FW_VERSION);
    ota.setSecurityKey(HMAC_KEY);
    ota.requireSignature(true);
    ota.enableVersionCheck(true);
    ota.enableRollbackProtection(true);
    ota.setMaxRetries(MQTTOTAV5_MAX_RETRIES);

    Serial.printf("Free OTA space: %zu bytes\n", ota.getFreeOTASpace());
    MQTTOTAv5::logMemoryStatus();
  });

  mqtt.onDisconnect([](MQTTReasonCode rc) {
    Serial.printf("MQTT disconnected (0x%02X)\n", (uint8_t)rc);
  });

  mqtt.onError([](MQTTReasonCode rc, const String &msg) {
    Serial.printf("MQTT error: 0x%02X — %s\n", (uint8_t)rc, msg.c_str());
  });

  mqtt.connect(MQTT_CLIENT);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\n=== ChunkedOTAv5 ===");
  Serial.printf("Free heap at boot: %u\n", ESP.getFreeHeap());

  ota.onProgress([](int pct, const String &ver) {
    OTAv5Statistics stats = ota.getStatistics();
    Serial.printf("[%3d%%] chunks=%d  received=%zu  speed=%.1f KB/s  heap=%u\n",
                  pct, stats.chunkCount, stats.receivedBytes,
                  stats.avgSpeedBps / 1024.0f, ESP.getFreeHeap());
  });

  ota.onError([](const String &err, const String &ver) {
    Serial.printf("OTA ERROR [%s]: %s\n", ver.c_str(), err.c_str());
    MQTTOTAv5::logMemoryStatus();
  });

  ota.onSuccess([](const String &ver) {
    unsigned long elapsed = millis() - _otaStartMs;
    OTAv5Statistics stats = ota.getStatistics();
    Serial.printf("OTA SUCCESS: version=%s  time=%.1f s  speed=%.1f KB/s\n",
                  ver.c_str(), elapsed / 1000.0f, stats.avgSpeedBps / 1024.0f);
    ota.printDiagnostics();
  });

  ota.onStateChange([](uint8_t s) {
    // State 2=RECEIVING starts the clock
    if (s == (uint8_t)OTAV5_RECEIVING) {
      _otaStartMs = millis();
    }
    Serial.printf("OTA state → %d\n", s);
  });

  connectWiFi();
  connectMQTT();
}

void loop() {
  mqtt.loop();
  ota.handle();
  delay(5);
}
