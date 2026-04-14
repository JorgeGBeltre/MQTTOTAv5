#include "ESP32_MQTTv5.h"
#include "MQTTOTAv5.h"
#include <WiFi.h>

const char *WIFI_SSID = "your-ssid";
const char *WIFI_PASS = "your-password";

const char *MQTT_HOST = "[IP_ADDRESS]";
const uint16_t MQTT_PORT = 1883;
const char *MQTT_CLIENT = "esp32-ota-basic";
const char *DEVICE_NAME = "my-device";
const char *FW_VERSION = "1.0.0";

ESP32_MQTTv5 mqtt;
MQTTOTAv5 ota;

void connectWiFi() {
  Serial.printf("WiFi: connecting to %s ...\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print('.');
  }
  Serial.printf("\nWiFi: %s\n", WiFi.localIP().toString().c_str());
}

void connectMQTT() {
  mqtt.begin(MQTT_HOST, MQTT_PORT);
  mqtt.setKeepAlive(60);
  mqtt.setCleanStart(true);
  mqtt.setAutoReconnect(true, 2000, 30000);

  mqtt.onConnect([]() {
    Serial.println("MQTT: connected");
    // ota.begin() must be called AFTER mqtt.connect()
    ota.begin(mqtt, DEVICE_NAME, FW_VERSION);

    // Allow unsigned firmware for this basic example (development only!)
    ota.requireSignature(false);
  });

  mqtt.onDisconnect([](MQTTReasonCode rc) {
    Serial.printf("MQTT: disconnected (0x%02X)\n", (uint8_t)rc);
  });

  mqtt.connect(MQTT_CLIENT);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\n=== BasicOTAv5 ===");

  // Register OTA callbacks before connecting
  ota.onProgress([](int pct, const String &ver) {
    Serial.printf("OTA progress: %d%% (%s)\n", pct, ver.c_str());
  });

  ota.onError([](const String &err, const String &ver) {
    Serial.printf("OTA error: %s (%s)\n", err.c_str(), ver.c_str());
  });

  ota.onSuccess([](const String &ver) {
    Serial.printf("OTA SUCCESS: %s — restarting...\n", ver.c_str());
  });

  ota.onStateChange(
      [](uint8_t state) { Serial.printf("OTA state: %d\n", state); });

  connectWiFi();
  connectMQTT();
}

void loop() {
  mqtt.loop();  // must be first
  ota.handle(); // handles timeout + non-blocking restart
  delay(10);
}
