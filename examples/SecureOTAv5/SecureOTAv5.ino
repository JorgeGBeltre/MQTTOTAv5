#include "ESP32_MQTTv5.h"
#include "MQTTOTAv5.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>

const char *WIFI_SSID = "your-ssid";
const char *WIFI_PASS = "your-password";

const char *MQTT_HOST = "your-broker.example.com";
const uint16_t MQTT_PORT = 8883;
const char *MQTT_CLIENT = "esp32-ota-secure";
const char *MQTT_USER = "ota-user";
const char *MQTT_PASS = "ota-password";
const char *DEVICE_NAME = "my-secure-device";
const char *FW_VERSION = "2.0.0";

const char *HMAC_KEY = "my-super-secret-key";

/*
const char *BROKER_CA_CERT = \
"-----BEGIN CERTIFICATE-----\n" \
"Your_CERTIFICATE_HERE\n" \
"-----END CERTIFICATE-----\n";
*/

WiFiClientSecure wifiClient;
ESP32_MQTTv5 mqtt;
MQTTOTAv5 ota;

void connectWiFi() {
  Serial.printf("WiFi: connecting to %s\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print('.');
  }
  Serial.printf("\nWiFi: %s\n", WiFi.localIP().toString().c_str());
}

void connectMQTT() {
  // Configure TLS
  wifiClient.setCACert(BROKER_CA_CERT);
  // For development with self-signed certs, use:
  // wifiClient.setInsecure(); // WARNING: disables certificate verification!

  mqtt.begin(wifiClient, MQTT_HOST, MQTT_PORT);
  mqtt.setKeepAlive(60);
  mqtt.setCleanStart(true);
  mqtt.setAutoReconnect(true, 2000, 60000);
  mqtt.setBufferSize(4096); // larger buffer for OTA chunks

  mqtt.onConnect([]() {
    Serial.println("MQTT: connected (TLS)");

    // Initialize OTA — signature is REQUIRED by default
    ota.begin(mqtt, DEVICE_NAME, FW_VERSION);
    ota.setSecurityKey(HMAC_KEY);
    // ota.requireSignature(true); // default — explicit for clarity
  });

  mqtt.onDisconnect([](MQTTReasonCode rc) {
    Serial.printf("MQTT: disconnected (0x%02X)\n", (uint8_t)rc);
  });

  mqtt.onError([](MQTTReasonCode rc, const String &msg) {
    Serial.printf("MQTT error: 0x%02X — %s\n", (uint8_t)rc, msg.c_str());
  });

  mqtt.connect(MQTT_CLIENT, MQTT_USER, MQTT_PASS);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\n=== SecureOTAv5 ===");

  ota.onProgress([](int pct, const String &ver) {
    Serial.printf("OTA [%d%%] version=%s heap=%u\n", pct, ver.c_str(),
                  ESP.getFreeHeap());
  });

  ota.onError([](const String &err, const String &ver) {
    Serial.printf("OTA ERROR: %s (version=%s)\n", err.c_str(), ver.c_str());
  });

  ota.onSuccess([](const String &ver) {
    Serial.printf("OTA SUCCESS: %s\n", ver.c_str());
  });

  ota.onStateChange([](uint8_t s) { Serial.printf("OTA state → %d\n", s); });

  ota.onAuthRequired([](const String &method, const String &data) {
    Serial.printf("AUTH challenge: method=%s\n", method.c_str());
  });

  connectWiFi();
  connectMQTT();
}

void loop() {
  mqtt.loop();
  ota.handle();

  static unsigned long lastDiag = 0;
  if (ota.isUpdateInProgress() && millis() - lastDiag > 30000) {
    ota.printDiagnostics();
    lastDiag = millis();
  }

  delay(10);
}
