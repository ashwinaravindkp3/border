#include <WiFi.h>

#define WIFI_SSID "BORDER_SHIELD_FIELD"
#define WIFI_PASS "field_secure_2026"

void setup() {
  Serial.begin(115200);
  delay(1000);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.disconnect(true, true);
  delay(500);

  Serial.println();
  Serial.println("[WIFI] connecting to RPi hotspot...");
  Serial.print("[WIFI] SSID=");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASS);

  while (WiFi.status() != WL_CONNECTED) {
    Serial.print("[WIFI] status=");
    Serial.println(WiFi.status());
    delay(1000);
  }

  Serial.println("ohk");
  Serial.print("[WIFI] IP=");
  Serial.println(WiFi.localIP());
  Serial.print("[WIFI] gateway=");
  Serial.println(WiFi.gatewayIP());
  Serial.print("[WIFI] RSSI=");
  Serial.println(WiFi.RSSI());
}

void loop() {
  delay(1000);
}
