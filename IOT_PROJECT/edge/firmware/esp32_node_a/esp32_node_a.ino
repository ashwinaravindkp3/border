#include <WiFi.h>
#include <PubSubClient.h>
#include <HTTPClient.h>
#include <ESP32Servo.h>
#include <mbedtls/gcm.h>
#include <esp_system.h>

#define NODE_ID "BORDER_001"
#define MQTT_USER NODE_ID

const uint8_t AES_KEY[32] = {
  0x01, 0xf8, 0xe9, 0x28, 0xd1, 0x42, 0x37, 0xe7,
  0x37, 0x0e, 0xbc, 0x23, 0xc6, 0xb6, 0xc5, 0x91,
  0x06, 0xb7, 0x6e, 0x60, 0xd3, 0x81, 0x1c, 0xb9,
  0xf1, 0xee, 0x08, 0x15, 0x9f, 0x91, 0xc8, 0x3d
};

#define WIFI_SSID      "BORDER_SHIELD_FIELD"
#define WIFI_PASS      "field_secure_2026"
#define EDGE_IP        "10.42.0.1"
#define MQTT_PORT      1883
#define MQTT_PASS      "field_node_2026"
#define CAPTURE_TOKEN  "field_cam_2026"
#define EDGE_HTTP_PORT 8080

#define RADAR_RX   16
#define RADAR_TX   17
#define PAN_PIN    12
#define TILT_PIN   13

#define CAM_IP     "10.42.0.11"
#define CAM_PORT   80

struct GCMPacket {
  char nonce_hex[25];
  char ciphertext_hex[1024];
  char tag_hex[33];
  bool valid;
};

WiFiClient wifi_client;
PubSubClient mqtt(wifi_client);
Servo pan_servo;
Servo tilt_servo;

unsigned long seq_no = 0;
unsigned long last_heartbeat_ms = 0;
unsigned long last_trigger_ms = 0;
bool last_radar_state = false;

void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
  static const char HEX_CHARS[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[i * 2] = HEX_CHARS[(bytes[i] >> 4) & 0x0F];
    out[i * 2 + 1] = HEX_CHARS[bytes[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

bool hex_to_bytes(const char *hex, uint8_t *out, size_t max_len, size_t &out_len) {
  size_t hex_len = strlen(hex);
  if ((hex_len % 2) != 0 || (hex_len / 2) > max_len) {
    return false;
  }
  out_len = hex_len / 2;
  for (size_t i = 0; i < out_len; ++i) {
    char hi = hex[i * 2];
    char lo = hex[i * 2 + 1];
    uint8_t hi_val = (hi >= '0' && hi <= '9') ? hi - '0' : (uint8_t)(tolower(hi) - 'a' + 10);
    uint8_t lo_val = (lo >= '0' && lo <= '9') ? lo - '0' : (uint8_t)(tolower(lo) - 'a' + 10);
    if (hi_val > 15 || lo_val > 15) {
      return false;
    }
    out[i] = (uint8_t)((hi_val << 4) | lo_val);
  }
  return true;
}

bool json_get_string(const char *json, const char *key, char *out, size_t out_size) {
  String needle = "\"" + String(key) + "\"";
  const char *found = strstr(json, needle.c_str());
  if (!found) {
    return false;
  }
  const char *colon = strchr(found, ':');
  if (!colon) {
    return false;
  }
  const char *start = strchr(colon, '"');
  if (!start) {
    return false;
  }
  ++start;
  const char *end = strchr(start, '"');
  if (!end) {
    return false;
  }
  size_t len = (size_t)(end - start);
  if (len >= out_size) {
    len = out_size - 1;
  }
  memcpy(out, start, len);
  out[len] = '\0';
  return true;
}

GCMPacket encrypt_gcm(const char *plaintext) {
  GCMPacket packet = {};
  uint8_t nonce[12];
  uint8_t tag[16];
  uint8_t ciphertext[512];
  size_t pt_len = strlen(plaintext);
  if (pt_len == 0 || pt_len > sizeof(ciphertext)) {
    return packet;
  }
  esp_fill_random(nonce, sizeof(nonce));
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, pt_len, nonce, sizeof(nonce), nullptr, 0, (const unsigned char *)plaintext, ciphertext, sizeof(tag), tag);
  }
  mbedtls_gcm_free(&ctx);
  if (rc != 0) {
    return packet;
  }
  bytes_to_hex(nonce, sizeof(nonce), packet.nonce_hex);
  bytes_to_hex(ciphertext, pt_len, packet.ciphertext_hex);
  bytes_to_hex(tag, sizeof(tag), packet.tag_hex);
  packet.valid = true;
  return packet;
}

bool decrypt_gcm(const char *nonce_hex, const char *ct_hex, const char *tag_hex, char *out, size_t max_len) {
  uint8_t nonce[12];
  uint8_t ciphertext[512];
  uint8_t tag[16];
  uint8_t plaintext[512];
  size_t nonce_len = 0;
  size_t ct_len = 0;
  size_t tag_len = 0;
  if (!hex_to_bytes(nonce_hex, nonce, sizeof(nonce), nonce_len) || nonce_len != sizeof(nonce)) {
    return false;
  }
  if (!hex_to_bytes(ct_hex, ciphertext, sizeof(ciphertext), ct_len) || ct_len == 0) {
    return false;
  }
  if (!hex_to_bytes(tag_hex, tag, sizeof(tag), tag_len) || tag_len != sizeof(tag)) {
    return false;
  }
  if ((ct_len + 1) > max_len) {
    return false;
  }
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_auth_decrypt(&ctx, ct_len, nonce, nonce_len, nullptr, 0, tag, tag_len, ciphertext, plaintext);
  }
  mbedtls_gcm_free(&ctx);
  if (rc != 0) {
    return false;
  }
  memcpy(out, plaintext, ct_len);
  out[ct_len] = '\0';
  return true;
}

void mqtt_publish_encrypted(const char *topic, const char *plaintext) {
  GCMPacket packet = encrypt_gcm(plaintext);
  if (!packet.valid) {
    Serial.println("[ENC] encryption failed");
    return;
  }
  char envelope[1024];
  snprintf(envelope, sizeof(envelope), "{\"node_id\":\"%s\",\"nonce\":\"%s\",\"ciphertext\":\"%s\",\"tag\":\"%s\",\"seq_no\":%lu}", NODE_ID, packet.nonce_hex, packet.ciphertext_hex, packet.tag_hex, seq_no);
  if (!mqtt.publish(topic, envelope)) {
    Serial.printf("[MQTT] publish failed topic=%s\n", topic);
  }
}

void publish_event(const char *event_type, float value) {
  ++seq_no;
  char plaintext[256];
  snprintf(plaintext, sizeof(plaintext), "{\"node_id\":\"%s\",\"event_type\":\"%s\",\"seq_no\":%lu,\"timestamp_ms\":%lu,\"value\":%.2f}", NODE_ID, event_type, seq_no, millis(), value);
  String topic = String("border/") + NODE_ID + "/event";
  mqtt_publish_encrypted(topic.c_str(), plaintext);
}

void send_heartbeat() {
  ++seq_no;
  char plaintext[256];
  snprintf(plaintext, sizeof(plaintext), "{\"node_id\":\"%s\",\"event_type\":\"heartbeat\",\"seq_no\":%lu,\"timestamp_ms\":%lu,\"value\":1.00}", NODE_ID, seq_no, millis());
  String topic = String("border/") + NODE_ID + "/heartbeat";
  mqtt_publish_encrypted(topic.c_str(), plaintext);
  last_heartbeat_ms = millis();
}

void connect_wifi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.disconnect(true, true);
  delay(500);

  Serial.printf("[WIFI] scanning for SSID=%s\n", WIFI_SSID);
  int networks = WiFi.scanNetworks();
  bool found = false;
  for (int i = 0; i < networks; ++i) {
    Serial.printf("[WIFI] found ssid=%s rssi=%d channel=%d enc=%d\n",
                  WiFi.SSID(i).c_str(), WiFi.RSSI(i), WiFi.channel(i), WiFi.encryptionType(i));
    if (WiFi.SSID(i) == WIFI_SSID) {
      found = true;
    }
  }
  Serial.printf("[WIFI] target %s\n", found ? "found" : "not found");

  WiFi.scanDelete();
  WiFi.disconnect(true);
  delay(500);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.disconnect(true, true);
  delay(500);

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long wifi_start_ms = millis();
  while (WiFi.status() != WL_CONNECTED) {
    Serial.printf("[WIFI] connecting status=%d\n", WiFi.status());
    if (millis() - wifi_start_ms >= 15000UL) {
      Serial.println("[WIFI] FAILED → restarting");
      ESP.restart();
    }
    delay(1000);
  }
  Serial.print("[WIFI] IP=");
  Serial.println(WiFi.localIP());
  Serial.print("[WIFI] gateway=");
  Serial.println(WiFi.gatewayIP());
  Serial.print("[WIFI] RSSI=");
  Serial.println(WiFi.RSSI());
  delay(1000);
}

void connect_mqtt() {
  while (!mqtt.connected()) {
    Serial.print("[MQTT] connecting...");
    if (mqtt.connect(NODE_ID, MQTT_USER, MQTT_PASS)) {
      Serial.println("connected");
      String cmd_topic = String("border/") + NODE_ID + "/command";
      String challenge_topic = String("border/") + NODE_ID + "/challenge";
      mqtt.subscribe(cmd_topic.c_str());
      mqtt.subscribe(challenge_topic.c_str());
    } else {
      Serial.printf("failed rc=%d\n", mqtt.state());
      delay(2000);
    }
  }
}

void trigger_camera(int position) {
  HTTPClient http;
  String url = String("http://") + CAM_IP + "/capture?token=" + CAPTURE_TOKEN + "&position=" + String(position) + "&seq=" + String(seq_no);
  http.begin(url);
  http.setTimeout(3000);
  int code = http.GET();
  Serial.printf("[CAM] trigger pos=%d response=%d\n", position, code);
  http.end();
}

bool read_rd01() {
  while (Serial2.available() >= 3) {
    int b0 = Serial2.read();
    if (b0 != 0xAA) {
      continue;
    }
    int b1 = Serial2.read();
    if (b1 != 0xFF) {
      continue;
    }
    int data = Serial2.read();
    return (data & 0x01) != 0;
  }
  return false;
}

void patrol_sweep() {
  const int positions[] = {0, 45, 90, 135, 180};
  for (size_t i = 0; i < (sizeof(positions) / sizeof(positions[0])); ++i) {
    pan_servo.write(positions[i]);
    tilt_servo.write(60);
    delay(800);
    trigger_camera(positions[i]);
    delay(300);
  }
  pan_servo.write(90);
  tilt_servo.write(60);
}

void handle_command_json(const char *json) {
  char command[64];
  if (!json_get_string(json, "command", command, sizeof(command))) {
    Serial.println("[CMD] missing command");
    return;
  }
  if (strcmp(command, "patrol_sweep") == 0) {
    patrol_sweep();
  } else if (strcmp(command, "heartbeat_req") == 0) {
    send_heartbeat();
  } else {
    Serial.printf("[CMD] unknown=%s\n", command);
  }
}

void on_message(char *topic, byte *payload, unsigned int len) {
  char incoming[1024];
  size_t copy_len = len < (sizeof(incoming) - 1) ? len : (sizeof(incoming) - 1);
  memcpy(incoming, payload, copy_len);
  incoming[copy_len] = '\0';
  char nonce_hex[25];
  char ct_hex[1024];
  char tag_hex[33];
  if (!json_get_string(incoming, "nonce", nonce_hex, sizeof(nonce_hex)) || !json_get_string(incoming, "ciphertext", ct_hex, sizeof(ct_hex)) || !json_get_string(incoming, "tag", tag_hex, sizeof(tag_hex))) {
    Serial.println("[MQTT] invalid envelope");
    return;
  }
  char plaintext[512];
  if (!decrypt_gcm(nonce_hex, ct_hex, tag_hex, plaintext, sizeof(plaintext))) {
    Serial.println("[GCM] decrypt failed");
    return;
  }
  String topic_str(topic);
  if (topic_str.endsWith("/challenge")) {
    char challenge_nonce[64];
    if (!json_get_string(plaintext, "nonce", challenge_nonce, sizeof(challenge_nonce))) {
      strlcpy(challenge_nonce, "missing", sizeof(challenge_nonce));
    }
    ++seq_no;
    char response[128];
    snprintf(response, sizeof(response), "{\"nonce\":\"%s\",\"node_id\":\"%s\"}", challenge_nonce, NODE_ID);
    String response_topic = String("border/") + NODE_ID + "/challenge_response";
    mqtt_publish_encrypted(response_topic.c_str(), response);
  } else if (topic_str.endsWith("/command")) {
    handle_command_json(plaintext);
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  pan_servo.attach(PAN_PIN);
  tilt_servo.attach(TILT_PIN);
  pan_servo.write(90);
  tilt_servo.write(60);
  Serial2.begin(256000, SERIAL_8N1, RADAR_RX, RADAR_TX);
  connect_wifi();
  mqtt.setServer(EDGE_IP, MQTT_PORT);
  mqtt.setCallback(on_message);
  connect_mqtt();
}

void loop() {
  if (!mqtt.connected()) {
    connect_mqtt();
  }
  mqtt.loop();
  if (millis() - last_heartbeat_ms >= 30000UL) {
    send_heartbeat();
  }
  bool detected = read_rd01();
  if (detected && !last_radar_state && (millis() - last_trigger_ms >= 5000UL)) {
    trigger_camera(90);
    publish_event("radar_trigger", 1.0f);
    last_trigger_ms = millis();
  }
  last_radar_state = detected;
}
