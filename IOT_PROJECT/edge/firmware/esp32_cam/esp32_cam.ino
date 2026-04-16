#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <esp_camera.h>
#include <mbedtls/gcm.h>
#include <esp_system.h>

#define NODE_ID    "BORDER_001"
// Change to "BORDER_002" for the second camera.

const uint8_t AES_KEY[32] = {
  0x01, 0xf8, 0xe9, 0x28, 0xd1, 0x42, 0x37, 0xe7,
  0x37, 0x0e, 0xbc, 0x23, 0xc6, 0xb6, 0xc5, 0x91,
  0x06, 0xb7, 0x6e, 0x60, 0xd3, 0x81, 0x1c, 0xb9,
  0xf1, 0xee, 0x08, 0x15, 0x9f, 0x91, 0xc8, 0x3d
};
// Replace with BORDER_002 key for camera B.

IPAddress static_ip(10, 42, 0, 11);
// Change to IPAddress(10, 42, 0, 12) for camera B.
IPAddress gateway(10, 42, 0, 1);
IPAddress subnet(255, 255, 255, 0);

#define WIFI_SSID      "BORDER_SHIELD_FIELD"
#define WIFI_PASS      "field_secure_2026"
#define EDGE_IP        "10.42.0.1"
#define MQTT_PORT      1883
#define MQTT_PASS      "field_node_2026"
#define CAPTURE_TOKEN  "field_cam_2026"
#define EDGE_HTTP_PORT 8080

#define PWDN_GPIO_NUM    32
#define RESET_GPIO_NUM   -1
#define XCLK_GPIO_NUM     0
#define SIOD_GPIO_NUM    26
#define SIOC_GPIO_NUM    27
#define Y9_GPIO_NUM      35
#define Y8_GPIO_NUM      34
#define Y7_GPIO_NUM      39
#define Y6_GPIO_NUM      36
#define Y5_GPIO_NUM      21
#define Y4_GPIO_NUM      19
#define Y3_GPIO_NUM      18
#define Y2_GPIO_NUM       5
#define VSYNC_GPIO_NUM   25
#define HREF_GPIO_NUM    23
#define PCLK_GPIO_NUM    22

AsyncWebServer server(80);

void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
  static const char HEX_CHARS[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[i * 2] = HEX_CHARS[(bytes[i] >> 4) & 0x0F];
    out[i * 2 + 1] = HEX_CHARS[bytes[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

bool encrypt_frame_gcm(camera_fb_t *fb, uint8_t *ciphertext, uint8_t *tag, uint8_t *nonce) {
  esp_fill_random(nonce, 12);
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, fb->len, nonce, 12, nullptr, 0, fb->buf, ciphertext, 16, tag);
  }
  mbedtls_gcm_free(&ctx);
  return rc == 0;
}

int post_encrypted_image(const char *nonce_hex, const char *tag_hex, const String &seq_param, const String &position_param, const uint8_t *ciphertext, size_t ciphertext_len) {
  WiFiClient client;
  client.setTimeout(10000);
  if (!client.connect(EDGE_IP, EDGE_HTTP_PORT)) {
    return -1;
  }

  String boundary = "----esp32camfieldupload";
  String part1 = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"node_id\"\r\n\r\n" + String(NODE_ID) + "\r\n";
  String part2 = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"nonce\"\r\n\r\n" + String(nonce_hex) + "\r\n";
  String part3 = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\n" + String(tag_hex) + "\r\n";
  String part4 = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"seq_no\"\r\n\r\n" + seq_param + "\r\n";
  String part5 = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"position\"\r\n\r\n" + position_param + "\r\n";
  String fileHeader = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"image\"; filename=\"capture.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n";
  String closing = "\r\n--" + boundary + "--\r\n";
  size_t content_length = part1.length() + part2.length() + part3.length() + part4.length() + part5.length() + fileHeader.length() + ciphertext_len + closing.length();

  client.print("POST /upload_image HTTP/1.1\r\n");
  client.print(String("Host: ") + EDGE_IP + ":" + EDGE_HTTP_PORT + "\r\n");
  client.print("Connection: close\r\n");
  client.print(String("Content-Type: multipart/form-data; boundary=") + boundary + "\r\n");
  client.print(String("Content-Length: ") + content_length + "\r\n\r\n");
  client.print(part1);
  client.print(part2);
  client.print(part3);
  client.print(part4);
  client.print(part5);
  client.print(fileHeader);
  client.write(ciphertext, ciphertext_len);
  client.print(closing);

  String status_line = client.readStringUntil('\n');
  int status_code = -2;
  if (status_line.startsWith("HTTP/1.1 ")) {
    status_code = status_line.substring(9, 12).toInt();
  }
  while (client.connected() || client.available()) {
    while (client.available()) {
      client.read();
    }
    delay(1);
  }
  client.stop();
  return status_code;
}

void handle_capture(AsyncWebServerRequest *request) {
  if (!request->hasParam("token") || !request->hasParam("position") || !request->hasParam("seq")) {
    request->send(400, "application/json", "{\"status\":\"error\",\"code\":400}");
    return;
  }

  String token = request->getParam("token")->value();
  String position = request->getParam("position")->value();
  String seq = request->getParam("seq")->value();
  if (token != CAPTURE_TOKEN) {
    request->send(403, "application/json", "{\"status\":\"error\",\"code\":403}");
    return;
  }

  camera_fb_t *fb = esp_camera_fb_get();
  if (!fb) {
    request->send(500, "application/json", "{\"status\":\"error\",\"code\":500}");
    return;
  }

  uint8_t *ciphertext = (uint8_t *)malloc(fb->len);
  if (!ciphertext) {
    esp_camera_fb_return(fb);
    request->send(500, "application/json", "{\"status\":\"error\",\"code\":501}");
    return;
  }

  uint8_t nonce[12];
  uint8_t tag[16];
  char nonce_hex[25];
  char tag_hex[33];
  if (!encrypt_frame_gcm(fb, ciphertext, tag, nonce)) {
    free(ciphertext);
    esp_camera_fb_return(fb);
    request->send(500, "application/json", "{\"status\":\"error\",\"code\":502}");
    return;
  }

  bytes_to_hex(nonce, sizeof(nonce), nonce_hex);
  bytes_to_hex(tag, sizeof(tag), tag_hex);
  Serial.printf("[CAM] frame %u bytes\n", (unsigned int)fb->len);
  Serial.printf("[CAM] nonce=%s\n", nonce_hex);
  int rpi_status = post_encrypted_image(nonce_hex, tag_hex, seq, position, ciphertext, fb->len);
  Serial.printf("[CAM] POST -> RPi status=%d\n", rpi_status);
  Serial.printf("[CAM] position=%s seq=%s\n", position.c_str(), seq.c_str());

  free(ciphertext);
  esp_camera_fb_return(fb);

  if (rpi_status >= 200 && rpi_status < 300) {
    request->send(200, "application/json", String("{\"status\":\"ok\",\"rpi\":") + rpi_status + "}");
  } else {
    request->send(502, "application/json", String("{\"status\":\"error\",\"code\":") + rpi_status + "}");
  }
}

void setup_camera() {
  camera_config_t config = {};
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer = LEDC_TIMER_0;
  config.pin_d0 = Y2_GPIO_NUM;
  config.pin_d1 = Y3_GPIO_NUM;
  config.pin_d2 = Y4_GPIO_NUM;
  config.pin_d3 = Y5_GPIO_NUM;
  config.pin_d4 = Y6_GPIO_NUM;
  config.pin_d5 = Y7_GPIO_NUM;
  config.pin_d6 = Y8_GPIO_NUM;
  config.pin_d7 = Y9_GPIO_NUM;
  config.pin_xclk = XCLK_GPIO_NUM;
  config.pin_pclk = PCLK_GPIO_NUM;
  config.pin_vsync = VSYNC_GPIO_NUM;
  config.pin_href = HREF_GPIO_NUM;
  config.pin_sscb_sda = SIOD_GPIO_NUM;
  config.pin_sscb_scl = SIOC_GPIO_NUM;
  config.pin_pwdn = PWDN_GPIO_NUM;
  config.pin_reset = RESET_GPIO_NUM;
  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG;
  config.frame_size = FRAMESIZE_VGA;
  config.jpeg_quality = 12;
  config.fb_count = 1;

  if (esp_camera_init(&config) != ESP_OK) {
    Serial.println("[CAM] init failed");
    while (true) {
      delay(1000);
    }
  }
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

  WiFi.config(static_ip, gateway, subnet);
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

void setup() {
  Serial.begin(115200);
  delay(500);
  connect_wifi();
  setup_camera();

  camera_fb_t *warmup = esp_camera_fb_get();
  if (warmup) {
    esp_camera_fb_return(warmup);
  }

  server.on("/capture", HTTP_GET, handle_capture);
  server.on("/health", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "application/json", String("{\"status\":\"ok\",\"node\":\"") + NODE_ID + "\"}");
  });
  server.begin();
}

void loop() {
}
