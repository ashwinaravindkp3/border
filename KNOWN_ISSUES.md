# Border Shield IoT — Known Issues

## What Works

- **Edge node startup**: `edge_node.py` starts, creates the WiFi hotspot, fetches node keys and
  coordinates from fog, connects to both brokers, and enters the main loop.
- **Fog node startup**: `fog_node.py` starts, connects to the edge MQTT broker and server MQTT
  broker, starts the HTTP proxy on port 8080, and initialises the SQLite buffer.
- **MQTT uplink security checks**: rate limiting, duplicate-seq detection, oversized-payload
  rejection, and unknown-node blocking all execute correctly.
- **GCM encryption/decryption**: AES-256-GCM verify (`algo_1_gcm_verify`) and
  `encrypt_for_node` work for nodes whose keys have been fetched.
- **Challenge-response protocol** (logic only): the edge issues challenges over MQTT and
  validates HMAC responses correctly when a node is present.
- **Anomaly scoring + decay**: `algo_6_anomaly_score` accumulates and decays scores correctly.
- **Blacklist expiry**: expired blacklist entries are cleared automatically on the next received
  message from that node, and by `algo_4_whitelist`.
- **Downlink command filtering**: fog drops any command not in `KNOWN_COMMANDS`; edge
  encrypts valid commands before forwarding to field nodes.
- **Mosquitto bridge config** (`mosquitto_fog.conf`): directional topic rules prevent the
  feedback loop. Deploy this file to the fog Pi.
- **Buffer retry with reconnect**: the fog's retry thread checks upstream connectivity and
  reconnects before attempting to re-publish queued messages (fixes rc=4).
- **Async security/L7 proxy**: `proxy_security_event` and `proxy_l7_alert` return immediately
  and dispatch the server call in a daemon thread — fog never blocks on server downtime.
- **HTTP timeout**: all `server_request` calls are capped at 3 s (was 10–15 s).
- **ESP32-CAM WiFi watchdog**: reconnects automatically if the association drops. Power-save
  mode is disabled for stable connectivity.

---

## Partially Working

- **Fog ↔ server MQTT bridge (Python)**: the `bridge_to_server` / `bridge_local` clients in
  `fog_node.py` subscribe to the right topics and filter directions. Full verification requires
  the server broker to be running and the bridge to sustain a connection.
- **Image relay pipeline** (`/relay_image` → `/upload_image`): fog and edge endpoints are
  implemented; end-to-end relay needs a live ESP32-CAM, running server, and tested upload.
- **Plausibility / teleportation detection** (`algo_7_plausibility`): logic is correct but
  requires at least two nodes with real GPS coordinates registered in the server database.
- **Heartbeat anomaly detection**: baseline statistics need ≥ 5 heartbeat intervals to activate;
  first few minutes after startup will not flag anything.
- **Anomaly score decay**: decays 1 point/minute — correct, but needs long-running deployment
  to verify the decay keeps scores stable under light traffic.

---

## Needs Hardware to Test

- **ESP32-CAM WiFi connection**: `WIFI_PS_NONE` power-save disable and the watchdog in
  `loop()` require a physical ESP32-CAM board to validate.
- **Challenge-response end-to-end**: the edge sends encrypted challenges over MQTT; the ESP32
  nodes must compute and publish the HMAC response. Requires live firmware on boards.
- **MQTT bridge QoS / reconnect**: upstream broker disconnect recovery (rc=128, rc=4) must be
  tested with a real server running Mosquitto and a real network interruption.
- **Static IP assignment on ESP32-CAM**: `WiFi.config()` + `delay(100)` settling behaviour is
  hardware-dependent; confirm the camera receives `10.42.0.11` on the field AP.
- **ACL file + Mosquitto restart** (`write_acl_file`): requires `sudo` on the Pi and a running
  Mosquitto service.
- **Hotspot bring-up** (`start_hotspot`): requires `nmcli`, `wlan0`, and NetworkManager on the
  Pi; tested paths include the "conflicting client profile" removal step.

---

## What to Do When X Error Appears

### `[FOG UPLINK] forward queued rc=4`
Upstream MQTT client not connected. The buffer retry thread now reconnects automatically every
10 s. Check the server broker is running and reachable from the fog Pi (`ping 10.42.0.1`).
If the broker is up but the Pi still shows rc=4, restart `fog_node.py`.

### `[FOG BRIDGE] reconnect failed: <error>`
The server broker rejected the reconnect. Common causes: broker is down, network unreachable,
or client ID collision. Verify `mosquitto` is running on the server and that no other client
uses `fog_bridge_01` or `fog-server-bridge`.

### `[EDGE SECURITY] liveness_failure BORDER_00x`
A challenge was issued but no response arrived within 60 s (was 10 s). Score increases by +10
(was +30). Three missed challenges = 30 points — well below the 90-point blacklist threshold.
Expected during initial deployment before ESP32 nodes are flashed and connected.

### `[EDGE] BORDER_00x blacklist expired, cleared`
Normal. Node was previously blacklisted (e.g. many liveness failures), blacklist expired (60 s,
was 300 s), and the next message from the node cleared the entry automatically.

### `[WIFI] FAILED → restarting` (ESP32-CAM serial)
The ESP32-CAM could not associate within 15 s. Check:
1. Edge Pi hotspot is up: `nmcli con show border-shield-ap`
2. SSID/password match `BORDER_SHIELD_FIELD` / `field_secure_2026`
3. Camera is within range (RSSI < −80 dBm is marginal)
4. Only 2.4 GHz band is used (ESP32 does not support 5 GHz)

### `[WIFI] connecting status=1 (NO_SSID)` (ESP32-CAM serial)
Hotspot SSID is not visible to the camera. Confirm channel 6 / band bg on the Pi AP profile
and that the Pi's wlan0 is in AP mode (`iwconfig wlan0`).

### `[FOG PROXY] request failed … Connection refused`
Server Flask app is down. Fog will queue MQTT messages in SQLite and retry every 10 s. HTTP
security events are fire-and-forget (dropped silently). Restart the server and messages will
drain automatically.

### `rc=128` on MQTT disconnect
Mosquitto broker crashed or the network dropped. Both edge and fog clients have auto-reconnect
configured with exponential back-off (2–10 s). No manual action needed; monitor logs to confirm
reconnection.

### `Unknown command dropped` in fog log
A `border/+/command` message arrived from the server with a command value not in
`KNOWN_COMMANDS`. Either the server is sending an unsupported command or the payload is
malformed. Check the server-side command dispatch and add the new command to `KNOWN_COMMANDS`
in `fog_node.py` if it is intentional.
