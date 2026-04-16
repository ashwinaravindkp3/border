import io
import json
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime

import paho.mqtt.client as mqtt
import requests
from flask import Flask, jsonify, request


SERVER_IP = "10.42.0.1"
SERVER_PORT = 5000
SERVER_MQTT_PORT = 1883
EDGE_IP = "192.168.1.2"
EDGE_MQTT_PORT = 1883
FOG_HTTP_PORT = 8080
RATE_LIMIT_MSG_PER_SEC = 10
DUPLICATE_WINDOW_SECS = 30
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
BUFFER_DB = "fog_buffer.db"

KNOWN_COMMANDS = [
    "patrol_sweep",
    "trigger_alarm",
    "stop_alarm",
    "heartbeat_req",
]

LOGIN_USERNAME = "hq_officer"
LOGIN_PASSWORD = "border2026"
NODE_CACHE_TTL_SECS = 60
ANOMALY_WINDOW_SECS = 60
ANOMALY_EVENT_THRESHOLD = 20
IMAGE_RATE_WINDOW_SECS = 2
IMAGE_MAX_BYTES = 10 * 1024 * 1024
BUFFER_RETRY_INTERVAL_SECS = 10
HTTP_TIMEOUT_SECS = 15
IMAGE_HTTP_TIMEOUT_SECS = 30
LOCAL_BROKER_HOST = "localhost"
LOCAL_BROKER_PORT = 1883


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(layer, message):
    print(f"[{ts()}][{layer}] {message}", flush=True)


class FogNode:
    def __init__(self):
        self.db_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.session = requests.Session()
        self.session.trust_env = False
        self.jwt_token = None
        self.known_nodes = set()
        self.last_cache_refresh = 0.0

        self.rate_tracker = defaultdict(list)
        self.seen_seqs = defaultdict(dict)
        self.anomaly_tracker = defaultdict(list)
        self.image_rate_tracker = defaultdict(list)

        callback_api = getattr(getattr(mqtt, "CallbackAPIVersion", None), "VERSION2", None)
        if callback_api is not None:
            self.client_edge = mqtt.Client(callback_api_version=callback_api, client_id="fog-edge-bridge", clean_session=True)
            self.client_server = mqtt.Client(callback_api_version=callback_api, client_id="fog-server-bridge", clean_session=True)
        else:
            self.client_edge = mqtt.Client(client_id="fog-edge-bridge", clean_session=True)
            self.client_server = mqtt.Client(client_id="fog-server-bridge", clean_session=True)

        self.client_edge.on_connect = self.on_edge_connect
        self.client_edge.on_disconnect = self.on_edge_disconnect
        self.client_edge.on_message = self.on_edge_message

        self.client_server.on_connect = self.on_server_connect
        self.client_server.on_disconnect = self.on_server_disconnect
        self.client_server.on_message = self.on_server_message

        self.bridge_to_server = None
        self.bridge_local = None

        self.app = Flask(__name__)
        self._configure_routes()

    def _configure_routes(self):
        @self.app.route("/")
        @self.app.route("/health")
        def health():
            return jsonify({
                "status": "ok",
                "nodes_cached": len(self.known_nodes),
                "fog_ip": "192.168.1.1",
                "server_ip": SERVER_IP,
            }), 200

        @self.app.route("/node_keys", methods=["GET", "POST"])
        def proxy_node_keys():
            if request.method == "POST":
                data = request.get_json(force=True) or {}
                node_ids = data.get("node_ids", [])
            else:
                node_ids_str = request.args.get("node_ids", "")
                node_ids = [n.strip() for n in node_ids_str.split(",") if n.strip()]

            if not node_ids:
                return jsonify({"error": "missing node_ids"}), 400

            node_ids_str = ",".join(node_ids)

            resp = self.server_request(
                "GET",
                "/api/node_keys",
                params={"node_ids": node_ids_str},
                extra_headers={"X-Edge-Token": "edge_secret_2026"},
            )
            if resp is None:
                return jsonify({"error": "server unavailable"}), 502
            print(
                f"[FOG PROXY] node_keys status={resp.status_code} nodes={len(node_ids)}",
                flush=True,
            )
            return self.make_proxy_response(resp)

        @self.app.route("/node_coords")
        def proxy_node_coords():
            resp = self.server_request("GET", "/api/nodes")
            if resp is None:
                return jsonify({"error": "server unavailable"}), 502
            try:
                nodes = resp.json()
            except ValueError:
                return jsonify({"error": "invalid server response"}), 502
            coords = {
                n["node_id"]: {
                    "lat": n["lat"],
                    "lng": n["lng"],
                }
                for n in nodes
                if isinstance(n, dict) and "node_id" in n
            }
            return jsonify(coords), 200

        @self.app.route("/security_event", methods=["POST"])
        def proxy_security_event():
            data = request.get_json(force=True) or {}
            print(
                f"[FOG PROXY] security_event {data.get('attack_type')} from {data.get('node_id')}",
                flush=True,
            )
            # Fire and forget — never block fog on a slow/down server
            def send_async():
                try:
                    self.server_request("POST", "/api/security_log", json=data)
                except Exception:
                    pass  # Server down — ignore
            threading.Thread(target=send_async, daemon=True).start()
            return jsonify({"status": "queued"}), 200

        @self.app.route("/l7_alert", methods=["POST"])
        def proxy_l7_alert():
            data = request.get_json(force=True) or {}
            print(f"[FOG PROXY] L7 alert from {data.get('node_id')}", flush=True)
            # Fire and forget — never block fog on a slow/down server
            def send_async():
                try:
                    self.server_request("POST", "/api/l7_alert", json=data)
                except Exception:
                    pass  # Server down — ignore
            threading.Thread(target=send_async, daemon=True).start()
            return jsonify({"status": "queued"}), 200

        @self.app.post("/relay_image")
        def relay_image():
            print("[DEBUG] relay_image called", flush=True)
            print(f"[DEBUG] form data: {dict(request.form)}", flush=True)
            print(f"[DEBUG] files: {list(request.files.keys())}", flush=True)
            print(f"[DEBUG] known_nodes count: {len(self.known_nodes)}", flush=True)
            print(f"[DEBUG] node_id from form: {request.form.get('node_id')}", flush=True)
            node_id = (request.form.get("node_id") or "").strip()
            if not node_id:
                return jsonify({"error": "node_id required"}), 400

            if not self.is_known_node(node_id):
                self.post_security_log(node_id, "unknown_node", "image relay rejected", blocked=True)
                log("FOG SECURITY", f"unknown node blocked for image relay: node={node_id}")
                return jsonify({"error": "unknown node"}), 403

            image_file = request.files.get("image")
            if image_file is None:
                return jsonify({"error": "image required"}), 400

            image_bytes = image_file.read()
            if len(image_bytes) > IMAGE_MAX_BYTES:
                self.post_security_log(node_id, "oversized_payload", f"image_size={len(image_bytes)}", blocked=True)
                log("FOG SECURITY", f"oversized image blocked: node={node_id} bytes={len(image_bytes)}")
                return jsonify({"error": "image too large"}), 413

            now = time.time()
            with self.state_lock:
                timestamps = [ts for ts in self.image_rate_tracker[node_id] if now - ts <= IMAGE_RATE_WINDOW_SECS]
                if len(timestamps) >= 1:
                    self.image_rate_tracker[node_id] = timestamps
                    self.post_security_log(node_id, "ddos_detected", "image_rate_exceeded", blocked=True)
                    log("FOG SECURITY", f"image rate limit exceeded: node={node_id}")
                    return jsonify({"error": "rate limited"}), 429
                timestamps.append(now)
                self.image_rate_tracker[node_id] = timestamps

            try:
                files = {
                    "image": (
                        image_file.filename or "image.jpg",
                        io.BytesIO(image_bytes),
                        image_file.mimetype or "application/octet-stream",
                    )
                }
                data = dict(request.form)
                response = self.session.post(
                    self.server_url("/api/upload_image"),
                    data=data,
                    files=files,
                    timeout=IMAGE_HTTP_TIMEOUT_SECS,
                )
                log("FOG IMAGE", f"image relayed: node={node_id} status={response.status_code}")
                return response.content, response.status_code, {"Content-Type": response.headers.get("Content-Type", "application/json")}
            except requests.RequestException as exc:
                log("FOG IMAGE", f"relay failed: node={node_id} error={exc}")
                return jsonify({"error": "server upload failed", "detail": str(exc)}), 502

    def server_url(self, path):
        return f"http://{SERVER_IP}:{SERVER_PORT}{path}"

    def make_proxy_response(self, resp):
        if resp is None:
            return jsonify({"error": "server unavailable"}), 502
        try:
            return jsonify(resp.json()), resp.status_code
        except ValueError:
            return jsonify({"error": "invalid server response", "body": resp.text[:500]}), resp.status_code

    def auth_headers(self):
        headers = {}
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        return headers

    def server_request(self, method, path, **kwargs):
        url = self.server_url(path)
        extra_headers = dict(kwargs.pop("extra_headers", {}) or {})
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.update(extra_headers)
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        try:
            resp = self.session.request(
                method,
                url,
                headers=headers,
                timeout=3,
                **kwargs,
            )
        except requests.RequestException as exc:
            log("FOG PROXY", f"request failed: method={method} path={path} error={exc}")
            return None

        if resp.status_code == 401:
            self.login()
            headers = dict(kwargs.pop("headers", {}) or {})
            headers.update(extra_headers)
            if self.jwt_token:
                headers["Authorization"] = f"Bearer {self.jwt_token}"
            try:
                resp = self.session.request(
                    method,
                    url,
                    headers=headers,
                    timeout=3,
                    **kwargs,
                )
            except requests.RequestException as exc:
                log("FOG PROXY", f"retry failed: method={method} path={path} error={exc}")
                return None
        return resp

    def init_db(self):
        with self.db_lock:
            conn = sqlite3.connect(BUFFER_DB)
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS buffer(
                        id INTEGER PRIMARY KEY,
                        topic TEXT,
                        payload TEXT,
                        received_at TIMESTAMP,
                        forwarded BOOLEAN DEFAULT 0
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def login(self):
        payload = {"username": LOGIN_USERNAME, "password": LOGIN_PASSWORD}
        endpoints = ["/api/login", "/login", "/api/auth/login"]

        for endpoint in endpoints:
            try:
                response = self.session.post(self.server_url(endpoint), json=payload, timeout=HTTP_TIMEOUT_SECS)
            except requests.RequestException as exc:
                log("FOG CACHE", f"login request failed at {endpoint}: {exc}")
                continue

            if response.status_code != 200:
                continue

            try:
                body = response.json()
            except ValueError:
                continue

            token = (
                body.get("access_token")
                or body.get("token")
                or body.get("jwt")
                or body.get("access")
            )
            if token:
                self.jwt_token = token
                log("FOG CACHE", f"JWT login successful via {endpoint}")
                return True

        log("FOG CACHE", "JWT login unavailable; continuing without token")
        return False

    def fetch_nodes(self, force=False):
        now = time.time()
        if not force and now - self.last_cache_refresh < NODE_CACHE_TTL_SECS:
            return True

        for attempt in range(2):
            try:
                response = self.session.get(
                    self.server_url("/api/nodes"),
                    headers=self.auth_headers(),
                    timeout=HTTP_TIMEOUT_SECS,
                )
            except requests.RequestException as exc:
                log("FOG CACHE", f"node cache refresh failed: {exc}")
                return False

            if response.status_code == 401 and attempt == 0:
                self.login()
                continue

            if response.status_code != 200:
                log("FOG CACHE", f"node cache refresh failed: status={response.status_code}")
                return False

            try:
                payload = response.json()
            except ValueError as exc:
                log("FOG CACHE", f"invalid node cache response: {exc}")
                return False

            node_ids = self.extract_node_ids(payload)
            with self.state_lock:
                self.known_nodes = node_ids
                self.last_cache_refresh = now
            log("FOG CACHE", f"{len(node_ids)} nodes cached")
            return True

        return False

    def extract_node_ids(self, payload):
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            items = payload.get("nodes") or payload.get("data") or []
            if isinstance(items, dict):
                items = items.values()
        else:
            items = []

        node_ids = set()
        for item in items:
            if isinstance(item, str):
                node_ids.add(item)
            elif isinstance(item, dict):
                node_id = item.get("node_id") or item.get("id") or item.get("name")
                if node_id:
                    node_ids.add(str(node_id))
        return node_ids

    def post_security_log(self, node_id, attack_type, detail, blocked):
        payload = {
            "node_id": node_id,
            "attack_type": attack_type,
            "detail": detail,
            "blocked": blocked,
        }

        for attempt in range(2):
            try:
                response = self.session.post(
                    self.server_url("/api/security_log"),
                    json=payload,
                    headers=self.auth_headers(),
                    timeout=HTTP_TIMEOUT_SECS,
                )
            except requests.RequestException as exc:
                log("FOG SECURITY", f"security log post failed: type={attack_type} error={exc}")
                return

            if response.status_code == 401 and attempt == 0:
                self.login()
                continue

            if response.status_code >= 400:
                log("FOG SECURITY", f"security log rejected: type={attack_type} status={response.status_code}")
            return

    def buffer_message(self, topic, payload_text):
        with self.db_lock:
            conn = sqlite3.connect(BUFFER_DB)
            try:
                cursor = conn.execute(
                    "INSERT INTO buffer(topic, payload, received_at, forwarded) VALUES (?, ?, ?, 0)",
                    (topic, payload_text, datetime.now().isoformat(timespec="seconds")),
                )
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def mark_forwarded(self, row_id):
        with self.db_lock:
            conn = sqlite3.connect(BUFFER_DB)
            try:
                conn.execute("UPDATE buffer SET forwarded = 1 WHERE id = ?", (row_id,))
                conn.commit()
            finally:
                conn.close()

    def get_pending_messages(self):
        with self.db_lock:
            conn = sqlite3.connect(BUFFER_DB)
            try:
                rows = conn.execute(
                    "SELECT id, topic, payload FROM buffer WHERE forwarded = 0 ORDER BY id ASC"
                ).fetchall()
                return rows
            finally:
                conn.close()

    def extract_node_id(self, topic):
        parts = topic.split("/")
        if len(parts) >= 3 and parts[0] == "border":
            return parts[1]
        return None

    def parse_json_payload(self, payload_bytes):
        try:
            return json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None

    def is_known_node(self, node_id):
        with self.state_lock:
            if node_id in self.known_nodes and time.time() - self.last_cache_refresh < NODE_CACHE_TTL_SECS:
                return True

        self.fetch_nodes(force=True)
        with self.state_lock:
            return node_id in self.known_nodes

    def run_uplink_security_checks(self, topic, payload_bytes):
        node_id = self.extract_node_id(topic)
        if not node_id:
            self.post_security_log("unknown", "unknown_node", f"topic={topic}", blocked=True)
            return False, None, None

        now = time.time()
        parsed = self.parse_json_payload(payload_bytes)
        anomaly_flag = False

        with self.state_lock:
            rate_times = [ts for ts in self.rate_tracker[node_id] if now - ts <= 1.0]
            rate_times.append(now)
            self.rate_tracker[node_id] = rate_times
            if len(rate_times) > RATE_LIMIT_MSG_PER_SEC:
                detail = f"rate={len(rate_times)}/s"
                self.post_security_log(node_id, "ddos_detected", detail, blocked=True)
                log("FOG SECURITY", f"attack detected: type=ddos_detected node={node_id} detail={detail}")
                return False, node_id, parsed

            seq_map = self.seen_seqs[node_id]
            expired = [seq for seq, ts in seq_map.items() if now - ts > DUPLICATE_WINDOW_SECS]
            for seq in expired:
                del seq_map[seq]

            seq_no = parsed.get("seq_no") if isinstance(parsed, dict) else None
            if seq_no is not None:
                seq_key = str(seq_no)
                if seq_key in seq_map:
                    detail = f"seq_no={seq_key}"
                    self.post_security_log(node_id, "duplicate_packet", detail, blocked=True)
                    log("FOG SECURITY", f"attack detected: type=duplicate_packet node={node_id} detail={detail}")
                    return False, node_id, parsed
                seq_map[seq_key] = now

        if len(payload_bytes) > MAX_PAYLOAD_BYTES:
            detail = f"bytes={len(payload_bytes)}"
            self.post_security_log(node_id, "oversized_payload", detail, blocked=True)
            log("FOG SECURITY", f"attack detected: type=oversized_payload node={node_id} detail={detail}")
            return False, node_id, parsed

        if not self.is_known_node(node_id):
            self.post_security_log(node_id, "unknown_node", "uplink rejected", blocked=True)
            log("FOG SECURITY", f"attack detected: type=unknown_node node={node_id}")
            return False, node_id, parsed

        with self.state_lock:
            anomaly_times = [ts for ts in self.anomaly_tracker[node_id] if now - ts <= ANOMALY_WINDOW_SECS]
            anomaly_times.append(now)
            self.anomaly_tracker[node_id] = anomaly_times
            if len(anomaly_times) > ANOMALY_EVENT_THRESHOLD:
                anomaly_flag = True

        if anomaly_flag:
            detail = f"events_60s={len(self.anomaly_tracker[node_id])}"
            self.post_security_log(node_id, "anomaly_burst", detail, blocked=False)
            log("FOG SECURITY", f"anomaly detected: type=anomaly_burst node={node_id} detail={detail}")

        return True, node_id, parsed

    def forward_uplink(self, topic, payload_bytes, anomaly_flag):
        payload_to_send = payload_bytes
        if anomaly_flag:
            parsed = self.parse_json_payload(payload_bytes)
            if isinstance(parsed, dict):
                parsed["fog_anomaly_flag"] = True
                payload_to_send = json.dumps(parsed).encode("utf-8")

        try:
            payload_text = payload_to_send.decode("utf-8")
        except UnicodeDecodeError:
            payload_text = payload_to_send.decode("utf-8", errors="replace")

        row_id = self.buffer_message(topic, payload_text)
        info = self.client_server.publish(topic, payload_to_send)
        if info.rc == mqtt.MQTT_ERR_SUCCESS:
            self.mark_forwarded(row_id)
            log("FOG UPLINK", f"message forwarded: topic={topic} node={self.extract_node_id(topic)}")
        else:
            log("FOG UPLINK", f"forward queued in buffer: topic={topic} rc={info.rc}")

    def on_edge_connect(self, client, userdata, flags, reason_code, properties=None):
        connected = (
            str(reason_code) == "Success"
            or (reason_code.value == 0 if hasattr(reason_code, "value") else int(reason_code) == 0)
        )
        if connected:
            client.subscribe("border/+/heartbeat")
            client.subscribe("border/+/event")
            client.subscribe("border/+/status")
            print(f"[{ts()}][FOG UPLINK] connected to edge broker", flush=True)
        else:
            print(f"[{ts()}][FOG UPLINK] edge connect failed: {reason_code}", flush=True)

    def on_edge_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None):
        rc = getattr(reason_code, 'value', reason_code if isinstance(reason_code, int) else 0)
        log("FOG UPLINK", f"edge broker disconnected: rc={rc}")

    def on_server_connect(self, client, userdata, flags, reason_code, properties=None):
        connected = (
            str(reason_code) == "Success"
            or (reason_code.value == 0 if hasattr(reason_code, "value") else int(reason_code) == 0)
        )
        if connected:
            client.subscribe("border/+/command")
            client.subscribe("border/zone/+/command")
            print(f"[{ts()}][FOG DOWNLINK] connected to server broker", flush=True)
        else:
            print(f"[{ts()}][FOG DOWNLINK] server connect failed: {reason_code}", flush=True)

    def on_server_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None):
        rc = getattr(reason_code, 'value', reason_code if isinstance(reason_code, int) else 0)
        log("FOG DOWNLINK", f"server broker disconnected: rc={rc}")

    def on_edge_message(self, client, userdata, msg):
        topic = msg.topic
        # Never forward commands upstream — commands only flow server → edge
        if "/command" in topic:
            return
        if "/challenge" in topic:
            return
        log("FOG UPLINK", f"message received: topic={topic} bytes={len(msg.payload)}")
        allowed, node_id, _ = self.run_uplink_security_checks(topic, msg.payload)
        if not allowed:
            return

        anomaly_flag = False
        with self.state_lock:
            anomaly_flag = len(self.anomaly_tracker[node_id]) > ANOMALY_EVENT_THRESHOLD
        self.forward_uplink(topic, msg.payload, anomaly_flag)

    def on_server_message(self, client, userdata, msg):
        topic = msg.topic
        # Only forward commands downstream — heartbeats/events must not loop back
        if "/command" not in topic:
            return
        node_id = self.extract_node_id(topic) or "unknown"
        payload = self.parse_json_payload(msg.payload)
        command = payload.get("command") if isinstance(payload, dict) else None

        if command not in KNOWN_COMMANDS:
            log("FOG SECURITY", f"Unknown command dropped: {command}")
            self.post_security_log("server", "unknown_command", f"command={command}", blocked=True)
            return

        info = self.client_edge.publish(topic, msg.payload)
        if info.rc == mqtt.MQTT_ERR_SUCCESS:
            log("FOG DOWNLINK", f"command={command} -> node={node_id}")
        else:
            log("FOG DOWNLINK", f"command publish failed: command={command} rc={info.rc}")

    def connect_mqtt(self):
        self.client_edge.reconnect_delay_set(min_delay=2, max_delay=10)
        self.client_server.reconnect_delay_set(min_delay=2, max_delay=10)

        try:
            self.client_edge.connect(EDGE_IP, EDGE_MQTT_PORT, keepalive=30)
        except Exception as exc:
            log("FOG UPLINK", f"initial edge connect failed: {exc}")

        try:
            self.client_server.connect(SERVER_IP, SERVER_MQTT_PORT, keepalive=30)
        except Exception as exc:
            log("FOG DOWNLINK", f"initial server connect failed: {exc}")

        self.client_edge.loop_start()
        self.client_server.loop_start()

    def start_local_bridge(self):
        callback_api = getattr(getattr(mqtt, "CallbackAPIVersion", None), "VERSION2", None)
        if callback_api is not None:
            self.bridge_to_server = mqtt.Client(callback_api_version=callback_api, client_id="fog-bridge")
            self.bridge_local = mqtt.Client(callback_api_version=callback_api, client_id="fog-bridge-local")
        else:
            self.bridge_to_server = mqtt.Client(client_id="fog-bridge")
            self.bridge_local = mqtt.Client(client_id="fog-bridge-local")

        self.bridge_to_server.on_connect = self.on_bridge_server_connect
        self.bridge_to_server.on_message = self.on_bridge_server_message
        self.bridge_to_server.on_disconnect = self.on_bridge_server_disconnect

        self.bridge_local.on_connect = self.on_bridge_local_connect
        self.bridge_local.on_message = self.on_bridge_local_message
        self.bridge_local.on_disconnect = self.on_bridge_local_disconnect

        self.bridge_to_server.reconnect_delay_set(min_delay=2, max_delay=10)
        self.bridge_local.reconnect_delay_set(min_delay=2, max_delay=10)

        try:
            self.bridge_to_server.connect(SERVER_IP, SERVER_MQTT_PORT, keepalive=30)
            self.bridge_to_server.loop_start()
        except Exception as exc:
            log("FOG BRIDGE", f"server bridge connect failed: {exc}")

        try:
            self.bridge_local.connect(LOCAL_BROKER_HOST, LOCAL_BROKER_PORT, keepalive=30)
            self.bridge_local.loop_start()
        except Exception as exc:
            log("FOG BRIDGE", f"local bridge connect failed: {exc}")

    def on_bridge_local_connect(self, client, userdata, flags, reason_code, properties=None):
        connected = (
            str(reason_code) == "Success"
            or (reason_code.value == 0 if hasattr(reason_code, "value") else int(reason_code) == 0)
        )
        if connected:
            client.subscribe("border/#")
            log("FOG BRIDGE", f"local broker connected: {LOCAL_BROKER_HOST}:{LOCAL_BROKER_PORT}")
        else:
            log("FOG BRIDGE", f"local broker connect failed: {reason_code}")

    def on_bridge_server_connect(self, client, userdata, flags, reason_code, properties=None):
        connected = (
            str(reason_code) == "Success"
            or (reason_code.value == 0 if hasattr(reason_code, "value") else int(reason_code) == 0)
        )
        if connected:
            client.subscribe("border/+/command")
            client.subscribe("border/zone/+/command")
            log("FOG BRIDGE", f"server broker connected: {SERVER_IP}:{SERVER_MQTT_PORT}")
        else:
            log("FOG BRIDGE", f"server broker connect failed: {reason_code}")

    def on_bridge_local_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None):
        rc = getattr(reason_code, "value", reason_code if isinstance(reason_code, int) else 0)
        log("FOG BRIDGE", f"local broker disconnected: rc={rc}")

    def on_bridge_server_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None):
        rc = getattr(reason_code, "value", reason_code if isinstance(reason_code, int) else 0)
        log("FOG BRIDGE", f"server broker disconnected: rc={rc}")

    def on_bridge_local_message(self, client, userdata, msg):
        # Never forward commands or challenges upstream — these only flow server → edge
        if "/command" in msg.topic:
            return
        if "/challenge" in msg.topic:
            return
        if self.bridge_to_server is None:
            return
        info = self.bridge_to_server.publish(msg.topic, msg.payload, qos=0)
        if info.rc == mqtt.MQTT_ERR_SUCCESS:
            log("FOG BRIDGE", f"{msg.topic} -> server")
        else:
            log("FOG BRIDGE", f"uplink bridge failed: topic={msg.topic} rc={info.rc}")

    def on_bridge_server_message(self, client, userdata, msg):
        if self.bridge_local is None:
            return
        info = self.bridge_local.publish(msg.topic, msg.payload, qos=0)
        if info.rc == mqtt.MQTT_ERR_SUCCESS:
            log("FOG BRIDGE", f"cmd <- server {msg.topic}")
        else:
            log("FOG BRIDGE", f"downlink bridge failed: topic={msg.topic} rc={info.rc}")

    def start_http_server(self):
        thread = threading.Thread(
            target=self.app.run,
            kwargs={"host": "0.0.0.0", "port": FOG_HTTP_PORT, "debug": False, "use_reloader": False},
            daemon=True,
            name="fog-http-server",
        )
        thread.start()
        return thread

    def buffer_retry_loop(self):
        while not self.stop_event.is_set():
            self.stop_event.wait(BUFFER_RETRY_INTERVAL_SECS)
            # Ensure upstream is connected before attempting retries (rc=4 = MQTT_ERR_NO_CONN)
            if not self.client_server.is_connected():
                try:
                    self.client_server.reconnect()
                    log("FOG BRIDGE", "upstream reconnected")
                except Exception as exc:
                    log("FOG BRIDGE", f"reconnect failed: {exc}")
                    continue

            conn = sqlite3.connect(BUFFER_DB)
            cur = conn.cursor()
            cur.execute(
                "SELECT id, topic, payload FROM buffer WHERE forwarded=0 LIMIT 10"
            )
            rows = cur.fetchall()
            retried = 0
            for row_id, topic, payload in rows:
                try:
                    result = self.client_server.publish(topic, payload.encode("utf-8"), qos=0)
                    if result.rc == mqtt.MQTT_ERR_SUCCESS:
                        cur.execute("UPDATE buffer SET forwarded=1 WHERE id=?", (row_id,))
                        retried += 1
                except Exception:
                    pass
            conn.commit()
            conn.close()
            if rows:
                pending = len(rows) - retried
                log("FOG BUFFER", f"{pending} pending, {retried} retried")

    def cache_refresh_loop(self):
        while not self.stop_event.is_set():
            self.fetch_nodes(force=True)
            self.stop_event.wait(NODE_CACHE_TTL_SECS)

    def start_background_threads(self):
        buffer_thread = threading.Thread(target=self.buffer_retry_loop, daemon=True, name="fog-buffer-retry")
        cache_thread = threading.Thread(target=self.cache_refresh_loop, daemon=True, name="fog-cache-refresh")
        buffer_thread.start()
        cache_thread.start()
        return [buffer_thread, cache_thread]

    def print_startup_summary(self):
        log("FOG NODE", "Started")
        log("FOG NODE", f"Edge broker: {EDGE_IP}:{EDGE_MQTT_PORT}")
        log("FOG NODE", f"Server: {SERVER_IP}:{SERVER_PORT}")
        log("FOG NODE", f"HTTP relay: 0.0.0.0:{FOG_HTTP_PORT}")
        log("FOG NODE", f"Nodes cached: {len(self.known_nodes)}")
        log("FOG NODE", "Ready")

    def run(self):
        self.init_db()
        self.login()
        self.fetch_nodes(force=True)
        self.connect_mqtt()
        self.start_local_bridge()
        self.start_http_server()
        self.start_background_threads()
        self.print_startup_summary()

        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            log("FOG NODE", "Shutdown requested")
        finally:
            self.stop_event.set()
            try:
                self.client_edge.loop_stop()
                self.client_server.loop_stop()
                if self.bridge_to_server is not None:
                    self.bridge_to_server.loop_stop()
                    self.bridge_to_server.disconnect()
                if self.bridge_local is not None:
                    self.bridge_local.loop_stop()
                    self.bridge_local.disconnect()
                self.client_edge.disconnect()
                self.client_server.disconnect()
            except Exception:
                pass


def main():
    FogNode().run()


if __name__ == "__main__":
    main()
