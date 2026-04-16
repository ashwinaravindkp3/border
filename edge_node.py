import atexit
import hashlib
import hmac
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque, defaultdict
from datetime import datetime
from math import atan2, cos, radians, sin, sqrt

PID_FILE = "/tmp/edge_node.pid"


def check_single_instance():
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            old_pid = f.read().strip()
        try:
            os.kill(int(old_pid), 0)
            print(f"[EDGE] Already running as PID {old_pid}. Exiting.")
            sys.exit(1)
        except ProcessLookupError:
            pass  # old pid is dead, continue
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def cleanup_pid():
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)


atexit.register(cleanup_pid)

import paho.mqtt.client as mqtt
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request


TESTING_MODE = False

NODE_IDS = ["BORDER_001", "BORDER_002", "BORDER_003"]

EDGE_MQTT_PORT = 1883
FOG_IP        = "192.168.1.1"
FOG_MQTT_PORT = 1883
FOG_HTTP_PORT = 8080
# SERVER_IP and SERVER_PORT removed â€” edge talks only to fog

AP_SSID = "BORDER_SHIELD_FIELD"
AP_PASSWORD = "field_secure_2026"
AP_SUBNET = "192.168.4.0/24"
AP_IP = "10.42.0.1"

RATE_LIMIT_PER_SEC = 10
REPLAY_WINDOW_SECS = 30
REPLAY_WINDOW_SIZE = 1000
CHALLENGE_INTERVAL_SECS = 300
CHALLENGE_TIMEOUT_SECS = 10
BLACKLIST_DURATION_SECS = 300
ANOMALY_SCORE_THRESHOLD = 60
MAX_HUMAN_SPEED_MS = 3.0
MAX_VEHICLE_SPEED_MS = 30.0

EDGE_SECRET = os.getenv("EDGE_SECRET", "edge_secret_2026")
FIELD_BROKER_HOST = "localhost"
UPSTREAM_BROKER_HOST = FOG_IP
IMAGE_RELAY_URL = f"http://{FOG_IP}:{FOG_HTTP_PORT}/relay_image"
FOG_BASE = f"http://{FOG_IP}:{FOG_HTTP_PORT}"
MAX_IMAGE_SIZE = 10 * 1024 * 1024

_node_keys = {}
seen_nonces = {node_id: deque(maxlen=REPLAY_WINDOW_SIZE) for node_id in NODE_IDS}
rate_tracker = {node_id: deque() for node_id in NODE_IDS}
image_rate_tracker = {node_id: deque() for node_id in NODE_IDS}
blacklist = {}
anomaly_scores = {node_id: 0 for node_id in NODE_IDS}
pending_challenges = {}
node_coords = {}
recent_events = {node_id: deque(maxlen=20) for node_id in NODE_IDS}
heartbeat_baselines = {}

state_lock = threading.Lock()
recent_forwarded = deque(maxlen=128)
recent_downlinks = deque(maxlen=128)
stop_event = threading.Event()

client_field = None
client_upstream = None
http_thread = None
http_app = Flask(__name__)


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def edge_log(tag: str, message: str):
    print(f"[{ts()}][{tag}] {message}")


def now_ms() -> int:
    return int(time.time() * 1000)


def record_forwarded(topic: str, payload: bytes, cache: deque):
    digest = hashlib.sha256(topic.encode() + payload).hexdigest()
    with state_lock:
        cache.append((digest, time.time()))


def seen_forwarded(topic: str, payload: bytes, cache: deque, ttl: float = 0.25) -> bool:
    digest = hashlib.sha256(topic.encode() + payload).hexdigest()
    cutoff = time.time() - ttl
    with state_lock:
        while cache and cache[0][1] < cutoff:
            cache.popleft()
        return any(item_digest == digest for item_digest, _ in cache)


def post_security_event(node_id: str, attack_type: str, detail: str):
    try:
        requests.post(
            f"{FOG_BASE}/security_event",
            json={"node_id": node_id, "attack_type": attack_type, "detail": detail},
            timeout=5,
        )
    except Exception as exc:
        edge_log("EDGE SECURITY", f"server log failed {node_id}: {exc}")


def post_l7_alert(node_id: str, reason: str, threat_score: int):
    try:
        requests.post(
            f"{FOG_BASE}/l7_alert",
            json={"node_id": node_id, "reason": reason, "threat_score": threat_score},
            timeout=5,
        )
    except Exception as exc:
        edge_log("EDGE SECURITY", f"l7 post failed {node_id}: {exc}")


def log_security(node_id: str, reason: str, detail: str | None = None):
    msg = f"{reason} {node_id}"
    if detail:
        msg = f"{msg} {detail}"
    edge_log("EDGE SECURITY", msg)
    post_security_event(node_id, reason, detail or reason)


def algo_6_anomaly_score(node_id: str, delta: int, reason: str):
    with state_lock:
        score = max(0, min(100, anomaly_scores.get(node_id, 0) + delta))
        anomaly_scores[node_id] = score
    edge_log("EDGE INTEL", f"{node_id} score={score} reason={reason}")
    if score > ANOMALY_SCORE_THRESHOLD:
        post_security_event(node_id, "anomaly_threshold", f"score={score} reason={reason}")
    if score > 80:
        with state_lock:
            blacklist[node_id] = time.time() + BLACKLIST_DURATION_SECS
        post_l7_alert(node_id, reason, score)
    return score


def algo_1_gcm_verify(node_id: str, ciphertext_hex: str, nonce_hex: str, tag_hex: str):
    key = _node_keys.get(node_id)
    if not key:
        return False, "unknown_node"
    try:
        aesgcm = AESGCM(key)
        aesgcm.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ciphertext_hex) + bytes.fromhex(tag_hex), None)
    except Exception:
        algo_6_anomaly_score(node_id, 10, "gcm_tag_failure")
        return False, "gcm_tag_failure"
    return True, "ok"


def algo_2_replay_detect(node_id: str, nonce_hex: str, timestamp_ms: int):
    now = now_ms()
    if abs(now - int(timestamp_ms or 0)) > REPLAY_WINDOW_SECS * 1000:
        return False, "stale_packet"
    with state_lock:
        entries = seen_nonces.setdefault(node_id, deque(maxlen=REPLAY_WINDOW_SIZE))
        if nonce_hex in entries:
            return False, "replay_attack"
        entries.append(nonce_hex)
    return True, "ok"


def algo_3_rate_limit(node_id: str):
    now = time.time()
    with state_lock:
        tracker = rate_tracker.setdefault(node_id, deque())
        tracker.append(now)
        while tracker and tracker[0] < now - 1:
            tracker.popleft()
        count = len(tracker)
        if count > RATE_LIMIT_PER_SEC * 5:
            blacklist[node_id] = now + BLACKLIST_DURATION_SECS
            return False, "ddos_attack"
        if count > RATE_LIMIT_PER_SEC:
            anomaly_scores[node_id] = min(100, anomaly_scores.get(node_id, 0) + 5)
            return False, "rate_limited"
    return True, "ok"


def algo_4_whitelist(node_id: str):
    if node_id not in NODE_IDS:
        return False, "rogue_node"
    expiry = blacklist.get(node_id)
    if expiry and expiry > time.time():
        return False, "blacklisted"
    if expiry and expiry <= time.time():
        with state_lock:
            blacklist.pop(node_id, None)
    return True, "ok"


def haversine_distance(lat1, lng1, lat2, lng2) -> float:
    earth_radius = 6371000
    lat1, lng1, lat2, lng2 = map(radians, [lat1, lng1, lat2, lng2])
    dlat = lat2 - lat1
    dlng = lng2 - lng1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlng / 2) ** 2
    return earth_radius * 2 * atan2(sqrt(a), sqrt(1 - a))


def record_event(node_id: str, event_time: datetime, event_type: str):
    with state_lock:
        recent_events.setdefault(node_id, deque(maxlen=20)).append((event_time, event_type))


def algo_7_plausibility(node_id: str, event_time: datetime):
    if node_id not in node_coords:
        return "ok"
    lat1, lng1 = node_coords[node_id]
    with state_lock:
        snapshot = {other: list(events) for other, events in recent_events.items()}
    for other_id, events in snapshot.items():
        if other_id == node_id or other_id not in node_coords:
            continue
        lat2, lng2 = node_coords[other_id]
        distance = haversine_distance(lat1, lng1, lat2, lng2)
        for prev_time, _ in events:
            time_diff = abs((event_time - prev_time).total_seconds())
            if time_diff < 1:
                time_diff = 1
            speed = distance / time_diff
            if speed > MAX_VEHICLE_SPEED_MS:
                edge_log("EDGE INTEL", f"teleportation {node_id}")
                score = algo_6_anomaly_score(node_id, 50, "teleportation_attack")
                post_l7_alert(node_id, "teleportation_attack", score)
                return "teleportation_attack"
            if speed > MAX_HUMAN_SPEED_MS:
                edge_log("EDGE INTEL", f"vehicle {node_id}")
                algo_6_anomaly_score(node_id, 15, "vehicle_detected")
                return "vehicle_detected"
    return "ok"


def update_heartbeat_baseline(node_id: str, heartbeat_time: datetime):
    with state_lock:
        baseline = heartbeat_baselines.get(node_id)
        if baseline is None:
            heartbeat_baselines[node_id] = {
                "last_time": heartbeat_time,
                "intervals": deque(maxlen=20),
                "mean": 0.0,
                "std": 0.0,
            }
            return
        interval = (heartbeat_time - baseline["last_time"]).total_seconds()
        baseline["last_time"] = heartbeat_time
        baseline["intervals"].append(interval)
        intervals = list(baseline["intervals"])
        if len(intervals) < 5:
            return
        mean = sum(intervals) / len(intervals)
        variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
        std = variance ** 0.5
        baseline["mean"] = mean
        baseline["std"] = std
    if std > 0.1:
        z_score = abs(interval - mean) / std
        if z_score > 3.0:
            algo_6_anomaly_score(node_id, 10, f"heartbeat_anomaly z={z_score:.1f}")


def encrypt_for_node(node_id: str, payload: dict):
    key = _node_keys.get(node_id)
    if not key:
        return None
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    encrypted = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "nonce": nonce.hex(),
        "ciphertext": encrypted[:-16].hex(),
        "tag": encrypted[-16:].hex(),
        "timestamp_ms": now_ms(),
    }


def challenge_expected(node_id: str, nonce_hex: str) -> str:
    key = _node_keys[node_id]
    return hmac.new(key, f"{nonce_hex}{node_id}".encode(), hashlib.sha256).hexdigest()


def challenge_thread():
    while not stop_event.is_set():
        for node_id in NODE_IDS:
            if node_id not in _node_keys:
                continue
            nonce_hex = secrets.token_hex(32)
            challenge = {
                "type": "challenge",
                "nonce": nonce_hex,
                "timestamp": now_ms(),
            }
            encrypted = encrypt_for_node(node_id, challenge)
            if not encrypted:
                continue
            with state_lock:
                pending_challenges[node_id] = {
                    "nonce": nonce_hex,
                    "issued_at": datetime.now(),
                    "expected_response": challenge_expected(node_id, nonce_hex),
                }
            client_field.publish(f"border/{node_id}/challenge", json.dumps(encrypted), qos=1)
            deadline = time.time() + CHALLENGE_TIMEOUT_SECS
            while time.time() < deadline and not stop_event.is_set():
                with state_lock:
                    if node_id not in pending_challenges:
                        break
                time.sleep(0.2)
            else:
                score = algo_6_anomaly_score(node_id, 30, "liveness_failure")
                log_security(node_id, "liveness_failure")
                if score > ANOMALY_SCORE_THRESHOLD:
                    post_l7_alert(node_id, "liveness_failure", score)
        stop_event.wait(CHALLENGE_INTERVAL_SECS)


def anomaly_decay_thread():
    while not stop_event.wait(60):
        with state_lock:
            for node_id in list(anomaly_scores.keys()):
                anomaly_scores[node_id] = max(0, anomaly_scores[node_id] - 1)


def fetch_node_keys():
    while True:
        try:
            response = requests.post(
                f"{FOG_BASE}/node_keys",
                headers={
                    "X-Edge-Token": EDGE_SECRET,
                    "Content-Type": "application/json"
                },
                json={"node_ids": NODE_IDS},
                timeout=10
            )
            response.raise_for_status()
            keys = response.json()
            for node_id, hex_key in keys.items():
                _node_keys[node_id] = \
                    bytes.fromhex(hex_key)
            print(f"[EDGE] Loaded "
                  f"{len(_node_keys)} node keys")
            return
        except Exception as e:
            print(f"[EDGE] Key fetch failed: "
                  f"{e} â€” retrying in 5s")
            time.sleep(5)


def fetch_node_coords():
    while True:
        try:
            response = requests.get(
                f"{FOG_BASE}/node_coords",
                headers={
                    "X-Edge-Token": EDGE_SECRET
                },
                timeout=10
            )
            response.raise_for_status()
            coords = response.json()
            for node_id, pos in coords.items():
                node_coords[node_id] = (
                    pos['lat'], pos['lng']
                )
            print(f"[EDGE] Loaded "
                  f"{len(node_coords)} "
                  f"node coordinates")
            return
        except Exception as e:
            print(f"[EDGE] Coord fetch failed: "
                  f"{e} â€” retrying in 5s")
            time.sleep(5)


def start_hotspot(retries=3):
    """Bring up the WiFi access point so border nodes can auto-connect.

    Idempotent â€” safe to call on every startup.  Enforces 2.4 GHz / channel 6 /
    WPA2-RSN-CCMP on every run so the profile can never drift to an incompatible
    state between reboots.
    """
    con_name = "border-shield-ap"
    iface    = "wlan0"

    def _run(cmd, check=True):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        return result

    try:
        # â”€â”€ Step 1: Remove any client-mode profiles sharing our SSID â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # NetworkManager will auto-connect wlan0 to the SSID it is also
        # broadcasting unless we delete those client entries first.
        all_cons = _run(["nmcli", "-t", "-f", "NAME", "con", "show"], check=False).stdout.splitlines()
        for name in all_cons:
            name = name.strip()
            if not name or name == con_name:
                continue
            info = _run(
                ["nmcli", "-t", "-f", "802-11-wireless.ssid,802-11-wireless.mode",
                 "con", "show", name],
                check=False,
            ).stdout
            ssid_line = next((l for l in info.splitlines() if l.startswith("802-11-wireless.ssid:")), "")
            mode_line = next((l for l in info.splitlines() if l.startswith("802-11-wireless.mode:")), "")
            saved_ssid = ssid_line.split(":", 1)[-1].strip()
            saved_mode = mode_line.split(":", 1)[-1].strip()
            if saved_ssid == AP_SSID and saved_mode != "ap":
                _run(["sudo", "nmcli", "con", "delete", name])
                edge_log("EDGE AP", f"Removed conflicting client profile '{name}'")

        # â”€â”€ Step 2: Create profile once if absent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        all_cons = _run(["nmcli", "-t", "-f", "NAME", "con", "show"], check=False).stdout.splitlines()
        all_cons = [n.strip() for n in all_cons]
        if con_name not in all_cons:
            edge_log("EDGE AP", f"Creating hotspot profile '{con_name}'...")
            _run([
                "sudo", "nmcli", "con", "add",
                "type", "wifi",
                "ifname", iface,
                "con-name", con_name,
                "ssid", AP_SSID,
            ])
            edge_log("EDGE AP", "Hotspot profile created")
        else:
            edge_log("EDGE AP", f"Profile '{con_name}' exists â€” reusing")

        # â”€â”€ Step 3: Always enforce exact settings (idempotent every run) â”€â”€â”€â”€â”€â”€
        # Forces 2.4 GHz band, channel 6, WPA2-RSN-CCMP â€” never let the profile
        # drift to settings that ESP32 devices cannot associate with.
        _run([
            "sudo", "nmcli", "con", "modify", con_name,
            "802-11-wireless.ssid",     AP_SSID,
            "802-11-wireless.mode",     "ap",
            "802-11-wireless.band",     "bg",
            "802-11-wireless.channel",  "6",
            "ipv4.method",              "shared",
            "ipv4.addresses",           f"{AP_IP}/24",
            "wifi-sec.key-mgmt",        "wpa-psk",
            "wifi-sec.proto",           "rsn",
            "wifi-sec.pairwise",        "ccmp",
            "wifi-sec.group",           "ccmp",
            "wifi-sec.psk",             AP_PASSWORD,
            "connection.autoconnect",   "yes",
        ])
        edge_log("EDGE AP", "Hotspot settings enforced (band=bg ch=6 WPA2/CCMP)")

        # â”€â”€ Step 4: Disconnect wlan0 from any current association â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        _run(["sudo", "nmcli", "device", "disconnect", iface], check=False)

        # â”€â”€ Step 5: Disable WiFi power save (critical for ESP32 stability) â”€â”€â”€â”€
        _run(["sudo", "iw", "dev", iface, "set", "power_save", "off"], check=False)

        # â”€â”€ Step 6: Bring hotspot up with retry logic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        brought_up = False
        for attempt in range(1, retries + 1):
            edge_log("EDGE AP", f"Bringing up '{con_name}' (attempt {attempt}/{retries})...")
            result = _run(["sudo", "nmcli", "con", "up", con_name], check=False)
            if result.returncode == 0:
                brought_up = True
                break
            edge_log("EDGE AP", f"nmcli up failed (attempt {attempt}): {result.stderr.strip()}")
            if attempt < retries:
                time.sleep(2)

        if not brought_up:
            edge_log("EDGE AP", f"ERROR: hotspot failed after {retries} attempts â€” nodes must connect manually")
            return

        # â”€â”€ Step 7: Verify wlan0 received the AP IP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        time.sleep(2)  # allow NetworkManager to assign the address
        ip_check = _run(["ip", "-4", "addr", "show", iface], check=False).stdout
        if AP_IP in ip_check:
            edge_log("EDGE AP", f"SUCCESS â€” {iface} has IP {AP_IP}, SSID={AP_SSID}, ch=6, WPA2/CCMP")
        else:
            edge_log("EDGE AP", f"WARNING â€” hotspot up but {iface} does not show IP {AP_IP}; check NM logs")

    except subprocess.CalledProcessError as exc:
        edge_log("EDGE AP", f"WARNING: hotspot setup failed: {exc} â€” nodes must connect manually")
    except FileNotFoundError:
        edge_log("EDGE AP", "WARNING: nmcli not found â€” skipping hotspot setup")


def write_acl_file():
    acl_content = ""
    for node_id in NODE_IDS:
        acl_content += f"user {node_id}\n"
        acl_content += f"topic readwrite border/{node_id}/#\n\n"

    acl_path = "/tmp/border_acl.conf"
    with open(acl_path, "w", encoding="ascii") as handle:
        handle.write(acl_content)

    conf_content = (
        "listener 1883 0.0.0.0\n"
        "allow_anonymous true\n"
        f"acl_file {acl_path}\n"
    )
    conf_path = "/etc/mosquitto/conf.d/edge.conf"
    try:
        with open(conf_path, "w", encoding="ascii") as handle:
            handle.write(conf_content)
        edge_log("EDGE", f"ACL and config written for {len(NODE_IDS)} nodes")
        if not TESTING_MODE:
            subprocess.run(["sudo", "systemctl", "restart", "mosquitto"], check=True)
    except PermissionError:
        edge_log("EDGE", f"WARNING: cannot write {conf_path} â€” run with sudo or pre-create")


def on_field_connect(client, userdata, connect_flags, reason_code, properties):
    del userdata, connect_flags, properties
    if not reason_code.is_failure:
        client.subscribe("border/+/heartbeat")
        client.subscribe("border/+/event")
        client.subscribe("border/+/status")
        client.subscribe("border/+/challenge_response")
        edge_log("EDGE", "Field broker connected")


def on_field_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    del userdata, disconnect_flags, properties
    print(f"[EDGE] Field broker disconnected rc={reason_code} â€” reconnecting...")
    while True:
        try:
            client.reconnect()
            print("[EDGE] Field reconnected")
            break
        except Exception as e:
            print(f"[EDGE] Field reconnect failed: {e} â€” retry 5s")
            time.sleep(5)


def on_upstream_connect(client, userdata, connect_flags, reason_code, properties):
    del userdata, connect_flags, properties
    if not reason_code.is_failure:
        client.subscribe("border/+/command")
        edge_log("EDGE", "Upstream broker connected")


def on_upstream_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    del userdata, disconnect_flags, properties
    print(f"[EDGE] Upstream disconnected rc={reason_code} â€” reconnecting...")
    while True:
        try:
            client.reconnect()
            print("[EDGE] Upstream reconnected")
            break
        except Exception as e:
            print(f"[EDGE] Reconnect failed: {e} â€” retry in 5s")
            time.sleep(5)


def handle_challenge_response(node_id: str, data: dict):
    response_value = data.get("response")
    with state_lock:
        challenge = pending_challenges.get(node_id)
    if not challenge:
        return
    if response_value == challenge["expected_response"]:
        with state_lock:
            pending_challenges.pop(node_id, None)
        edge_log("EDGE CHALLENGE", f"{node_id} responded ok")
        return
    score = algo_6_anomaly_score(node_id, 50, "impersonation_detected")
    with state_lock:
        blacklist[node_id] = time.time() + BLACKLIST_DURATION_SECS
        pending_challenges.pop(node_id, None)
    log_security(node_id, "impersonation_detected")
    post_l7_alert(node_id, "impersonation_detected", score)


def on_field_message(client, userdata, msg):
    del client, userdata
    if seen_forwarded(msg.topic, msg.payload, recent_forwarded):
        return
    parts = msg.topic.split("/")
    if len(parts) < 3:
        return
    node_id = parts[1]
    try:
        data = json.loads(msg.payload.decode())
    except Exception:
        return

    ok, reason = algo_4_whitelist(node_id)
    if not ok:
        log_security(node_id, reason)
        return

    ok, reason = algo_3_rate_limit(node_id)
    if not ok:
        log_security(node_id, reason)
        return

    if parts[2] == "challenge_response":
        handle_challenge_response(node_id, data)
        return

    if "ciphertext" in data:
        ok, reason = algo_1_gcm_verify(node_id, data.get("ciphertext", ""), data.get("nonce", ""), data.get("tag", ""))
        if not ok:
            log_security(node_id, reason)
            return
        ok, reason = algo_2_replay_detect(node_id, data.get("nonce", ""), data.get("timestamp_ms", 0))
        if not ok:
            log_security(node_id, reason)
            return
        record_forwarded(msg.topic, msg.payload, recent_forwarded)
        client_upstream.publish(msg.topic, msg.payload, qos=1)
        edge_log("EDGE UPLINK", f"{node_id} verified + forwarded (GCM)")
    else:
        seq_no = data.get("seq_no", 0)
        ok, reason = algo_2_replay_detect(node_id, str(seq_no), now_ms())
        if not ok:
            log_security(node_id, reason)
            return
        record_forwarded(msg.topic, msg.payload, recent_forwarded)
        client_upstream.publish(msg.topic, msg.payload, qos=1)
        edge_log("EDGE UPLINK", f"{node_id} forwarded (HMAC legacy)")

    if parts[2] == "event":
        record_event(node_id, datetime.now(), data.get("event", "event"))
        flag = algo_7_plausibility(node_id, datetime.now())
        if flag == "teleportation_attack":
            post_security_event(node_id, "teleportation_attack", "Physically impossible event timing")

    if parts[2] == "heartbeat":
        update_heartbeat_baseline(node_id, datetime.now())


def on_upstream_message(client, userdata, msg):
    del client, userdata
    if seen_forwarded(msg.topic, msg.payload, recent_downlinks):
        return
    try:
        data = json.loads(msg.payload.decode())
    except Exception:
        return
    if "ciphertext" in data:
        return
    node_id = msg.topic.split("/")[1]
    command = data.get("command")
    allowed = {"patrol_sweep", "trigger_alarm", "stop_alarm", "heartbeat_req"}
    if command not in allowed:
        log_security("server", "unknown_command", f"command={command}")
        return
    encrypted = encrypt_for_node(node_id, data)
    if not encrypted:
        log_security(node_id, "unknown_node", "missing AES key for downlink")
        return
    payload = json.dumps(encrypted).encode()
    record_forwarded(msg.topic, payload, recent_downlinks)
    client_field.publish(msg.topic, payload, qos=1)
    edge_log("EDGE DOWNLINK", f"{command} -> {node_id} (encrypted)")


@http_app.route("/upload_image", methods=["POST"])
def upload_image():
    node_id = request.form.get("node_id", "")
    nonce_hex = request.form.get("nonce", "")
    tag_hex = request.form.get("tag", "")
    seq_no = request.form.get("seq_no", "0")
    image = request.files.get("image")

    ok, reason = algo_4_whitelist(node_id)
    if not ok:
        log_security(node_id, reason)
        return jsonify({"error": reason}), 403

    now = time.time()
    with state_lock:
        tracker = image_rate_tracker.setdefault(node_id, deque())
        tracker.append(now)
        while tracker and tracker[0] < now - 2:
            tracker.popleft()
        if len(tracker) > 1:
            log_security(node_id, "image_rate_limited")
            return jsonify({"error": "rate_limited"}), 429

    if not image:
        return jsonify({"error": "missing image"}), 400
    image_bytes = image.read()
    if len(image_bytes) > MAX_IMAGE_SIZE:
        log_security(node_id, "image_too_large")
        return jsonify({"error": "too_large"}), 413

    ok, reason = algo_1_gcm_verify(node_id, image_bytes.hex(), nonce_hex, tag_hex)
    if not ok:
        log_security(node_id, reason)
        return jsonify({"error": reason}), 403

    files = {"image": ("capture.bin", image_bytes, "application/octet-stream")}
    data = {"node_id": node_id, "nonce": nonce_hex, "tag": tag_hex, "seq_no": seq_no}
    try:
        response = requests.post(IMAGE_RELAY_URL, data=data, files=files, timeout=30)
        edge_log("EDGE IMAGE", f"image relayed {node_id}")
        return (response.text, response.status_code, {"Content-Type": response.headers.get("Content-Type", "application/json")})
    except Exception as exc:
        log_security(node_id, "image_relay_failed", str(exc))
        return jsonify({"error": "relay_failed"}), 502


@http_app.route("/health", methods=["GET"])
def health():
    active_blacklist = [node_id for node_id, expiry in blacklist.items() if expiry > time.time()]
    return jsonify({
        "status": "ok",
        "nodes_monitored": len(NODE_IDS),
        "blacklisted": len(active_blacklist),
    })


def start_http_server():
    global http_thread
    http_thread = threading.Thread(
        target=lambda: http_app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False),
        daemon=True,
    )
    http_thread.start()
    edge_log("EDGE", "HTTP server on :8080")


def build_clients():
    global client_field, client_upstream

    _run_id = uuid.uuid4().hex[:8]

    client_field = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                               client_id=f"edge_field_{_run_id}")
    client_field.on_connect = on_field_connect
    client_field.on_disconnect = on_field_disconnect
    client_field.on_message = on_field_message

    def connect_field():
        while True:
            try:
                client_field.connect(
                    FIELD_BROKER_HOST,
                    EDGE_MQTT_PORT,
                    keepalive=60
                )
                print(f"[EDGE] Field broker connected")
                return
            except Exception as e:
                print(f"[EDGE] Field connect failed: {e} â€” retrying in 5s")
                time.sleep(5)

    connect_field()
    client_field.loop_start()

    client_upstream = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                   client_id=f"edge_upstream_{_run_id}")
    client_upstream.on_connect = on_upstream_connect
    client_upstream.on_disconnect = on_upstream_disconnect
    client_upstream.on_message = on_upstream_message

    def connect_upstream():
        while True:
            try:
                client_upstream.connect(
                    UPSTREAM_BROKER_HOST,
                    FOG_MQTT_PORT,
                    keepalive=60
                )
                print(f"[EDGE] Upstream broker connected")
                return
            except Exception as e:
                print(f"[EDGE] Upstream connect failed: {e} â€” retrying in 5s")
                time.sleep(5)

    connect_upstream()
    client_upstream.loop_start()


def print_banner():
    print("â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•")
    print("BORDER SHIELD â€” EDGE NODE")
    print("â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•")


def print_ready():
    print("â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•")
    print("[EDGE] READY")
    print(f"Nodes: {', '.join(NODE_IDS)}")
    print(f"Field broker: {FIELD_BROKER_HOST}:{EDGE_MQTT_PORT}")
    print(f"Upstream: {UPSTREAM_BROKER_HOST}:{FOG_MQTT_PORT}")
    print("HTTP relay: 0.0.0.0:8080")
    print(f"Mode: {'TESTING' if TESTING_MODE else 'DEPLOYMENT'}")
    print("â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•")


def shutdown(*_args):
    stop_event.set()
    if client_field:
        client_field.loop_stop()
        client_field.disconnect()
    if client_upstream:
        client_upstream.loop_stop()
        client_upstream.disconnect()
    raise SystemExit(0)


def main():
    check_single_instance()
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    print_banner()
    start_hotspot()
    fetch_node_keys()
    fetch_node_coords()
    build_clients()
    start_http_server()
    write_acl_file()

    threading.Thread(target=challenge_thread, daemon=True).start()
    edge_log("EDGE", "Challenge thread started")
    threading.Thread(target=anomaly_decay_thread, daemon=True).start()
    edge_log("EDGE", "Anomaly decay started")
    print_ready()

    while not stop_event.wait(1):
        pass


if __name__ == "__main__":
    main()
