import paho.mqtt.client as mqtt
import json
import time
import os
import threading
from datetime import datetime
from dotenv import load_dotenv
from app.database import get_pg
from app.crypto import load_key_cache
from app.intelligence import (
    check_physical_plausibility,
    decay_threat_scores,
    load_node_coords,
    record_event,
    update_heartbeat_baseline,
    update_threat_score,
)
from app.security import log_attack, verify_gcm_packet, verify_packet

load_dotenv()

HEARTBEAT_TIMEOUT = 90
last_heartbeat = {}

# In-memory LoRa/WiFi status store — reset on server restart
lora_status = {}

# Module-level reference set by start_mqtt() so routes can import it
mqtt_client = None

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("[MQTT] Connected to broker")
        client.subscribe("border/+/heartbeat")
        client.subscribe("border/+/event")
        client.subscribe("border/+/status")
        print("[MQTT] Subscribed to all border topics")
    else:
        print(f"[MQTT] Connection failed: rc={rc}")

def on_message(client, userdata, msg):
    topic = msg.topic
    try:
        data = json.loads(msg.payload.decode())
    except Exception:
        print(f"[MQTT] Bad JSON on {topic}")
        return

    node_id = data.get("node_id")

    if {"ciphertext", "nonce", "tag", "seq_no"} <= data.keys():
        seq_no = int(data.get("seq_no", -1))
        ok, reason, payload = verify_gcm_packet(
            node_id,
            data.get("ciphertext", ""),
            data.get("nonce", ""),
            data.get("tag", ""),
            seq_no,
        )
        if not ok:
            print(f"[SECURITY] Packet rejected from {node_id}: {reason}")
            return
        payload["node_id"] = node_id
        payload.setdefault("seq_no", seq_no)
        data = payload
    else:
        seq_no = data.get("seq_no", -1)
        hmac_val = data.get("hmac", "")
        payload_for_verify = json.dumps(
            {k: v for k, v in data.items() if k != "hmac"},
            separators=(",", ":"),
            sort_keys=True,
        )
        ok, reason = verify_packet(node_id, payload_for_verify, hmac_val, seq_no)
        if not ok:
            print(f"[SECURITY] Packet rejected from {node_id}: {reason}")
            return

    if "heartbeat" in topic:
        handle_heartbeat(node_id, data)
    elif "event" in topic:
        handle_event(node_id, data, client)
    elif "status" in topic:
        handle_status(node_id, data)

def handle_heartbeat(node_id, data):
    last_heartbeat[node_id] = time.time()
    try:
        conn = get_pg()
        cur  = conn.cursor()
        cur.execute(
            "UPDATE nodes SET last_seen = NOW(), status = 'online' WHERE node_id = %s",
            (node_id,)
        )
        cur.execute(
            "INSERT INTO heartbeats (node_id, seq_no, rssi) VALUES (%s, %s, %s)",
            (node_id, data.get("seq_no"), data.get("rssi"))
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"[HEARTBEAT] {node_id} alive")

        normal, z_score = update_heartbeat_baseline(node_id, datetime.now())
        if not normal:
            update_threat_score(
                node_id,
                +10,
                f"heartbeat_anomaly z={z_score:.1f}",
            )
    except Exception as e:
        print(f"[HEARTBEAT ERROR] {e}")

def handle_status(node_id, data):
    wifi_active  = data.get("wifi_active", True)
    lora_active  = data.get("lora_active", False)
    battery_pct  = data.get("battery_pct", -1)

    new_status = "online" if wifi_active else "degraded"
    try:
        conn = get_pg()
        cur  = conn.cursor()
        cur.execute(
            "UPDATE nodes SET status = %s WHERE node_id = %s",
            (new_status, node_id)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[STATUS ERROR] {e}")

    lora_status[node_id] = {
        "lora_active": lora_active,
        "battery_pct": battery_pct,
        "updated_at":  datetime.now().isoformat(),
    }
    print(f"[STATUS] {node_id} wifi={wifi_active} lora={lora_active} bat={battery_pct}%")


def trigger_zone(node_id, data, mqtt_client):
    """Notify all nodes in a zone when a radar trigger occurs"""
    try:
        conn = get_pg()
        cur = conn.cursor()
        cur.execute("SELECT zone FROM nodes WHERE node_id = %s", (node_id,))
        row = cur.fetchone()
        if row:
            zone = row[0]
            action = {"command": "trigger_alarm", "zone": zone, "source": node_id}
            mqtt_client.publish(f"border/zone/{zone}/command", json.dumps(action), qos=1)
            print(f"[ZONE TRIGGER] Zone {zone} activated by {node_id}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[ZONE TRIGGER ERROR] {e}")

def handle_event(node_id, data, mqtt_client):
    event_type = data.get("event", "unknown")
    event_time = datetime.now()
    print(f"[EVENT] {node_id} → {event_type}")
    try:
        conn = get_pg()
        cur  = conn.cursor()
        cur.execute(
            """INSERT INTO events (node_id, event_type, alert_level, seq_no, verified, lat, lng)
               SELECT %s, %s, 1, %s, TRUE, lat, lng FROM nodes WHERE node_id = %s
               RETURNING id""",
            (node_id, event_type, data.get("seq_no"), node_id)
        )
        event_id = cur.fetchone()[0]
        cur.execute(
            """INSERT INTO alerts (event_id, level) VALUES (%s, 1)""",
            (event_id,)
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"[EVENT] Logged event_id={event_id} for {node_id}")

        record_event(node_id, event_time, event_type)
        result = check_physical_plausibility(node_id, event_time, event_type)
        if result["flag"] == "teleportation_attack":
            update_threat_score(node_id, +50, "teleportation_attack")
            log_attack(node_id, "teleportation_attack", result["details"])
            print(f"[INTEL] SPOOFED EVENT DETECTED: {result['details']}")
        elif result["flag"] == "vehicle_detected":
            update_threat_score(node_id, +15, "vehicle_detected")
            print(f"[INTEL] VEHICLE: {result['details']}")

        if event_type == "radar_trigger":
            trigger_zone(node_id, data, mqtt_client)

    except Exception as e:
        print(f"[EVENT ERROR] {e}")

def check_node_health(mqtt_client):
    while True:
        time.sleep(30)
        now = time.time()
        try:
            conn = get_pg()
            cur  = conn.cursor()
            cur.execute("SELECT node_id FROM nodes")
            nodes = [r[0] for r in cur.fetchall()]
            cur.close()
            conn.close()
        except Exception:
            continue

        for node_id in nodes:
            last = last_heartbeat.get(node_id)
            if last is None:
                continue
            gap = now - last
            if gap > HEARTBEAT_TIMEOUT * 3:
                update_node_status(node_id, "blackout", 6)
            elif gap > HEARTBEAT_TIMEOUT * 2:
                update_node_status(node_id, "silent", 4)
            elif gap > HEARTBEAT_TIMEOUT:
                update_node_status(node_id, "unresponsive", 3)

def update_node_status(node_id, status, level):
    try:
        conn = get_pg()
        cur  = conn.cursor()
        cur.execute("UPDATE nodes SET status = %s WHERE node_id = %s", (status, node_id))
        cur.execute(
            "INSERT INTO events (node_id, event_type, alert_level, verified) VALUES (%s, %s, %s, TRUE)",
            (node_id, f"node_{status}", level)
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"[HEALTH] {node_id} marked {status} — L{level} alert raised")
    except Exception as e:
        print(f"[HEALTH ERROR] {e}")

def start_mqtt():
    global mqtt_client
    load_key_cache()
    load_node_coords()

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(os.getenv("MQTT_BROKER"), int(os.getenv("MQTT_PORT")))

    t = threading.Thread(target=check_node_health, args=(client,), daemon=True)
    t.start()

    def decay_loop():
        while True:
            time.sleep(60)
            decay_threat_scores()

    decay_thread = threading.Thread(target=decay_loop, daemon=True)
    decay_thread.start()

    def keep_simulation_nodes_alive():
        while True:
            time.sleep(60)
            try:
                conn = get_pg()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE nodes SET "
                    "status='online', "
                    "last_seen=NOW() "
                    "WHERE node_id NOT IN "
                    "('BORDER_001',"
                    "'BORDER_002',"
                    "'BORDER_003')"
                )
                conn.commit()
                cur.close()
                conn.close()
            except Exception as e:
                print(f"[SIM] keepalive error: {e}")

    sim_thread = threading.Thread(
        target=keep_simulation_nodes_alive,
        daemon=True,
    )
    sim_thread.start()
    print("[SIM] Simulation nodes keepalive started")

    client.loop_start()
    mqtt_client = client
    return client
