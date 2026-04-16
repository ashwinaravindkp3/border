from flask import Blueprint, request, jsonify, Response, g
from app.database import get_pg, get_mongo
from app.crypto import get_node_key
from app.intelligence import (
    check_physical_plausibility,
    get_threat_score,
    record_event,
    update_threat_score,
)
from app.yolo_handler import detect_humans
from app.security import log_attack, seen_sequences, verify_packet
from app.auth import jwt_required, jwt_role_required
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
import os, json, uuid, datetime, requests, jwt

load_dotenv()
bp = Blueprint("main", __name__)

SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
EDGE_SECRET = os.getenv("EDGE_SECRET", "edge_secret_2026")

# Valid operator accounts  {username: {password, role}}
_USERS = {
    "hq_officer": {"password": "border2026", "role": "hq"},
    "barracks":   {"password": "isr2026",    "role": "barracks"},
}

# Camera registry — maps physical camera ID to Pi-side MJPEG stream URL
CAMERA_REGISTRY = {
    "BORDER_A1": "http://PI_ETHERNET_IP:8080/stream",
    "BORDER_A2": "http://PI_ETHERNET_IP:8080/stream",
}

# Virtual node → physical camera owner mapping
NODE_CAMERA_MAP = {
    **{f"BORDER_{str(i).zfill(3)}": "BORDER_A1" for i in range(1, 45)},
    **{f"BORDER_{str(i).zfill(3)}": "BORDER_A2" for i in range(45, 90)},
}

_SWEEP_FALLBACK = {}


def _threat_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "elevated"
    return "normal"


def _edge_authorized() -> bool:
    return request.headers.get("X-Edge-Token", "") == EDGE_SECRET


def _emit_alert(alert_payload: dict):
    try:
        from app import socketio as _sio
        _sio.emit("alert_update", alert_payload)
    except Exception as exc:
        print(f"[SOCKET ALERT EMIT] {exc}")


def _create_alert_for_node(node_id: str, event_type: str, level: int, notes: str | None = None):
    conn = get_pg()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events (node_id, event_type, alert_level, verified, lat, lng, notes)
        SELECT %s, %s, %s, TRUE, lat, lng, %s
        FROM nodes
        WHERE node_id = %s
        RETURNING id, lat, lng
        """,
        (node_id, event_type, level, notes, node_id),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return None
    event_id, lat, lng = row
    cur.execute(
        "INSERT INTO alerts (event_id, level) VALUES (%s, %s) RETURNING id, triggered_at",
        (event_id, level),
    )
    alert_id, triggered_at = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    payload = {
        "id": alert_id,
        "node_id": node_id,
        "level": f"L{level}",
        "triggered_at": str(triggered_at),
        "resolved": False,
        "event_type": event_type,
        "lat": lat,
        "lng": lng,
        "image_ref": None,
    }
    _emit_alert(payload)
    return payload


def _store_detection(node_id: str, event_id: int, filename: str, result: dict):
    try:
        db = get_mongo()
        db.detections.insert_one({
            "node_id":           node_id,
            "event_id":          event_id,
            "image_file":        filename,
            "yolo_result":       result,
            "timestamp":         datetime.datetime.utcnow().isoformat(),
            "armed":             result.get("armed", False),
            "weapon_confidence": result.get("weapon_confidence", 0.0),
            "weapon_class":      result.get("weapon_class", "")
        })
    except Exception as mongo_err:
        print(f"[MONGO FALLBACK] {mongo_err}")
        fallback = {
            "node_id":    node_id,
            "timestamp":  datetime.datetime.utcnow().isoformat(),
            "yolo_result": result,
            "image_file": filename
        }
        with open(os.path.join(os.getenv("UPLOAD_FOLDER", "uploads"), "mongo_fallback.jsonl"), "a") as f:
            f.write(json.dumps(fallback) + "\n")


def _process_image_upload(node_id: str, event_id: int, save_path: str, filename: str):
    result = detect_humans(save_path)
    _store_detection(node_id, event_id, filename, result)

    event_time = datetime.datetime.now()
    record_event(node_id, event_time, "image_upload")
    plausibility = check_physical_plausibility(node_id, event_time, "image_upload")

    if plausibility["flag"] == "teleportation_attack":
        update_threat_score(node_id, +50, "teleportation_attack")
        log_attack(node_id, "teleportation_attack", plausibility["details"])
    elif plausibility["flag"] == "vehicle_detected":
        update_threat_score(node_id, +15, "vehicle_detected")

    if result.get("human_detected") and event_id:
        conn = get_pg()
        cur  = conn.cursor()
        if result.get("armed"):
            notes_str = f"ARMED INTRUDER — auto-escalated, weapon: {result.get('weapon_class')} confidence: {result.get('weapon_confidence')}"
            cur.execute(
                "UPDATE events SET alert_level = 2, image_ref = %s, notes = %s WHERE id = %s",
                (filename, notes_str, event_id)
            )
            cur.execute(
                "UPDATE alerts SET resolved = TRUE WHERE event_id = %s AND level = 1",
                (event_id,)
            )
            cur.execute(
                "INSERT INTO alerts (event_id, level) VALUES (%s, 2)",
                (event_id,)
            )
            print(f"[YOLO] ARMED human detected at {node_id} — L2 auto-escalated")
        else:
            cur.execute(
                "UPDATE events SET alert_level = 2, image_ref = %s WHERE id = %s",
                (filename, event_id)
            )
            cur.execute(
                "INSERT INTO alerts (event_id, level) VALUES (%s, 2)",
                (event_id,)
            )
            print(f"[YOLO] Human detected at {node_id} — L2 alert raised")
        conn.commit()
        cur.close()
        conn.close()

    return {
        "status": "ok",
        "filename": filename,
        "yolo": result,
        "armed": result.get("armed", False),
        "weapon_class": result.get("weapon_class", ""),
        "human_detected": result.get("human_detected", False),
        "plausibility": plausibility["flag"],
    }


def _save_sweep(sweep_doc: dict):
    try:
        db = get_mongo()
        db.sweeps.insert_one(sweep_doc)
    except Exception as mongo_err:
        print(f"[SWEEP FALLBACK] {mongo_err}")
        _SWEEP_FALLBACK[sweep_doc["node_id"]] = sweep_doc


def _get_latest_sweep(node_id: str) -> dict | None:
    try:
        db = get_mongo()
        return db.sweeps.find_one({"node_id": node_id}, sort=[("requested_at", -1)])
    except Exception:
        return _SWEEP_FALLBACK.get(node_id)


def _update_sweep_frames(node_id: str, frame_doc: dict):
    sweep = _get_latest_sweep(node_id)
    if not sweep or sweep.get("complete"):
        return

    updated_frames = sweep.get("frames", []) + [frame_doc]
    is_complete = len(updated_frames) >= 5

    try:
        db = get_mongo()
        db.sweeps.update_one(
            {"_id": sweep["_id"]},
            {"$set": {"frames": updated_frames, "complete": is_complete}},
        )
    except Exception:
        sweep["frames"] = updated_frames
        sweep["complete"] = is_complete
        _SWEEP_FALLBACK[node_id] = sweep


# ---------- Authentication ----------

@bp.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    user = _USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "invalid credentials"}), 401
    payload = {
        "sub": username,
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token, "role": user["role"]})


# ---------- Protected API Endpoints ----------

@bp.route("/api/nodes", methods=["GET"])
def get_nodes():
    if not _edge_authorized():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        try:
            payload = jwt.decode(auth.split(" ", 1)[1], SECRET_KEY, algorithms=["HS256"])
            g.user = {"username": payload["sub"], "role": payload["role"]}
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({"error": "unauthorized"}), 401

    conn = get_pg()
    cur  = conn.cursor()
    cur.execute("SELECT node_id, lat, lng, zone, status, last_seen FROM nodes ORDER BY node_id ASC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{
        "node_id":   r[0], "lat": r[1], "lng": r[2],
        "zone":      r[3], "status": r[4],
        "last_seen": str(r[5]) if r[5] else None
    } for r in rows])


@bp.route("/api/node_keys", methods=["GET", "POST"])
def node_keys():
    token = request.headers.get("X-Edge-Token", "")
    expected = os.getenv("EDGE_SECRET", "edge_secret_2026")
    if token != expected:
        return jsonify({"error": "unauthorized"}), 401

    if request.method == "POST":
        data = request.get_json(force=True) or {}
        node_ids = data.get("node_ids", [])
    else:
        node_ids_str = request.args.get("node_ids", "")
        node_ids = [n.strip() for n in node_ids_str.split(",") if n.strip()]

    if not node_ids:
        return jsonify({"error": "missing node_ids"}), 400

    conn = get_pg()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_id, aes_key FROM nodes WHERE node_id = ANY(%s) AND aes_key IS NOT NULL",
        (node_ids,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({node_id: aes_key for node_id, aes_key in rows}), 200


@bp.route("/api/alerts")
@jwt_required
def get_alerts():
    conn = get_pg()
    cur  = conn.cursor()
    cur.execute("""
        SELECT a.id, e.node_id, a.level, a.triggered_at, a.resolved,
               e.event_type, e.lat, e.lng, e.image_ref, e.notes
        FROM alerts a JOIN events e ON a.event_id = e.id
        ORDER BY a.triggered_at DESC LIMIT 50
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    alerts_out = []
    for r in rows:
        notes = r[9] or ""
        armed = "ARMED INTRUDER" in notes
        weapon_class = ""
        if armed and "weapon: " in notes:
            weapon_class = notes.split("weapon: ")[1].split(" ")[0]
            
        alerts_out.append({
            "id":           r[0], "node_id": r[1], "level": r[2],
            "triggered_at": str(r[3]), "resolved": r[4],
            "event_type":   r[5], "lat": r[6], "lng": r[7],
            "image_ref":    r[8],
            "armed":        armed,
            "weapon_class": weapon_class
        })
    return jsonify(alerts_out)


@bp.route("/api/threat_scores")
@jwt_required
def threat_scores():
    conn = get_pg()
    cur = conn.cursor()
    cur.execute("SELECT node_id FROM nodes ORDER BY node_id ASC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    scores = []
    for (node_id,) in rows:
        score = get_threat_score(node_id)
        scores.append({
            "node_id": node_id,
            "score": score,
            "level": _threat_level(score),
        })
    return jsonify({"scores": scores})


@bp.route("/api/upload_image", methods=["POST"])
def upload_image():
    node_id  = request.form.get("node_id")
    seq_no_raw = request.form.get("seq_no", "0")
    seq_no   = int(seq_no_raw)
    hmac_val = request.form.get("hmac", "")
    event_id_raw = request.form.get("event_id", "0")
    event_id = int(event_id_raw)
    file     = request.files.get("image")

    if not all([node_id, file]):
        return jsonify({"error": "missing fields"}), 400

    payload_str = json.dumps(
        {"node_id": node_id, "seq_no": seq_no, "event_id": event_id_raw},
        separators=(",", ":"), sort_keys=True
    )
    ok, reason = verify_packet(node_id, payload_str, hmac_val, seq_no)
    if not ok:
        return jsonify({"error": f"rejected: {reason}"}), 403

    filename  = f"{node_id}_{uuid.uuid4().hex}.jpg"
    save_path = os.path.join(os.getenv("UPLOAD_FOLDER"), filename)
    file.save(save_path)

    return jsonify(_process_image_upload(node_id, event_id, save_path, filename))


@bp.route("/api/upload_image_gcm", methods=["POST"])
def upload_image_gcm():
    node_id = request.form.get("node_id")
    nonce_hex = request.form.get("nonce")
    tag_hex = request.form.get("tag")
    event_id = int(request.form.get("event_id", 0))
    seq_no = int(request.form.get("seq_no", 0))
    file = request.files.get("image")

    if not all([node_id, nonce_hex, tag_hex, file]):
        return jsonify({"error": "missing fields"}), 400

    image_bytes = file.read()

    key = get_node_key(node_id)
    if not key:
        log_attack(node_id, "unknown_node", "GCM image upload")
        return jsonify({"error": "rejected"}), 403

    last_seq = seen_sequences.get(node_id, -1)
    if seq_no <= last_seq:
        log_attack(
            node_id,
            "replay_attack",
            f"seq_no {seq_no} already seen, last was {last_seq}",
        )
        update_threat_score(node_id, +10, "replay_attack")
        return jsonify({"error": "rejected: replay"}), 403

    try:
        aesgcm = AESGCM(key)
        nonce = bytes.fromhex(nonce_hex)
        tag = bytes.fromhex(tag_hex)
        plaintext = aesgcm.decrypt(nonce, image_bytes + tag, None)
        seen_sequences[node_id] = seq_no
    except Exception:
        log_attack(node_id, "gcm_tag_failure", "Image GCM tag invalid")
        update_threat_score(node_id, +10, "gcm_tag_failure")
        return jsonify({"error": "rejected: tampered"}), 403

    filename = f"{node_id}_{uuid.uuid4().hex}.jpg"
    save_path = os.path.join(os.getenv("UPLOAD_FOLDER"), filename)
    with open(save_path, "wb") as output_file:
        output_file.write(plaintext)

    response = _process_image_upload(node_id, event_id, save_path, filename)
    response["seq_no"] = seq_no
    return jsonify(response)


@bp.route("/api/confirm_alert/<int:alert_id>", methods=["POST"])
@jwt_role_required("hq")
def confirm_alert(alert_id):
    body     = request.get_json(silent=True) or {}
    operator = body.get("operator", "unknown")
    conn = get_pg()
    cur  = conn.cursor()
    cur.execute(
        "UPDATE alerts SET confirmed_by = %s, confirmed_at = NOW() WHERE id = %s",
        (operator, alert_id)
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "confirmed", "alert_id": alert_id})


@bp.route("/api/resolve_alert/<int:alert_id>", methods=["POST"])
@jwt_required
def resolve_alert(alert_id):
    conn = get_pg()
    cur  = conn.cursor()
    cur.execute("UPDATE alerts SET resolved = TRUE WHERE id = %s", (alert_id,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "resolved"})


@bp.route("/api/security_log", methods=["GET", "POST"])
def security_log():
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        node_id = body.get("node_id")
        attack_type = body.get("attack_type")
        detail = body.get("detail", "")
        if not node_id or not attack_type:
            return jsonify({"error": "missing fields"}), 400
        log_attack(node_id, attack_type, detail)
        return jsonify({"status": "logged"})

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401
    try:
        payload = jwt.decode(auth.split(" ", 1)[1], SECRET_KEY, algorithms=["HS256"])
        g.user = {"username": payload["sub"], "role": payload["role"]}
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({"error": "unauthorized"}), 401

    conn = get_pg()
    cur  = conn.cursor()
    cur.execute(
        "SELECT node_id, attack_type, detail, logged_at FROM security_log ORDER BY logged_at DESC LIMIT 50"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{
        "node_id":     r[0], "attack_type": r[1],
        "detail":      r[2], "logged_at": str(r[3])
    } for r in rows])


@bp.route("/api/l7_alert", methods=["POST"])
def l7_alert():
    body = request.get_json(silent=True) or {}
    node_id = body.get("node_id")
    reason = body.get("reason", "unspecified")
    threat_score = body.get("threat_score", 0)
    if not node_id:
        return jsonify({"error": "missing node_id"}), 400
    payload = _create_alert_for_node(
        node_id=node_id,
        event_type="l7_security_alert",
        level=7,
        notes=f"L7 alert: {reason} threat_score={threat_score}",
    )
    if payload is None:
        return jsonify({"error": "unknown node"}), 404
    return jsonify({"status": "ok", "alert": payload})


@bp.route("/api/stream/<node_id>")
@jwt_required
def stream(node_id):
    physical   = NODE_CAMERA_MAP.get(node_id, node_id)
    stream_url = CAMERA_REGISTRY.get(physical)
    if not stream_url:
        return jsonify({"error": "no camera at this node"}), 404

    def generate():
        try:
            r = requests.get(stream_url, stream=True, timeout=10)
            for chunk in r.iter_content(chunk_size=4096):
                yield chunk
        except Exception as e:
            print(f"[STREAM] Error: {e}")

    return Response(
        generate(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
        headers={"Cache-Control": "no-cache"}
    )


@bp.route("/api/camera_map")
@jwt_required
def camera_map():
    return jsonify({
        "physical_cameras":      list(CAMERA_REGISTRY.keys()),
        "node_camera_map":       NODE_CAMERA_MAP,
        "max_concurrent_streams": 2
    })


# ---------- Patrol Sweep ----------

@bp.route("/api/patrol_sweep/<node_id>", methods=["POST"])
@jwt_role_required("hq")
def patrol_sweep(node_id):
    from app import socketio as _sio
    from app.mqtt_handler import mqtt_client as _mqtt

    sweep_id = str(uuid.uuid4())
    sweep_doc = {
        "sweep_id":      sweep_id,
        "node_id":       node_id,
        "requested_by":  g.user["username"],
        "requested_at":  datetime.datetime.utcnow().isoformat(),
        "frames":        [],
        "complete":      False,
    }
    _save_sweep(sweep_doc)

    if _mqtt:
        payload = json.dumps({
            "command":   "patrol_sweep",
            "positions": [0, 45, 90, 135, 180],
            "node_id":   node_id,
        })
        _mqtt.publish(f"border/{node_id}/command", payload, qos=1)
        print(f"[SWEEP] Initiated sweep {sweep_id} for {node_id}")

    return jsonify({"status": "initiated", "sweep_id": sweep_id})


@bp.route("/api/sweep_frame", methods=["POST"])
def sweep_frame():
    from app import socketio as _sio

    node_id     = request.form.get("node_id")
    position    = int(request.form.get("position", 0))
    frame_index = int(request.form.get("frame_index", 0))
    seq_no      = int(request.form.get("seq_no", 0))
    hmac_val    = request.form.get("hmac", "")
    file        = request.files.get("image")

    if not all([node_id, file]):
        return jsonify({"error": "missing fields"}), 400

    payload_str = json.dumps(
        {"node_id": node_id, "seq_no": seq_no, "frame_index": frame_index, "position": position},
        separators=(",", ":"), sort_keys=True
    )
    ok, reason = verify_packet(node_id, payload_str, hmac_val, seq_no)
    if not ok:
        return jsonify({"error": f"rejected: {reason}"}), 403

    filename  = f"sweep_{node_id}_{frame_index}.jpg"
    save_path = os.path.join(os.getenv("UPLOAD_FOLDER", "uploads"), filename)
    file.save(save_path)

    result = detect_humans(save_path)

    frame_doc = {
        "position":       position,
        "frame_index":    frame_index,
        "image_path":     filename,
        "human_detected": result.get("human_detected", False),
        "armed":          result.get("armed", False),
        "confidence":     result.get("confidence", 0.0),
        "weapon_class":   result.get("weapon_class", ""),
    }

    _update_sweep_frames(node_id, frame_doc)

    if result.get("human_detected"):
        conn = get_pg()
        cur  = conn.cursor()
        if result.get("armed"):
            cur.execute(
                """INSERT INTO events (node_id, event_type, alert_level, verified, lat, lng)
                   SELECT %s, 'sweep_armed_contact', 2, TRUE, lat, lng FROM nodes WHERE node_id = %s
                   RETURNING id""",
                (node_id, node_id)
            )
            row = cur.fetchone()
            if row:
                cur.execute(
                    "INSERT INTO alerts (event_id, level) VALUES (%s, 2)", (row[0],)
                )
                print(f"[SWEEP] ARMED contact at {node_id} frame {frame_index} — L2 raised")
        else:
            cur.execute(
                """INSERT INTO events (node_id, event_type, alert_level, verified, lat, lng)
                   SELECT %s, 'sweep_contact', 1, TRUE, lat, lng FROM nodes WHERE node_id = %s
                   RETURNING id""",
                (node_id, node_id)
            )
            row = cur.fetchone()
            if row:
                cur.execute(
                    "INSERT INTO alerts (event_id, level) VALUES (%s, 1)", (row[0],)
                )
                print(f"[SWEEP] Human contact at {node_id} frame {frame_index} — L1 raised")
        conn.commit()
        cur.close()
        conn.close()

    _sio.emit("sweep_frame", {
        "node_id":        node_id,
        "frame_index":    frame_index,
        "position":       position,
        "human_detected": result.get("human_detected", False),
        "armed":          result.get("armed", False),
        "image_url":      f"/uploads/{filename}",
    })

    return jsonify({
        "status":         "ok",
        "frame_index":    frame_index,
        "human_detected": result.get("human_detected", False),
        "armed":          result.get("armed", False),
    })


@bp.route("/api/sweep_results/<node_id>")
@jwt_required
def sweep_results(node_id):
    sweep = _get_latest_sweep(node_id)
    if not sweep:
        return jsonify({"error": "no sweep found"}), 404
    if "_id" in sweep:
        sweep["_id"] = str(sweep["_id"])
    return jsonify(sweep)


# ---------- Health Check ----------

@bp.route("/api/health")
def health():
    from app.mqtt_handler import mqtt_client as _mqtt

    pg_ok, mongo_ok, mqtt_ok = False, False, False
    nodes_online, active_alerts = 0, 0

    try:
        conn = get_pg()
        cur  = conn.cursor()
        cur.execute("SELECT 1")
        cur.execute("SELECT COUNT(*) FROM nodes WHERE status='online'")
        nodes_online = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE resolved=FALSE")
        active_alerts = cur.fetchone()[0]
        cur.close()
        conn.close()
        pg_ok = True
    except Exception as e:
        print(f"[HEALTH] PostgreSQL error: {e}")

    try:
        db = get_mongo()
        db.command("ping")
        mongo_ok = True
    except Exception as e:
        print(f"[HEALTH] MongoDB error: {e}")

    try:
        mqtt_ok = bool(_mqtt and _mqtt.is_connected())
    except Exception:
        pass

    all_ok = pg_ok and mongo_ok and mqtt_ok
    return jsonify({
        "status":        "ok" if all_ok else "degraded",
        "postgres":      pg_ok,
        "mongodb":       mongo_ok,
        "mqtt":          mqtt_ok,
        "nodes_online":  nodes_online,
        "active_alerts": active_alerts,
        "timestamp":     datetime.datetime.utcnow().isoformat(),
    })
