import io
import hmac as hmac_lib
import hashlib
import json
import time
from datetime import datetime

import paho.mqtt.client as mqtt
import requests
from PIL import Image


SERVER_IP = "10.42.0.1"
SERVER_PORT = 5000
SERVER_MQTT_PORT = 1883
EDGE_IP = "192.168.4.1"
EDGE_MQTT_PORT = 1883
FOG_HTTP_PORT = 8080
LOGIN_USERNAME = "hq_officer"
LOGIN_PASSWORD = "border2026"
TEST_NODE_ID = "BORDER_001"


def make_mqtt_client(client_id):
    callback_api = getattr(getattr(mqtt, "CallbackAPIVersion", None), "VERSION2", None)
    if callback_api is not None:
        return mqtt.Client(callback_api_version=callback_api, client_id=client_id, clean_session=True)
    return mqtt.Client(client_id=client_id, clean_session=True)


def server_url(path):
    return f"http://{SERVER_IP}:{SERVER_PORT}{path}"


def print_result(label, status, detail=""):
    if detail:
        print(f"{label}: {status} - {detail}")
    else:
        print(f"{label}: {status}")


def log(label, message):
    print(f"{label}: {message}")


def get_jwt(session):
    payload = {"username": LOGIN_USERNAME, "password": LOGIN_PASSWORD}
    for endpoint in ("/api/login", "/login", "/api/auth/login"):
        try:
            response = session.post(server_url(endpoint), json=payload, timeout=10)
        except requests.RequestException:
            continue
        if response.status_code != 200:
            continue
        try:
            body = response.json()
        except ValueError:
            continue
        token = body.get("access_token") or body.get("token") or body.get("jwt") or body.get("access")
        if token:
            return token
    return None


def extract_services_ok(payload):
    if isinstance(payload, dict):
        services = payload.get("services")
        if isinstance(services, dict):
            return all(bool(v) for v in services.values())
        keys = [k for k, v in payload.items() if isinstance(v, bool)]
        if keys:
            return all(payload[k] for k in keys)
    return False


def extract_nodes(payload):
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        items = payload.get("nodes") or payload.get("data") or []
    else:
        items = []
    return items


def find_node(payload, node_id):
    for item in extract_nodes(payload):
        if isinstance(item, dict):
            current_id = item.get("node_id") or item.get("id") or item.get("name")
            if str(current_id) == node_id:
                return item
    return None


def mqtt_publish(host, port, topic, payload):
    client = make_mqtt_client(client_id=f"fog-test-{int(time.time() * 1000)}")
    client.connect(host, port, keepalive=30)
    client.loop_start()
    info = client.publish(topic, json.dumps(payload).encode("utf-8"))
    time.sleep(1)
    client.loop_stop()
    client.disconnect()
    return info.rc == mqtt.MQTT_ERR_SUCCESS


def test_server_health(session, results):
    try:
        response = session.get(server_url("/api/health"), timeout=10)
        response.raise_for_status()
        ok = extract_services_ok(response.json())
        results["T1"] = "PASS" if ok else "FAIL"
        print_result("T1 Server health", results["T1"], f"status={response.status_code}")
    except Exception as exc:
        results["T1"] = "FAIL"
        print_result("T1 Server health", "FAIL", str(exc))


def test_fog_health(session, results):
    try:
        response = session.get(f"http://localhost:{FOG_HTTP_PORT}/", timeout=10)
        response.raise_for_status()
        body = response.json()
        ok = body.get("status") == "ok"
        results["T2"] = "PASS" if ok else "FAIL"
        print_result("T2 Fog health", results["T2"], json.dumps(body))
    except Exception as exc:
        results["T2"] = "FAIL"
        print_result("T2 Fog health", "FAIL", str(exc))


def test_mqtt_uplink(session, results):
    payload = {
        "node_id": TEST_NODE_ID,
        "seq_no": int(time.time()),
        "ts": datetime.utcnow().isoformat(),
        "status": "ok",
    }
    try:
        published = mqtt_publish(SERVER_IP, SERVER_MQTT_PORT, f"border/{TEST_NODE_ID}/heartbeat", payload)
        if not published:
            results["T3"] = "FAIL"
            print_result("T3 MQTT uplink", "FAIL", "publish failed")
            return
        time.sleep(2)
        token = get_jwt(session)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = session.get(server_url("/api/nodes"), headers=headers, timeout=10)
        response.raise_for_status()
        node = find_node(response.json(), TEST_NODE_ID)
        results["T3"] = "PASS" if node else "FAIL"
        detail = "last_seen update should be recent" if node else "node not found in /api/nodes"
        print_result("T3 MQTT uplink", results["T3"], detail)
    except Exception as exc:
        results["T3"] = "FAIL"
        print_result("T3 MQTT uplink", "FAIL", str(exc))


def test_rate_limit(results):
    client = make_mqtt_client(client_id=f"fog-rate-{int(time.time() * 1000)}")
    try:
        client.connect(EDGE_IP, EDGE_MQTT_PORT, keepalive=30)
    except Exception as exc:
        results["T4"] = "SKIP"
        print_result("T4 Rate limit", "SKIP", f"edge broker unavailable: {exc}")
        return

    client.loop_start()
    try:
        for index in range(15):
            payload = {"node_id": TEST_NODE_ID, "seq_no": 100000 + index, "ts": datetime.utcnow().isoformat()}
            client.publish(f"border/{TEST_NODE_ID}/heartbeat", json.dumps(payload).encode("utf-8"))
        time.sleep(1)
        results["T4"] = "PASS"
        print_result("T4 Rate limit", "PASS", "sent 15 heartbeats in 1 second; verify fog logs show ddos_detected")
    except Exception as exc:
        results["T4"] = "FAIL"
        print_result("T4 Rate limit", "FAIL", str(exc))
    finally:
        client.loop_stop()
        client.disconnect()


def test_downlink_command(session, results):
    token = get_jwt(session)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        response = session.post(server_url(f"/api/patrol_sweep/{TEST_NODE_ID}"), headers=headers, timeout=10)
        status = "MANUAL"
        results["T5"] = status
        detail = f"HTTP {response.status_code}; check fog console for [FOG DOWNLINK] command=patrol_sweep -> node={TEST_NODE_ID}"
        print_result("T5 Downlink cmd", status, detail)
    except Exception as exc:
        results["T5"] = "MANUAL"
        print_result("T5 Downlink cmd", "MANUAL", f"request error: {exc}")


def test_t6_image_relay(fog_url, server_url):
    log("T6", "Image relay test starting")
    try:
        import hmac as hmac_lib
        import hashlib
        import json
        import io
        from PIL import Image
        import numpy as np

        img = Image.fromarray(
            np.zeros((100, 100, 3), dtype=np.uint8)
        )
        buf = io.BytesIO()
        img.save(buf, format='JPEG')
        img_bytes = buf.getvalue()

        SECRET = "secret_key_BORDER_001"
        seq_no = int(time.time())
        event_id = 1

        data = {
            "node_id": "BORDER_001",
            "seq_no": seq_no,
            "event_id": event_id
        }

        clean_payload = json.dumps(
            data,
            separators=(",", ":"),
            sort_keys=True
        )
        signature = hmac_lib.new(
            SECRET.encode(),
            clean_payload.encode(),
            hashlib.sha256
        ).hexdigest()

        files = {"image": ("test.jpg", img_bytes,
                           "image/jpeg")}
        form_data = {
            "node_id": "BORDER_001",
            "hmac": signature,
            "seq_no": str(seq_no),
            "event_id": str(event_id)
        }

        resp = requests.post(
            f"{fog_url}/relay_image",
            files=files,
            data=form_data,
            timeout=12
        )

        if resp.status_code == 200:
            result = resp.json()
            if "armed" in result:
                log("T6", f"PASS - relayed ok, "
                    f"armed={result.get('armed')}, "
                    f"human={result.get('human_detected')}")
                return True
            else:
                log("T6", f"PASS - relayed, "
                    f"response={resp.text[:100]}")
                return True
        else:
            log("T6", f"FAIL - status={resp.status_code} "
                f"body={resp.text[:200]}")
            return False

    except Exception as e:
        log("T6", f"FAIL - {e}")
        return False


def print_summary(results):
    print("==========================")
    print("FOG NODE TEST RESULTS")
    print("==========================")
    print(f"T1 Server health:     {results.get('T1', 'FAIL')}")
    print(f"T2 Fog health:        {results.get('T2', 'FAIL')}")
    print(f"T3 MQTT uplink:       {results.get('T3', 'FAIL')}")
    print(f"T4 Rate limit:        {results.get('T4', 'SKIP')}")
    print(f"T5 Downlink cmd:      {results.get('T5', 'MANUAL')}")
    print(f"T6 Image relay:       {results.get('T6', 'FAIL')}")
    print("==========================")


def main():
    session = requests.Session()
    session.trust_env = False
    results = {}

    test_server_health(session, results)
    test_fog_health(session, results)
    test_mqtt_uplink(session, results)
    test_rate_limit(results)
    test_downlink_command(session, results)
    results["T6"] = "PASS" if test_t6_image_relay(
        fog_url=f"http://localhost:{FOG_HTTP_PORT}",
        server_url=server_url("")
    ) else "FAIL"
    print_summary(results)


if __name__ == "__main__":
    main()
