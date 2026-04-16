import hmac
import hashlib
import time
from app.database import get_pg
from app.crypto import decrypt_gcm

seen_sequences = {}

def verify_packet(node_id, payload_str, received_hmac, seq_no):
    conn = get_pg()
    cur = conn.cursor()
    cur.execute("SELECT secret_key FROM nodes WHERE node_id = %s", (node_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        log_attack(node_id, "unknown_node", "Node ID not in registry")
        return False, "unknown_node"

    secret_key = row[0].encode()
    expected = hmac.new(secret_key, payload_str.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, received_hmac):
        log_attack(node_id, "hmac_mismatch", f"Expected {expected[:8]}... got {received_hmac[:8]}...")
        return False, "hmac_mismatch"

    last_seq = seen_sequences.get(node_id, -1)
    if seq_no <= last_seq:
        log_attack(node_id, "replay_attack", f"seq_no {seq_no} already seen, last was {last_seq}")
        return False, "replay_attack"

    seen_sequences[node_id] = seq_no
    return True, "ok"

def log_attack(node_id, attack_type, detail):
    try:
        conn = get_pg()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO security_log (node_id, attack_type, detail, blocked) VALUES (%s, %s, %s, TRUE)",
            (node_id, attack_type, detail)
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"[SECURITY] {attack_type} from {node_id}: {detail}")
    except Exception as e:
        print(f"[SECURITY LOG ERROR] {e}")


def verify_gcm_packet(
    node_id,
    ciphertext_hex,
    nonce_hex,
    tag_hex,
    seq_no,
):
    """
    Verify AES-256-GCM packet from node.
    Checks: key exists, tag valid, no replay.
    Returns (success, reason, payload).
    """
    last_seq = seen_sequences.get(node_id, -1)
    if seq_no <= last_seq:
        log_attack(
            node_id,
            "replay_attack",
            f"seq_no {seq_no} already seen, last was {last_seq}",
        )
        return False, "replay_attack", None

    payload = decrypt_gcm(node_id, ciphertext_hex, nonce_hex, tag_hex)
    if payload is None:
        return False, "gcm_tag_failure", None

    seen_sequences[node_id] = seq_no
    return True, "ok", payload
