import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.database import get_pg

# In-memory key cache
# {node_id: bytes(32)}
_key_cache = {}
_cache_loaded = False


def load_key_cache():
    """Load all AES keys from DB into memory on startup."""
    global _cache_loaded
    conn = get_pg()
    cur = conn.cursor()
    cur.execute(
        "SELECT node_id, aes_key "
        "FROM nodes WHERE aes_key IS NOT NULL"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    for node_id, hex_key in rows:
        _key_cache[node_id] = bytes.fromhex(hex_key)
    _cache_loaded = True
    print(f"[CRYPTO] Loaded {len(_key_cache)} AES-256 keys")


def get_node_key(node_id: str) -> bytes | None:
    """Get AES key for node. Returns None if unknown node."""
    if not _cache_loaded:
        load_key_cache()
    return _key_cache.get(node_id)


def decrypt_gcm(
    node_id: str,
    ciphertext_hex: str,
    nonce_hex: str,
    tag_hex: str,
) -> dict | None:
    """
    Decrypt AES-256-GCM payload from node.
    Returns parsed dict or None on failure.
    """
    from app.security import log_attack

    key = get_node_key(node_id)
    if not key:
        log_attack(node_id, "unknown_node", "No AES key found for node")
        return None
    try:
        aesgcm = AESGCM(key)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        tag = bytes.fromhex(tag_hex)
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
        return json.loads(plaintext.decode())
    except Exception as e:
        log_attack(
            node_id,
            "gcm_tag_failure",
            f"GCM decryption failed: {str(e)[:50]}",
        )
        return None


def verify_gcm_tag(
    node_id: str,
    ciphertext_hex: str,
    nonce_hex: str,
    tag_hex: str,
) -> bool:
    """Verify GCM tag only."""
    result = decrypt_gcm(node_id, ciphertext_hex, nonce_hex, tag_hex)
    return result is not None


def encrypt_gcm_for_node(node_id: str, data: dict) -> dict | None:
    """
    Encrypt data for sending to a node.
    Returns {nonce, ciphertext, tag} as hex.
    """
    key = get_node_key(node_id)
    if not key:
        return None
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(
        data,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }
