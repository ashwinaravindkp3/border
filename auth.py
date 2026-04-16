import jwt
import os
from functools import wraps
from flask import request, jsonify, g
from dotenv import load_dotenv

load_dotenv()
_SECRET = os.getenv("FLASK_SECRET_KEY")

if not _SECRET:
    raise RuntimeError(
        "FLASK_SECRET_KEY not set in environment. "
        "Server cannot start without a signing key."
    )


def _decode(token: str) -> dict:
    return jwt.decode(token, _SECRET, algorithms=["HS256"])


def jwt_required(f):
    """Verify Bearer JWT; on success sets g.user = {username, role}."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        try:
            payload = _decode(auth.split(" ", 1)[1])
            g.user = {"username": payload["sub"], "role": payload["role"]}
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def jwt_role_required(role: str):
    """Verify Bearer JWT and require a specific role."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "unauthorized"}), 401
            try:
                payload = _decode(auth.split(" ", 1)[1])
                g.user = {"username": payload["sub"], "role": payload["role"]}
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                return jsonify({"error": "unauthorized"}), 401
            if g.user["role"] != role:
                return jsonify({"error": "forbidden"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
