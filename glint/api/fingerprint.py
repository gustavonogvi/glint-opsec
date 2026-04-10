import uuid
import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app

bp = Blueprint("fingerprint", __name__, url_prefix="/api")


def _remote_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _validate(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "payload must be a JSON object"
    if "browser" not in payload:
        return "missing field: browser"
    if not isinstance(payload["browser"], dict):
        return "browser must be an object"
    return None


@bp.route("/fingerprint", methods=["POST"])
def receive():
    payload = request.get_json(silent=True)

    error = _validate(payload)
    if error:
        return jsonify({"error": error}), 400

    scan_id   = str(uuid.uuid4())
    remote_ip = _remote_ip()
    user_agent = request.headers.get("User-Agent", "unknown")
    created_at = datetime.now(timezone.utc).isoformat()

    result = {
        "scan_id":         scan_id,
        "composite_score": 0.0,
        "risk_level":      "LOW",
        "dimensions":      [],
        "recommendations": [],
        "server_observed": {
            "remote_ip":     remote_ip,
            "user_agent":    user_agent,
        },
    }

    cfg = current_app.config["GLINT_CONFIG"]

    import sqlite3
    with sqlite3.connect(cfg.DATABASE_PATH) as conn:
        conn.execute(
            """INSERT INTO scans
               (id, created_at, ip_address, user_agent, composite_score, risk_level, raw_payload, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                created_at,
                remote_ip,
                user_agent,
                result["composite_score"],
                result["risk_level"],
                json.dumps(payload),
                json.dumps(result),
            ),
        )

    return jsonify(result), 200
