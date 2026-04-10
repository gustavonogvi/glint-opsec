import uuid
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app
from glint.engine.risk import run as run_risk
from glint.db.repository import ScanRepository

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

    scan_id    = str(uuid.uuid4())
    remote_ip  = _remote_ip()
    user_agent = request.headers.get("User-Agent", "unknown")
    created_at = datetime.now(timezone.utc).isoformat()

    cfg             = current_app.config["GLINT_CONFIG"]
    request_headers = dict(request.headers)
    result          = run_risk(
        scan_id,
        payload,
        remote_ip,
        request_headers,
        cfg.CLEAN_RESOLVERS,
        cfg.RISK_WEIGHTS,
    )

    repo = ScanRepository(cfg.DATABASE_PATH)
    repo.save(
        scan_id=scan_id,
        created_at=created_at,
        ip_address=remote_ip,
        user_agent=user_agent,
        composite_score=result.composite_score,
        risk_level=result.risk_level,
        raw_payload=payload,
        result=result.to_dict(),
    )

    return jsonify(result.to_dict()), 200
