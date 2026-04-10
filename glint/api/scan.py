from flask import Blueprint, jsonify, current_app
from glint.db.repository import ScanRepository

bp = Blueprint("scan", __name__, url_prefix="/api")


@bp.route("/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    cfg  = current_app.config["GLINT_CONFIG"]
    repo = ScanRepository(cfg.DATABASE_PATH)
    scan = repo.get(scan_id)

    if scan is None:
        return jsonify({"error": "scan not found"}), 404

    payload = dict(scan.result_json)
    payload["raw_payload"] = scan.raw_payload
    return jsonify(payload), 200


@bp.route("/scans", methods=["GET"])
def list_scans():
    cfg   = current_app.config["GLINT_CONFIG"]
    repo  = ScanRepository(cfg.DATABASE_PATH)
    scans = repo.list_all()

    return jsonify([
        {
            "scan_id":         s.id,
            "created_at":      s.created_at,
            "ip_address":      s.ip_address,
            "composite_score": s.composite_score,
            "risk_level":      s.risk_level,
        }
        for s in scans
    ]), 200
