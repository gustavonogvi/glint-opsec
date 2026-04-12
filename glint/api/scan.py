from flask import Blueprint, jsonify, current_app, Response
from glint.db.repository import ScanRepository
from glint.export import generate

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


@bp.route("/scan/<scan_id>/export", methods=["GET"])
def export_scan(scan_id: str):
    cfg  = current_app.config["GLINT_CONFIG"]
    repo = ScanRepository(cfg.DATABASE_PATH)
    scan = repo.get(scan_id)

    if scan is None:
        return jsonify({"error": "scan not found"}), 404

    report   = generate(scan.id, scan.created_at, scan.ip_address,
                        scan.user_agent, scan.raw_payload, scan.result_json)
    filename = f"glint_{scan.id[:8]}.txt"

    return Response(
        report.encode("utf-8"),
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


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
