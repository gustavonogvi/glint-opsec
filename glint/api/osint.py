from flask import Blueprint, request, jsonify, current_app
from glint.collectors.hibp import check_email

bp = Blueprint("osint", __name__, url_prefix="/api")


@bp.route("/osint", methods=["POST"])
def osint():
    payload = request.get_json(silent=True)

    if not payload or "email" not in payload:
        return jsonify({"error": "missing field: email"}), 400

    email = payload.get("email", "")
    if not isinstance(email, str) or "@" not in email or len(email) > 254:
        return jsonify({"error": "invalid email"}), 400

    cfg    = current_app.config["GLINT_CONFIG"]
    result = check_email(email, cfg.HIBP_API_KEY)

    return jsonify({
        "checked":      result.checked,
        "breach_count": result.breach_count,
        "breaches":     result.breaches,
        "available":    result.available,
        "error":        result.error,
    }), 200
