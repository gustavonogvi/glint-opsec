import sqlite3
from pathlib import Path
from flask import Flask
from .config import Config
from .db.migrations import create_tables

_ROOT = Path(__file__).parent.parent


def create_app(config: Config | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(_ROOT / "templates"),
        static_folder=str(_ROOT / "static"),
    )

    cfg = config or Config()
    app.secret_key = cfg.SECRET_KEY
    app.config["GLINT_CONFIG"] = cfg

    # Initialize database on startup
    with sqlite3.connect(cfg.DATABASE_PATH) as conn:
        create_tables(conn)

    from .api.fingerprint import bp as fingerprint_bp
    app.register_blueprint(fingerprint_bp)

    @app.route("/")
    def index():
        from flask import render_template
        return render_template("index.html")

    return app


def main() -> None:
    import os
    app = create_app()
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host="127.0.0.1", port=5000)


if __name__ == "__main__":
    main()
