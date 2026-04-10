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
    from .api.osint import bp as osint_bp
    from .api.scan import bp as scan_bp
    app.register_blueprint(fingerprint_bp)
    app.register_blueprint(osint_bp)
    app.register_blueprint(scan_bp)

    @app.route("/")
    def index():
        from flask import render_template
        return render_template("index.html")

    @app.route("/results/<scan_id>")
    def results(scan_id: str):
        from flask import render_template
        return render_template("results.html", scan_id=scan_id)

    @app.route("/history")
    def history():
        from flask import render_template
        return render_template("history.html")

    return app


def _free_port(port: int) -> None:
    import os
    import socket
    import subprocess
    import sys

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex(("127.0.0.1", port)) != 0:
            return

    if sys.platform == "win32":
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if f":{port} " in line and "LISTENING" in line:
                parts = line.split()
                pid = parts[-1]
                if pid.isdigit() and int(pid) != os.getpid():
                    subprocess.run(
                        ["taskkill", "/F", "/PID", pid], capture_output=True
                    )
                    print(f" * killed existing process on :{port} (PID {pid})")
    else:
        result = subprocess.run(
            ["lsof", "-ti", f":{port}"], capture_output=True, text=True
        )
        for pid_str in result.stdout.strip().splitlines():
            if pid_str.isdigit() and int(pid_str) != os.getpid():
                os.kill(int(pid_str), 9)
                print(f" * killed existing process on :{port} (PID {pid_str})")


def main() -> None:
    import os
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    _free_port(port)
    app = create_app()
    app.run(debug=debug, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
