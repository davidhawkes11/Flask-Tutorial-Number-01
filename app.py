import os
import logging
import secrets
from datetime import timedelta
from flask import Flask, jsonify, Blueprint, request
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

"""
Secure Flask application factory (app.py)

- Requires: flask, flask-wtf, flask-talisman, flask-limiter (optional but recommended)
- Configure via environment variables:
    SECRET_KEY (recommended)
    FLASK_ENV (optional)
    SESSION_COOKIE_SECURE (optional; default True)
    CSP_REPORT_URI (optional)
"""



# Optional security extensions
try:
    except Exception:
    CSRFProtect = None

try:
    except Exception:
    Talisman = None

try:
    except Exception:
    Limiter = None
    get_remote_address = None


def create_app():
    # Basic app and configuration
    app = Flask(__name__, static_folder="static", static_url_path="/static")

    # Security-sensitive config from environment (with sensible defaults)
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        # Fallback to ephemeral key (not suitable for production). Log the risk.
        secret_key = secrets.token_urlsafe(32)
        app.logger.warning(
            "SECRET_KEY not set in environment; using ephemeral key. "
            "This is insecure for production."
        )
    app.config["SECRET_KEY"] = secret_key

    # Session cookie hardening
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    # Default to secure cookies in non-dev environments; allow override for dev/testing
    default_secure = os.environ.get("SESSION_COOKIE_SECURE")
    if default_secure is None:
        app.config["SESSION_COOKIE_SECURE"] = True
    else:
        app.config["SESSION_COOKIE_SECURE"] = default_secure.lower() in ("1", "true", "yes")

    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)

    # If app runs behind a proxy (common in containers), honor X-Forwarded headers
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    # Configure logging (structured enough for container environments)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s"
        )
    )
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(handler)

    # HTTP security headers via Flask-Talisman (if installed)
    csp = {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "img-src": ["'self' data:"],
    }
    talisman_kwargs = {
        "content_security_policy": csp,
        "content_security_policy_nonce_in": ["script-src"],
        "frame_options": "DENY",
        "force_https": True,
        "strict_transport_security": True,
        "strict_transport_security_max_age": 31536000,  # 1 year
        "strict_transport_security_include_subdomains": True,
    }
    # Allow an optional report URI via env
    report_uri = os.environ.get("CSP_REPORT_URI")
    if report_uri:
        csp["report-uri"] = report_uri

    if Talisman is not None:
        Talisman(app, **talisman_kwargs)
    else:
        app.logger.warning("flask-talisman not installed; security headers not enforced by Talisman.")

    # CSRF protection
    if CSRFProtect is not None:
        csrf = CSRFProtect()
        csrf.init_app(app)
    else:
        app.logger.warning("flask-wtf (CSRFProtect) not installed; CSRF protection disabled.")

    # Rate limiting (best-effort)
    if Limiter is not None and get_remote_address is not None:
        limiter = Limiter(
            app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"],
            storage_uri="memory://",
        )
    else:
        app.logger.info("flask-limiter not installed; rate limiting disabled.")

    # Simple blueprint for main routes
    bp = Blueprint("main", __name__)

    @bp.route("/", methods=["GET"])
    def index():
        # Minimal safe endpoint
        return jsonify({"message": "Welcome to the secure Flask app"}), 200

    @bp.route("/healthz", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    @bp.route("/echo", methods=["POST"])
    def echo():
        # Echo only JSON input to avoid XSS/injection; do not render raw input into HTML
        data = request.get_json(silent=True)
        if data is None:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        # Implement any input validation here as needed
        return jsonify({"received": data}), 200

    app.register_blueprint(bp)

    # Generic JSON error handlers (avoid leaking internals)
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Internal server error")
        return jsonify({"error": "Internal server error"}), 500

    return app


# Allow running with `python app.py` for local development (not for production)
if __name__ == "__main__":
    app = create_app()
    # Use port and debug from environment for convenience
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "").lower() == "development"
    # In development you may want to allow insecure cookies; ensure env overrides used above.
    app.run(host="0.0.0.0", port=port, debug=debug)