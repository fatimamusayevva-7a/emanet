"""Flask tətbiq fabriki."""
from __future__ import annotations

import json
import logging
import pathlib
import secrets
import sys

from flask import Flask, g, request, send_from_directory
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from .api import auth as auth_api
from .api import system as system_api
from .api import trustee as trustee_api
from .api import vault as vault_api
from .clock import OffsetClock, SystemClock
from .config import Settings, load_settings
from .db import Database
from .kms import build_kms
from .notify import build_notifier
from .security import ApiError, apply_security_headers, json_error
from .services import Emanet
from .storage import build_storage
from .validation import ValidationError

WEB = pathlib.Path(__file__).resolve().parents[1] / "web"


class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({"level": record.levelname, "logger": record.name, "msg": record.getMessage(),
                           "request_id": getattr(g, "request_id", None) if _has_ctx() else None},
                          ensure_ascii=False)


def _has_ctx() -> bool:
    from flask import has_request_context
    return has_request_context()


def create_app(settings: Settings | None = None, *, clock=None, kms=None, storage=None, notifier=None) -> Flask:
    settings = settings or load_settings()
    db = Database(settings.data_dir / "emanet.db")
    if clock is None:
        clock = OffsetClock(db) if settings.demo_mode else SystemClock()
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes
    app.config["JSON_AS_ASCII"] = False
    app.json.ensure_ascii = False
    app.extensions["emanet"] = Emanet(settings=settings, db=db, kms=kms or build_kms(settings),
                                      storage=storage or build_storage(settings),
                                      notifier=notifier or build_notifier(settings), clock=clock)

    if not logging.getLogger("emanet").handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(JsonFormatter())
        logging.getLogger("emanet").addHandler(h)
        logging.getLogger("emanet").setLevel(logging.INFO if settings.env != "test" else logging.ERROR)

    for bp in (auth_api.bp, vault_api.bp, trustee_api.bp, system_api.bp):
        app.register_blueprint(bp)

    @app.before_request
    def _rid():
        g.request_id = secrets.token_hex(8)
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.path.startswith("/api/") \
                and request.content_length and not request.is_json:
            raise ApiError(415, "unsupported_media_type", "yalnız application/json qəbul olunur")

    @app.teardown_request
    def _flush(exc):
        from .security import flush_deferred
        flush_deferred()

    @app.after_request
    def _headers(resp):
        resp.headers["X-Request-ID"] = g.get("request_id", "")
        return apply_security_headers(resp)

    @app.errorhandler(ApiError)
    def _api_error(e):
        return json_error(e)

    @app.errorhandler(ValidationError)
    def _validation(e):
        if e.unknown:
            from . import audit
            from .security import client_ip, ctx, now
            with ctx().db.tx() as conn:
                audit.security_event(conn, ts=now(), kind="mass_assignment_attempt", actor=g.get("user_id"),
                                     ip=client_ip(), fields=",".join(e.unknown)[:200])
        return json_error(ApiError(400, "validation", str(e), field=e.field))

    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(e):
        return json_error(ApiError(413, "too_large", "sorğu çox böyükdür"))

    @app.errorhandler(HTTPException)
    def _http(e):
        return json_error(ApiError(e.code or 500, "http_error", e.name))

    @app.errorhandler(Exception)
    def _unhandled(e):
        # Daxili xəta detalları (stack trace, SQL) müştəriyə göstərilmir — yalnız sorğu id-si
        logging.getLogger("emanet").exception("unhandled error")
        return json_error(ApiError(500, "internal", "daxili xəta", request_id=g.get("request_id")))

    # ------------------------------------------------------------- statik fayllar
    @app.get("/")
    def index():
        return send_from_directory(WEB, "index.html")

    @app.get("/checkin.html")
    def checkin_page():
        return send_from_directory(WEB, "checkin.html")

    @app.get("/<path:sub>")
    def static_files(sub):
        if not (sub.startswith("js/") or sub.startswith("css/") or sub in ("favicon.svg", "manifest.webmanifest")):
            return json_error(ApiError(404, "not_found", "tapılmadı"))
        resp = send_from_directory(WEB, sub)
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    return app


def main() -> None:
    import os
    app = create_app()
    app.run(host=os.environ.get("EMANET_HOST", "127.0.0.1"), port=int(os.environ.get("EMANET_PORT", "8000")),
            threaded=True)


if __name__ == "__main__":
    main()


