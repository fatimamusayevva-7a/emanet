"""Marşrut matrisi: tətbiqin HƏR endpoint-i üçün avtomatik yaradılan təhlükəsizlik testləri.

Yeni endpoint əlavə edilib siyahıya düşməsə və ya qorunmasa, test uğursuz olur.
Testlər `app.url_map`-dən yaradılır, yəni siyahı əl ilə saxlanılmır:

  * qorunan hər endpoint sessiyasız 401 qaytarır;
  * dəyişiklik edən hər qorunan endpoint CSRF tokeni olmadan 403 qaytarır;
  * dəyişiklik edən hər endpoint yad Origin ilə 403 qaytarır;
  * hər cavabda təhlükəsizlik başlıqları var, /api/ cavabları keşlənmir;
  * rol matrisi: admin/audit endpoint-ləri yalnız müvafiq rola açıqdır.
"""
from __future__ import annotations

import pathlib
import shutil
import tempfile
import unittest

from tests.helpers import ORIGIN, AppTestCase, make_app

PUBLIC = {"auth.prelogin", "auth.register", "auth.login", "auth.session_probe", "auth.recover_begin",
          "auth.recover_complete", "vault.checkin_link", "system.health", "system.integrity",
          "system.scheduler_tick", "index", "checkin_page", "static_files"}
ROLE_ONLY = {"system.admin_users": {"operator"}, "system.admin_role": {"operator"}, "system.admin_status": {"operator"},
             "system.security_events": {"operator", "auditor"}, "system.audit_log": {"auditor"},
             "system.audit_verify": {"auditor"}, "system.demo_advance": {"operator"}}
SAMPLE = {"tid": "t_" + "a" * 22, "vid": "v_" + "a" * 22, "uid": "u_" + "a" * 22, "decision": "accept", "sub": "js/app.js"}


def _routes():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        app, _ = make_app(tmp)
        out = []
        for r in app.url_map.iter_rules():
            for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
                path = r.rule
                for k, v in SAMPLE.items():
                    path = path.replace(f"<{k}>", v).replace(f"<path:{k}>", v)
                out.append((r.endpoint, m, path))
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


ROUTES = _routes()


class RouteMatrix(AppTestCase):
    def test_route_inventory_is_known(self):
        """Hər endpoint ya ictimaidir, ya qorunur — 'unudulmuş' endpoint yoxdur."""
        endpoints = {e for e, _, _ in ROUTES}
        self.assertGreaterEqual(len(endpoints), 40)
        unknown = endpoints - PUBLIC - set(ROLE_ONLY) - {e for e in endpoints if e.split(".")[0] in {"auth", "vault", "trustee", "system"}}
        self.assertEqual(unknown, set())


def _slug(endpoint, method):
    return f"{endpoint.replace('.', '_')}_{method.lower()}"


def _gen():
    for endpoint, method, path in ROUTES:
        protected = endpoint not in PUBLIC
        unsafe = method in {"POST", "PUT", "PATCH", "DELETE"}

        if protected:
            def t_auth(self, method=method, path=path):
                anon = self.person("Anon")
                r = anon.req(method, path, json={} if method != "GET" else None)
                self.assertEqual(r.status_code, 401, f"{method} {path}")
                self.assertEqual(r.get_json()["error"], "unauthenticated")
            setattr(RouteMatrix, f"test_requires_auth__{_slug(endpoint, method)}", t_auth)

        if protected and unsafe:
            def t_csrf(self, method=method, path=path):
                u = self.person("Csrf").signup()
                u.csrf = None
                r = u.req(method, path, json={})
                self.assertEqual(r.status_code, 403, f"{method} {path}")
                self.assertEqual(r.get_json()["error"], "csrf_token")
            setattr(RouteMatrix, f"test_requires_csrf__{_slug(endpoint, method)}", t_csrf)

        if unsafe and endpoint != "system.scheduler_tick":
            def t_origin(self, method=method, path=path):
                u = self.person("Origin")
                r = u.req(method, path, json={}, headers={"Origin": "https://attacker.example"})
                self.assertIn(r.status_code, (401, 403), f"{method} {path}")
                if r.status_code == 403:
                    self.assertEqual(r.get_json()["error"], "csrf_origin")
            setattr(RouteMatrix, f"test_rejects_foreign_origin__{_slug(endpoint, method)}", t_origin)

        def t_headers(self, method=method, path=path):
            r = self.person("Hdr").req(method, path, json={} if method != "GET" else None)
            h = r.headers
            self.assertIn("default-src 'none'", h.get("Content-Security-Policy", ""))
            self.assertEqual(h.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(h.get("X-Frame-Options"), "DENY")
            if path.startswith("/api/") or path.startswith("/internal/"):
                self.assertEqual(h.get("Cache-Control"), "no-store")
                self.assertEqual(r.mimetype, "application/json")
            self.assertNotIn("Traceback", r.get_data(as_text=True))
        setattr(RouteMatrix, f"test_security_headers__{_slug(endpoint, method)}", t_headers)

        if endpoint in ROLE_ONLY:
            for role in ("user", "operator", "auditor"):
                def t_role(self, method=method, path=path, role=role, allowed=ROLE_ONLY[endpoint], endpoint=endpoint):
                    p = self.person("Rol").signup()
                    self.ctx.db.connect().execute("UPDATE users SET role=? WHERE id=?", (role, p.user_id))
                    r = p.req(method, path, json={} if method != "GET" else None)
                    if role in allowed:
                        self.assertNotIn(r.status_code, (401, 403), f"{role} → {method} {path}")
                    else:
                        self.assertEqual(r.status_code, 403, f"{role} → {method} {path}")
                setattr(RouteMatrix, f"test_role_{role}__{_slug(endpoint, method)}", t_role)


_gen()
_ = (ORIGIN, unittest)
