"""Əməliyyat əmrləri.

    python -m emanet.cli tick                    # planlaşdırıcının bir addımı (cron/systemd timer)
    python -m emanet.cli grant-role EMAIL ROLE   # ilk operator/auditoru təyin etmək
    python -m emanet.cli verify-audit            # audit zəncirinin bütövlüyü
    python -m emanet.cli rotate-kms              # LocalKMS: yeni açar versiyası + bütün R-lərin yenidən sarınması
    python -m emanet.cli integrity               # brauzer kodunun SHA-256 manifesti
    python -m emanet.cli pause-all 7             # uzun fasilədən sonra bütün seyflərə pauza (BCP RB-05)
"""
from __future__ import annotations

import argparse
import json
import sys

from .app import create_app
from .audit import record, verify
from .kms import LocalKMS, release_context


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="emanet")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("tick")
    g = sub.add_parser("grant-role")
    g.add_argument("email")
    g.add_argument("role", choices=["user", "operator", "auditor"])
    sub.add_parser("verify-audit")
    sub.add_parser("rotate-kms")
    sub.add_parser("integrity")
    pa = sub.add_parser("pause-all", help="Xidmət uzun müddət dayananda bütün seyflərə pauza (RB-05)")
    pa.add_argument("days", type=int)
    args = ap.parse_args(argv)

    app = create_app()
    c = app.extensions["emanet"]

    if args.cmd == "tick":
        from .services import tick
        print(json.dumps(tick(c), ensure_ascii=False))
    elif args.cmd == "grant-role":
        with c.db.tx() as conn:
            n = conn.execute("UPDATE users SET role=? WHERE email=?", (args.role, args.email.lower())).rowcount
            if n:
                record(conn, c.audit_key, ts=c.clock.now(), actor="cli", action="admin.role_changed",
                       target=args.email.lower(), new=args.role)
        print("ok" if n else "istifadəçi tapılmadı")
        return 0 if n else 1
    elif args.cmd == "verify-audit":
        res = verify(c.db, c.audit_key)
        print(json.dumps(res, ensure_ascii=False))
        return 0 if res["intact"] else 2
    elif args.cmd == "rotate-kms":
        if not isinstance(c.kms, LocalKMS):
            print("AWS KMS illik avtomatik rotasiya edir (enable_key_rotation = true)")
            return 0
        new = c.kms.rotate()
        n = 0
        with c.db.tx() as conn:
            for v in conn.execute("SELECT id, release_key_ct FROM vaults").fetchall():
                conn.execute("UPDATE vaults SET release_key_ct=? WHERE id=?",
                             (c.kms.rewrap(v["release_key_ct"], release_context(v["id"])), v["id"]))
                n += 1
            record(conn, c.audit_key, ts=c.clock.now(), actor="cli", action="kms.rotated", version=new, rewrapped=n)
        print(json.dumps({"new_version": new, "rewrapped": n}))
    elif args.cmd == "pause-all":
        if not 1 <= args.days <= 90:
            print("days 1..90 olmalıdır")
            return 1
        until = c.clock.now() + args.days * 86400
        with c.db.tx() as conn:
            n = conn.execute("UPDATE vaults SET paused_until=MAX(COALESCE(paused_until,0), ?) "
                             "WHERE state NOT IN ('setup','released','pending_release')", (until,)).rowcount
            # Gözləmə müddətindəki seyflərin açılma vaxtı da irəli çəkilir: sahib fasilə ərzində etiraz edə bilməzdi
            n += conn.execute("UPDATE vaults SET release_at = release_at + ? WHERE state='pending_release'",
                              (args.days * 86400,)).rowcount
            record(conn, c.audit_key, ts=c.clock.now(), actor="cli", action="ops.pause_all", days=args.days, vaults=n)
        print(json.dumps({"paused": n, "days": args.days}))
    elif args.cmd == "integrity":
        with app.test_request_context():
            from .api.system import integrity
            print(json.dumps(integrity().get_json(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
