"""Etibarlı şəxsin API-si: dəvətlər, seyflərin vəziyyəti, açılma tələbi, hissələrin ötürülməsi.

Etibarlı şəxs sahibin son aktivlik vaxtını, seyfin ölçüsünü və ya məzmununu
GÖRMÜR — yalnız vəziyyəti (active/awaiting/…), həddi və təsdiq sayını.
Açılmadan əvvəl hissəsini də ala bilməz: hissə yalnız RELEASED-də verilir.
"""
from __future__ import annotations

import json

from flask import Blueprint, g, jsonify, request

from .. import audit, notify
from ..crypto import primitives as P
from ..security import ApiError, client_ip, ctx, defer, deferred_event, now, rate_limit, require_auth
from ..services import (accepted_trustees, approvals_count, evaluate_vault, new_id, release_key_plain,
                        vault_status)
from ..validation import EciesBox, Id, Int, ListOf, Obj, parse

bp = Blueprint("trustee", __name__, url_prefix="/api/trustee")


def _body():
    data = request.get_json(silent=True)
    if data is None:
        raise ApiError(400, "bad_json", "JSON gövdə gözlənilirdi")
    return data


def _membership(conn, vault_id: str):
    """BOLA: istifadəçi bu seyfin QƏBUL ETMİŞ etibarlı şəxsi deyilsə — 404 (varlığı da sızmasın)."""
    row = conn.execute("SELECT t.*, v.owner_id FROM trustees t JOIN vaults v ON v.id=t.vault_id "
                       "WHERE t.vault_id=? AND t.user_id=? AND t.status='accepted'", (vault_id, g.user_id)).fetchone()
    if row is None:
        deferred_event("bola_denied", actor=g.user_id, path=request.path[:120])
        raise ApiError(404, "not_found", "tapılmadı")
    return row


@bp.get("/invitations")
@require_auth()
def invitations():
    c = ctx()
    rows = c.db.all("SELECT t.id, t.status, t.created_at, u.display_name AS owner FROM trustees t "
                    "JOIN vaults v ON v.id=t.vault_id JOIN users u ON u.id=v.owner_id "
                    "WHERE t.user_id=? AND t.status='invited'", (g.user_id,))
    return jsonify({"invitations": [dict(r) for r in rows]})


@bp.post("/invitations/<tid>/<decision>")
@require_auth()
def answer_invitation(tid, decision):
    if decision not in ("accept", "decline"):
        raise ApiError(404, "not_found", "tapılmadı")
    c = ctx()
    with c.db.tx() as conn:
        row = conn.execute("SELECT * FROM trustees WHERE id=? AND user_id=? AND status='invited'",
                           (tid, g.user_id)).fetchone()
        if row is None:
            raise ApiError(404, "not_found", "dəvət tapılmadı")
        status = "accepted" if decision == "accept" else "declined"
        conn.execute("UPDATE trustees SET status=? WHERE id=?", (status, tid))
        audit.record(conn, c.audit_key, ts=now(), actor=g.user_id, action=f"trustee.{status}",
                     vault_id=row["vault_id"], ip=client_ip())
    return jsonify({"status": status})


@bp.get("/vaults")
@require_auth()
def my_vaults():
    c = ctx()
    ids = [r["vault_id"] for r in c.db.all("SELECT vault_id FROM trustees WHERE user_id=? AND status='accepted'",
                                           (g.user_id,))]
    out = []
    for vid in ids:
        evaluate_vault(c, vid)
        with c.db.tx() as conn:
            v = conn.execute("SELECT * FROM vaults WHERE id=?", (vid,)).fetchone()
            if v is None:
                continue
            owner = conn.execute("SELECT display_name FROM users WHERE id=?", (v["owner_id"],)).fetchone()
            mine = conn.execute("SELECT x, fingerprint_verified FROM trustees WHERE vault_id=? AND user_id=?",
                                (vid, g.user_id)).fetchone()
            approved = conn.execute("SELECT 1 FROM approvals WHERE vault_id=? AND trustee_user_id=? AND "
                                    "distribution_version=?", (vid, g.user_id, v["distribution_version"])).fetchone()
            st = vault_status(c, conn, v, now(), for_owner=False)
            st.update({"owner": owner["display_name"], "my_x": mine["x"], "i_approved": bool(approved),
                       "verified_by_owner": bool(mine["fingerprint_verified"])})
            out.append(st)
    return jsonify({"vaults": out})


@bp.post("/vaults/<vid>/approve")
@require_auth()
def approve(vid):
    c = ctx()
    Id("v")(vid, "vault_id")
    rate_limit(f"approve:{g.user_id}", 20, 3600, actor=g.user_id)
    t = now()
    evaluate_vault(c, vid, t)
    with c.db.tx() as conn:
        m = _membership(conn, vid)
        v = conn.execute("SELECT * FROM vaults WHERE id=?", (vid,)).fetchone()
        if m["x"] is None:
            raise ApiError(409, "no_share", "sizə hələ hissə paylanmayıb")
        if v["state"] != "awaiting":
            # Vaxtından əvvəl cəhd: rədd et, sahibə xəbər ver, təhlükəsizlik hadisəsi yaz
            me = conn.execute("SELECT display_name FROM users WHERE id=?", (g.user_id,)).fetchone()
            owner = conn.execute("SELECT email FROM users WHERE id=?", (v["owner_id"],)).fetchone()
            uid, ip, state = g.user_id, client_ip(), v["state"]

            def _record(cn):
                audit.security_event(cn, ts=t, kind="premature_release_attempt", actor=uid, ip=ip, state=state)
                audit.record(cn, c.audit_key, ts=t, actor=uid, action="release.premature_attempt",
                             vault_id=vid, ip=ip, state=state)
                notify.enqueue(cn, owner["email"], "premature_attempt", t, trustee=me["display_name"])
            defer(_record)
            raise ApiError(409, "not_awaiting", "seyf hələ açılma tələbi qəbul etmir", state=v["state"])
        conn.execute("INSERT OR IGNORE INTO approvals(vault_id, trustee_user_id, distribution_version, created_at) "
                     "VALUES(?,?,?,?)", (vid, g.user_id, v["distribution_version"], t))
        audit.record(conn, c.audit_key, ts=t, actor=g.user_id, action="release.approved", vault_id=vid, ip=client_ip())
    state = evaluate_vault(c, vid, t)
    with c.db.tx() as conn:
        v = conn.execute("SELECT * FROM vaults WHERE id=?", (vid,)).fetchone()
        n = approvals_count(conn, v)
    return jsonify({"state": state, "approvals": n, "threshold": v["threshold"], "release_at": v["release_at"]})


@bp.delete("/vaults/<vid>/approve")
@require_auth()
def withdraw(vid):
    c = ctx()
    Id("v")(vid, "vault_id")
    with c.db.tx() as conn:
        _membership(conn, vid)
        v = conn.execute("SELECT state FROM vaults WHERE id=?", (vid,)).fetchone()
        if v["state"] == "released":
            raise ApiError(409, "released", "seyf artıq açılıb")
        conn.execute("DELETE FROM approvals WHERE vault_id=? AND trustee_user_id=?", (vid, g.user_id))
        audit.record(conn, c.audit_key, ts=now(), actor=g.user_id, action="release.approval_withdrawn",
                     vault_id=vid, ip=client_ip())
    return jsonify({"ok": True})


@bp.get("/vaults/<vid>/release")
@require_auth()
def release_material(vid):
    """Yalnız RELEASED: R (KMS-dən), öz şifrəli hissəm, mənə ötürülmüş hissələr, şifrəli seyf."""
    c = ctx()
    Id("v")(vid, "vault_id")
    evaluate_vault(c, vid)
    with c.db.tx() as conn:
        m = _membership(conn, vid)
        v = conn.execute("SELECT * FROM vaults WHERE id=?", (vid,)).fetchone()
        if v["state"] != "released":
            deferred_event("premature_material_request", actor=g.user_id)
            raise ApiError(409, "not_released", "seyf hələ açılmayıb", state=v["state"])
        others = [{"user_id": t["user_id"], "x": t["x"], "public_key": t["u_pub"], "display_name": t["u_name"]}
                  for t in accepted_trustees(conn, vid) if t["user_id"] != g.user_id and t["x"] is not None]
        commitments = {str(t["x"]): t["commitment"] for t in accepted_trustees(conn, vid) if t["x"] is not None}
        handoffs = [{"from_user": h["from_user"], "x": h["x"], "box": json.loads(h["box"])} for h in conn.execute(
            "SELECT * FROM handoffs WHERE vault_id=? AND to_user=?", (vid, g.user_id))]
        owner = conn.execute("SELECT display_name FROM users WHERE id=?", (v["owner_id"],)).fetchone()
        audit.record(conn, c.audit_key, ts=now(), actor=g.user_id, action="release.material_fetched",
                     vault_id=vid, ip=client_ip(), handoffs=len(handoffs))
    R = release_key_plain(c, v)
    return jsonify({
        "vault_id": vid, "owner": owner["display_name"], "threshold": v["threshold"],
        "release_key": P.b64u(R), "wrapped_dek_release": json.loads(v["wrapped_dek_release"]),
        "my_share": {"x": m["x"], "box": json.loads(m["share_box"])}, "commitments": commitments,
        "others": others, "handoffs": handoffs,
        "content": {"version": v["version"], "box": c.storage.get(v["blob_key"]) if v["version"] else None},
    })


HANDOFF = Obj({"to_user": Id("u"), "x": Int(1, 255), "box": EciesBox()})


@bp.post("/vaults/<vid>/handoffs")
@require_auth()
def post_handoffs(vid):
    """Öz hissəmi digər etibarlı şəxslərin açıq açarlarına şifrələyib ötürürəm (server açıq hissəni görmür)."""
    c = ctx()
    Id("v")(vid, "vault_id")
    data = parse(_body(), {"items": ListOf(HANDOFF, 1, 6)})
    t = now()
    with c.db.tx() as conn:
        m = _membership(conn, vid)
        v = conn.execute("SELECT state FROM vaults WHERE id=?", (vid,)).fetchone()
        if v["state"] != "released":
            raise ApiError(409, "not_released", "seyf hələ açılmayıb")
        valid_to = {t_["user_id"] for t_ in accepted_trustees(conn, vid) if t_["user_id"] != g.user_id}
        for it in data["items"]:
            if it["x"] != m["x"]:
                raise ApiError(400, "wrong_x", "yalnız öz hissənizi ötürə bilərsiniz")
            if it["to_user"] not in valid_to:
                raise ApiError(400, "bad_recipient", "alıcı bu seyfin etibarlı şəxsi deyil")
            conn.execute("INSERT INTO handoffs(id, vault_id, from_user, to_user, x, box, created_at) VALUES(?,?,?,?,?,?,?) "
                         "ON CONFLICT(vault_id, from_user, to_user) DO UPDATE SET box=excluded.box, x=excluded.x",
                         (new_id("h"), vid, g.user_id, it["to_user"], it["x"], json.dumps(it["box"]), t))
        audit.record(conn, c.audit_key, ts=t, actor=g.user_id, action="release.share_handed_off", vault_id=vid,
                     ip=client_ip(), recipients=len(data["items"]))
    return jsonify({"ok": True, "count": len(data["items"])})
