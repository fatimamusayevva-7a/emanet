"""Compliance-as-code: ISO/IEC 27001:2022 nəzarətlərinin avtomatik yoxlanması.

Hər yoxlama konkret Annex A nəzarətinə bağlıdır və SÜBUT qaytarır (fayl, sətir,
dəyər). Nəticə: evidence/compliance-report.json və .md. CI hər commit-də işə salır;
`--strict` rejimində bir uğursuz yoxlama build-i dayandırır.

    python compliance/check_controls.py [--strict]
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import pathlib
import re
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TF = ROOT / "infra" / "terraform" / "aws"
RESULTS: list[dict] = []


def check(cid: str, control: str, title: str):
    def deco(fn):
        def run():
            try:
                ok, evidence = fn()
            except Exception as exc:  # yoxlamanın özü xəta verdisə — FAIL
                ok, evidence = False, f"yoxlama xətası: {type(exc).__name__}: {exc}"
            RESULTS.append({"id": cid, "control": control, "title": title, "status": "PASS" if ok else "FAIL",
                            "evidence": evidence})
        run.__name__ = fn.__name__
        CHECKS.append(run)
        return run
    return deco


CHECKS: list = []


def tf_all() -> str:
    return "\n".join(p.read_text() for p in sorted(TF.glob("*.tf")))


def tf_resource(kind: str, name: str) -> str:
    src = tf_all()
    m = re.search(rf'resource\s+"{kind}"\s+"{name}"\s*\{{', src)
    if not m:
        return ""
    depth, i = 0, m.end() - 1
    for j in range(i, len(src)):
        depth += src[j] == "{"
        depth -= src[j] == "}"
        if depth == 0:
            return src[i:j + 1]
    return ""


# ====================================================================== kriptoqrafiya
@check("C-01", "A.8.24", "PBKDF2 iterasiyası ≥ 600 000 və brauzer ilə server eynidir")
def c01():
    from emanet.crypto.primitives import PBKDF2_ITERATIONS
    js = re.search(r"PBKDF2_ITERATIONS\s*=\s*(\d+)", (ROOT / "web/js/crypto.js").read_text())
    jsv = int(js.group(1)) if js else 0
    return PBKDF2_ITERATIONS >= 600_000 and jsv == PBKDF2_ITERATIONS, f"python={PBKDF2_ITERATIONS}, js={jsv}"


@check("C-02", "A.8.24", "Argon2id parametrləri OWASP minimumundan aşağı deyil (m≥19 MiB, t≥2)")
def c02():
    from emanet.crypto.passwords import DEFAULT_PARAMS as p
    return p.memory_kib >= 19456 and p.iterations >= 2, f"m={p.memory_kib} KiB, t={p.iterations}, p={p.lanes}"


@check("C-03", "A.8.24", "Qadağan olunmuş alqoritmlər/rejimlər istifadə olunmur (MD5, ECB, DES, RC4, Math.random)")
def c03():
    bad = []
    pats = [r"\bmd5\b", r"\bMODE_ECB\b|modes\.ECB", r"\bDES3?\b", r"\bRC4\b|ARC4", r"Math\.random"]
    for p in list((ROOT / "emanet").rglob("*.py")) + list((ROOT / "web/js").glob("*.js")):
        src = re.sub(r"(#|//)[^\n]*", "", p.read_text())
        for pat in pats:
            if re.search(pat, src, re.I):
                bad.append(f"{p.relative_to(ROOT)}: {pat}")
    return not bad, "tapılmadı" if not bad else "; ".join(bad)


@check("C-04", "A.8.24", "Bütün AES-GCM çağırışları AAD ilə aparılır (seal/open_sealed boş AAD-ı qəbul etmir)")
def c04():
    src = (ROOT / "web/js/crypto.js").read_text() + (ROOT / "emanet/crypto/primitives.py").read_text()
    calls = re.findall(r"\bseal\([^)]*\)", src)
    empty = [c for c in calls if re.search(r',\s*(""|\'\')\s*\)', c)]
    return not empty and len(calls) > 3, f"{len(calls)} seal çağırışı, boş AAD: {len(empty)}"


@check("C-05", "A.8.24", "Kriptoqrafik uyğunluq vektorları mövcuddur (Python ↔ JS)")
def c05():
    v = json.loads((ROOT / "tests/js/vectors.json").read_text())
    need = {"shamir", "kdf", "release_kek", "ecies", "seal", "pad", "recovery", "commitment"}
    return need <= set(v), f"vektor bölmələri: {sorted(v)}"


# ====================================================================== tətbiq
@check("C-06", "A.8.26", "CSP ciddidir: script-src 'self', unsafe-inline yoxdur, Trusted Types məcburidir")
def c06():
    from emanet.security import CSP
    ok = "script-src 'self'" in CSP and "unsafe" not in CSP and "require-trusted-types-for 'script'" in CSP \
        and "frame-ancestors 'none'" in CSP
    return ok, CSP


@check("C-07", "A.8.28", "Brauzer kodunda innerHTML/eval/document.write və brauzer yaddaşı yoxdur")
def c07():
    bad = []
    for p in (ROOT / "web/js").glob("*.js"):
        src = re.sub(r"//[^\n]*", "", p.read_text())
        for tok in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                    "localStorage", "sessionStorage", "indexedDB"):
            if tok in src:
                bad.append(f"{p.name}:{tok}")
    return not bad, f"{len(list((ROOT / 'web/js').glob('*.js')))} fayl yoxlanıldı; pozuntu: {bad or 'yoxdur'}"


@check("C-08", "A.8.31", "İstehsal konfiqurasiyası təhlükəli rejimləri rədd edir (demo, HTTP, lokal KMS)")
def c08():
    from emanet.config import ConfigError, load_settings
    secrets = {n: b"x" * 32 for n in ("secret_key", "audit_hmac_key", "scheduler_hmac_key", "local_kms_master_key")}
    base = dict(env="production", public_origin="https://e.az", cookie_secure=True, kms_backend="aws", secrets=secrets)
    rejected = []
    for bad in ({"demo_mode": True}, {"public_origin": "http://e.az"}, {"cookie_secure": False}, {"kms_backend": "local"}):
        try:
            load_settings(**{**base, **bad})
        except ConfigError:
            rejected.append(list(bad)[0])
    return len(rejected) == 4, f"rədd edilən: {rejected}"


def _app_session():
    from tests.helpers import Person, make_app
    tmp = pathlib.Path(tempfile.mkdtemp())
    app, _ = make_app(tmp)
    return app, Person, tmp


@check("C-09", "A.8.5", "Sessiya cookie-si: __Host-, HttpOnly, Secure, SameSite=Strict; DB-də yalnız heş")
def c09():
    app, Person, tmp = _app_session()
    try:
        p = Person(app, "Compliance")
        p.register()
        r = p.login()
        sess = next(c for c in r.headers.getlist("Set-Cookie") if c.startswith("__Host-emanet_session="))
        flags = all(f in sess for f in ("HttpOnly", "Secure", "SameSite=Strict"))
        token = sess.split("=", 1)[1].split(";")[0]
        stored = app.extensions["emanet"].db.one("SELECT token_hash FROM sessions")["token_hash"]
        return flags and token != stored and len(stored) == 64, "bayraqlar ✓, DB-də SHA-256(token)"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("C-10", "A.8.12", "Audit metadata-sında sirr adlı açarlar bloklanır")
def c10():
    from emanet.audit import AuditLeakError, _check_details
    blocked = 0
    for k in ("password", "auth_key", "release_key", "privkey", "dek"):
        try:
            _check_details({k: "x"})
        except AuditLeakError:
            blocked += 1
    return blocked == 5, f"{blocked}/5 qadağan açar bloklandı"


@check("C-11", "A.5.3", "Operatorun açılmanı məcbur edən endpoint-i yoxdur; audit yalnız auditora açıqdır")
def c11():
    src = (ROOT / "emanet/api/system.py").read_text()
    no_force = not re.search(r"@bp\.(post|put)\([^)]*release", src)
    audit_role = re.search(r'@bp\.get\("/api/audit"\)\s*\n@require_auth\("auditor"\)', src) is not None
    return no_force and audit_role, f"force-release endpoint: {'yoxdur' if no_force else 'VAR'}, /api/audit → auditor"


@check("C-12", "A.8.10", "Crypto-shredding: seyf silinəndə R, DEK sarğıları və hissələr məhv edilir")
def c12():
    db = (ROOT / "emanet/db.py").read_text()
    cascades = db.count("REFERENCES vaults(id) ON DELETE CASCADE")
    shred = "def shred_vault" in (ROOT / "emanet/services.py").read_text()
    return shred and cascades >= 3 and "secure_delete=ON" in db, f"shred_vault ✓, CASCADE: {cascades}, secure_delete ✓"


@check("C-13", "A.8.11", "Sxemdə açıq mətn sütunu yoxdur (password, plaintext, dek, share)")
def c13():
    from emanet.db import SCHEMA
    cols = re.findall(r"^\s+(\w+)\s+(?:TEXT|INTEGER|REAL)", SCHEMA, re.M)
    bad = [c for c in cols if c in {"password", "plaintext", "dek", "share", "secret", "release_key", "content"}]
    return not bad, f"{len(cols)} sütun, qadağan: {bad or 'yoxdur'}"


# ====================================================================== bulud (IaC)
@check("C-14", "A.8.20", "Security Group-da SSH (22) və ya bütün portlar açıq deyil")
def c14():
    sg = tf_resource("aws_security_group", "app")
    ports = re.findall(r"ingress\s*\{[^}]*from_port\s*=\s*(\d+)", sg, re.S)
    return sg and set(ports) <= {"80", "443"} and "22" not in ports, f"ingress portları: {ports}"


@check("C-15", "A.8.2", "EC2-də SSH açarı yoxdur, IMDSv2 məcburidir, EBS şifrəlidir")
def c15():
    ec2 = tf_resource("aws_instance", "app")
    ok = 'http_tokens                 = "required"' in ec2 and not re.search(r"^\s*key_name\s*=", ec2, re.M) \
        and "encrypted             = true" in ec2
    return ok, "key_name yoxdur, http_tokens=required, encrypted=true"


@check("C-16", "A.8.24", "Bütün KMS açarlarında avtomatik rotasiya aktivdir")
def c16():
    src = tf_all()
    keys = re.findall(r'resource\s+"aws_kms_key"\s+"(\w+)"', src)
    rot = [k for k in keys if "enable_key_rotation     = true" in tf_resource("aws_kms_key", k)
           or "enable_key_rotation      = true" in tf_resource("aws_kms_key", k)]
    return keys and len(rot) == len(keys), f"açarlar: {keys}, rotasiya: {rot}"


@check("C-17", "A.5.3", "KMS release açarının siyasətində admin-ə kms:Decrypt verilmir; tətbiq yalnız kontekstlə")
def c17():
    k = tf_resource("aws_kms_key", "release")
    admin = re.search(r'Sid\s*=\s*"AccountAdmin".*?Resource', k, re.S).group(0)
    return "kms:Decrypt" not in admin and "kms:*" not in admin and "kms:EncryptionContext:purpose" in k, \
        "AccountAdmin: Decrypt yoxdur; AppUseWithContextOnly: EncryptionContext şərti"


@check("C-18", "A.8.13", "S3: versioning + Object Lock + SSE-KMS + public access block")
def c18():
    src = tf_all()
    ok = all(s in src for s in ('object_lock_enabled = true', 'status = "Enabled"', 'sse_algorithm     = "aws:kms"',
                                "restrict_public_buckets = true", 'mode = "GOVERNANCE"'))
    return ok, "Versioning=Enabled, ObjectLock=GOVERNANCE, SSE=aws:kms, BPA=4/4"


@check("C-19", "A.5.14", "S3 bucket siyasəti TLS olmayan və TLS<1.2 girişləri rədd edir")
def c19():
    pol = tf_resource("aws_s3_bucket_policy", "vaults")
    return '"aws:SecureTransport" = "false"' in pol and '"s3:TlsVersion" = "1.2"' in pol, "DenyInsecureTransport + DenyOldTLS"


@check("C-20", "A.8.15", "CloudTrail: multi-region, log file validation, KMS şifrələmə")
def c20():
    t = tf_resource("aws_cloudtrail", "main")
    return all(s in t for s in ("is_multi_region_trail         = true", "enable_log_file_validation    = true",
                                "kms_key_id")), "multi-region ✓, validation ✓, KMS ✓"


@check("C-21", "A.8.16", "Monitorinq: təhlükəsizlik metric filter-ləri, planlaşdırıcı və KMS alarmları")
def c21():
    src = tf_all()
    filters = re.findall(r"^\s{4}(\w+)\s*=\s*\{ pattern", src, re.M)
    tick = all(f'"{n}"' in src for n in ("tick_errors", "tick_missing")) or ("tick_errors" in src and "tick_missing" in src)
    kms = "kms_danger" in src
    return len(filters) >= 8 and tick and kms, f"{len(filters)} metric filter, tick alarmları ✓, KMS EventBridge ✓"


@check("C-22", "A.5.17", "Repozitoriyada sirr yoxdur (AWS açarı, PEM şəxsi açar, .env)")
def c22():
    bad = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or any(x in p.parts for x in (".git", "data", "__pycache__", "node_modules", "evidence")):
            continue
        if p.suffix in {".png", ".zip", ".pdf"}:
            continue
        try:
            s = p.read_text(errors="ignore")
        except OSError:
            continue
        if re.search(r"AKIA[0-9A-Z]{16}", s) or "-----BEGIN" + " PRIVATE KEY" in s:
            bad.append(str(p.relative_to(ROOT)))
    env = (ROOT / ".env").exists()
    return not bad and not env, f"pozuntu: {bad or 'yoxdur'}, .env: {'VAR' if env else 'yoxdur'}"


@check("C-23", "A.5.21", "Əsas asılılıqlar dəqiq versiya ilə bərkidilib")
def c23():
    lines = [l.strip() for l in (ROOT / "requirements.txt").read_text().splitlines() if l.strip() and not l.startswith("#")]
    core = [l for l in lines if l.split("=")[0].split(">")[0].lower() in {"flask", "werkzeug", "cryptography", "gunicorn"}]
    return all("==" in l for l in core) and len(core) == 4, "; ".join(core)


# ====================================================================== İTİS sənədləri
def soa_rows():
    return list(csv.DictReader(open(ROOT / "isms/05-statement-of-applicability.csv", encoding="utf-8")))


@check("C-24", "6.1.3 d", "SoA bütün 93 Annex A nəzarətini əhatə edir, hər birinin əsaslandırması var")
def c24():
    rows = soa_rows()
    ids = [r["control"] for r in rows]
    expected = [f"5.{i}" for i in range(1, 38)] + [f"6.{i}" for i in range(1, 9)] + \
        [f"7.{i}" for i in range(1, 15)] + [f"8.{i}" for i in range(1, 35)]
    just = all(len(r["justification_and_implementation"]) > 20 for r in rows)
    app = sum(r["applicable"] == "Y" for r in rows)
    return ids == expected and just, f"{len(ids)} nəzarət (tətbiq olunan {app}, istisna {len(ids) - app})"


@check("C-25", "7.5", "SoA-dakı bütün sübut faylları mövcuddur")
def c25():
    missing = set()
    for r in soa_rows():
        for p in r["evidence"].split(";"):
            p = p.strip().split("::")[0]
            if p and not (ROOT / p).exists():
                missing.add(p)
    return not missing, f"çatışmayan: {sorted(missing) or 'yoxdur'}"


def risks():
    return list(csv.DictReader(open(ROOT / "isms/04-risk-register.csv", encoding="utf-8")))


@check("C-26", "6.1.2", "Risk reyestri: bal = L×I, qalıq ≤ inherent, qalıq ≤ iştah (8), sahib və müalicə var")
def c26():
    errs = []
    for r in risks():
        L, I, inh = int(r["L"]), int(r["I"]), int(r["inherent"])
        rl, ri, res = int(r["res_L"]), int(r["res_I"]), int(r["residual"])
        if L * I != inh or rl * ri != res:
            errs.append(f"{r['id']}: hesab")
        if res > inh:
            errs.append(f"{r['id']}: qalıq > ilkin")
        if res > 8:
            errs.append(f"{r['id']}: iştahdan yuxarı ({res})")
        if not r["owner"] or r["treatment"] not in {"Azaltmaq", "Qəbul etmək", "Ötürmək", "Qaçmaq"}:
            errs.append(f"{r['id']}: sahib/müalicə")
    rs = risks()
    before = sum(int(r["inherent"]) for r in rs)
    after = sum(int(r["residual"]) for r in rs)
    return not errs, f"{len(rs)} risk; cəmi bal {before} → {after} (−{100 - round(100 * after / before)}%); xəta: {errs or 'yoxdur'}"


@check("C-27", "6.1.3", "Risklərdəki nəzarətlər SoA-da 'tətbiq olunur' kimi qeyd olunub")
def c27():
    app = {r["control"] for r in soa_rows() if r["applicable"] == "Y"}
    bad = [f"{r['id']}:{c}" for r in risks() for c in r["controls"].split(";") if c.strip() not in app]
    return not bad, f"uyğunsuzluq: {bad or 'yoxdur'}"


@check("C-28", "6.1.2", "Risklərin aktivləri aktiv reyestrində var")
def c28():
    assets = {r["id"] for r in csv.DictReader(open(ROOT / "isms/02-asset-register.csv", encoding="utf-8"))}
    bad = [f"{r['id']}:{a}" for r in risks() for a in r["assets"].split(";") if a.strip() not in assets]
    return not bad, f"{len(assets)} aktiv; uyğunsuzluq: {bad or 'yoxdur'}"


@check("C-29", "9.1", "Risk reyestrində istinad edilən testlər həqiqətən mövcuddur")
def c29():
    alltests = "\n".join(p.read_text() for p in (ROOT / "tests").rglob("*.py"))
    refs = re.findall(r"tests/[\w/]+\.py::(\w+)", "\n".join(r["implementation"] for r in risks()))
    missing = [t for t in refs if not re.search(rf"(def|class) {t}\b", alltests)]
    return refs and not missing, f"{len(refs)} istinad, çatışmayan: {missing or 'yoxdur'}"


@check("C-30", "5.1", "Mövzu siyasətləri mövcuddur və əsas siyasətdən istinad olunur")
def c30():
    main = (ROOT / "isms/policies/information-security-policy.md").read_text()
    pols = [p.name for p in (ROOT / "isms/policies").glob("*.md") if p.name != "information-security-policy.md"]
    unlinked = [p for p in pols if p not in main]
    return len(pols) >= 8 and not unlinked, f"{len(pols)} siyasət; istinadsız: {unlinked or 'yoxdur'}"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    strict = "--strict" in sys.argv
    for c in CHECKS:
        c()
    passed = sum(r["status"] == "PASS" for r in RESULTS)
    out = ROOT / "evidence"
    out.mkdir(exist_ok=True)
    ts = dt.datetime.now(dt.timezone(dt.timedelta(hours=4))).strftime("%Y-%m-%d %H:%M (Bakı)")
    report = {"generated": ts, "passed": passed, "total": len(RESULTS), "results": RESULTS}
    (out / "compliance-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md = [f"# Compliance-as-code hesabatı\n", f"Yaradılıb: {ts} · **{passed}/{len(RESULTS)} PASS**\n",
          "| ID | Nəzarət | Yoxlama | Nəticə | Sübut |", "|---|---|---|---|---|"]
    for r in RESULTS:
        ev = str(r["evidence"]).replace("|", "\\|")
        md.append(f"| {r['id']} | {r['control']} | {r['title']} | {'✅' if r['status'] == 'PASS' else '❌'} {r['status']} | {ev} |")
    (out / "compliance-report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    for r in RESULTS:
        print(f"{r['status']:4}  {r['id']}  {r['control']:8}  {r['title']}")
    print(f"\n{passed}/{len(RESULTS)} PASS → evidence/compliance-report.md")
    return 1 if strict and passed != len(RESULTS) else 0


if __name__ == "__main__":
    sys.exit(main())
