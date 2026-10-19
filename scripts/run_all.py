"""Bütün yoxlamaları işə sal və sübut fayllarını yarat (evidence/).

    python scripts/run_all.py            # hamısı (E2E daxil)
    python scripts/run_all.py --no-e2e   # brauzer testi olmadan

Yaradılan fayllar:
  evidence/test-results.md     — Python + JS testləri, modullar üzrə
  evidence/crypto-demos.md     — 4 kriptoqrafik demonun çıxışı
  evidence/benchmarks.md       — KDF ölçmələri (brauzer mühərriki və server)
  evidence/compliance-report.* — compliance-as-code (30 yoxlama)
"""
from __future__ import annotations

import collections
import datetime as dt
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EV = ROOT / "evidence"
sys.path.insert(0, str(ROOT))
NOW = dt.datetime.now(dt.timezone(dt.timedelta(hours=4))).strftime("%Y-%m-%d %H:%M (Bakı)")


class CountingResult(unittest.TextTestResult):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.per_module = collections.defaultdict(lambda: {"ok": 0, "fail": 0, "skip": 0, "time": 0.0})
        self._t0 = {}

    def startTest(self, test):
        self._t0[test.id()] = time.perf_counter()
        super().startTest(test)

    def _mod(self, test):
        return test.id().split(".")[1] if test.id().startswith("tests.") else test.id().split(".")[0]

    def _time(self, test):
        self.per_module[self._mod(test)]["time"] += time.perf_counter() - self._t0.get(test.id(), time.perf_counter())

    def addSuccess(self, test):
        super().addSuccess(test); self.per_module[self._mod(test)]["ok"] += 1; self._time(test)

    def addFailure(self, test, err):
        super().addFailure(test, err); self.per_module[self._mod(test)]["fail"] += 1; self._time(test)

    def addError(self, test, err):
        super().addError(test, err); self.per_module[self._mod(test)]["fail"] += 1; self._time(test)

    def addSkip(self, test, reason):
        super().addSkip(test, reason); self.per_module[self._mod(test)]["skip"] += 1

    def addSubTest(self, test, subtest, outcome):
        super().addSubTest(test, subtest, outcome)
        self.subtests = getattr(self, "subtests", 0) + 1


DESCR = {
    "test_shamir": "Shamir GF(256): sahə aksiomları, bütün (n,t) konfiqurasiyaları, mütləq məxfilik, χ²",
    "test_primitives": "AES-GCM (hər bitin dəyişdirilməsi), ECIES, KDF, doldurma, bərpa kodu, RFC vektorları",
    "test_switch": "'Sağam' vəziyyət maşını: keçidlər, 990 kombinasiyalı invariant şəbəkəsi, 2 000 təsadüfi ssenari",
    "test_api_security": "Autentifikasiya, sessiya, CSRF, BOLA, mass assignment, rate limit, vəzifə bölgüsü, başlıqlar",
    "test_vault_api": "Seyf qaydaları: paylanma, versiyalar, açılma, saxta hissə, R əvəzlənməsi, saxlama",
    "test_flow": "Tam həyat dövrü ssenariləri (API səviyyəsində)",
    "test_zero_knowledge": "Serverin bütün diskinin skanı: açıq mətn, açar, hissə, parol yoxdur",
    "test_infra": "KMS (lokal + AWS imitasiyası), anbar, konfiqurasiya, planlaşdırıcı, audit, CLI, Lambda",
    "test_crossimpl": "JS → Python kriptoqrafik uyğunluq",
    "test_route_matrix": "Hər endpoint üçün avtomatik: auth, CSRF, Origin, başlıqlar, rol matrisi",
    "e2e": "Real Chromium: 6 istifadəçi, 68 gün, 2/3 açılma, 18 ekran görüntüsü",
}


def run_python(include_e2e: bool):
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
    if not include_e2e:
        suite = unittest.TestSuite(t for t in _flatten(suite) if ".e2e." not in t.id())
    stream = open(os.devnull, "w", encoding="utf-8")
    runner = unittest.TextTestRunner(stream=stream, resultclass=CountingResult, verbosity=0)
    t0 = time.perf_counter()
    res = runner.run(suite)
    return res, time.perf_counter() - t0


def _flatten(s):
    for t in s:
        if isinstance(t, unittest.TestSuite):
            yield from _flatten(t)
        else:
            yield t


def run_node():
    files = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "tests/js").glob("*.test.mjs"))
    out = subprocess.run(["node", "--test", *files], cwd=ROOT, capture_output=True, text=True)
    passed = int(re.search(r"# pass (\d+)", out.stdout).group(1))
    failed = int(re.search(r"# fail (\d+)", out.stdout).group(1))
    names = re.findall(r"^ok \d+ - (.+)$", out.stdout, re.M)
    return passed, failed, names


def run_demos():
    md = [f"# Kriptoqrafik demolar\n\nYaradılıb: {NOW}\n"]
    for p in sorted((ROOT / "demos").glob("*.py")):
        doc = (p.read_text().split('"""')[1].strip().splitlines() or [""])[0]
        out = subprocess.run([sys.executable, str(p)], cwd=ROOT, capture_output=True, text=True, timeout=120)
        md += [f"## {p.name}\n", f"_{doc}_\n", "```", out.stdout.rstrip(), "```\n"]
    (EV / "crypto-demos.md").write_text("\n".join(md), encoding="utf-8")


def run_bench():
    from emanet.crypto import passwords
    from emanet.crypto import primitives as P
    t = time.perf_counter(); P.master_key("bench-parol-2026", b"s" * 16); py_pbkdf2 = time.perf_counter() - t
    t = time.perf_counter(); passwords.hash_password("x"); argon = time.perf_counter() - t
    import hashlib
    t = time.perf_counter()
    for _ in range(100000):
        hashlib.sha256(b"bench-parol-2026").digest()
    sha = (time.perf_counter() - t) / 100000
    js = subprocess.run(["node", "-e", """
      import('./web/js/crypto.js').then(async C => {
        const t=performance.now(); await C.masterKey('bench-parol-2026', new Uint8Array(16)); const a=performance.now()-t;
        const s=C.randomBytes(32); const sh=await import('./web/js/shamir.js');
        const t2=performance.now(); for(let i=0;i<1000;i++){ sh.combine(sh.split(s,3,2).slice(0,2)); } const b=(performance.now()-t2)/1000;
        console.log(JSON.stringify({pbkdf2_ms:a, shamir_ms:b}));
      })"""], cwd=ROOT, capture_output=True, text=True)
    j = json.loads(js.stdout)
    guesses_pbkdf2 = 1 / py_pbkdf2
    space = 70 ** 10
    md = f"""# Ölçmələr (benchmark)

Yaradılıb: {NOW} · {platform.processor() or platform.machine()} · Python {platform.python_version()} · Node {subprocess.run(['node','--version'],capture_output=True,text=True).stdout.strip()}

| Əməliyyat | Vaxt | Şərh |
|---|---|---|
| PBKDF2-SHA256, 600 000 iter. (Node WebCrypto — brauzer mühərriki) | **{j['pbkdf2_ms']:.0f} ms** | Giriş zamanı bir dəfə; istifadəçi hiss etmir |
| PBKDF2-SHA256, 600 000 iter. (Python/OpenSSL) | {py_pbkdf2*1000:.0f} ms | 1 nüvədə hücumçu: ≈ {guesses_pbkdf2:.1f} təxmin/san |
| Argon2id m=19 MiB, t=2 (server, auth_key üzərində) | {argon*1000:.0f} ms | Onlayn hücum üçün əlavə qat |
| Adi SHA-256 (müqayisə üçün) | {sha*1e6:.2f} µs | ≈ {1/sha:,.0f} təxmin/san |
| Shamir split(3) + combine(2), 32 bayt (JS) | {j['shamir_ms']:.3f} ms | Praktiki olaraq ani |

**Nəticə:** PBKDF2(600k) adi SHA-256-dan ≈ **{py_pbkdf2/sha:,.0f} dəfə** yavaşdır. 10 simvollu təsadüfi parol (70 simvollu əlifba,
{space:.2e} variant) üçün 1 nüvədə tam axtarış ≈ {space/guesses_pbkdf2/3.15e7:.1e} il çəkir. GPU fermasında bu müddət qısalır. Ona görə də
parol siyasəti 12+ simvol tələb edir və brauzerdə Argon2id-ə keçid yol xəritəsindədir (R-12).
"""
    (EV / "benchmarks.md").write_text(md, encoding="utf-8")
    return j, py_pbkdf2, argon


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    EV.mkdir(exist_ok=True)
    include_e2e = "--no-e2e" not in sys.argv
    res, secs = run_python(include_e2e)
    node_pass, node_fail, node_names = run_node()
    run_demos()
    run_bench()
    py_total = res.testsRun
    py_fail = len(res.failures) + len(res.errors)
    lines = [f"# Test nəticələri\n", f"Yaradılıb: {NOW} · Python {platform.python_version()} · `python scripts/run_all.py`\n",
             "## Xülasə\n", "| Dəst | Test | Keçdi | Uğursuz | Müddət |", "|---|---|---|---|---|",
             f"| Python (unittest) | {py_total} | {py_total - py_fail - len(res.skipped)} | {py_fail} | {secs:.1f} s |",
             f"| JavaScript (node:test, WebCrypto) | {node_pass + node_fail} | {node_pass} | {node_fail} | — |",
             f"| **Cəmi** | **{py_total + node_pass + node_fail}** | **{py_total - py_fail - len(res.skipped) + node_pass}** | **{py_fail + node_fail}** | |",
             f"\nAlt testlər (subTest): {getattr(res, 'subtests', 0)} · Compliance: PENDING\n",
             "## Python modulları üzrə\n", "| Modul | Nə yoxlanılır | Keçdi | Uğursuz | Müddət |", "|---|---|---|---|---|"]
    for mod, c in sorted(res.per_module.items()):
        lines.append(f"| `{mod}` | {DESCR.get(mod, '')} | {c['ok']} | {c['fail']} | {c['time']:.1f} s |")
    lines += ["\n## JavaScript testləri\n"] + [f"- ✅ {n}" for n in node_names]
    if py_fail:
        lines += ["\n## Uğursuz testlər\n"] + [f"- {t.id()}" for t, _ in res.failures + res.errors]
    (EV / "test-results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Compliance test hesabatından SONRA (C-25 sübut fayllarının mövcudluğunu yoxlayır)
    subprocess.run([sys.executable, "compliance/check_controls.py"], cwd=ROOT, capture_output=True, text=True)
    comp = subprocess.run([sys.executable, "compliance/check_controls.py", "--strict"], cwd=ROOT, capture_output=True, text=True)
    comp_line = comp.stdout.strip().splitlines()[-1]
    text = (EV / "test-results.md").read_text().replace("Compliance: PENDING", "Compliance: " + comp_line)
    (EV / "test-results.md").write_text(text, encoding="utf-8")
    print("\n".join(lines[:12]))
    return 0 if py_fail == 0 and node_fail == 0 and comp.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
