"""Demo 4 — Şifrəmətnin uzunluğu da məlumatdır (metadata sızması) və doldurma (padding).

AES-GCM məzmunu gizlədir, amma uzunluğu gizlətmir: şifrəmətn = açıq mətn + 16 bayt teq.
Server seyfin ölçüsünə baxıb "neçə qeyd var", "sənəd əlavə olunub" kimi nəticə çıxara bilər.
Əmanət açıq mətni 4 KiB (böyük seyflərdə 64 KiB) addımlarla doldurur.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from emanet.crypto import primitives as P  # noqa: E402

key = os.urandom(32)
print(f"{'Qeyd sayı':>10} │ {'padding-siz':>12} │ {'padding ilə':>12}")
print("───────────┼──────────────┼─────────────")
for n in (0, 1, 2, 5, 10, 25, 60):
    content = json.dumps({"items": [{"title": f"Hesab {i}", "secret": "x" * 20} for i in range(n)]}).encode()
    raw = len(P.b64u_d(P.seal(key, content, "a")["ct"]))
    padded = len(P.b64u_d(P.seal(key, P.pad(content), "a")["ct"]))
    print(f"{n:>10} │ {raw:>10} B │ {padded:>10} B")
print("\nPadding-siz: hər yeni qeyd ölçünü dəyişir → server izləyə bilər.")
print("Padding ilə: 0–60 qeyd eyni və ya bir neçə sabit ölçüdə görünür.")
