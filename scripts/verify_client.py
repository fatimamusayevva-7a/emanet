"""Canlı saytın brauzer kodunu (JS/HTML/CSS) repozitoriyadakı versiya ilə müqayisə et.

Zero-knowledge sistemin ən zəif yeri: server istifadəçiyə dəyişdirilmiş JS göndərsə,
həmin JS parolu oğurlaya bilər. Bu skript müstəqil auditora/istifadəçiyə imkan verir:
  1) canlı saytdan /api/integrity manifestini alır;
  2) hər faylı canlı saytdan YÜKLƏYİB heşini özü hesablayır (manifestə kor-koranə güvənmir);
  3) nəticəni yerli repozitoriyadakı fayllarla müqayisə edir.

    python scripts/verify_client.py https://emanet.example.az
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import urllib.request

WEB = pathlib.Path(__file__).resolve().parents[1] / "web"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=20) as r:   # noqa: S310
        return r.read()


def main(base: str) -> int:
    base = base.rstrip("/")
    manifest = json.loads(fetch(base + "/api/integrity"))
    bad = 0
    for rel, claimed in sorted(manifest["files"].items()):
        live = hashlib.sha256(fetch(f"{base}/{rel}" if rel != "index.html" else base + "/")).hexdigest()
        local_p = WEB / rel
        local = hashlib.sha256(local_p.read_bytes()).hexdigest() if local_p.exists() else "—"
        ok = live == claimed == local
        bad += not ok
        print(f"{'OK ' if ok else 'XƏTA'}  {rel:28} canlı={live[:12]} manifest={claimed[:12]} repo={local[:12]}")
    print(f"\n{'Bütün fayllar uyğundur' if not bad else f'{bad} uyğunsuzluq tapıldı!'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"))
