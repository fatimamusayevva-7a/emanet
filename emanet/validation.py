"""Giriş validasiyası — icazə siyahısı (allowlist) prinsipi.

`parse(body, schema)` sxemdə olmayan sahəni RƏDD edir (mass assignment-ə
qarşı: istifadəçi `"role": "operator"` əlavə etsə, sorğu 400 alır və
təhlükəsizlik hadisəsi yazılır). Hər sahənin tipi, uzunluğu və formatı yoxlanılır.
"""
from __future__ import annotations

import re
from typing import Any, Callable

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
B64U_RE = re.compile(r"^[A-Za-z0-9_-]+$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(Exception):
    def __init__(self, message: str, field: str | None = None, unknown: list[str] | None = None):
        super().__init__(message)
        self.field = field
        self.unknown = unknown or []


Validator = Callable[[Any, str], Any]


def _b64u_len(s: str) -> int:
    return len(s) * 3 // 4


def Email() -> Validator:
    def v(x, f):
        if not isinstance(x, str) or not EMAIL_RE.match(x.strip()) or len(x) > 254:
            raise ValidationError("e-poçt formatı yanlışdır", f)
        return x.strip().lower()
    return v


def Text(min_len: int = 1, max_len: int = 200) -> Validator:
    def v(x, f):
        if not isinstance(x, str):
            raise ValidationError("mətn gözlənilirdi", f)
        x = x.strip()
        if not min_len <= len(x) <= max_len or any(ord(c) < 32 for c in x):
            raise ValidationError(f"uzunluq {min_len}..{max_len} olmalıdır, idarəedici simvol qadağandır", f)
        return x
    return v


def B64U(nbytes: int | None = None, max_bytes: int = 4096) -> Validator:
    def v(x, f):
        if not isinstance(x, str) or not B64U_RE.match(x) or len(x) % 4 == 1:
            raise ValidationError("base64url gözlənilirdi", f)
        n = _b64u_len(x)
        if (nbytes is not None and n != nbytes) or n > max_bytes:
            raise ValidationError(f"uzunluq {nbytes or ('≤' + str(max_bytes))} bayt olmalıdır", f)
        return x
    return v


def Int(lo: int, hi: int) -> Validator:
    def v(x, f):
        if not isinstance(x, int) or isinstance(x, bool) or not lo <= x <= hi:
            raise ValidationError(f"{lo}..{hi} aralığında tam ədəd gözlənilirdi", f)
        return x
    return v


def Num(lo: float, hi: float) -> Validator:
    def v(x, f):
        if not isinstance(x, (int, float)) or isinstance(x, bool) or not lo <= x <= hi:
            raise ValidationError(f"{lo}..{hi} aralığında ədəd gözlənilirdi", f)
        return float(x)
    return v


def Digits(n: int) -> Validator:
    def v(x, f):
        if not isinstance(x, str) or len(x) != n or not x.isdigit():
            raise ValidationError(f"{n} rəqəmli kod gözlənilirdi", f)
        return x
    return v


def Hex64() -> Validator:
    def v(x, f):
        if not isinstance(x, str) or not HEX64_RE.match(x):
            raise ValidationError("64 simvollu hex gözlənilirdi", f)
        return x
    return v


def Id(prefix: str) -> Validator:
    rx = re.compile(rf"^{prefix}_[A-Za-z0-9_-]{{16,40}}$")

    def v(x, f):
        if not isinstance(x, str) or not rx.match(x):
            raise ValidationError("identifikator formatı yanlışdır", f)
        return x
    return v


def SealedBox(max_ct_bytes: int = 8192) -> Validator:
    """AES-GCM qutusu {v:1, iv, ct}"""
    def v(x, f):
        return parse(x, {"v": Int(1, 1), "iv": B64U(12), "ct": B64U(max_bytes=max_ct_bytes)}, prefix=f + ".")
    return v


def EciesBox() -> Validator:
    def v(x, f):
        return parse(x, {"v": Int(1, 1), "epk": B64U(65), "iv": B64U(12), "ct": B64U(max_bytes=256)}, prefix=f + ".")
    return v


def ListOf(item: Validator, min_len: int = 0, max_len: int = 20) -> Validator:
    def v(x, f):
        if not isinstance(x, list) or not min_len <= len(x) <= max_len:
            raise ValidationError(f"{min_len}..{max_len} elementli siyahı gözlənilirdi", f)
        return [item(e, f"{f}[{i}]") for i, e in enumerate(x)]
    return v


def Obj(schema: dict, optional: set[str] | None = None) -> Validator:
    def v(x, f):
        return parse(x, schema, optional=optional, prefix=f + ".")
    return v


def parse(body: Any, schema: dict[str, Validator], optional: set[str] | None = None, prefix: str = "") -> dict:
    optional = optional or set()
    if not isinstance(body, dict):
        raise ValidationError("JSON obyekt gözlənilirdi", prefix.rstrip(".") or None)
    unknown = sorted(set(body) - set(schema))
    if unknown:
        raise ValidationError("icazə verilməyən sahələr: " + ", ".join(prefix + u for u in unknown),
                              unknown=[prefix + u for u in unknown])
    out = {}
    for name, validator in schema.items():
        if name not in body or body[name] is None:
            if name in optional:
                continue
            raise ValidationError("məcburi sahə yoxdur", prefix + name)
        out[name] = validator(body[name], prefix + name)
    return out
