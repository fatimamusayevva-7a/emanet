"""Saat abstraksiyası — "sağam" yoxlaması zamandan asılıdır, testlər isə zamanı idarə etməlidir.

* SystemClock — real vaxt (istehsal).
* OffsetClock — real vaxt + DB-də saxlanan sürüşmə; YALNIZ demo rejimində
  (komissiya qarşısında 60 günü bir kliklə "keçirmək" üçün). İstehsalda
  `Settings.validate()` demo rejimini qadağan edir və compliance yoxlaması da bunu təsdiqləyir.
* FrozenClock — testlər üçün tam idarə olunan saat.
"""
from __future__ import annotations

import time

DAY = 86400.0


class SystemClock:
    def now(self) -> float:
        return time.time()


class OffsetClock:
    def __init__(self, db):
        self.db = db

    def offset(self) -> float:
        return float(self.db.get_kv("demo_clock_offset", "0"))

    def advance(self, seconds: float) -> None:
        self.db.set_kv("demo_clock_offset", str(self.offset() + seconds))

    def reset(self) -> None:
        self.db.set_kv("demo_clock_offset", "0")

    def now(self) -> float:
        return time.time() + self.offset()


class FrozenClock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds

    def advance_days(self, days: float) -> None:
        self.t += days * DAY
