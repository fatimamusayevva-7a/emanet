""""Sağam" yoxlaması (dead man's switch) — təmiz vəziyyət maşını.

Funksiya `evaluate()` yan təsirsizdir: (seyf, indiki vaxt, təsdiq sayı) →
(yeni vəziyyət, görüləcək işlər). Ona görə də bütün keçidlər zaman şəbəkəsi
üzərində tam (exhaustive) test oluna bilir — `tests/test_switch.py`.

    setup ──paylanma──▶ active ──interval──▶ reminding ──inactivity──▶ awaiting
                          ▲                      │                        │ t təsdiq
                          │◀──── sahib aktivdir ─┴────────────────────────┤
                          │                                               ▼
                          └──────────── sahib aktivdir ◀──────── pending_release
                                                                          │ waiting_days keçdi
                                                                          ▼
                                                                       released

Təhlükəsizlik invariantları (testlərlə yoxlanılır):
  I1. released yalnız pending_release-dən gəlir.
  I2. pending_release yalnız inactivity_days dolduqdan VƏ ≥ t təsdiqdən sonra başlayır.
  I3. pending_release-dən released-ə keçid ən azı waiting_days çəkir.
  I4. sahibin istənilən aktivliyi released-dən əvvəlki istənilən vəziyyəti active-ə qaytarır.
  I5. pauza müddəti ərzində heç bir xatırlatma/eskalasiya olmur.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DAY = 86400.0
REMINDER_EVERY_DAYS = 7

STATES = ("setup", "active", "reminding", "awaiting", "pending_release", "released")

LIMITS = {
    "checkin_interval_days": (7, 90),
    "inactivity_days": (14, 365),
    "waiting_days": (3, 30),
}


@dataclass(frozen=True)
class SwitchView:
    state: str
    last_activity_at: float
    checkin_interval_days: int
    inactivity_days: int
    waiting_days: int
    threshold: int | None
    last_reminder_at: float | None = None
    paused_until: float | None = None
    release_at: float | None = None


@dataclass
class Decision:
    state: str
    actions: list[str] = field(default_factory=list)   # "remind", "final_warning", "notify_trustees", …
    release_at: float | None = None

    def changed(self, old: SwitchView) -> bool:
        return self.state != old.state or bool(self.actions)


def validate_settings(interval: int, inactivity: int, waiting: int) -> list[str]:
    problems = []
    for name, val in (("checkin_interval_days", interval), ("inactivity_days", inactivity), ("waiting_days", waiting)):
        lo, hi = LIMITS[name]
        if not isinstance(val, int) or isinstance(val, bool) or not lo <= val <= hi:
            problems.append(f"{name} {lo}..{hi} aralığında olmalıdır")
    if not problems and inactivity < interval + 7:
        problems.append("inactivity_days ən azı checkin_interval_days + 7 olmalıdır (xatırlatmaya vaxt qalsın)")
    return problems


def effective_last_activity(v: SwitchView) -> float:
    return max(v.last_activity_at, v.paused_until or 0.0)


def evaluate(v: SwitchView, now: float, approvals: int) -> Decision:
    if v.state not in STATES:
        raise ValueError(f"naməlum vəziyyət: {v.state}")
    if v.state in ("setup", "released"):
        return Decision(v.state)

    if v.state == "pending_release":
        if v.release_at is not None and now >= v.release_at:
            return Decision("released", ["released"])
        return Decision("pending_release", release_at=v.release_at)

    if v.paused_until and now < v.paused_until:
        return Decision("active")      # I5: pauza zamanı heç nə olmur

    idle_days = (now - effective_last_activity(v)) / DAY

    if idle_days >= v.inactivity_days:
        if v.threshold and approvals >= v.threshold:
            return Decision("pending_release", ["release_pending"], release_at=now + v.waiting_days * DAY)
        if v.state != "awaiting":
            return Decision("awaiting", ["final_warning", "notify_trustees"])
        return Decision("awaiting")

    if idle_days >= v.checkin_interval_days:
        due = v.last_reminder_at is None or v.last_reminder_at < effective_last_activity(v) \
            or (now - v.last_reminder_at) >= REMINDER_EVERY_DAYS * DAY
        return Decision("reminding", ["remind"] if due else [])

    return Decision("active")


def on_owner_activity(state: str) -> Decision:
    """I4: sahib aktivdir → released-dən əvvəlki hər şey ləğv olunur."""
    if state in ("setup", "released"):
        return Decision(state)
    actions = ["release_cancelled"] if state in ("awaiting", "pending_release") else []
    return Decision("active", actions)


def days_until_awaiting(v: SwitchView, now: float) -> float:
    return max(0.0, v.inactivity_days - (now - effective_last_activity(v)) / DAY)
