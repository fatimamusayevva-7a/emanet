"""'Sağam' vəziyyət maşını: invariantlar zaman şəbəkəsi üzərində tam yoxlanılır."""
from __future__ import annotations

import itertools
import random
import unittest

from emanet import switch
from emanet.switch import DAY, SwitchView, evaluate, on_owner_activity, validate_settings

T0 = 1_800_000_000.0


def view(state="active", idle_days=0.0, interval=30, inactivity=60, waiting=7, threshold=2, last_reminder=None,
         paused_until=None, release_at=None, now=T0):
    return SwitchView(state=state, last_activity_at=now - idle_days * DAY, checkin_interval_days=interval,
                      inactivity_days=inactivity, waiting_days=waiting, threshold=threshold,
                      last_reminder_at=last_reminder, paused_until=paused_until, release_at=release_at)


class Transitions(unittest.TestCase):
    def test_active_stays_active_before_interval(self):
        for d in (0, 1, 15, 29.99):
            self.assertEqual(evaluate(view(idle_days=d), T0, 0).state, "active")

    def test_reminding_after_interval(self):
        d = evaluate(view(idle_days=30), T0, 0)
        self.assertEqual((d.state, d.actions), ("reminding", ["remind"]))

    def test_reminder_repeats_weekly_not_daily(self):
        d = evaluate(view("reminding", idle_days=33, last_reminder=T0 - 3 * DAY), T0, 0)
        self.assertEqual(d.actions, [])
        d = evaluate(view("reminding", idle_days=37, last_reminder=T0 - 7 * DAY), T0, 0)
        self.assertEqual(d.actions, ["remind"])

    def test_awaiting_after_inactivity(self):
        d = evaluate(view("reminding", idle_days=60), T0, 0)
        self.assertEqual(d.state, "awaiting")
        self.assertIn("notify_trustees", d.actions)
        self.assertIn("final_warning", d.actions)

    def test_awaiting_notifies_once(self):
        self.assertEqual(evaluate(view("awaiting", idle_days=70), T0, 1).actions, [])

    def test_threshold_reached_starts_waiting_period(self):
        d = evaluate(view("awaiting", idle_days=61), T0, 2)
        self.assertEqual(d.state, "pending_release")
        self.assertEqual(d.release_at, T0 + 7 * DAY)

    def test_pending_releases_only_after_waiting(self):
        v = view("pending_release", idle_days=65, release_at=T0 + 1)
        self.assertEqual(evaluate(v, T0, 2).state, "pending_release")
        self.assertEqual(evaluate(v, T0 + 1, 2).state, "released")

    def test_released_and_setup_are_terminal_for_evaluate(self):
        for st in ("released", "setup"):
            self.assertEqual(evaluate(view(st, idle_days=500), T0, 9).state, st)

    def test_pause_suppresses_everything(self):
        d = evaluate(view("active", idle_days=200, paused_until=T0 + DAY), T0, 3)
        self.assertEqual((d.state, d.actions), ("active", []))

    def test_pause_end_counts_as_activity(self):
        v = view("active", idle_days=200, paused_until=T0 - 5 * DAY)
        self.assertEqual(evaluate(v, T0, 0).state, "active")       # pauzadan 5 gün keçib
        self.assertEqual(evaluate(v, T0 + 26 * DAY, 0).state, "reminding")

    def test_owner_activity_cancels(self):
        for st in ("active", "reminding", "awaiting", "pending_release"):
            d = on_owner_activity(st)
            self.assertEqual(d.state, "active")
            self.assertEqual("release_cancelled" in d.actions, st in ("awaiting", "pending_release"))
        self.assertEqual(on_owner_activity("released").state, "released")
        self.assertEqual(on_owner_activity("setup").state, "setup")

    def test_unknown_state(self):
        with self.assertRaises(ValueError):
            evaluate(view("hacked"), T0, 0)

    def test_no_threshold_never_pending(self):
        self.assertEqual(evaluate(view("awaiting", idle_days=100, threshold=None), T0, 5).state, "awaiting")


class Invariants(unittest.TestCase):
    """Bütün vəziyyət × boş gün × təsdiq sayı × parametr kombinasiyaları üzrə təhlükəsizlik invariantları."""

    def test_grid(self):
        cases = 0
        for state, idle, approvals, (iv, ia, wd), thr in itertools.product(
                ("active", "reminding", "awaiting"), [0, 6.9, 7, 29.9, 30, 44, 59.99, 60, 61, 90, 400],
                range(0, 5), [(7, 14, 3), (30, 60, 7), (90, 365, 30)], (2, 3)):
            d = evaluate(view(state, idle, iv, ia, wd, thr), T0, approvals)
            # I1: released yalnız pending_release-dən
            self.assertNotEqual(d.state, "released")
            # I2: pending_release yalnız inactivity + hədd ilə
            if d.state == "pending_release":
                self.assertGreaterEqual(idle, ia)
                self.assertGreaterEqual(approvals, thr)
                # I3: gözləmə ən azı waiting_days
                self.assertGreaterEqual(d.release_at - T0, wd * DAY)
            if idle < ia:
                self.assertIn(d.state, ("active", "reminding"))
            if idle < iv:
                self.assertEqual(d.state, "active")
            cases += 1
        self.assertEqual(cases, 3 * 11 * 5 * 3 * 2)

    def test_random_walk_never_releases_early(self):
        """Təsadüfi gəzinti: 2 000 ssenari, hər addımda saat irəliləyir, bəzən sahib aktivdir,
        bəzən təsdiqlər gəlir. Seyf heç vaxt (son aktivlik + inactivity + waiting)-dən tez açılmamalıdır."""
        rnd = random.Random(42)
        for _ in range(2000):
            iv, ia, wd = rnd.choice([(7, 14, 3), (30, 60, 7), (14, 30, 5)])
            t = T0
            st = dict(state="active", last=t, last_rem=None, release_at=None)
            approvals = 0
            for _step in range(rnd.randint(5, 60)):
                t += rnd.uniform(0.1, 9) * DAY
                if rnd.random() < 0.15:
                    d = on_owner_activity(st["state"])
                    st.update(state=d.state, last=t, last_rem=None)
                    if "release_cancelled" in d.actions:
                        approvals, st["release_at"] = 0, None
                    continue
                if st["state"] == "awaiting" and rnd.random() < 0.4:
                    approvals += 1
                v = SwitchView(st["state"], st["last"], iv, ia, wd, 2, st["last_rem"], None, st["release_at"])
                d = evaluate(v, t, approvals)
                if "remind" in d.actions:
                    st["last_rem"] = t
                if d.state == "pending_release" and st["state"] != "pending_release":
                    st["release_at"] = d.release_at
                if d.state == "released":
                    self.assertGreaterEqual(t, st["last"] + (ia + wd) * DAY)
                st["state"] = d.state
                if d.state == "released":
                    break


class Settings(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_settings(30, 60, 7), [])

    def test_bounds(self):
        for args in [(6, 60, 7), (91, 120, 7), (30, 13, 7), (30, 366, 7), (30, 60, 2), (30, 60, 31), (30, 36, 7)]:
            with self.subTest(args=args):
                self.assertTrue(validate_settings(*args))

    def test_bool_is_not_int(self):
        self.assertTrue(validate_settings(True, 60, 7))

    def test_days_until_awaiting(self):
        self.assertAlmostEqual(switch.days_until_awaiting(view(idle_days=10), T0), 50)
        self.assertEqual(switch.days_until_awaiting(view(idle_days=100), T0), 0)


if __name__ == "__main__":
    unittest.main()
