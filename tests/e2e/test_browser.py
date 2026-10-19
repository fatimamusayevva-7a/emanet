"""Real brauzerdə (Chromium, Playwright) uçdan-uca ssenari.

Bütün kriptoqrafiya həqiqətən brauzerin WebCrypto-sunda işləyir; server ayrıca
prosesdə real HTTP ilə qalxır. Ssenari komissiya qarşısındakı demonu təkrarlayır:

  1. Aysel qeydiyyatdan keçir, bərpa kodunu saxlayır, seyfə qeyd və məktub yazır.
  2. Rəşad, Nigar, Elvin qeydiyyatdan keçir; Aysel onları dəvət edir, onlar qəbul edir.
  3. Aysel barmaq izlərini yoxlayır və hissələri 2/3 həddi ilə paylayır.
  4. Operator demo saatını 31 + 30 gün irəli çəkir → "etibarlı şəxslər gözlənilir".
  5. Rəşad və Nigar təsdiqləyir → 7 günlük gözləmə → seyf açılır.
  6. Rəşad TƏK hissə ilə açmağa çalışır → alınmır (1/2).
  7. Nigar hissəsini ötürür → Rəşad seyfi açır və Ayselin məktubunu oxuyur.

Hər addımda ekran görüntüsü evidence/screenshots/ qovluğuna yazılır.
Brauzer konsolunda hər hansı xəta (o cümlədən CSP/Trusted Types pozuntusu) testi uğursuz edir.

İşə salma:  python -m unittest tests.e2e.test_browser
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
SHOTS = ROOT / "evidence" / "screenshots"

try:
    from playwright.sync_api import sync_playwright, expect
except ImportError:  # pragma: no cover
    sync_playwright = None

PASSWORD = "Xəzərin sahili 2026-cı ilin yazında"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@unittest.skipIf(sync_playwright is None, "playwright yoxdur")
class BrowserE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="emanet-e2e-"))
        cls.port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = {**os.environ, "EMANET_DATA_DIR": str(cls.tmp), "EMANET_DEMO_MODE": "1", "EMANET_PORT": str(cls.port),
               "EMANET_PUBLIC_ORIGIN": cls.base, "EMANET_BOOTSTRAP_OPERATOR_EMAIL": "operator@emanet.az"}
        cls.server = subprocess.Popen([sys.executable, "-m", "emanet.app"], cwd=ROOT, env=env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.base + "/api/health", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()
        SHOTS.mkdir(parents=True, exist_ok=True)
        cls.console_errors: list[str] = []

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.server.terminate()
        cls.server.wait(5)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ------------------------------------------------------------------ köməkçilər
    def new_page(self, who: str):
        ctx = self.browser.new_context(viewport={"width": 1280, "height": 860}, locale="az-AZ")
        page = ctx.new_page()
        page.set_default_timeout(20000)

        def on_console(msg):
            if msg.type == "error":
                self.console_errors.append(f"[{who}] {msg.text}")
        page.on("console", on_console)
        page.on("pageerror", lambda e: self.console_errors.append(f"[{who}] pageerror: {e}"))
        page.goto(self.base + "/")
        return page

    def shot(self, page, name: str):
        page.screenshot(path=str(SHOTS / f"{name}.png"), full_page=True)

    def register(self, page, name: str, email: str, shot_prefix: str | None = None):
        page.click("text=Hesab yarat")
        page.fill("#reg-name", name)
        page.fill("#reg-email", email)
        page.fill("#reg-password", PASSWORD)
        page.fill("#reg-password2", PASSWORD)
        page.check("#reg-ack")
        if shot_prefix:
            self.shot(page, f"{shot_prefix}-register")
        page.click("#reg-submit")
        page.wait_for_selector("#recovery-code", timeout=60000)
        code = page.inner_text("#recovery-code").strip()
        self.assertRegex(code, r"^[A-Z2-9]{5}(-[A-Z2-9]{5}){4}$")
        if shot_prefix:
            self.shot(page, f"{shot_prefix}-recovery-code")
        page.check("#rc-ack")
        page.click("#rc-continue")
        page.wait_for_selector("#hero-title")
        return code

    def owner_tab(self, page, tab):
        page.click(f"#tab-{tab}")

    # ------------------------------------------------------------------ ssenari
    def test_full_story_in_real_browser(self):
        aysel = self.new_page("Aysel")
        self.shot(aysel, "01-landing")
        self.register(aysel, "Aysel Məmmədova", "aysel@example.az", "02")
        self.shot(aysel, "03-empty-vault")

        # Seyfə qeyd və məktub
        aysel.click("#btn-add-item")
        aysel.fill("#item-title", "Kapital Bank — internet bankinq")
        aysel.fill("#item-user", "aysel.m")
        aysel.fill("#item-secret", "PIN 4821 · parol: Qumlu-Sahil-77")
        aysel.fill("#item-note", "Kart qəhvəyi qovluqdadır, ikinci rəfdə.")
        aysel.click(".modal button.brass")
        aysel.fill("#letter", "Əzizlərim, bu məktubu oxuyursunuzsa, deməli mənə nəsə olub. Ailəmə kömək edin.")
        aysel.click("#btn-save")
        aysel.wait_for_selector("text=Yadda saxlanılıb")
        self.shot(aysel, "04-vault-content")

        # Etibarlı şəxslər
        trustees = {}
        for name, email in [("Rəşad Əliyev", "reshad@example.az"), ("Nigar Həsənova", "nigar@example.az"),
                            ("Elvin Quliyev", "elvin@example.az")]:
            p = self.new_page(name.split()[0])
            self.register(p, name, email)
            trustees[email] = p
            self.owner_tab(aysel, "trustees")
            aysel.fill("#invite-email", email)
            aysel.click("#btn-invite")
            aysel.wait_for_selector(f"text={email}")
        for email, p in trustees.items():
            p.goto(self.base + "/#/trustee")
            p.wait_for_selector("text=Dəvətlər")
            if email == "reshad@example.az":
                self.shot(p, "05-trustee-invitation")
            p.click("button.brass:has-text('Qəbul et')")
            p.wait_for_selector("text=Sahib hələ hissələri paylamayıb")

        aysel.reload()
        aysel.fill("#unlock-password", PASSWORD)
        aysel.click("#unlock-submit")
        aysel.wait_for_selector("#hero-title")
        self.owner_tab(aysel, "trustees")
        self.shot(aysel, "06-trustees-before-verify")
        for email, p in trustees.items():
            fp_trustee = p.inner_text("#my-fingerprint").strip()
            btn = aysel.locator(f"button[data-verify='{email}']")
            btn.click()
            fp_owner = aysel.inner_text(".modal .fp").strip()
            self.assertEqual(fp_owner, fp_trustee, "barmaq izləri iki tərəfdə eyni olmalıdır")
            if email == "reshad@example.az":
                self.shot(aysel, "07-fingerprint-compare")
            aysel.check("#fp-ack")
            aysel.click(".modal button.brass")
            aysel.wait_for_selector(f"button[data-verify='{email}']", state="detached")
        aysel.select_option("#threshold", "2")
        aysel.click("#btn-distribute")
        aysel.wait_for_selector("text=Hər şey qaydasındadır")
        self.shot(aysel, "08-armed-active")

        # Vaxtından əvvəl təsdiq cəhdi — düymə ümumiyyətlə görünmür
        reshad, nigar = trustees["reshad@example.az"], trustees["nigar@example.az"]
        reshad.reload()
        reshad.fill("#unlock-password", PASSWORD)
        reshad.click("#unlock-submit")
        reshad.wait_for_selector("text=Hər şey qaydasındadır")
        self.assertEqual(reshad.locator("button:has-text('Açılmanı təsdiqlə')").count(), 0)
        self.shot(reshad, "09-trustee-active")

        # Operator: 61 gün
        op = self.new_page("Operator")
        self.register(op, "Sistem Operatoru", "operator@emanet.az")
        op.goto(self.base + "/#/admin")
        op.wait_for_selector("#demo-panel")
        op.click("#demo-31")
        op.wait_for_selector("text=+31 gün. Saat")
        aysel.goto(self.base + "/#/mail")
        aysel.wait_for_selector("#mailbox")
        self.shot(aysel, "10-reminder-email")
        op.click("#demo-30")
        op.wait_for_selector("text=Saat sürüşməsi: 61")
        self.shot(op, "11-operator-demo-clock")

        for p in (reshad, nigar):
            p.goto(self.base + "/#/trustee")
            p.reload()
            p.fill("#unlock-password", PASSWORD)
            p.click("#unlock-submit")
            p.wait_for_selector("text=uzun müddətdir cavab vermir")
        self.shot(reshad, "12-trustee-awaiting")
        for p in (reshad, nigar):
            p.click("button:has-text('Açılmanı təsdiqlə')")
            p.click(".modal button.brass")
            p.wait_for_timeout(500)
        nigar.wait_for_selector("text=Gözləmə müddəti")

        aysel.goto(self.base + "/#/vault")
        aysel.wait_for_selector("text=seyfin açılması gözlənilir")
        self.shot(aysel, "13-owner-pending-release")

        op.click("#demo-7")
        op.wait_for_selector("text=+7 gün")
        for p in (reshad, nigar):
            p.reload()
            p.fill("#unlock-password", PASSWORD)
            p.click("#unlock-submit")
            p.wait_for_selector("text=Seyf açılıb")
        self.shot(reshad, "14-released")

        # 1 hissə kifayət etmir
        vid = reshad.locator("[data-vault]").first.get_attribute("data-vault")
        reshad.click(f"#open-{vid}")
        reshad.wait_for_selector(f"#shares-{vid}")
        self.assertIn("1 / 2", reshad.inner_text(f"#shares-{vid}"))
        self.assertEqual(reshad.locator("#opened-vault").count(), 0)
        self.shot(reshad, "15-one-share-not-enough")

        # Nigar hissəsini ötürür → Rəşad açır
        nigar.click(f"#handoff-{vid}")
        nigar.wait_for_selector("text=şifrəli ötürüldü")
        reshad.click(f"#open-{vid}")
        reshad.wait_for_selector("#opened-vault")
        text = reshad.inner_text("#opened-vault")
        self.assertIn("PIN 4821", text)
        self.assertIn("Əzizlərim", text)
        self.shot(reshad, "16-vault-opened-by-two")

        # Audit zənciri
        aud = self.new_page("Auditor")
        self.register(aud, "Daxili Auditor", "auditor@emanet.az")
        subprocess.run([sys.executable, "-m", "emanet.cli", "grant-role", "auditor@emanet.az", "auditor"], cwd=ROOT,
                       env={**os.environ, "EMANET_DATA_DIR": str(self.tmp)}, check=True, capture_output=True)
        aud.goto(self.base + "/#/")
        aud.reload()
        aud.fill("#unlock-password", PASSWORD)
        aud.click("#unlock-submit")
        aud.click("#btn-logout")
        aud.fill("#login-email", "auditor@emanet.az")
        aud.fill("#login-password", PASSWORD)
        aud.click("#login-submit")
        aud.wait_for_selector("#audit-verdict")
        self.assertIn("Zəncir bütövdür", aud.inner_text("#audit-verdict"))
        self.shot(aud, "17-audit-chain-intact")

        # Mobil görünüş
        mob = self.browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2).new_page()
        mob.goto(self.base + "/")
        mob.fill("#login-email", "aysel@example.az")
        mob.fill("#login-password", PASSWORD)
        mob.click("#login-submit")
        mob.wait_for_selector("#hero-title")
        self.shot(mob, "18-mobile-owner")

        self.maxDiff = None
        self.assertEqual(self.console_errors, [], "brauzer konsolunda xəta olmamalıdır")


if __name__ == "__main__":
    unittest.main()
