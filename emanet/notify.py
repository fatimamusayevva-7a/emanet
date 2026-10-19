"""Bildirişlər: xatırlatmalar, xəbərdarlıqlar, açılma bildirişləri.

Bütün məktublar əvvəlcə `outbox` cədvəlinə yazılır (transactional outbox
nümunəsi): vəziyyət dəyişikliyi və bildiriş eyni tranzaksiyadadır, deməli
"vəziyyət dəyişdi, amma məktub itdi" halı olmur. Sonra `deliver_pending`
onları göndərir (SES) və ya inkişaf mühitində sadəcə "göndərilmiş" sayır.

Məktublarda seyfin məzmunu və ya açarlar heç vaxt olmur.
"""
from __future__ import annotations

import logging

log = logging.getLogger("emanet.notify")

TEMPLATES = {
    "welcome": ("Əmanət-ə xoş gəlmisiniz",
                "Salam, {name}! Hesabınız yaradıldı. Bərpa kodunuzu kağızda, təhlükəsiz yerdə saxlayın."),
    "trustee_invited": ("{owner} sizi etibarlı şəxs seçdi",
                        "{owner} sizi Əmanət seyfi üçün etibarlı şəxs təyin etmək istəyir. "
                        "Qəbul etmək üçün daxil olun: {origin}/#/trustee"),
    "reminder": ("Əmanət: hər şey qaydasındadır?",
                 "Salam, {name}! Son {days} gündür aktivlik görmürük. Bir kliklə təsdiqləyin: {link}"),
    "final_warning": ("ƏMANƏT: son xəbərdarlıq",
                      "{name}, {days} gündür cavab yoxdur. Etibarlı şəxslər artıq seyfin açılmasını "
                      "tələb edə bilər. Əgər hər şey qaydasındadırsa, dərhal təsdiqləyin: {link}"),
    "trustees_may_request": ("{owner}: seyfin açılması tələb oluna bilər",
                             "{owner} {days} gündür cavab vermir. Zəruri hesab edirsinizsə, "
                             "açılma tələbini təsdiqləyin: {origin}/#/trustee"),
    "release_pending": ("TƏCİLİ: seyfinizin açılması {date} tarixində baş verəcək",
                        "{name}, etibarlı şəxslər seyfinizin açılmasını təsdiqlədi. Əgər bu səhvdirsə, "
                        "{date} tarixinə qədər istənilən vaxt daxil olun və ya bu linkə basın: {link}"),
    "release_pending_trustee": ("{owner}: gözləmə müddəti başladı",
                                "Tələb qəbul olundu. {date} tarixində, sahib etiraz etməsə, seyf açılacaq."),
    "release_cancelled": ("{owner}: açılma ləğv edildi",
                          "Sahib aktivlik göstərdi və açılma prosesi ləğv olundu. Təsdiqlər sıfırlandı."),
    "released": ("{owner}: seyf açıldı", "Seyf açıldı. Hissənizi təqdim etmək üçün daxil olun: {origin}/#/trustee"),
    "released_owner": ("Əmanət: seyfiniz açıldı", "Seyfiniz etibarlı şəxslər üçün açıldı."),
    "premature_attempt": ("Əmanət: vaxtından əvvəl açılma cəhdi",
                          "{trustee} seyfinizin açılmasını vaxtından əvvəl tələb etməyə cəhd etdi. Cəhd rədd edildi."),
    "account_locked": ("Əmanət: hesab müvəqqəti bloklandı",
                       "Çoxlu uğursuz giriş cəhdi səbəbindən hesabınız 15 dəqiqəlik bloklandı."),
    "recovered": ("Əmanət: hesab bərpa kodu ilə bərpa olundu",
                  "Hesabınızın parolu bərpa kodu ilə dəyişdirildi. Bu siz deyilsinizsə, dərhal bizə yazın."),
}


class _Safe(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def render(kind: str, **params) -> tuple[str, str]:
    subject, body = TEMPLATES[kind]
    return subject.format_map(_Safe(params)), body.format_map(_Safe(params))


def enqueue(conn, to_email: str, kind: str, now: float, **params) -> None:
    subject, body = render(kind, **params)
    conn.execute("INSERT INTO outbox(to_email, kind, subject, body, created_at) VALUES(?,?,?,?,?)",
                 (to_email, kind, subject, body, now))


class OutboxNotifier:
    """İnkişaf/demo: məktublar yalnız DB-də qalır (UI-da "Poçt qutusu" kimi görünür)."""
    name = "outbox"

    def send(self, to_email: str, subject: str, body: str) -> None:
        log.info("məktub (outbox): to=%s subject=%s", to_email, subject)


class SesNotifier:
    name = "ses"

    def __init__(self, sender: str, region: str, client=None):
        self.sender = sender
        if client is None:
            import boto3
            client = boto3.client("sesv2", region_name=region)
        self.client = client

    def send(self, to_email: str, subject: str, body: str) -> None:
        self.client.send_email(FromEmailAddress=self.sender, Destination={"ToAddresses": [to_email]},
                               Content={"Simple": {"Subject": {"Data": subject, "Charset": "UTF-8"},
                                                   "Body": {"Text": {"Data": body, "Charset": "UTF-8"}}}})


def build_notifier(settings):
    if settings.notifier_backend == "ses":
        return SesNotifier(settings.ses_sender, settings.aws_region)
    return OutboxNotifier()


def deliver_pending(db, notifier, now: float, limit: int = 100) -> int:
    rows = db.all("SELECT id, to_email, subject, body FROM outbox WHERE sent_at IS NULL ORDER BY id LIMIT ?", (limit,))
    sent = 0
    for r in rows:
        try:
            notifier.send(r["to_email"], r["subject"], r["body"])
            with db.tx() as c:
                c.execute("UPDATE outbox SET sent_at=?, error=NULL WHERE id=?", (now, r["id"]))
            sent += 1
        except Exception as exc:  # növbəti tick-də yenidən cəhd
            with db.tx() as c:
                c.execute("UPDATE outbox SET error=? WHERE id=?", (type(exc).__name__, r["id"]))
    return sent
