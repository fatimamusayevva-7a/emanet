# Arxitektura

## Komponentlər və etibar sərhədləri

```mermaid
flowchart LR
  subgraph B[Brauzer — ETİBARLI ZONA]
    UI[UI · vanilla JS] --> WC[WebCrypto<br/>PBKDF2 · HKDF · AES-GCM · ECDH]
    WC --> SH[Shamir GF256]
  end
  subgraph AWS[AWS eu-central-1 — YARIM ETİBARLI: yalnız şifrəmətn görür]
    C[Caddy · TLS 1.3] --> A[Əmanət API · Flask]
    A --> DB[(SQLite: sarınmış açarlar,<br/>şifrəli hissələr, audit)]
    A --> S3[(S3 · Versioning + Object Lock)]
    A --> K[[KMS · R açarları]]
    A --> SM[[Secrets Manager]]
    A --> SES[SES]
    EB[EventBridge 1 saat] --> L[Lambda tick] -- HMAC --> A
    K -.-> CT[(CloudTrail)]
  end
  B -- HTTPS · cookie + CSRF --> C
```

**Əsas fikir:** server **yarım etibarlıdır** (honest-but-curious). O, düzgün işləyir, amma onun gördüyü heç nə seyfi açmağa kifayət etmir. Brauzer kodu etibar zonasındadır. Bu zonanın bütövlüyü CSP, Trusted Types və `/api/integrity` manifesti ilə qorunur (R-05).

## Açar iyerarxiyası və "iki açarlı kilid"

```
             ┌───────────── brauzer ─────────────┐        ┌──── server ────┐
parol ─PBKDF2(600k)─▶ MK ─HKDF─┬▶ auth_key ────────────────▶ Argon2id(auth)
                               └▶ enc_key ─┬─ AES-GCM ─▶ wrap(priv P-256)
                                           └─ AES-GCM ─▶ wrap(DEK, "owner")
                   DEK ─ AES-GCM ─▶ seyf (doldurulmuş, versiya AAD-da) ──────▶ S3
                   S ─Shamir(t,n)─▶ hissə_i ─ECIES(pub_i)─▶ ───────────────────▶ DB
                   R ◀──────────────────── KMS.GenerateDataKey ◀─── KMS
     KEK = HKDF(S ‖ R, salt=vault_id) ─ AES-GCM ─▶ wrap(DEK, "release") ──────▶ DB
```

| Kimdə nə var | Seyfi aça bilərmi? |
|---|---|
| Server (DB + KMS) | **Xeyr** — S yoxdur |
| t etibarlı şəxs, vaxtından əvvəl | **Xeyr** — R yoxdur |
| t−1 etibarlı şəxs + R | **Xeyr** — Shamir: t−1 hissə 0 bit verir |
| t etibarlı şəxs + R (RELEASED) | **Bəli** |
| Sahib (parol və ya bərpa kodu) | **Bəli**, həmişə |

Bunu `demos/03_two_key_lock.py` və `tests/test_zero_knowledge.py` sübut edir.

## "Sağam" vəziyyət maşını

```mermaid
stateDiagram-v2
  [*] --> setup
  setup --> active: hissələr paylandı
  active --> reminding: interval (30 gün)
  reminding --> awaiting: inactivity (60 gün)
  awaiting --> pending_release: ≥ t təsdiq
  pending_release --> released: waiting (7 gün)
  reminding --> active: sahib aktivdir
  awaiting --> active: sahib aktivdir (ləğv)
  pending_release --> active: sahib aktivdir (ləğv)
```

`emanet/switch.py` funksiyası **təmiz funksiyadır**: daxil olan seyf, vaxt və təsdiq sayıdır, çıxan yeni vəziyyət və görüləcək işlərdir. Bu sayədə invariantlar 990 kombinasiyalı şəbəkədə və 2 000 təsadüfi ssenaridə yoxlanılır (`tests/test_switch.py`).

## Açılma axını (sequence)

```mermaid
sequenceDiagram
  participant O as Sahib
  participant S as Server
  participant T1 as Etibarlı şəxs 1
  participant T2 as Etibarlı şəxs 2
  Note over O: 60 gün cavab yoxdur
  S->>T1: "tələb edə bilərsiniz" (e-poçt)
  T1->>S: approve
  T2->>S: approve → pending_release (7 gün)
  S->>O: TƏCİLİ: açılma {tarix}-də (link ilə ləğv)
  Note over S: 7 gün keçdi
  S->>T1: released
  T2->>S: GET /release → R, öz hissəsi (şifrəli)
  T2->>T2: hissəni aç, T1-in açıq açarına ECIES
  T2->>S: POST /handoffs
  T1->>S: GET /release → R, öz hissəsi, T2-dən gələn
  T1->>T1: 2 hissə → S → KEK → DEK → seyf
```

## Dizayn qərarları

| Qərar | Alternativ | Niyə bu |
|---|---|---|
| Hissələr brauzerdə birləşdirilir | Server birləşdirir | Server açıq hissəni görsə, zero-knowledge pozulur |
| ECDH P-256 | X25519 | Bütün brauzerlərin WebCrypto-sunda var |
| PBKDF2 (brauzer) + Argon2id (server) | Yalnız Argon2id | WebCrypto Argon2-ni dəstəkləmir. Xarici WASM isə təchizat zənciri riskidir (R-12) |
| SQLite (WAL) | RDS PostgreSQL | Tək instansiya, aşağı xərc, EBS snapshot. Miqyas lazım olduqda keçid asandır |
| EventBridge + Lambda planlaşdırıcısı | EC2-də cron | EC2 dayansa da planlaşdırma qalır, Lambda xətaları alarm verir |
| Lazy qiymətləndirmə + tick | Yalnız tick | Planlaşdırıcı dayansa da vəziyyət düzgün hesablanır |
| Vanilla JS, build yoxdur | React + npm | Audit ediləcək kod azdır, asılılıq yoxdur, CSP sadədir |
| Sessiya cookie-də, açarlar yaddaşda | JWT localStorage-də | XSS cookie-ni oxuya bilmir. Açarlar heç vaxt yaddaşdan kənara çıxmır |
