# 🔏 Əmanət — rəqəmsal etibar seyfi

> Rəqəmsal həyatınızın açarlarını etibar etdiyiniz insanlara — **yalnız lazım olanda**.

**Fərdi layihə** · Azərbaycan Dövlət Neft və Sənaye Universiteti, Rəqəmsal Texnologiyalar fakültəsi · 2026–2027 payız semestri
Üç fənnin kəsişməsində: **Kriptoqrafiyanın əsasları** · **Bulud təhlükəsizliyi** · **İnformasiya təhlükəsizliyinin idarəedilməsi sistemləri (ISO/IEC 27001)**

![tests](https://img.shields.io/badge/tests-455%20passed-brightgreen) ![e2e](https://img.shields.io/badge/real%20browser%20E2E-passed-brightgreen) ![compliance](https://img.shields.io/badge/ISO%2027001%20checks-30%2F30-brightgreen) ![soa](https://img.shields.io/badge/Annex%20A-93%20controls-blue) ![crypto](https://img.shields.io/badge/Shamir%20·%20ECIES%20P--256%20·%20AES--256--GCM-informational)

---

## Problem
İnsan dünyasını dəyişəndə və ya ağır xəstələnəndə ailəsi onun bank, e-poçt, bulud və sosial media hesablarına çata bilmir. Parolları bir nəfərə vermək təhlükəlidir, kağıza yazmaq isə daha da təhlükəlidir. İri şirkətlərin "irs kontaktı" funksiyaları yalnız öz xidmətlərini əhatə edir.

## Həll
İstifadəçi vacib məlumatları **brauzerində şifrələnən** seyfə yazır və 2–7 etibarlı şəxs seçir. Seyf yalnız üç şərt **birlikdə** ödənəndə açılır:

1. sahib uzun müddət (defolt 60 gün) xatırlatmalara cavab vermir;
2. etibarlı şəxslərdən kifayət qədəri (məsələn, 3-dən 2-si) açılmanı təsdiqləyir;
3. sahibə verilən etiraz müddəti (defolt 7 gün) bitir. Bu müddətdə sahibin istənilən hərəkəti prosesi ləğv edir.

Server seyfin içini **heç vaxt** görmür. Açar iki hissədən ibarətdir:

```
KEK = HKDF-SHA256( S ‖ R )      S — Shamir ilə etibarlı şəxslər arasında bölünüb (server görmür)
                                R — KMS-də, yalnız vaxt şərti ödəniləndə buraxılır (etibarlı şəxslər görmür)
```

| Kim | Seyfi aça bilərmi? |
|---|---|
| Server, admin, DB-ni oğurlayan | ❌ (S yoxdur) |
| Bir etibarlı şəxs | ❌ (Shamir: 1 hissə 0 bit məlumat verir) |
| Bütün etibarlı şəxslər **vaxtından əvvəl** | ❌ (R yoxdur) |
| t etibarlı şəxs **vaxtı çatanda** | ✅ |
| Sahib özü | ✅ həmişə |

## Üç fənn layihədə necə birləşir

| Fənn | Mövzu | Reallaşdırma | Sübut |
|---|---|---|---|
| **Kriptoqrafiya** | Gizli bölgü | Shamir GF(2⁸), iki dildə (Python + JS) bayt-bayt uyğun | `tests/test_shamir.py`, `tests/js/` |
| | Yoxlanıla bilən bölgü | Feldman VSS, 2048-bit qrup (RFC 3526) | `demos/02_feldman_vss.py` |
| | Autentifikasiyalı şifrələmə | AES-256-GCM, AAD (seyf id + versiya + məqsəd) | `test_every_ciphertext_bit_flip_detected` |
| | Açıq açarla şifrələmə | ECIES = ECDH P-256 + HKDF + AES-GCM, invalid-curve qorunması | `Ecies` testləri |
| | Açar törətmə | PBKDF2 600k → HKDF açar ayrılığı (auth ≠ enc); Argon2id | `evidence/benchmarks.md` |
| | Bütövlük | Hissə öhdəlikləri (SHA-256), HMAC audit zənciri | `test_forged_share_detected_by_commitment` |
| | Metadata | Doldurma: ölçü qeydlərin sayını açmır | `demos/04_size_leak_and_padding.py` |
| | MITM | Açıq açar barmaq izinin ayrıca kanalda yoxlanması | `test_distribution_requires_verified_fingerprints` |
| **Bulud** | IaC | Terraform: VPC, EC2, S3, KMS, Secrets Manager, Lambda, EventBridge, SES, CloudWatch, CloudTrail, Backup, GuardDuty | `infra/terraform/aws/` |
| | IAM | Statik açar yoxdur; KMS şərti `EncryptionContext`; admin-ə `Decrypt` yoxdur | `kms.tf`, `iam.tf` |
| | Məlumat | S3 Versioning + **Object Lock** + SSE-KMS + TLS-only; crypto-shredding | `s3.tf` |
| | Hesablama | IMDSv2, SSH yoxdur (SSM), şifrəli EBS, auto-recover | `compute.tf` |
| | Serverless | EventBridge Scheduler → Lambda → HMAC imzalı tick | `scheduler.tf`, `infra/lambda/tick.py` |
| | Monitorinq | 9 metric filter, planlaşdırıcı və KMS alarmları, dashboard | `monitoring.tf` |
| | Konteyner | Root olmayan, read-only, cap_drop ALL, Caddy TLS 1.3 + HSTS | `Dockerfile`, `docker-compose.yml` |
| | DevSecOps | Testlər, Bandit, pip-audit, Gitleaks, Trivy, Checkov, SBOM | `.github/workflows/ci.yml` |
| **İTİS** | Kontekst, əhatə | Şərti şirkət "Əmanət MMC", maraqlı tərəflər, qanunvericilik | `isms/00-context-and-scope.md` |
| | Risk | Metodologiya + **27 risk**; qalıq ≤ iştah (8) | `isms/03-*`, `isms/04-risk-register.csv` |
| | SoA | **93 nəzarətin hamısı**: 84 tətbiq olunur, 9 əsaslandırılmış istisna | `isms/05-statement-of-applicability.csv` |
| | Siyasətlər | 9 siyasət + 6 insident playbook-u + DPIA | `isms/policies/`, `isms/06-dpia.md` |
| | Check | Compliance-as-code (30 yoxlama), daxili audit (tapıntılar → kod düzəlişi) | `compliance/`, `isms/08-internal-audit.md` |
| | Act | İdarəetmə təhlili, NIST CSF 2.0 xəritəsi | `isms/09-*`, `isms/10-*` |

## Sürətli başlanğıc

```bash
pip install -r requirements.txt
EMANET_DEMO_MODE=1 EMANET_BOOTSTRAP_OPERATOR_EMAIL=operator@emanet.az python -m emanet.app
# → http://127.0.0.1:8000   (demo ssenarisi: docs/deployment.md, A bölməsi)

python scripts/run_all.py                 # 455 test + demolar + benchmark + compliance → evidence/
python compliance/check_controls.py       # 30/30
node --test tests/js/*.test.mjs           # brauzer kriptoqrafiyası
```

Yerləşdirmə: [`docs/deployment.md`](docs/deployment.md) — lokal demo · istənilən VPS (Docker + Let's Encrypt) · AWS (Terraform).

## Testlər və sübutlar

| Dəst | Say | Nə sübut edir |
|---|---|---|
| Shamir + primitivlər | 109 | Riyazi düzgünlük, hər bitin dəyişdirilməsinin aşkarlanması, RFC 5869/6238/4231 vektorları |
| Vəziyyət maşını | 19 (990 + 2 000 ssenari daxilində) | Seyf heç vaxt vaxtından əvvəl açılmır |
| API təhlükəsizliyi | 58 | Auth, CSRF, BOLA, mass assignment, rate limit, vəzifə bölgüsü |
| Marşrut matrisi | 151 | **Hər** endpoint: auth, CSRF, Origin, başlıqlar, rol |
| Seyf qaydaları + axın | 43 | Paylanma, açılma, saxta hissə, R əvəzlənməsi, saxlama müddəti |
| Sıfır bilik | 4 | Serverin bütün diskində açıq mətn, açar, hissə, parol **yoxdur** |
| İnfrastruktur | 39 | KMS, AWS KMS imitasiyası, konfiqurasiya, planlaşdırıcı, Lambda (real HTTP) |
| Python ↔ JS | 6 + 12 | İki istiqamətli kriptoqrafik uyğunluq |
| JS vahid | 13 | WebCrypto implementasiyası |
| **Real brauzer E2E** | 1 (tam ssenari) | Chromium-da 6 istifadəçi, konsolda 0 xəta (CSP/Trusted Types daxil) |

Ətraflı: [`evidence/test-results.md`](evidence/test-results.md) · [`evidence/compliance-report.md`](evidence/compliance-report.md) · [`evidence/crypto-demos.md`](evidence/crypto-demos.md) · [`evidence/benchmarks.md`](evidence/benchmarks.md) · [`evidence/screenshots/`](evidence/screenshots/)

## Repozitoriyanın strukturu

```
emanet/                 Backend (Flask)
  crypto/               shamir · primitives (AES-GCM, ECIES, HKDF, PBKDF2) · passwords (Argon2id) · totp · audit_chain
  api/                  auth · vault · trustee · system
  switch.py             "sağam" vəziyyət maşını (təmiz funksiya)
  services.py · security.py · validation.py · audit.py · kms.py · storage.py · notify.py · config.py · cli.py
web/                    Brauzer: vanilla JS + WebCrypto, xarici asılılıq YOXDUR
  js/crypto.js · shamir.js · session.js · views-*.js · app.js
tests/                  430 Python + 25 JS test, e2e/test_browser.py (Playwright)
demos/                  4 kriptoqrafik demo
infra/terraform/aws/    13 fayl IaC · infra/lambda/tick.py · infra/Caddyfile
isms/                   kontekst · rollar · aktivlər · metodologiya · risklər · SoA · DPIA · məqsədlər · audit · təhlil · NIST CSF
isms/policies/          9 siyasət
compliance/             compliance-as-code (30 yoxlama)
docs/                   arxitektura · təhdid modeli · paylaşılan məsuliyyət · yerləşdirmə · runbook-lar
evidence/               avtomatik yaradılmış sübutlar + 18 ekran görüntüsü
project-management/     backlog (30 tapşırıq, fənn + Annex A + risk ilə)
```

## Məhdudiyyətlər (dürüst)

| Məhdudiyyət | Niyə | Plan |
|---|---|---|
| Server zərərli JS göndərsə, parol oğurlana bilər | Bütün veb zero-knowledge sistemlərinin ümumi problemidir | CSP + manifest + `verify_client.py` var; plan: imzalı brauzer genişlənməsi |
| Brauzerdə Argon2id yoxdur (PBKDF2 600k) | WebCrypto Argon2-ni dəstəkləmir | WASM Argon2id (R-12) |
| Məcburiyyət altında olan sahibi texnika qoruya bilmir | Sosial təhdiddir | Qəbul edilib (R-03), bütün dəyişikliklər jurnalda görünür |
| ECDH P-256 kvanta qarşı davamlı deyil | — | ML-KEM-768 hibrid (R-27) |
| E-poçt yeganə bildiriş kanalıdır | — | SMS (R-08) |
| SQLite, tək instansiya | Sadəlik, xərc | RDS, çox-AZ |
| Seyf vəsiyyətnamə deyil | Hüquqi status | İstifadə şərtlərində açıq bəyan (R-22) |
| AWS-ə real yerləşdirmə müəllif tərəfindən edilməlidir | Bu mühitdə AWS hesabı yoxdur | `docs/deployment.md` — addımlar və 15 ekran görüntüsü siyahısı |

## Mənbələr
- Shamir A. *How to Share a Secret.* CACM 22(11), 1979 · Feldman P. *A Practical Scheme for Non-interactive Verifiable Secret Sharing.* FOCS 1987
- Boneh D., Shoup V. *A Graduate Course in Applied Cryptography* · Katz J., Lindell Y. *Introduction to Modern Cryptography*
- NIST SP 800-38D (GCM), SP 800-56A (ECDH), SP 800-57 (açar idarəsi), SP 800-61r2 (insidentlər), SP 800-88 (silmə), FIPS 197, FIPS 203, CSF 2.0
- RFC 5869 (HKDF), 8018 (PBKDF2), 9106 (Argon2), 6238 (TOTP), 4231 (HMAC), 3526 (MODP qrupları), 8446 (TLS 1.3)
- ISO/IEC 27001:2022, 27002:2022, 27005:2022, 27017, 27701 · OWASP ASVS 4.0, Password Storage Cheat Sheet · CIS AWS Foundations
- W3C Web Cryptography API, Trusted Types, Content Security Policy Level 3 · AWS KMS, S3 Object Lock sənədləri

---
*Müəllif: ______________ · Qrup: ______ · Rəhbər: Həsənli X.F. · Lisenziya: MIT*
