# Təhdid modeli (STRIDE) və təhlükəsizlik tələbləri

## Hücumçular
| Kim | İmkanı | Məqsədi |
|---|---|---|
| H1 · Kənar hücumçu | İnternetdən sorğular, oğurlanmış parollar | Hesabı ələ keçirmək, seyfi oxumaq |
| H2 · Maraqlı etibarlı şəxs | Qanuni hesab, öz hissəsi | Seyfi vaxtından əvvəl açmaq |
| H3 · Sui-qəsd edən t etibarlı şəxs | t hissə | Eyni |
| H4 · Daxili operator | Tətbiqdə operator rolu, SSM girişi | Seyfi oxumaq, açılmaya səbəb olmaq |
| H5 · Kompromis olmuş server | DB, KMS istifadəsi, cavabları dəyişmək | Məzmun, açıq açarların əvəzlənməsi |
| H6 · Təchizat zənciri | Asılılıq paketi, CI | Zərərli kod |

## STRIDE

| Kateqoriya | Təhdid | Hücumçu | Nəzarət | Test / sübut |
|---|---|---|---|---|
| **S**poofing | Başqasının adından giriş | H1 | Zero-knowledge auth, Argon2id, TOTP, kilidləmə | `test_api_security.py::Authentication` |
| S | Server saxta açıq açar qoyur (MITM) | H5 | Barmaq izinin ayrıca kanalda müqayisəsi məcburidir | `test_distribution_requires_verified_fingerprints` |
| S | Planlaşdırıcıdan saxta tick | H1 | HMAC imza, ±300 s, replay qorunması | `test_infra.py::Scheduler` |
| **T**ampering | Seyf obyektinin dəyişdirilməsi | H5 | AES-GCM + AAD (vault_id, versiya) | `test_vault_box_cannot_be_replayed_as_other_version` |
| T | Saxta Shamir hissəsi | H2 | SHA-256 öhdəlik → saxtakar nömrəsi ilə aşkarlanır | `test_forged_share_detected_by_commitment` |
| T | R-in dəyişdirilməsi | H5 | GCM teqi fail-closed | `test_server_swapped_release_key_fails_closed` |
| T | Audit jurnalının dəyişdirilməsi | H4 | HMAC zənciri + CloudTrail | `test_chain_detects_db_tampering` |
| **R**epudiation | "Mən təsdiqləməmişəm" | H2 | Hər təsdiq audit zəncirindədir və sahibə görünür | `test_activity_log_visible_to_owner` |
| **I**nformation disclosure | DB sızması | H1/H5 | Server yalnız şifrəmətn saxlayır | `test_zero_knowledge.py` |
| I | Seyfin ölçüsündən nəticə çıxarmaq | H5 | Doldurma (4 KiB / 64 KiB) | `demos/04_size_leak_and_padding.py` |
| I | Hesabın varlığının aşkarlanması | H1 | Saxta, amma sabit salt; vaxt bərabərləşdirmə | `test_prelogin_does_not_reveal_existence` |
| I | XSS ilə açar oğurluğu | H1 | CSP + Trusted Types, innerHTML yoxdur | `SecurityHeaders`, E2E konsol xətası yoxdur |
| I | Etibarlı şəxs sahibin aktivliyini izləyir | H2 | Yalnız vəziyyət göstərilir | `test_trustee_view_hides_owner_activity` |
| **D**enial of service | Planlaşdırıcı dayanır | — | Lambda alarmları, lazy qiymətləndirmə | `test_lazy_evaluation_without_scheduler` |
| D | Sahibin hesabının dayandırılması ilə açılma | H4 | Seyf dondurulur | `OperatorCannotCauseRelease` |
| D | Böyük sorğular, brute-force | H1 | 8 MiB limit, sürət limiti | `test_body_too_large`, `RateLimits` |
| **E**levation of privilege | `role` sahəsi ilə qeydiyyat | H1 | Allowlist validasiya | `test_mass_assignment_rejected_and_logged` |
| E | Başqasının seyfinə çatmaq (BOLA) | H1 | Sessiya ilə məhdud sorğular, 404 | `ObjectLevelAuthorization` |
| E | Vaxtından əvvəl açılma | H2/H3 | İki açarlı kilid + vəziyyət maşını | `test_premature_approval_rejected_and_owner_notified`, `Invariants` |
| E | Operator açılmanı məcbur edir | H4 | Belə endpoint yoxdur, KMS admin Decrypt-siz | `test_no_endpoint_lets_operator_force_release` |

## Qəbul edilmiş qalıq təhdidlər
1. **Zərərli JS (H5/H6):** server kodu dəyişdirsə, növbəti girişdə parol oğurlana bilər. Bu, bütün veb zero-knowledge sistemlərinin ümumi məhdudiyyətidir. Azaldıcı tədbirlər: CSP, manifest, `verify_client.py`. Plan: imzalı brauzer genişlənməsi.
2. **Məcburiyyət (R-03):** zor altında olan sahibi texnika qoruya bilmir.
3. **Kvant (R-27):** P-256 uzunmüddətli perspektivdə.

## Tətbiq təhlükəsizliyi tələbləri (OWASP ASVS 4.0 L2-dən seçmə)

| ASVS | Tələb | Vəziyyət |
|---|---|---|
| V2.1.1 | Parol ≥ 12 simvol | ✓ (brauzer siyasəti) |
| V2.2.1 | Brute-force qorunması | ✓ sürət limiti + kilidləmə |
| V2.4.1 | Parollar güclü adaptiv heşlə saxlanılır | ✓ Argon2id (auth_key üzərində) |
| V2.8.1 | TOTP | ✓ RFC 6238, replay qorunması |
| V3.4.1–3 | Cookie: Secure, HttpOnly, SameSite | ✓ `__Host-` prefiksi |
| V3.3.1 | Çıxışda sessiya ləğvi | ✓ |
| V4.2.1 | BOLA qorunması | ✓ |
| V5.1.3 | Giriş validasiyası allowlist ilə | ✓ |
| V6.2.1 | Təsdiqlənmiş kriptoqrafik modullar | ✓ PyCA cryptography, WebCrypto |
| V6.2.5 | Təhlükəsiz olmayan rejimlər yoxdur (ECB və s.) | ✓ |
| V7.1.1 | Loglarda sirr yoxdur | ✓ `AuditLeakError` |
| V8.3.1 | Həssas məlumat URL-də deyil | ✓ check-in tokeni fraqmentdə |
| V13.2.3 | CSRF qorunması | ✓ iki qat |
| V14.4.3 | CSP | ✓ Trusted Types daxil |
