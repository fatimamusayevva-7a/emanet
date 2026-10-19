# Daxili audit proqramı (ISO 27001 9.2, A.5.35, A.8.34)

## Proqram
- İllik plan: bütün bəndlər (4–10) və Annex A nəzarətləri 12 ay ərzində ən azı bir dəfə yoxlanılır. Yüksək riskli sahələr (açar idarəsi, vəziyyət maşını, giriş) **rüblük** yoxlanılır.
- Auditor yoxladığı işi özü görməyib (müstəqillik). Tətbiqdə `auditor` rolu yalnız oxuya bilir.
- Texniki yoxlamalar istehsalda yalnız oxuma rejimində aparılır. Pentest staging mühitində, yazılı razılıq və vaxt pəncərəsi ilə aparılır (A.8.34).
- Hər auditdən sonra hesabat: uyğunsuzluq (böyük/kiçik), müşahidə, yaxşılaşdırma imkanı.

## Rüblük yoxlama siyahısı (qısa)
1. `GET /api/audit/verify` → `intact: true`; CloudTrail digest fayllarının `aws cloudtrail validate-logs` ilə yoxlanılması.
2. Giriş hüquqları icmalı: operator/auditor rollarının siyahısı, AWS IAM istifadəçiləri (statik açar olmamalıdır).
3. KMS: rotasiya aktivdir, açar siyasətində admin üçün `Decrypt` yoxdur.
4. S3: Object Lock aktivdir, public access block 4/4.
5. `compliance/check_controls.py` hesabatı: hamısı PASS.
6. Bərpa testi (RB-04) aparılıb və nəticə qeyd olunub.
7. Risk reyestrində son baxış tarixi ≤ 90 gün.

## İlk daxili audit — 2026-10 (pilot)

**Əhatə:** A.5.3, A.5.15, A.5.17, A.8.5, A.8.13, A.8.15, A.8.24, A.8.25, A.8.29; bənd 6.1, 8.2.
**Metod:** sənəd icmalı, kod review, testlərin icrası, konfiqurasiya yoxlaması.

| # | Tapıntı | Növ | Nəzarət | Düzəldici tədbir | Status |
|---|---|---|---|---|---|
| F-1 | Operator sahibin hesabını dayandırsa, sahib "sağam" deyə bilmir və seyf səhvən açıla bilərdi | **Böyük uyğunsuzluq** | A.5.3 | Dayandırılmış sahibin seyfi dondurulur, dondurma müddəti hərəkətsizlik sayılmır; regressiya testi əlavə edildi (`OperatorCannotCauseRelease`) | **Bağlanıb** |
| F-2 | Demo saatı sessiyaların ömrünə də təsir edirdi (sessiyalar biznes saatı ilə ölçülürdü) | Kiçik uyğunsuzluq | A.8.5 | Sessiya və sürət limitləri real divar saatına keçirildi (`security.wall_now`) | **Bağlanıb** |
| F-3 | Rədd edilən sorğularda təhlükəsizlik hadisəsi tranzaksiya ilə birlikdə geri qaytarılırdı (ROLLBACK) | Kiçik uyğunsuzluq | A.8.15 | "Deferred event" mexanizmi: hadisələr ayrıca tranzaksiyada yazılır; testlə yoxlanılır | **Bağlanıb** |
| F-4 | Brauzerdə Argon2id yoxdur (WebCrypto dəstəkləmir), PBKDF2 istifadə olunur | Müşahidə | A.8.24 | R-12 kimi qəbul edilib; yol xəritəsi: WASM Argon2id | Açıq (plan) |
| F-5 | JS kodunun bütövlüyü istifadəçi tərəfindən avtomatik yoxlanılmır | Müşahidə | A.8.25 | `scripts/verify_client.py` + manifest; yol xəritəsi: imzalı brauzer genişlənməsi | Açıq (plan) |
| F-6 | E-poçt yeganə bildiriş kanalıdır | Yaxşılaşdırma imkanı | A.8.14 | SMS və ya push ikinci kanal (v1.2) | Açıq (plan) |

**Nəticə:** İTİS tətbiq olunub və effektivdir. Böyük uyğunsuzluq auditin özündə aşkarlanıb, düzəldilib və testlə təsdiqlənib.
