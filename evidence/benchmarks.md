# Ölçmələr (benchmark)

Yaradılıb: 2026-10-19 01:00 (Bakı) · Intel64 Family 6 Model 142 Stepping 9, GenuineIntel · Python 3.12.10 · Node v22.23.2

| Əməliyyat | Vaxt | Şərh |
|---|---|---|
| PBKDF2-SHA256, 600 000 iter. (Node WebCrypto — brauzer mühərriki) | **436 ms** | Giriş zamanı bir dəfə; istifadəçi hiss etmir |
| PBKDF2-SHA256, 600 000 iter. (Python/OpenSSL) | 456 ms | 1 nüvədə hücumçu: ≈ 2.2 təxmin/san |
| Argon2id m=19 MiB, t=2 (server, auth_key üzərində) | 71 ms | Onlayn hücum üçün əlavə qat |
| Adi SHA-256 (müqayisə üçün) | 2.70 µs | ≈ 370,756 təxmin/san |
| Shamir split(3) + combine(2), 32 bayt (JS) | 0.224 ms | Praktiki olaraq ani |

**Nəticə:** PBKDF2(600k) adi SHA-256-dan ≈ **169,059 dəfə** yavaşdır. 10 simvollu təsadüfi parol (70 simvollu əlifba,
2.82e+18 variant) üçün 1 nüvədə tam axtarış ≈ 4.1e+10 il çəkir. GPU fermasında bu müddət qısalır. Ona görə də
parol siyasəti 12+ simvol tələb edir və brauzerdə Argon2id-ə keçid yol xəritəsindədir (R-12).
