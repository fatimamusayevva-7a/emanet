# Rəhbərlik, rollar və məsuliyyətlər (ISO 27001 bənd 5, A.5.2–A.5.4)

## Rəhbərliyin öhdəliyi
CEO İTİS siyasətini təsdiqləyir, illik təhlükəsizlik büdcəsini ayırır (gəlirin ≥ 10%-i) və **risk iştahını** müəyyən edir:
- qalıq risk balı **≤ 8** (5×5 şkalası üzrə) olan risklər qəbul edilə bilər;
- **9–14** üçün müddətli müalicə planı və CEO imzası tələb olunur;
- **≥ 15** qəbul edilmir, xidmət dayandırılır və ya funksiya söndürülür.

## Rollar

| Rol | Kim | Əsas məsuliyyət | Texniki sərhəd |
|---|---|---|---|
| CEO / risk sahibi | Təsisçi | Risk qəbulu, büdcə, idarəetmə təhlili | AWS-də yalnız billing və break-glass |
| CISO + DPO | 1 nəfər | Siyasətlər, risk reyestri, DPIA, insident koordinasiyası | AWS SecurityAudit (yalnız oxuma) |
| İnkişaf etdirici | 2 nəfər | Təhlükəsiz kod, testlər, review | İstehsala birbaşa giriş yoxdur, yalnız PR |
| Operator (DevOps) | 1 nəfər | Yerləşdirmə, monitorinq, istifadəçi dəstəyi | Tətbiqdə `operator` rolu: istifadəçi metadata-sı. Audit jurnalı, seyf məzmunu, R açarları ona əlçatmazdır |
| Daxili auditor | Yarımştat | Audit, zəncirin yoxlanması, uyğunluq | Tətbiqdə `auditor` rolu: yalnız oxuma, idarəetmə yoxdur |

## RACI — əsas proseslər

| Proses | CEO | CISO | Dev | Operator | Auditor |
|---|---|---|---|---|---|
| Risk qiymətləndirməsi | A | R | C | C | I |
| SoA və siyasətlər | A | R | C | C | C |
| Kod dəyişikliyi | I | C | R | C | I |
| Yerləşdirmə | I | C | C | R/A | I |
| İnsident cavabı | I | A | R | R | I |
| Səhv açılma insidenti (P1) | A | R | R | R | I |
| Daxili audit | I | C | I | I | R/A |
| İdarəetmə təhlili | A/R | R | I | I | C |
| Açar rotasiyası | I | A | C | R | I |

R — icra edir, A — cavabdehdir, C — məsləhət verir, I — məlumatlandırılır.

## Niyə heç kim seyfi aça bilmir (texniki vəzifə bölgüsü)
Kiçik komandada inzibati qaydalar kifayət deyil, ona görə bölgü **riyazi** təmin olunur:
1. Seyf məzmunu istifadəçinin brauzerində şifrələnir və açarı serverə getmir.
2. Açılma üçün S lazımdır: o, etibarlı şəxslər arasında Shamir ilə bölünüb.
3. R açarı KMS-dədir. KMS açar siyasəti admin-ə `Decrypt` icazəsi vermir, tətbiq rolu isə yalnız `EncryptionContext` ilə istifadə edə bilir.
4. Açılmanı məcbur edən endpoint yoxdur (`tests/test_api_security.py::test_no_endpoint_lets_operator_force_release`).
5. Operator sahibin hesabını dayandırsa, seyf "dondurulur" və açılmır (R-26).
