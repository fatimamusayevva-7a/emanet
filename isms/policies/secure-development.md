# Təhlükəsiz inkişaf siyasəti (A.8.4, A.8.8, A.8.25–A.8.33)

## Həyat dövrü
1. **Tələb:** hər funksiya üçün "sui-istifadə ssenarisi" yazılır. Məsələn: "etibarlı şəxs vaxtından əvvəl açmaq istəyir".
2. **Dizayn:** təhdid modeli (`docs/threat-model.md`) yenilənir, kriptoqrafik dəyişikliklər CISO ilə razılaşdırılır.
3. **Kod:** qaydalar aşağıdadır. PR-da ən azı 1 review tələb olunur, kriptoqrafik kodda 2.
4. **Test:** hər təhlükəsizlik nəzarətinin testi var. Test yoxdursa, nəzarət də "tətbiq olunub" sayılmır.
5. **CI:** testlər, Bandit (SAST), pip-audit (SCA), Gitleaks, Trivy (IaC və obraz), Checkov, SBOM. Kritik tapıntı merge-i bloklayır.
6. **Buraxılış:** imzalı git tag, obraz heşi qeyd olunur, `/api/integrity` manifesti buraxılış qeydlərinə əlavə edilir.

## Kodlaşdırma qaydaları (A.8.28)
- Bütün API girişləri `emanet/validation.py` ilə **icazə siyahısı** üzrə yoxlanılır. Naməlum sahə rədd edilir və təhlükəsizlik hadisəsi yazılır.
- SQL yalnız parametrləşdirilmiş sorğularla yazılır.
- Brauzerdə `innerHTML`, `eval`, `document.write`, inline script və style qadağandır. CSP və Trusted Types bunu brauzer səviyyəsində məcbur edir.
- Sirlərin müqayisəsi sabit zamanlıdır (`hmac.compare_digest`).
- Xəta mesajlarında stack trace, SQL və fayl yolu olmur.
- Audit metadata-sına sirr adlı açarlar yazmaq mümkün deyil (`AuditLeakError`).
- Yeni asılılıq üçün CISO təsdiqi lazımdır. Brauzerdə xarici kitabxana yoxdur, yalnız WebCrypto.

## Mühitlər (A.8.31) və test məlumatı (A.8.33)
- `development` (lokal), `staging` (ayrıca AWS hesabı), `production`. İstehsal konfiqurasiyası kodda yoxlanılır: demo rejimi, HTTP origin, lokal KMS istehsalda işə düşmür.
- Testlər yalnız sintetik məlumatdan istifadə edir. İstehsal məlumatı heç vaxt test mühitinə köçürülmür. Onsuz da şifrəli olduğu üçün testdə faydasızdır.

## Zəifliklərin idarəsi (A.8.8)
| Ciddilik (CVSS) | Bağlanma müddəti |
|---|---|
| Kritik (9.0+) | 7 gün |
| Yüksək (7.0–8.9) | 30 gün |
| Orta | 90 gün |

## Kənar inkişaf (A.8.30)
Hazırda yoxdur. Gələcəkdə olarsa, bu siyasətin tələbləri müqaviləyə daxil edilir və kod eyni CI-dan keçir.

## Dəyişiklik idarəsi (A.8.32)
`main` qorunur: PR, yaşıl CI və review olmadan dəyişiklik edilmir. İnfrastruktur dəyişikliyi üçün `terraform plan` çıxışı PR-a əlavə edilir. Təcili düzəliş (hotfix) sonradan 24 saat ərzində review olunur.
