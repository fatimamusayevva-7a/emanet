# Məlumatların saxlanması və silinməsi (A.5.33, A.7.14, A.8.10)

| Məlumat | Saxlama müddəti | Silinmə üsulu |
|---|---|---|
| Seyf (aktiv) | Sahib silənə qədər | Crypto-shredding: sarınmış R, DEK-lər, hissələr DB-dən silinir (`secure_delete=ON`), obyektlər silinir |
| Seyfin köhnə versiyaları | 90 gün (Object Lock: ilk 30 gün silinmir) | Lifecycle qaydası. Açarlar silindiyi üçün bu müddətdə də oxunmazdır |
| Açılmış seyf | Açılmadan 1 il sonra | Sahibin əvvəlcədən seçimi; defolt: 1 il, sonra crypto-shred |
| Hesab (e-poçt, ad) | Hesab aktiv olduqca + sorğudan sonra 30 gün | DB-dən silinmə |
| Audit jurnalı | 7 il (vərəsəlik mübahisələrində sübut) | Arxivləşdirmə, sonra silinmə |
| Tətbiq logları (CloudWatch) | 365 gün | Avtomatik |
| CloudTrail | 7 il (90 gündən sonra Glacier) | Lifecycle |
| EBS snapshot-ları | 35 gün | AWS Backup |
| Sessiyalar, check-in tokenləri, sürət limiti qeydləri | 12 saat / 14 gün / 24 saat | Planlaşdırıcı təmizləyir |
| Outbox məktubları | 90 gün | Planlaşdırıcı |

## Crypto-shredding niyə kifayətdir
Silinmədən sonra S3-də qalan obyekt AES-256-GCM şifrəmətnidir. Onu açmaq üçün DEK lazımdır. DEK isə yalnız üç sarınmış formada mövcud olub və üçü də silinib. DEK-i bərpa etmək 2²⁵⁶ variantı yoxlamaq deməkdir. Bu yanaşma dəyişməz ehtiyat nüsxəni (ransomware-ə qarşı) və "unudulma hüququnu" barışdırır.

## Avadanlıq
Noutbuklar NIST SP 800-88 "Purge" səviyyəsində silinir (tam disk şifrələməsi + açarın məhvi). AWS daxilində mediaların məhvi AWS-in məsuliyyətidir.
