# Biznesin davamlılığı və İKT hazırlığı (A.5.29, A.5.30, A.8.13, A.8.14)

## Biznes təsirinin təhlili (BIA)

| Funksiya | Fasilənin təsiri | RTO | RPO |
|---|---|---|---|
| Seyfin açılması (released → material) | Vərəsələr gözləyir; günlərlə gecikmə qəbul ediləndir, məlumat itkisi isə yox | 24 saat | 0 (məlumat itkisi qəbul edilmir) |
| "Sağam" düyməsi və giriş | Sahib aktivliyini göstərə bilmir. Bu müddət çox uzansa səhv açılma riski yaranır | **4 saat** | 24 saat |
| Planlaşdırıcı və bildirişlər | Xatırlatmalar gecikir | 6 saat | — |
| Seyf məzmununun redaktəsi | Narahatlıq | 24 saat | 24 saat |

**Vacib dizayn qərarı:** sistemin dayanması **heç vaxt** seyfin tez açılmasına səbəb olmur. Bunun səbəbi var: gözləmə müddəti real vaxta bağlıdır, amma açılma üçün sahibin uzun müddət cavab verməməsi və insanların razılığı da lazımdır. Uzun fasilədən sonra (məsələn, 2 gün) idarəetmə qərarı ilə bütün seyflərə **avtomatik pauza** tətbiq olunur. Pauza müddəti fasilə müddəti + 7 gündür (RB-05).

## Ehtiyat nüsxələr
| Nə | Necə | Saxlama | Dəyişməzlik |
|---|---|---|---|
| Seyf obyektləri | S3 Versioning | Cari + 90 gün köhnə versiyalar | Object Lock GOVERNANCE 30 gün |
| SQLite DB (EBS) | AWS Backup gündəlik 03:00 | 35 gün | Backup Vault Lock (min 7 gün) |
| Sirlər | Secrets Manager | Versiyalı | 30 günlük bərpa pəncərəsi |
| İnfrastruktur | Terraform kodu (GitHub) | Tam tarixçə | — |
| KMS açarları | AWS tərəfindən idarə olunur | — | 30 günlük silinmə pəncərəsi |

## Bərpa ssenariləri
1. **EC2 nasazdır:** auto-recover alarmı instansiyanı başqa hosta köçürür (avtomatik, ~5 dəq.).
2. **EBS və ya DB korlanıb:** son snapshot-dan yeni həcm yaradılır (`docs/runbooks.md` RB-04), ~1 saat.
3. **AZ və ya region itib:** başqa regionda `terraform apply` + snapshot-un kopyası + S3 obyektləri. Qeyd: S3 CRR v1.1-də planlaşdırılıb. Hazırda bu ssenari üçün RTO ~8 saatdır və risk qəbul edilib (R-21).
4. **Ransomware və ya səhv silinmə:** S3-də obyektin əvvəlki versiyası bərpa olunur, Object Lock silinməni bloklayır.

## Test
Bərpa testi **rüblük** aparılır: snapshot-dan staging mühiti qurulur, `audit/verify` yoxlanılır, test seyfi açılır. Nəticə 07-objectives faylında O-8 kimi qeyd edilir.
