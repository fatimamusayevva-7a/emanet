# Paylaşılan məsuliyyət modeli

| Qat | AWS | Əmanət | İstifadəçi |
|---|---|---|---|
| Fiziki data mərkəzi, aparat, şəbəkə avadanlığı | **●** | | |
| Hipervizor, KMS HSM-ləri, S3 davamlılığı | **●** | | |
| EC2 əməliyyat sistemi, yeniləmələr (IaaS) | | **●** (dnf-automatic) | |
| Docker, Caddy, tətbiq kodu | | **●** | |
| Şəbəkə konfiqurasiyası (VPC, SG) | alətlər | **●** konfiqurasiya | |
| IAM rolları, KMS açar siyasəti | alətlər | **●** | |
| S3 konfiqurasiyası (public block, Object Lock) | alətlər | **●** | |
| Lambda icra mühiti (PaaS/FaaS) | **●** | kod | |
| Seyf məzmununun şifrələnməsi | | brauzer kodu | **●** (parolu) |
| Master parol və bərpa kodu | | | **●** |
| Etibarlı şəxslərin seçimi, barmaq izi yoxlaması | | alət | **●** |
| İstifadəçinin cihazının təhlükəsizliyi | | | **●** |

## Xidmət modelləri

| AWS xidməti | Model | Nəyə görə məsuliyyət daşıyırıq |
|---|---|---|
| EC2 | IaaS | ƏS, paketlər, konteynerlər, firewall |
| S3, KMS, Secrets Manager, SES | PaaS (idarə olunan) | Konfiqurasiya, IAM, şifrələmə parametrləri |
| Lambda + EventBridge Scheduler | FaaS | Funksiya kodu, rol, mühit dəyişənləri |
| CloudTrail, CloudWatch, GuardDuty, Backup | PaaS | Aktivləşdirmə, saxlama, alarm qaydaları |
| GitHub | SaaS | Hesab təhlükəsizliyi, branch protection |

## Fiziki nəzarətlər (Annex A 7.x) niyə "tətbiq olunmur"
A.7.1, 7.2, 7.4–7.6 və 7.11–7.12 AWS data mərkəzlərinə aiddir. AWS-in ISO/IEC 27001 sertifikatı və SOC 2 hesabatı **AWS Artifact**-dan yüklənib təchizatçı faylına əlavə olunur. Ofis üçün (A.7.3, 7.7–7.10, 7.13–7.14) nəzarətlər tətbiq olunur.
