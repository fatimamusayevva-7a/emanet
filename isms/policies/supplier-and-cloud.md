# Təchizatçılar və bulud xidmətləri (A.5.19–A.5.23)

## Təchizatçı reyestri

| Təchizatçı | Xidmət | Kritiklik | Məlumata girişi | Təminat | Baxış |
|---|---|---|---|---|---|
| Amazon Web Services | IaaS/PaaS (EC2, S3, KMS, …) | Kritik | Yalnız şifrəmətn və metadata; KMS HSM-də | ISO 27001/27017/27018, SOC 2 (AWS Artifact), DPA + SCC | İllik |
| GitHub | Mənbə kodu, CI | Yüksək | Kod (ictimai ola bilər), sirr yoxdur | SOC 2, 2FA məcburi | İllik |
| Let's Encrypt | TLS sertifikatı | Orta | Domen adı | Açıq CA, CT logları | — |
| PyPI paketləri (Flask, cryptography) | Kitabxana | Yüksək | Prosesdə işləyir | Dəqiq versiya, pip-audit, SBOM | Hər buraxılış |

## Bulud xidmətlərinin istifadəsi (A.5.23)
- **Region:** eu-central-1 (Frankfurt). Məlumat AB daxilində saxlanılır. Regionu dəyişmək üçün DPO-nun təsdiqi lazımdır.
- **Paylaşılan məsuliyyət:** `docs/shared-responsibility.md`.
- **Konfiqurasiya:** yalnız Terraform. Konsolda əl ilə edilən dəyişiklik drift sayılır və aylıq `terraform plan` ilə aşkarlanır.
- **Çıxış strategiyası (vendor lock-in):** tətbiq `LocalKMS`, `LocalStorage` və `OutboxNotifier` ilə istənilən VPS-də işləyir (docker compose `standalone` profili). AWS KMS-dən çıxmaq üçün R açarları yeni KMS ilə yenidən sarınır. Bu, sahiblərin iştirakını tələb etmir.
- **Müştəri tərəfli şifrələmə:** bulud provayderi kompromis olsa belə seyf məzmunu oxunmazdır. Buludda yalnız brauzerdə şifrələnmiş məlumat saxlanılır.

## Monitorinq (A.5.22)
AWS Health Dashboard bildirişləri SNS-ə gəlir. Kritik təchizatçı insidentində CISO 24 saat ərzində təsir qiymətləndirməsi aparır.
