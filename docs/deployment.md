# Yerləşdirmə bələdçisi

Üç variant var: lokal demo (5 dəqiqə), istənilən VPS (Docker + Caddy, real HTTPS), AWS (Terraform, tam istehsal stack-i).

## A. Lokal demo (komissiya qarşısında)

```bash
python3 -m pip install -r requirements.txt
EMANET_DEMO_MODE=1 EMANET_BOOTSTRAP_OPERATOR_EMAIL=operator@emanet.az \
  EMANET_DATA_DIR=./data-demo python -m emanet.app
# → http://127.0.0.1:8000
```

Demo addımları:
1. 4 brauzer pəncərəsi (və ya Chrome profili) açın: **Aysel** (sahib), **Rəşad**, **Nigar**, **Elvin** (etibarlı şəxslər), əlavə olaraq **operator@emanet.az**.
2. Aysel seyfə qeyd yazır və 3 nəfəri dəvət edir. Onlar qəbul edir.
3. Aysel hər birinin barmaq izini ekrandan müqayisə edir, sonra hissələri **2/3** həddi ilə paylayır.
4. Operator paneli: **+31 gün** düyməsi basılır, Ayselin "Poçt qutusu"na xatırlatma gəlir. Sonra **+30 gün** basılır və seyf "Etibarlı şəxslər gözlənilir" vəziyyətinə keçir.
5. Rəşad və Nigar açılmanı təsdiqləyir. Ayseldə qırmızı xəbərdarlıq görünür.
6. *(İstəyə bağlı)* Aysel "Sağam" düyməsini basır və hər şey ləğv olunur. Göstərdikdən sonra 4–5-ci addımları təkrarlayın.
7. **+7 gün** basılır və seyf açılır.
8. Rəşad "Seyfi aç" düyməsini basır: **1/2 — açılmır**. Nigar "Hissəmi ötür" düyməsini basır, sonra Rəşad yenə "Seyfi aç" düyməsini basır: **açılır**, Ayselin məktubu görünür.

Bu ssenari avtomatik olaraq `tests/e2e/test_browser.py`-da da işləyir. Ekran görüntüləri: `evidence/screenshots/`.

## B. İstənilən VPS (Docker, real HTTPS)

```bash
git clone https://github.com/USERNAME/emanet.git && cd emanet
cp .env.example .env    # DOMAIN, ACME_EMAIL, EMANET_PUBLIC_ORIGIN; KMS/S3 üçün "local" seçin
# Lokal KMS/storage ilə: EMANET_KMS_BACKEND=local, EMANET_STORAGE_BACKEND=local, EMANET_NOTIFIER=outbox
#   və EMANET_ENV=development (istehsal rejimi AWS KMS tələb edir)
docker compose --profile standalone up -d --build
```
Caddy Let's Encrypt sertifikatını avtomatik alır. Domen yoxdursa `DOMAIN=<IP>.sslip.io` yazın.

## C. AWS (Terraform)

**Ön şərtlər:** AWS hesabı, `aws configure sso`, Terraform ≥ 1.6. Kodu GitHub-a push edin.

```bash
cd infra/terraform/aws
cp terraform.tfvars.example terraform.tfvars    # e-poçtlar, repo_url, repo_ref
terraform init
terraform plan -out plan.tfplan                 # ← planın ekran görüntüsü hesabata
terraform apply plan.tfplan
terraform output url                            # https://<IP>.sslip.io
```

İlk açılış ~5 dəqiqə çəkir: paketlər, Docker obrazı, sertifikat. Sonra:
1. SNS abunəliyini təsdiqləyin (e-poçta gələn link).
2. SES göndərən ünvanını təsdiqləyin. SES sandbox-dadırsa, alıcı ünvanlarını da təsdiqləyin.
3. `alert_email` ilə qeydiyyatdan keçin. Bu hesab avtomatik operator olur.
4. Auditoru təyin edin: `aws ssm start-session --target <instance_id>` →
   `sudo docker compose -f /opt/emanet/docker-compose.yml exec app python -m emanet.cli grant-role auditor@... auditor`

### Hesabat üçün çəkiləcək ekran görüntüləri
| # | Harada | Nə görünməlidir |
|---|---|---|
| 1 | Brauzer | `https://…` — kilid ikonu, sertifikat (Let's Encrypt), TLS 1.3 |
| 2 | securityheaders.com | A+ qiymət (CSP, HSTS, …) |
| 3 | EC2 → Instance → Security | IMDSv2 "Required", key pair "—", IAM rolu |
| 4 | Security Group | Yalnız 80/443 |
| 5 | KMS → release açarı | Rotation "Enabled", key policy (admin-də Decrypt yoxdur) |
| 6 | S3 → vaults bucket → Properties | Versioning, Object Lock (Governance 30 gün), SSE-KMS |
| 7 | S3 → Permissions | Block public access 4/4, bucket policy |
| 8 | Secrets Manager | `emanet-prod/app` (dəyər göstərilmədən) |
| 9 | EventBridge Scheduler + Lambda | rate(1 hour), son çağırışlar uğurlu |
| 10 | CloudWatch → Alarms | 13+ alarm, OK vəziyyətində |
| 11 | CloudWatch → Dashboard | Təhlükəsizlik hadisələri qrafiki |
| 12 | CloudTrail → Event history | `Decrypt` hadisəsi, `EncryptionContext.vault_id` ilə |
| 13 | AWS Backup | Uğurlu gündəlik iş |
| 14 | GuardDuty | Aktiv, tapıntı yoxdur |
| 15 | Tətbiq | `/api/integrity` + `python scripts/verify_client.py https://…` → "Bütün fayllar uyğundur" |

### Xərc (təxmini, aylıq)
EC2 t3.small ~$17, EBS 20 GB ~$2, KMS 3 açar ~$3, Secrets Manager 2 sirr ~$1, CloudTrail (ilk trail pulsuz) + S3 ~$1, qalanları pulsuz həddə yaxındır. **Cəmi ≈ $25/ay.** AWS Free Tier ilə t3.micro seçsəniz, daha ucuz olur. Demo bitəndən sonra `terraform destroy` edin. Qeyd: S3 Object Lock olan bucket dərhal silinmir.
