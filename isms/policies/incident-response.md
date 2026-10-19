# İnsidentlərə cavab planı (A.5.24–A.5.28, A.6.8)

## Ciddilik matrisi

| Səviyyə | Nümunə | Cavab müddəti | Kim çağırılır |
|---|---|---|---|
| **P1 — kritik** | Seyfin səhv açılması; KMS açarının kompromisi; zərərli JS dərc olunub | 15 dəq. | CISO, CEO, bütün komanda |
| **P2 — yüksək** | DB sızması; hesabların ələ keçirilməsi; planlaşdırıcı > 6 saat işləmir | 1 saat | CISO, operator |
| **P3 — orta** | Credential stuffing dalğası; BOLA cəhdləri; tək hesabın kilidlənməsi | 4 saat | Operator |
| **P4 — aşağı** | Tək uğursuz cəhdlər, skanerlər | Növbəti iş günü | Operator |

## Proses (NIST SP 800-61r2)
1. **Hazırlıq:** alarmlar (`infra/terraform/aws/monitoring.tf`), playbook-lar, əlaqə siyahısı.
2. **Aşkarlama və təhlil:** alarm və ya `security@` məktubu gəlir → növbətçi 15 dəq. ərzində triaj edir → ciddilik təyin olunur → insident kartı açılır.
3. **Məhdudlaşdırma, aradan qaldırma, bərpa:** aşağıdakı playbook-lara uyğun.
4. **Sonrakı fəaliyyət:** 5 iş günü ərzində günahlandırmayan post-mortem; risk reyestri yenilənir; lazım olarsa test əlavə edilir (A.5.27).

**Sübutlar (A.5.28):** `GET /api/audit` çıxışı və `audit/verify` nəticəsi, CloudTrail logları, EBS snapshot. Hər sübut faylının SHA-256 heşi insident kartına yazılır.

## Playbook-lar

### PB-01: Seyfin səhv açılması (sahib sağdır)
1. Sahibi eşidən hər kəs dərhal CISO-ya xəbər verir.
2. Audit jurnalından açılma zəncirini çıxar: kim təsdiqləyib, hansı xatırlatmalar göndərilib, `release.material_fetched` hadisələri.
3. Açılmış məlumat geri alına bilməz. Sahibə dərhal seyfdəki **bütün parolları dəyişməyi** tövsiyə et. Yeni seyf yaratmasına kömək et.
4. Kök səbəbi tap: e-poçt çatmayıb? Gözləmə müddəti qısa olub? Vəziyyət maşınında xəta var? Tapılan səbəb üçün regressiya testi yaz.
5. Nəticəni sahibə və etibarlı şəxslərə yazılı izah et. Lazım olarsa fərdi məlumat sızması kimi bildiriş göndər (PB-04).

### PB-02: KMS açarının kompromisi və ya icazəsiz Decrypt
1. CloudTrail-də `Decrypt` çağırışlarını `EncryptionContext.vault_id` üzrə filtrlə.
2. Şübhəli IAM sessiyasını ləğv et, rol siyasətinə müvəqqəti `Deny` əlavə et.
3. Yada sal: R təkbaşına seyfi açmır, S də lazımdır. Riski bu baxımdan qiymətləndir.
4. Yeni KMS açarı yarat, bütün R-ləri yenidən sar (`rewrap`), köhnə açarı deaktiv et.

### PB-03: Zərərli və ya dəyişdirilmiş brauzer kodu
1. `scripts/verify_client.py https://<sayt>` ilə canlı faylları repozitoriya ilə müqayisə et.
2. Uyğunsuzluq varsa, saytı dərhal **xidmət dayandırma səhifəsinə** keçir (Caddy `respond 503`).
3. Təsir pəncərəsini müəyyən et: həmin müddətdə daxil olan istifadəçilərin parolları kompromis sayılır. Onlara parol dəyişikliyi və yenidən paylanma tövsiyə olunur.
4. Təchizat zəncirini araşdır: GitHub commit-ləri, CI logları, konteyner obrazının heşi.

### PB-04: Fərdi məlumat sızması
1. Hansı məlumatın sızdığını müəyyən et. Seyf məzmunu sızmır (zero-knowledge). E-poçt, ad, etibar qrafı sıza bilər.
2. DPO **72 saat** ərzində səlahiyyətli orqana bildiriş verir. Yüksək risk varsa, subyektlərə də yazılır.
3. Sızmış sessiyaları ləğv et. Lazım olarsa HMAC sirlərini rotasiya et.

### PB-05: Hesabın ələ keçirilməsi / credential stuffing
1. `LoginFailures` və `AccountLocked` alarmlarını yoxla, IP-ləri WAF/SG ilə blokla.
2. Təsirlənən istifadəçilərin sessiyalarını ləğv et (`status=suspended` → `active`), MFA-nı aktivləşdirməyi tövsiyə et.
3. Diqqət: sahib dayandırıldığı müddətdə seyfi dondurulur (R-26), bu səbəbdən açılma riski yoxdur.

### PB-06: Planlaşdırıcı işləmir
1. `tick-missing` və ya `tick-errors` alarmı gəlir → Lambda loglarını və `/api/health`-dəki `last_tick_age_s`-i yoxla.
2. Müvəqqəti həll: SSM sessiyasında `python -m emanet.cli tick`.
3. Qeyd: vəziyyət hər oxumada lazy hesablanır, ona görə gecikmə yalnız e-poçtlara təsir edir. Seyf heç vaxt **tez** açılmır (fail-closed).

## Əlaqə siyahısı (A.5.5)
| Kim | Necə |
|---|---|
| CISO (növbətçi) | Telefon + SNS e-poçt |
| AWS Support | Konsol (Business plan) |
| CERT.az | Rəsmi saytdakı insident forması |
| Fərdi məlumatlar üzrə səlahiyyətli orqan | Rəsmi kanal (DPO) |
| Hüquqşünas | Müqavilə üzrə |

## Məlumat vermə (A.6.8)
Hər əməkdaş şübhəli hadisəni **1 saat** ərzində `security@` ünvanına yazmalıdır. Kənar tədqiqatçılar üçün `SECURITY.md`-də məsuliyyətli açıqlama qaydası var.
