# İTİS: kontekst, maraqlı tərəflər və əhatə dairəsi

| | |
|---|---|
| **Təşkilat** | Əmanət Rəqəmsal Xidmətlər MMC (təlim ssenarisi üçün şərti şirkət) |
| **Standart** | ISO/IEC 27001:2022, bənd 4.1–4.4 |
| **Sənəd sahibi** | İnformasiya təhlükəsizliyi rəhbəri (CISO) |
| **Təsnifat** | DAXİLİ |
| **Versiya** | 1.0 · 2026-10 |

## 1. Təşkilat və xidmət

Əmanət şirkəti fiziki şəxslərə **rəqəmsal etibar seyfi** xidməti göstərir. İstifadəçi bank, e-poçt, bulud və sosial media hesablarının giriş məlumatlarını, sənədlərin harada saxlandığını və ailəsinə göstərişlərini seyfə yazır. İstifadəçi uzun müddət cavab verməsə və onun seçdiyi etibarlı şəxslərdən kifayət qədəri razılıq versə, seyf həmin şəxslər üçün açılır.

Komandada 6 nəfər çalışır: təsisçi və CEO, CISO (eyni zamanda DPO), 2 inkişaf etdirici, operator (DevOps) və yarımştat daxili auditor. Bütün infrastruktur AWS-dədir (eu-central-1). Şirkətin öz server otağı yoxdur.

## 2. Daxili və xarici amillər (4.1)

| Amil | Növ | İTİS-ə təsiri |
|---|---|---|
| Xidmətin dəyəri tamamilə **etimada** əsaslanır: bir sızma və ya səhv açılma biznesi bitirir | Daxili | Risk iştahı çox aşağıdır |
| Kiçik komanda: vəzifələri bölmək çətindir | Daxili | Vəzifələrin bölgüsü texniki məhdudiyyətlərlə təmin olunur: operator seyfi aça bilmir, auditor idarə edə bilmir |
| Bulud asılılığı (AWS) | Xarici | Paylaşılan məsuliyyət modeli, çıxış strategiyası |
| Fərdi məlumatlar qanunvericiliyi (AR və AB) | Xarici | DPIA, minimallaşdırma, silmə hüququ |
| Vərəsəlik hüququ: seyf vəsiyyətnamə deyil | Xarici | İstifadə şərtlərində açıq bəyan; mübahisələrdə şirkət hakim deyil |
| Kiber təhdidlər: credential stuffing, fişinq, təchizat zənciri | Xarici | MFA, sürət limiti, SCA/SBOM |
| Kvant hesablamaları (uzunmüddətli) | Xarici | Post-kvant miqrasiya planı (R-27) |

## 3. Maraqlı tərəflər və onların tələbləri (4.2)

| Tərəf | Tələb / gözlənti | Necə cavab verilir |
|---|---|---|
| Seyf sahibi | Məzmunu heç kim, şirkət də görməsin; vaxtından əvvəl açılmasın; vaxtı çatanda mütləq açılsın | Zero-knowledge, iki açarlı kilid, xatırlatma + gözləmə müddəti, monitorinq |
| Etibarlı şəxs | Sadə proses; şəxsi açarı qorunsun; öz rolunu başa düşsün | Barmaq izi bələdçisi, aydın vəziyyət ekranları |
| Vərəsələr və ailə | Lazım olanda məlumata çatmaq | Hədd (t-dən-n) — bir nəfər əlçatmaz olsa da seyf açılır |
| Fərdi məlumatlar üzrə səlahiyyətli orqan | Qanuna uyğun emal, insident bildirişi | DPIA, 72 saatlıq bildiriş proseduru |
| AWS | İstifadə şərtlərinə əməl olunması | AUP, təhlükəsizlik konfiqurasiyası |
| İnvestorlar | Davamlılıq, reputasiya | İdarəetmə təhlili, KPI-lar |
| Universitet komissiyası (təlim konteksti) | Üç fənnin tətbiqi | Hesabat, sübut faylları |

## 4. Hüquqi və tənzimləyici tələblər (5.31)

- **"Fərdi məlumatlar haqqında" Azərbaycan Respublikasının Qanunu (2010)** — fərdi məlumatların toplanması, emalı və qorunması; subyektin razılığı; məlumat mülkiyyətçisinin öhdəlikləri.
- **"İnformasiya, informasiyalaşdırma və informasiyanın mühafizəsi haqqında" Qanun** — informasiya ehtiyatlarının mühafizəsi.
- **GDPR (AB 2016/679)** — AB rezidenti olan istifadəçilər üçün: 25-ci maddə (məlumatın dizaynla qorunması), 32-ci (emalın təhlükəsizliyi), 33–34-cü (sızma bildirişi), 35-ci (DPIA).
- **Mülki Məcəllə, vərəsəlik bölməsi** — Əmanət vəsiyyətnamə **deyil** və notarial sənədi əvəz etmir. Seyf yalnız giriş məlumatlarını və göstərişləri ötürür. Əmlakın hüquqi bölgüsü qanunla və notariusla həll olunur. Bu, istifadə şərtlərində və UI-da açıq yazılır.

> Qeyd: hüquqi bəndlər tədris məqsədi ilə ümumiləşdirilib. Real xidmət işə salınmazdan əvvəl hüquqşünas rəyi tələb olunur (R-22).

## 5. Əhatə dairəsi (4.3)

**Daxildir:**
- Əmanət veb tətbiqi (backend, brauzer kodu), API və planlaşdırıcı;
- AWS infrastrukturu: VPC, EC2, S3, KMS, Secrets Manager, Lambda, EventBridge, SES, CloudWatch, CloudTrail, Backup, GuardDuty;
- mənbə kodu, CI/CD konveyeri (GitHub);
- əməkdaşların iş cihazları və istifadəçilərə dəstək prosesləri.

**Daxil deyil (əsaslandırma ilə):**
- AWS data mərkəzlərinin fiziki təhlükəsizliyi (AWS-in məsuliyyətidir; AWS ISO 27001 sertifikatı AWS Artifact-da mövcuddur);
- istifadəçilərin öz cihazları və bərpa kodu kağızının saxlanması (istifadəçinin məsuliyyətidir; təlimat verilir);
- etibarlı şəxslərin seyf açıldıqdan sonra məlumatla nə etdiyi (hüquqi məsələdir; audit jurnalında qeyd olunur).

**İnterfeyslər:** istifadəçi brauzeri (HTTPS), AWS API-ləri (IAM rolları), e-poçt (SES), GitHub.

## 6. İTİS prosesləri (4.4) — PDCA

| Mərhələ | Proses | Sənəd |
|---|---|---|
| **Plan** | Kontekst, risk qiymətləndirməsi, SoA, məqsədlər | 00, 03, 04, 05, 07 |
| **Do** | Siyasətlər, nəzarətlərin tətbiqi (kod + IaC), təlim | `policies/`, `emanet/`, `infra/` |
| **Check** | Compliance-as-code, monitorinq, daxili audit, idarəetmə təhlili | `compliance/`, 08, 09 |
| **Act** | Düzəldici tədbirlər, risk reyestrinin yenilənməsi | 08 (uyğunsuzluqlar), 09 (qərarlar) |
