# Test nəticələri

Yaradılıb: 2026-10-19 01:00 (Bakı) · Python 3.12.10 · `python scripts/run_all.py`

## Xülasə

| Dəst | Test | Keçdi | Uğursuz | Müddət |
|---|---|---|---|---|
| Python (unittest) | 430 | 428 | 2 | 417.9 s |
| JavaScript (node:test, WebCrypto) | 25 | 25 | 0 | — |
| **Cəmi** | **455** | **453** | **2** | |

Alt testlər (subTest): 77 · Compliance: 29/30 PASS → evidence/compliance-report.md

## Python modulları üzrə

| Modul | Nə yoxlanılır | Keçdi | Uğursuz | Müddət |
|---|---|---|---|---|
| `e2e` | Real Chromium: 6 istifadəçi, 68 gün, 2/3 açılma, 18 ekran görüntüsü | 1 | 0 | 43.7 s |
| `test_api_security` | Autentifikasiya, sessiya, CSRF, BOLA, mass assignment, rate limit, vəzifə bölgüsü, başlıqlar | 57 | 1 | 107.3 s |
| `test_crossimpl` | JS → Python kriptoqrafik uyğunluq | 6 | 0 | 0.7 s |
| `test_flow` | Tam həyat dövrü ssenariləri (API səviyyəsində) | 6 | 0 | 33.4 s |
| `test_infra` | KMS (lokal + AWS imitasiyası), anbar, konfiqurasiya, planlaşdırıcı, audit, CLI, Lambda | 38 | 1 | 21.4 s |
| `test_primitives` | AES-GCM (hər bitin dəyişdirilməsi), ECIES, KDF, doldurma, bərpa kodu, RFC vektorları | 43 | 0 | 0.8 s |
| `test_route_matrix` | Hər endpoint üçün avtomatik: auth, CSRF, Origin, başlıqlar, rol matrisi | 151 | 0 | 79.9 s |
| `test_shamir` | Shamir GF(256): sahə aksiomları, bütün (n,t) konfiqurasiyaları, mütləq məxfilik, χ² | 66 | 0 | 0.5 s |
| `test_switch` | 'Sağam' vəziyyət maşını: keçidlər, 990 kombinasiyalı invariant şəbəkəsi, 2 000 təsadüfi ssenari | 19 | 0 | 0.4 s |
| `test_vault_api` | Seyf qaydaları: paylanma, versiyalar, açılma, saxta hissə, R əvəzlənməsi, saxlama | 37 | 0 | 111.6 s |
| `test_zero_knowledge` | Serverin bütün diskinin skanı: açıq mətn, açar, hissə, parol yoxdur | 4 | 0 | 13.2 s |

## JavaScript testləri

- ✅ GF(256) vurma cədvəli Python ilə eynidir
- ✅ Shamir: eyni toxum → Python ilə eyni hissələr
- ✅ Shamir: Python hissələrinin hər 3-lük kombinasiyası JS-də bərpa olunur
- ✅ PBKDF2 (600 000) + HKDF açar ayrılığı Python ilə eynidir
- ✅ NFKC normallaşdırma: parçalanmış 'ı' / 'ə' eyni açar verir
- ✅ İki açarlı kilid KEK = HKDF(S‖R) Python ilə eynidir
- ✅ Hissə öhdəliyi (commitment) Python ilə eynidir
- ✅ Bərpa kodu açarları Python ilə eynidir
- ✅ Doldurma ölçüləri Python ilə eynidir
- ✅ Python-un AES-GCM qutusu JS-də açılır
- ✅ Python-un ECIES qutusu JS-də açılır, barmaq izi eynidir
- ✅ ECIES: başqa kontekstlə açmaq alınmır (hissə başqa seyfə köçürülə bilməz)
- ✅ Shamir: 2..7 bütün (n,t) və bütün t-alt çoxluqları
- ✅ Shamir: t-1 hissə səhv nəticə verir
- ✅ Shamir: yanlış parametrlər rədd edilir
- ✅ GF(256): hər sıfırdan fərqli elementin tərsi var
- ✅ AES-GCM: AAD, açar və şifrəmətn dəyişikliyi aşkarlanır
- ✅ Seyf: versiya AAD-dadır (köhnə versiyanı yeni kimi göstərmək olmur)
- ✅ ECIES: kontekstə bağlıdır, yanlış alıcı aça bilmir
- ✅ ECIES: əyri üzərində olmayan nöqtə rədd edilir
- ✅ Paylanma → bərpa (2/3), saxta hissə adla tutulur
- ✅ Doldurma: kiçik məzmunların ölçüsü eynidir, pozulmuş doldurma rədd edilir
- ✅ Bərpa kodu: format, unikal, normallaşma
- ✅ base64url: gidiş-dönüş və yanlış simvollar
- ✅ İki açarlı kilid: S və ya R dəyişsə KEK dəyişir

## Uğursuz testlər

- tests.test_api_security.SecurityHeaders.test_integrity_manifest
- tests.test_infra.Cli.test_integrity
