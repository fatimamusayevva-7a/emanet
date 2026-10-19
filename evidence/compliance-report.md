# Compliance-as-code hesabatı

Yaradılıb: 2026-10-19 01:07 (Bakı) · **29/30 PASS**

| ID | Nəzarət | Yoxlama | Nəticə | Sübut |
|---|---|---|---|---|
| C-01 | A.8.24 | PBKDF2 iterasiyası ≥ 600 000 və brauzer ilə server eynidir | ✅ PASS | python=600000, js=600000 |
| C-02 | A.8.24 | Argon2id parametrləri OWASP minimumundan aşağı deyil (m≥19 MiB, t≥2) | ✅ PASS | m=19456 KiB, t=2, p=1 |
| C-03 | A.8.24 | Qadağan olunmuş alqoritmlər/rejimlər istifadə olunmur (MD5, ECB, DES, RC4, Math.random) | ✅ PASS | tapılmadı |
| C-04 | A.8.24 | Bütün AES-GCM çağırışları AAD ilə aparılır (seal/open_sealed boş AAD-ı qəbul etmir) | ✅ PASS | 4 seal çağırışı, boş AAD: 0 |
| C-05 | A.8.24 | Kriptoqrafik uyğunluq vektorları mövcuddur (Python ↔ JS) | ✅ PASS | vektor bölmələri: ['commitment', 'ecies', 'gf', 'kdf', 'pad', 'recovery', 'release_kek', 'seal', 'shamir'] |
| C-06 | A.8.26 | CSP ciddidir: script-src 'self', unsafe-inline yoxdur, Trusted Types məcburidir | ✅ PASS | default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none' |
| C-07 | A.8.28 | Brauzer kodunda innerHTML/eval/document.write və brauzer yaddaşı yoxdur | ✅ PASS | 11 fayl yoxlanıldı; pozuntu: yoxdur |
| C-08 | A.8.31 | İstehsal konfiqurasiyası təhlükəli rejimləri rədd edir (demo, HTTP, lokal KMS) | ✅ PASS | rədd edilən: ['demo_mode', 'public_origin', 'cookie_secure', 'kms_backend'] |
| C-09 | A.8.5 | Sessiya cookie-si: __Host-, HttpOnly, Secure, SameSite=Strict; DB-də yalnız heş | ✅ PASS | bayraqlar ✓, DB-də SHA-256(token) |
| C-10 | A.8.12 | Audit metadata-sında sirr adlı açarlar bloklanır | ✅ PASS | 5/5 qadağan açar bloklandı |
| C-11 | A.5.3 | Operatorun açılmanı məcbur edən endpoint-i yoxdur; audit yalnız auditora açıqdır | ✅ PASS | force-release endpoint: yoxdur, /api/audit → auditor |
| C-12 | A.8.10 | Crypto-shredding: seyf silinəndə R, DEK sarğıları və hissələr məhv edilir | ✅ PASS | shred_vault ✓, CASCADE: 3, secure_delete ✓ |
| C-13 | A.8.11 | Sxemdə açıq mətn sütunu yoxdur (password, plaintext, dek, share) | ✅ PASS | 101 sütun, qadağan: yoxdur |
| C-14 | A.8.20 | Security Group-da SSH (22) və ya bütün portlar açıq deyil | ✅ PASS | ingress portları: ['443', '80'] |
| C-15 | A.8.2 | EC2-də SSH açarı yoxdur, IMDSv2 məcburidir, EBS şifrəlidir | ✅ PASS | key_name yoxdur, http_tokens=required, encrypted=true |
| C-16 | A.8.24 | Bütün KMS açarlarında avtomatik rotasiya aktivdir | ✅ PASS | açarlar: ['release', 'data', 'logs'], rotasiya: ['release', 'data', 'logs'] |
| C-17 | A.5.3 | KMS release açarının siyasətində admin-ə kms:Decrypt verilmir; tətbiq yalnız kontekstlə | ✅ PASS | AccountAdmin: Decrypt yoxdur; AppUseWithContextOnly: EncryptionContext şərti |
| C-18 | A.8.13 | S3: versioning + Object Lock + SSE-KMS + public access block | ✅ PASS | Versioning=Enabled, ObjectLock=GOVERNANCE, SSE=aws:kms, BPA=4/4 |
| C-19 | A.5.14 | S3 bucket siyasəti TLS olmayan və TLS<1.2 girişləri rədd edir | ✅ PASS | DenyInsecureTransport + DenyOldTLS |
| C-20 | A.8.15 | CloudTrail: multi-region, log file validation, KMS şifrələmə | ✅ PASS | multi-region ✓, validation ✓, KMS ✓ |
| C-21 | A.8.16 | Monitorinq: təhlükəsizlik metric filter-ləri, planlaşdırıcı və KMS alarmları | ✅ PASS | 9 metric filter, tick alarmları ✓, KMS EventBridge ✓ |
| C-22 | A.5.17 | Repozitoriyada sirr yoxdur (AWS açarı, PEM şəxsi açar, .env) | ❌ FAIL | pozuntu: ['.venv\\Lib\\site-packages\\boto3\\examples\\cloudfront.rst', '.venv\\Lib\\site-packages\\playwright\\driver\\node.exe'], .env: yoxdur |
| C-23 | A.5.21 | Əsas asılılıqlar dəqiq versiya ilə bərkidilib | ✅ PASS | Flask==3.1.3; Werkzeug==3.1.8; cryptography==50.0.1; gunicorn==23.0.0 |
| C-24 | 6.1.3 d | SoA bütün 93 Annex A nəzarətini əhatə edir, hər birinin əsaslandırması var | ✅ PASS | 93 nəzarət (tətbiq olunan 84, istisna 9) |
| C-25 | 7.5 | SoA-dakı bütün sübut faylları mövcuddur | ✅ PASS | çatışmayan: yoxdur |
| C-26 | 6.1.2 | Risk reyestri: bal = L×I, qalıq ≤ inherent, qalıq ≤ iştah (8), sahib və müalicə var | ✅ PASS | 27 risk; cəmi bal 262 → 132 (−50%); xəta: yoxdur |
| C-27 | 6.1.3 | Risklərdəki nəzarətlər SoA-da 'tətbiq olunur' kimi qeyd olunub | ✅ PASS | uyğunsuzluq: yoxdur |
| C-28 | 6.1.2 | Risklərin aktivləri aktiv reyestrində var | ✅ PASS | 16 aktiv; uyğunsuzluq: yoxdur |
| C-29 | 9.1 | Risk reyestrində istinad edilən testlər həqiqətən mövcuddur | ✅ PASS | 13 istinad, çatışmayan: yoxdur |
| C-30 | 5.1 | Mövzu siyasətləri mövcuddur və əsas siyasətdən istinad olunur | ✅ PASS | 8 siyasət; istinadsız: yoxdur |
