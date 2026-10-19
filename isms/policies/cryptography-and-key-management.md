# Kriptoqrafiya və açar idarəsi siyasəti (A.8.24)

## Təsdiqlənmiş alqoritmlər

| Məqsəd | Alqoritm | Parametrlər | Standart | Harada |
|---|---|---|---|---|
| Simmetrik şifrələmə | AES-256-GCM | 96-bit təsadüfi IV, 128-bit teq, AAD məcburi | NIST SP 800-38D | `web/js/crypto.js`, `emanet/crypto/primitives.py` |
| Açar törətmə | HKDF-SHA-256 | Domen ayrılığı üçün `info` sətirləri | RFC 5869 | eyni |
| Paroldan açar | PBKDF2-HMAC-SHA-256 | 600 000 iterasiya, 16 bayt salt, NFKC | RFC 8018, OWASP 2023 | brauzer |
| Server tərəfli heş | Argon2id | m = 19 MiB, t = 2, p = 1 | RFC 9106, OWASP | `emanet/crypto/passwords.py` |
| Açıq açarla şifrələmə | ECIES: ECDH P-256 + HKDF + AES-GCM | Hər mesaj üçün yeni efemer açar | NIST SP 800-56A | hissələrin paylanması |
| Gizli bölgü | Shamir, GF(2⁸) | 2 ≤ t ≤ n ≤ 7 | Shamir (1979) | `shamir.js`, `shamir.py` |
| Bütövlük öhdəliyi | SHA-256 | Domen prefiksi + seyf id | FIPS 180-4 | hissə öhdəlikləri |
| Audit zənciri | HMAC-SHA-256 | Ayrıca açar | RFC 2104 | `emanet/audit.py` |
| MFA | TOTP | 30 s, 6 rəqəm, ±1 addım, replay qorunması | RFC 6238 | `emanet/crypto/totp.py` |
| Nəqliyyat | TLS 1.2 / 1.3 | HSTS 2 il | RFC 8446 | Caddy |

**Qadağandır:** MD5, SHA-1 (TOTP-un HMAC-SHA1-i istisnadır, RFC 6238 uyğunluğu üçün), DES/3DES, RC4, ECB rejimi, statik IV, öz-özünə yazılmış blok şifrləri, `Math.random()`.

## Açar iyerarxiyası

```
master parol ──PBKDF2──▶ master açar ──HKDF──┬─▶ auth_key ──▶ (server: Argon2id)
                                            └─▶ enc_key ──▶ şəxsi P-256 açarını sarır
                                                         └─▶ DEK-i sarır (owner)
bərpa kodu ──HKDF──┬─▶ recovery_auth ──▶ (server: Argon2id)
                   └─▶ recovery_enc ──▶ şəxsi açarı və DEK-i sarır (recovery)
DEK (32 bayt, seyf başına) ──AES-GCM──▶ seyf məzmunu
S (32 bayt) ──Shamir──▶ n hissə ──ECIES──▶ hər etibarlı şəxs
R (32 bayt, KMS-dən) ──KMS sarğısı──▶ DB
KEK_release = HKDF(S ‖ R, salt=vault_id) ──AES-GCM──▶ DEK-i sarır (release)
```

## Açarların həyat dövrü (NIST SP 800-57)

| Açar | Yaradılma | Saxlama | Rotasiya | Məhv |
|---|---|---|---|---|
| KMS release/data/logs | Terraform, HSM | AWS KMS | İllik avtomatik | 30 günlük pəncərə, CISO + CEO təsdiqi |
| R (seyf başına) | `GenerateDataKey` | DB-də yalnız sarınmış | KMS rotasiyası ilə yenidən sarınır (`rotate-kms`) | Seyf silinəndə (crypto-shred) |
| DEK | Brauzer CSPRNG | Yalnız sarınmış (3 nüsxə) | Yeni seyf → yeni DEK | Crypto-shred |
| S və hissələr | Brauzer, hər paylanmada | Yalnız ECIES ilə şifrəli | Etibarlı şəxs silinəndə və ya yenidən paylanmada | Köhnə hissələr yeni S ilə faydasız olur |
| İstifadəçinin P-256 açarı | Brauzer, qeydiyyatda | enc_key və recovery ilə sarınmış | Parol dəyişəndə yenidən sarınır | Hesab silinəndə |
| HMAC sirləri | Terraform `random_bytes` | Secrets Manager | İllik və ya kompromisdə | Secrets Manager 30 günlük bərpa pəncərəsi |

## Qaydalar
1. Hər AES-GCM çağırışında **AAD** məqsədi və kontekstini daşıyır (seyf id, versiya, məqsəd). Bu, sarınmış açarın başqa yerə köçürülməsinin qarşısını alır.
2. Açıq açarlar paylanmadan əvvəl **barmaq izi** ilə ayrıca kanalda yoxlanılmalıdır. Bu, API səviyyəsində məcburidir.
3. Brauzerdə açarlar yalnız yaddaşda saxlanılır. localStorage və IndexedDB qadağandır (testlə yoxlanılır).
4. Kriptoqrafik kodda dəyişiklik iki nəfərin review-unu və uyğunluq vektorlarının yenilənməsini tələb edir.
5. Post-kvant: AES-256 saxlanılır; ECDH P-256 üçün 2027-də ML-KEM-768 hibrid planlaşdırılıb (R-27).
