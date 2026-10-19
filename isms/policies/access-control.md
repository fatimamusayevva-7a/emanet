# Giriş nəzarəti siyasəti (A.5.15–A.5.18, A.8.2–A.8.5, A.6.1, A.6.5)

## Tətbiq istifadəçiləri
- **Rollar:** `user` (sahib və/və ya etibarlı şəxs), `operator`, `auditor`. Rol yalnız başqa operator tərəfindən və ya CLI ilə SSM sessiyasında dəyişdirilə bilər. Öz rolunu dəyişmək qadağandır, sonuncu operator silinə bilməz.
- **Obyekt səviyyəsində giriş:** sahib yalnız öz seyfini görür, çünki sorğular sessiyanın istifadəçisi ilə məhdudlaşdırılır. Etibarlı şəxs yalnız qəbul etdiyi seyfin vəziyyətini görür. Material yalnız `released` vəziyyətində verilir. Üzv olmayan istifadəçiyə 404 qaytarılır ki, seyfin varlığı da sızmasın.
- **Autentifikasiya:** 12+ simvollu master parol (yayılmış parollar rədd edilir), isteğe bağlı TOTP MFA (operator və auditor üçün məcburi). 10 uğursuz cəhddən sonra hesab 15 dəqiqəlik kilidlənir və istifadəçiyə bildiriş gedir.
- **Sessiya:** 30 dəq. hərəkətsizlik, 12 saat mütləq limit. Parol və ya rol dəyişikliyində bütün sessiyalar ləğv olunur.

## İnfrastruktura giriş
- AWS-də fərdi IAM Identity Center hesabları, MFA (FIDO2) məcburidir. Statik access key qadağandır.
- Root hesab: aparat MFA ilə, seyfdə saxlanılan kağız zərfdə. Yalnız break-glass hallarında istifadə olunur və CEO ilə CISO-nun ikisi də iştirak edir.
- EC2-yə SSH yoxdur. Giriş yalnız SSM Session Manager ilə olur və sessiya CloudTrail-də qeyd edilir.
- `emanet-break-glass` rolu S3 Object Lock-dan yan keçə bilən yeganə roldur. İstifadəsi P1 insidenti kimi qeyd olunur.
- GitHub: 2FA, branch protection, `main`-ə birbaşa push qadağandır.

## Həyat dövrü
| Hadisə | Tədbir | Müddət |
|---|---|---|
| İşə qəbul | Arayış yoxlaması (A.6.1), NDA, rolun minimal hüquqlarla yaradılması | Başlamazdan əvvəl |
| Vəzifə dəyişikliyi | Köhnə hüquqların silinməsi, yenilərinin verilməsi | Eyni gün |
| İşdən çıxma | AWS, GitHub, tətbiq rolu, e-poçt ləğvi; noutbuk və YubiKey qaytarılır (A.5.11) | **Eyni gün** |
| Rüblük icmal | Auditor bütün imtiyazlı hesabları yoxlayır | Hər rüb |
