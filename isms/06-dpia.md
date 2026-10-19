# Məlumatların qorunmasına təsirin qiymətləndirilməsi (DPIA)

GDPR 35-ci maddəsi və ISO/IEC 27701 ruhunda. "Fərdi məlumatlar haqqında" AR Qanununun prinsipləri (qanunilik, məqsədəuyğunluq, minimallıq) nəzərə alınıb.

## 1. Emal nədir və niyə DPIA lazımdır
Xidmət insanların **ən həssas** məlumatlarını saxlayır: bank girişləri, sağlamlıq göstərişləri, ailə münasibətləri. Bundan əlavə, sistem insanın **ölümü və ya ağır xəstəliyi ehtimalı** barədə nəticə çıxarır (hərəkətsizlik). Bu, yüksək riskli emaldır, ona görə DPIA məcburidir.

## 2. Məlumat inventarı və minimallaşdırma

| Məlumat | Kimin | Server görür? | Niyə lazımdır | Minimallaşdırma |
|---|---|---|---|---|
| Seyf məzmunu | Sahib | **Xeyr** (zero-knowledge) | Xidmətin özü | Brauzerdə AES-256-GCM; ölçü doldurma ilə gizlədilir |
| E-poçt | Sahib, etibarlı şəxs | Bəli | Giriş, bildiriş | Telefon, ünvan, şəxsiyyət vəsiqəsi TOPLANMIR |
| Ad (görünən) | Sahib, etibarlı şəxs | Bəli | Etibarlı şəxs kimin seyfi olduğunu bilsin | İstənilən ad ola bilər; rəsmi ad tələb olunmur |
| Etibar qrafı | Sahib | Bəli | Hissələri paylamaq üçün | Etibarlı şəxslər bir-birini yalnız açılmadan sonra görür |
| Son aktivlik vaxtı | Sahib | Bəli | "Sağam" yoxlaması | **Etibarlı şəxslərə göstərilmir**, yalnız vəziyyət göstərilir |
| IP ünvanı | Hamı | Bəli (log) | Təhlükəsizlik, sürət limiti | Loglar 365 gün, sonra silinir |
| Ölüm faktı | — | **Toplanmır** | — | Sistem ölüm şəhadətnaməsi tələb etmir: yalnız hərəkətsizlik + insanların razılığı |

## 3. Riskin subyektlər üçün qiymətləndirilməsi

| Risk | Subyekt | Ehtimal | Ağırlıq | Tədbir | Qalıq |
|---|---|---|---|---|---|
| Seyfin vaxtından əvvəl açılması | Sahib | Aşağı | Çox ağır | Xatırlatmalar, gözləmə müddəti, istənilən aktivlik ləğv edir, pauza (R-01) | Aşağı |
| Məzmunun sızması | Sahib, üçüncü şəxslər | Çox aşağı | Çox ağır | Zero-knowledge (R-04) | Aşağı |
| Etibar qrafının sızması (kim kimə etibar edir) | Hamı | Aşağı | Orta | At-rest şifrələmə, giriş nəzarəti (R-20) | Aşağı |
| Etibarlı şəxsin rolu barədə məlumatsızlıq | Etibarlı şəxs | Orta | Aşağı | Dəvəti açıq qəbul etmək lazımdır; rədd etmək olar | Aşağı |
| Seyfin heç vaxt açılmaması (sahib həqiqətən öldü, amma sistem nasazdır) | Vərəsələr | Aşağı | Ağır | Planlaşdırıcı alarmları, lazy qiymətləndirmə (R-07) | Aşağı |

## 4. Subyektlərin hüquqları
- **Giriş hüququ:** sahib öz seyfi ilə bağlı bütün audit hadisələrini UI-da görür ("Fəaliyyət").
- **Silmə hüququ:** "Seyfi məhv et" funksiyası crypto-shredding edir. S3 Object Lock köhnə versiyaları 30 gün saxlasa da, açarlar məhv edildiyi üçün onlar oxunmazdır. Hesabın özü sorğu ilə 30 gün ərzində silinir.
- **Düzəliş hüququ:** sahib məzmunu istənilən vaxt dəyişir.
- **Daşınma hüququ:** sahib seyfi JSON kimi ixrac edə bilər (yol xəritəsi, v1.1).
- **Etiraz:** etibarlı şəxs dəvəti rədd edə və ya sonradan çıxa bilər.

## 5. Ölümdən sonra məlumat
AB-də GDPR mərhum şəxslərin məlumatına tətbiq olunmur, amma üzv dövlətlər öz qaydalarını qəbul edə bilər. Əmanət ehtiyatlı yanaşır: sahibin seyfi yalnız onun əvvəlcədən verdiyi açıq göstərişə (etibarlı şəxslərin seçimi, hədd, müddətlər) uyğun açılır. Açılmadan sonra etibarlı şəxslər məlumatı yalnız sahibin məktubunda göstərilən məqsədlə istifadə etməlidir (istifadə şərtləri).

## 6. Sızma bildirişi
CISO/DPO hadisəni öyrəndikdən sonra **72 saat** ərzində səlahiyyətli orqana, yüksək risk olarsa subyektlərə də məlumat verir (`policies/incident-response.md`, PB-04). Zero-knowledge sayəsində DB sızmasında belə seyf məzmunu açıq deyil. Bu, bildirişin məzmununa və riskin qiymətləndirilməsinə daxil edilir.

## 7. Nəticə
Qalıq risklər qəbul ediləndir. DPO DPIA-nı təsdiqləyir; illik və ya hər böyük funksiya dəyişikliyində yenilənir.
