# Risk qiymətləndirmə metodologiyası (ISO 27001 6.1.2, ISO/IEC 27005:2022)

## Yanaşma
Aktiv əsaslı və ssenari əsaslı yanaşmalar birləşdirilib. Hər ssenari bu suala cavab verir: "**hansı təhdid** hansı **zəiflikdən** istifadə edib hansı **aktivə** zərər vurur?" Təhdidlər STRIDE (`docs/threat-model.md`) və bu xidmətə xas ssenarilərdən (səhv açılma, sui-qəsd, məcburiyyət) götürülür.

## Ehtimal (L)

| Bal | Səviyyə | Təsvir |
|---|---|---|
| 1 | Çox aşağı | 5 ildə bir dəfədən az; xüsusi resurs tələb edir |
| 2 | Aşağı | 1–5 ildə bir; məqsədyönlü hücumçu lazımdır |
| 3 | Orta | İldə bir dəfə; ictimai alətlərlə mümkündür |
| 4 | Yüksək | Rüblük; avtomatlaşdırılmış hücumlar |
| 5 | Çox yüksək | Aylıq və ya daha tez |

## Təsir (I)

| Bal | Məxfilik | Bütövlük / əlçatanlıq | Biznes |
|---|---|---|---|
| 1 | Daxili, zərərsiz məlumat | Bir neçə dəqiqəlik narahatlıq | Yoxdur |
| 2 | Bir istifadəçinin metadata-sı | Bir saata qədər fasilə | Kiçik şikayət |
| 3 | Çox istifadəçinin metadata-sı | Bir günə qədər fasilə; xatırlatma gecikir | Media marağı |
| 4 | Bir seyfin məzmunu və ya etibar qrafı | Bir seyf səhv vəziyyətdə | Tənzimləyici bildiriş, müştəri itkisi |
| 5 | Çox seyfin məzmunu; **vaxtından əvvəl açılma** | Seyflər geri qaytarılmaz itir | Biznesin sonu |

## Risk balı və iştah
**Risk = L × I** (1–25). Rəng zonaları:

| Bal | Zona | Qərar |
|---|---|---|
| 1–4 | Aşağı | Qəbul edilir, illik baxış |
| 5–8 | Orta | Qəbul edilə bilər (risk iştahı ≤ 8), rüblük baxış |
| 9–14 | Yüksək | Müalicə planı məcburidir, CEO imzası |
| 15–25 | Kritik | Qəbul edilmir |

## Müalicə variantları
- **Azaltmaq** — nəzarət tətbiq etmək (Annex A); əksər risklər.
- **Qaçmaq** — funksiyanı ümumiyyətlə təqdim etməmək. Nümunə: "operator açılmanı məcbur edə bilər" funksiyası yoxdur.
- **Ötürmək** — sığorta və ya təchizatçı (fiziki təhlükəsizlik → AWS).
- **Qəbul etmək** — qalıq risk iştah daxilindədir, sahib imzalayır.

## Qalıq riskin hesablanması
Nəzarət tətbiq edildikdən sonra L və I yenidən qiymətləndirilir. Hər nəzarət üçün **sübut** (kod faylı, test, IaC resursu) göstərilir. Sübutu olmayan nəzarət qalıq riski azaltmır.

## Tezlik
- Tam qiymətləndirmə: ildə bir dəfə.
- Hədəfli qiymətləndirmə: hər böyük dəyişiklikdən, insidentdən və ya yeni təhdid xəbərindən sonra.
- Avtomatik yoxlama: hər commit-də `compliance/check_controls.py` reyestrin bütövlüyünü yoxlayır (hər riskin sahibi, nəzarəti və iştah daxilində qalıq balı var).
