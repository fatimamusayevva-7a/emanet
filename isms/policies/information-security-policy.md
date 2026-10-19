# İnformasiya təhlükəsizliyi siyasəti (A.5.1)

**Təsdiq edib:** CEO · **Sahibi:** CISO · **Təsnifat:** İCTİMAİ · **Baxış:** illik

## Məqsəd
Əmanət insanların ən həssas məlumatlarını və onların son istəklərini qoruyur. Bizim təhlükəsizlik vədimiz üç cümlədir:
1. **Biz seyfinizin içini görə bilmirik.** Görə bilməməyimiz texniki olaraq təmin olunub, sadəcə vəd deyil.
2. **Seyfiniz vaxtından əvvəl açılmayacaq.** Açılma üçün sizin uzun müddət cavab verməməyiniz, seçdiyiniz insanların razılığı və gözləmə müddəti birlikdə lazımdır.
3. **Vaxtı çatanda seyfiniz açılacaq.** Bunun üçün xidmətin əlçatanlığı və planlaşdırıcı davamlı izlənir.

## Prinsiplər
- **Dizaynla məxfilik:** mümkün olan hər yerdə məlumat server tərəfindən oxunmaz olsun.
- **Fail-closed:** şübhə və ya nasazlıq zamanı seyf açılmır.
- **Ən az imtiyaz və vəzifə bölgüsü:** heç bir əməkdaş təkbaşına seyfi aça və ya açılmanı məcbur edə bilməz.
- **Sübut olunan təhlükəsizlik:** hər nəzarətin avtomatik testi və ya sübut faylı var.
- **Şəffaflıq:** sahib öz seyfi ilə bağlı hər hadisəni görür.

## Məlumat təsnifatı (A.5.12)

| Səviyyə | Nümunə | Qayda |
|---|---|---|
| İCTİMAİ | Bu siyasət, mənbə kodu | Sərbəst paylaşıla bilər |
| DAXİLİ | Arxitektura sənədləri, runbook-lar | Yalnız komanda |
| MƏXFİ | E-poçtlar, etibar qrafı, audit jurnalı | Rol əsaslı giriş, at-rest şifrələmə |
| MƏHDUD | Seyf məzmunu, açarlar, sirlər | Kriptoqrafik qoruma məcburidir; açıq mətn heç vaxt serverdə saxlanılmır |

## Mövzu siyasətləri
- [Giriş nəzarəti](access-control.md)
- [Kriptoqrafiya və açar idarəsi](cryptography-and-key-management.md)
- [İnsidentlərə cavab](incident-response.md)
- [Biznesin davamlılığı](business-continuity.md)
- [Təhlükəsiz inkişaf](secure-development.md)
- [Təchizatçılar və bulud](supplier-and-cloud.md)
- [Məlumatların saxlanması və silinməsi](data-retention-and-deletion.md)
- [Məqbul istifadə](acceptable-use.md)

## Xarici əlaqələr (A.5.6)
OWASP, FIRST, AWS Security Bulletins və PyCA `cryptography` elanlarına abunəlik; CISO ayda bir dəfə icmal edir.

## Pozuntu
Siyasətin pozulması intizam prosesinə səbəb olur (`acceptable-use.md`, A.6.4).
