# Kriptoqrafik demolar

Yaradılıb: 2026-10-19 01:00 (Bakı)

## 01_naive_split_vs_shamir.py

_Demo 1 — "Parolu üç yerə bölmək" niyə təhlükəlidir və Shamir niyə fərqlidir._

```
Parol (24 simvol, əlifba 70): entropiya ≈ 147 bit

SADƏLÖVH BÖLGÜ:
  1-ci şəxs: huHuc4sW  (parolun 8 simvolunu açıq görür)
  2-ci şəxs: fSfnTZft  (parolun 8 simvolunu açıq görür)
  3-ci şəxs: XzTQv0Xn  (parolun 8 simvolunu açıq görür)
  1 nəfərin bildiyindən sonra qalan entropiya: 98 bit  (−49 bit sızdı)
  2 nəfər birləşsə qalan: 49 bit → 1 GPU (10^10 cəhd/s) ilə ≈ 16.0 saat
  1 nəfər itsə: parol BƏRPA OLUNMUR

SHAMIR (2-dən-3):
  1-ci şəxs: 7c290decbdc860057e02be8900ea201e148e3d8e5bbdba3d…
  2-ci şəxs: 40cdc25cc4d755f356f1cdbbfc21eaa0c08986f42c3187c8…
  3-ci şəxs: 549187c51a2b46a14ea0155ca891acca8c7def2b01bc659b…
  1 hissədən sonra qalan entropiya: 100% (informasiya-nəzəri məxfilik)
  1+2 birləşir → BƏRPA OLUNDU
  1+3 birləşir → BƏRPA OLUNDU
  2+3 birləşir → BƏRPA OLUNDU

  1-ci hissənin ilk baytı 0x7c ilə uyğun gələn mümkün sirr baytlarının sayı: 256/256
```

## 02_feldman_vss.py

_Demo 2 — Feldman yoxlanıla bilən gizli bölgüsü (Verifiable Secret Sharing)._

```
Qrup: 2048-bit təhlükəsiz sadə ədəd (RFC 3526 Group 14), paylama 70.4 ms
Öhdəliklər (ictimai): C0 = g^s = 0xadf9783f0ccb0b59adb8e1e43f24f455…, C1 = 0x1226002cd5425ccf4a29832c50c0c5e1…

1) Dürüst paylayıcı — hər şəxs öz hissəsini yoxlayır:
   şəxs 1: ✓ düzgündür
   şəxs 2: ✓ düzgündür
   şəxs 3: ✓ düzgündür

2) Saxtakar paylayıcı 2-ci şəxsə yanlış hissə verir:
   şəxs 1: ✓ düzgündür
   şəxs 2: ✗ SAXTA — dərhal aşkarlandı, bərpaya qədər gözləmək lazım deyil
   şəxs 3: ✓ düzgündür

3) Bərpa (istənilən 2 hissə):
   (1, 2): sirr bərpa olundu ✓
   (1, 3): sirr bərpa olundu ✓
   (2, 3): sirr bərpa olundu ✓

   Yoxlama: g^bərpa == C0 ? True
```

## 03_two_key_lock.py

_Demo 3 — "İki açarlı kilid": kim nəyi aça bilər?_

```
  Nəticə   │ Ssenari
──────────┼──────────────────────────────────────────────────────
  açılmadı │ Server/admin təkbaşına (R var, S yox)
  açılmadı │ Bir etibarlı şəxs (1 hissə + R)
  açılmadı │ 2 etibarlı şəxs VAXTINDAN ƏVVƏL sui-qəsd (S var, R yox)
  açılmadı │ DB oğurlandı (sarınmış R, şifrəli hissələr — açarlar yox)
  AÇILDI   │ Vaxt çatdı: R buraxıldı + 2 hissə (1 və 3)
  AÇILDI   │ Vaxt çatdı: R buraxıldı + 3 hissə

Nəticə: yalnız "insanlar + zaman" şərti BİRLİKDƏ ödəniləndə seyf açılır.
```

## 04_size_leak_and_padding.py

_Demo 4 — Şifrəmətnin uzunluğu da məlumatdır (metadata sızması) və doldurma (padding)._

```
 Qeyd sayı │  padding-siz │  padding ilə
───────────┼──────────────┼─────────────
         0 │         29 B │       4112 B
         1 │         83 B │       4112 B
         2 │        139 B │       4112 B
         5 │        307 B │       4112 B
        10 │        587 B │       4112 B
        25 │       1442 B │       4112 B
        60 │       3437 B │       4112 B

Padding-siz: hər yeni qeyd ölçünü dəyişir → server izləyə bilər.
Padding ilə: 0–60 qeyd eyni və ya bir neçə sabit ölçüdə görünür.
```
