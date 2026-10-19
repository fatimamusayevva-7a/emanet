# İTİS məqsədləri və ölçmə (ISO 27001 6.2, 9.1)

| # | Məqsəd | Göstərici (KPI) | Hədəf | Ölçmə mənbəyi | Tezlik | Cari |
|---|---|---|---|---|---|---|
| O-1 | Heç bir seyf vaxtından əvvəl açılmasın | Sahib tərəfindən "səhv açılma" şikayəti | **0** | İnsident reyestri | Aylıq | 0 |
| O-2 | Vaxtı çatan seyf mütləq açılsın | Planlaşdırıcının uğurlu tick nisbəti | ≥ 99.5% | CloudWatch `TickSucceeded` | Həftəlik | Pilotda ölçüləcək |
| O-3 | Sıfır bilik iddiası hər buraxılışda sübut olunsun | Disk skanı testi | 100% keçir | `tests/test_zero_knowledge.py` | Hər commit | 100% |
| O-4 | Uyğunluq davamlı yoxlansın | Avtomatik nəzarət yoxlamaları | 100% PASS | `evidence/compliance-report.md` | Hər commit | bax hesabat |
| O-5 | Zəifliklər tez bağlansın | Kritik CVE-nin bağlanma müddəti | ≤ 7 gün | pip-audit/Trivy | Aylıq | — |
| O-6 | Risklər iştah daxilində qalsın | Qalıq balı > 8 olan risklər | 0 | `isms/04-risk-register.csv` | Rüblük | 0 |
| O-7 | İnsidentlər tez aşkarlansın | MTTD (orta aşkarlanma vaxtı) | ≤ 15 dəq. | Alarm → insident | Rüblük | — |
| O-8 | Bərpa işləsin | Rüblük bərpa testinin nəticəsi | Uğurlu, RTO ≤ 4 saat | `docs/runbooks.md` RB-04 | Rüblük | — |
| O-9 | İstifadəçilər barmaq izini yoxlasın | Paylanmadan əvvəl yoxlanmış açarlar | 100% (texniki məcburi) | API | Davamlı | 100% |
| O-10 | Komanda təlimli olsun | İllik təlimi keçənlər | 100% | HR qeydi | İllik | — |

"—" — xidmət istehsala çıxdıqdan sonra ölçüləcək. Hazırda sistem pilot mərhələsindədir.
