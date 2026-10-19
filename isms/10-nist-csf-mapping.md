# NIST Cybersecurity Framework 2.0 ilə uyğunluq

| Funksiya | Kateqoriya | Əmanət-də tətbiq | Yetkinlik (1–4) |
|---|---|---|---|
| **GV — İdarəetmə** | GV.OC Kontekst, GV.RM Risk strategiyası | 00-context, 03-methodology, risk iştahı ≤ 8 | 3 |
| | GV.RR Rollar | 01-leadership: RACI, texniki vəzifə bölgüsü | 3 |
| | GV.SC Təchizat zənciri | Dəqiq versiyalar, SBOM, pip-audit, CDN yoxdur | 3 |
| **ID — Müəyyənləşdirmə** | ID.AM Aktivlər | 02-asset-register (16 aktiv) | 3 |
| | ID.RA Risk qiymətləndirməsi | 04-risk-register (27 risk), STRIDE | 3 |
| | ID.IM Təkmilləşdirmə | Daxili audit tapıntıları → kod düzəlişi → test | 3 |
| **PR — Qorunma** | PR.AA Kimlik və giriş | Zero-knowledge giriş, Argon2id, TOTP, RBAC, BOLA | 4 |
| | PR.DS Məlumat təhlükəsizliyi | AES-256-GCM, Shamir, iki açarlı kilid, KMS, Object Lock | 4 |
| | PR.PS Platforma təhlükəsizliyi | IMDSv2, SSH yoxdur, read-only konteyner, CSP + Trusted Types | 3 |
| | PR.IR Dayanıqlıq | Backup, auto-recover, IaC | 3 |
| **DE — Aşkarlama** | DE.CM Davamlı monitorinq | 9 metric filter, GuardDuty, VPC flow logs, KMS EventBridge | 3 |
| | DE.AE Hadisələrin təhlili | security_events, ciddilik matrisi | 2 |
| **RS — Cavab** | RS.MA İnsident idarəsi | 6 playbook, rollar | 3 |
| | RS.CO Kommunikasiya | 72 saat bildiriş, istifadəçi bildirişləri | 3 |
| **RC — Bərpa** | RC.RP Bərpa planı | RTO 4 saat / RPO 24 saat, rüblük test | 2 |

**Ən zəif sahə:** DE.AE (avtomatlaşdırılmış korrelyasiya yoxdur). Plan: CloudWatch Logs Insights sorğuları və həftəlik icmal. RC (bərpa testləri hələ istehsalda aparılmayıb).
