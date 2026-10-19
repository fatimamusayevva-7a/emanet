# Layihənin idarə edilməsi

**Metod:** Scrum-a yaxın, 2 həftəlik 6 sprint. GitHub Projects lövhəsi: *Backlog → Ready → In progress → Review → Done*.

**Hər tapşırıqda** (`backlog.csv`): fənn, Annex A nəzarəti, risk ID-si. Bu üç sahə imkan verir:
- hər riskin hansı tapşırıqla azaldıldığını izləmək (A.5.8 — layihə idarəsində təhlükəsizlik);
- hesabatda "fənn → tapşırıq → kod → test" zəncirini qurmaq.

**Definition of Done:**
1. Kod PR ilə gəlir, review olunur.
2. Təhlükəsizlik nəzarətinin **testi** var və CI yaşıldır.
3. Lazım olarsa risk reyestri və SoA yenilənib.
4. `compliance/check_controls.py` PASS verir.

| Sprint | Məqsəd | Nəticə |
|---|---|---|
| 1 | Kriptoqrafik nüvə | Shamir, ECIES, iki açarlı kilid, iki dildə uyğunluq |
| 2 | Backend və təhlükəsizlik qatı | Vəziyyət maşını, auth, CSRF, BOLA, audit |
| 3 | UI + bulud | Veb interfeys, E2E, Terraform |
| 4 | İTİS | Risk, SoA, siyasətlər, audit, compliance-as-code |
| 5 | Yerləşdirmə | Real AWS, ekran görüntüləri |
| 6 | Yol xəritəsi | Post-kvant, Argon2 WASM, kod imzası |

GitHub-a idxal: `gh issue create` ilə hər sətir üçün issue yaradılır (etiketlər: fənn, `annex-a:<id>`, `risk:<id>`).
