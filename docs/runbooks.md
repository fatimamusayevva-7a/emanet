# Əməliyyat runbook-ları (A.5.37)

Bütün əmrlər EC2-də SSM sessiyasında işlədilir:
`aws ssm start-session --target <instance_id>` → `cd /opt/emanet && alias em='sudo docker compose exec app python -m emanet.cli'`

## RB-01 · Yeni versiyanın yerləşdirilməsi
1. PR merge olunur, CI yaşıldır, tag yaradılır (`v1.2.0`).
2. `terraform apply -var repo_ref=v1.2.0` (user_data dəyişir → instansiya yenilənir) **və ya** SSM-də `git fetch && git checkout v1.2.0 && sudo docker compose up -d --build`.
3. `python scripts/verify_client.py https://<sayt>` → uyğunluq.
4. `em verify-audit` → `intact: true`.

## RB-02 · KMS açarının rotasiyası
- AWS: avtomatik (365 gün). Növbədənkənar: konsolda "Rotate now", sonra `em rotate-kms` bütün R-ləri yeni materiala sarır.
- Lokal: `em rotate-kms` → `{"new_version": N, "rewrapped": M}`.

## RB-03 · HMAC sirlərinin rotasiyası
1. Secrets Manager-də yeni dəyər yaradılır (`audit_hmac_key` istisnadır, aşağıya baxın).
2. `scheduler_hmac_key` üçün eyni dəyər `…/scheduler` sirrinə yazılır.
3. Konteyner yenidən başladılır.
4. `audit_hmac_key` dəyişəndə köhnə zəncir köhnə açarla yoxlanılır və arxivləşdirilir. Yeni zəncir yeni GENESIS ilə başlayır. Bu hadisə audit qeydi kimi yazılır.

## RB-04 · Snapshot-dan bərpa (rüblük test)
1. AWS Backup → son recovery point → "Restore" → yeni EBS həcmi (staging AZ).
2. Staging EC2-yə qoşun, `EMANET_DATA_DIR`-i ona yönəldin.
3. `em verify-audit`, test seyfinin açılması. Nəticə və vaxt O-8 metrikinə yazılır.

## RB-05 · Xidmət uzun müddət dayanıb (> 24 saat)
Sahiblər bu müddətdə "sağam" deyə bilməyiblər. Xidmət bərpa olunan kimi:
```
em pause-all <fasilə günləri + 7>
```
Bu əmr bütün aktiv seyflərə pauza tətbiq edir və gözləmə müddətindəki seyflərin açılma tarixini irəli çəkir. Sonra istifadəçilərə bildiriş göndərilir.

## RB-06 · Planlaşdırıcının əl ilə işlədilməsi
`em tick` → `{"evaluated": N, "emails_sent": M}`. Lambda-nı test etmək üçün: konsolda "Test" (boş hadisə).

## RB-07 · İlk operator/auditor
`em grant-role user@example.az operator` · `em grant-role audit@example.az auditor`
