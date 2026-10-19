# Tətbiq sirləri — Secrets Manager-də, KMS ilə şifrəli. Tətbiq onları başlanğıcda
# IAM rolu ilə oxuyur (EMANET_SECRETS_ID); diskdə, AMI-də və ya user_data-da sirr yoxdur.
resource "random_bytes" "secret_key" {
  length = 32
}
resource "random_bytes" "audit_hmac_key" {
  length = 32
}
resource "random_bytes" "scheduler_hmac_key" {
  length = 32
}
resource "random_bytes" "local_kms_master_key" {
  length = 32 # AWS rejimində istifadə olunmur, amma konfiqurasiya validasiyası tələb edir
}

resource "aws_secretsmanager_secret" "app" {
  name                    = "${local.name}/app"
  description             = "Emanet tetbiq sirleri (HMAC acarlari)"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    secret_key           = random_bytes.secret_key.base64
    audit_hmac_key       = random_bytes.audit_hmac_key.base64
    scheduler_hmac_key   = random_bytes.scheduler_hmac_key.base64
    local_kms_master_key = random_bytes.local_kms_master_key.base64
  })
}

# Planlaşdırıcı Lambda yalnız öz HMAC açarını görür (ən az imtiyaz) — ayrıca sirr
resource "aws_secretsmanager_secret" "scheduler" {
  name                    = "${local.name}/scheduler"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "scheduler" {
  secret_id     = aws_secretsmanager_secret.scheduler.id
  secret_string = jsonencode({ scheduler_hmac_key = random_bytes.scheduler_hmac_key.base64 })
}
