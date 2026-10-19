# CloudTrail — bütün AWS API çağırışları (KMS Decrypt daxil) dəyişdirilə bilməz jurnala.
resource "aws_cloudtrail" "main" {
  name                          = "${local.name}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true # SHA-256 + RSA imzalı digest faylları
  kms_key_id                    = aws_kms_key.logs.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.vaults.arn}/"]
    }
  }
  depends_on = [aws_s3_bucket_policy.trail]
}

# SES — göndərən ünvanın təsdiqi (DKIM domen üçün tövsiyə olunur)
resource "aws_sesv2_email_identity" "sender" {
  email_identity = var.ses_sender
}

# AWS Backup — EBS (SQLite DB) gündəlik snapshot, 35 gün saxlama; RPO ≤ 24 saat
resource "aws_backup_vault" "main" {
  name          = "${local.name}-backup"
  kms_key_arn   = aws_kms_key.data.arn
  force_destroy = var.teardown_friendly
}

# Vault Lock istehsalda həmişə aktivdir; yalnız qısa sınaq yerləşdirməsində söndürülür,
# əks halda ehtiyat nüsxələr müddəti bitənə qədər hesabı silmək mümkün olmazdı.
resource "aws_backup_vault_lock_configuration" "main" {
  count               = var.teardown_friendly ? 0 : 1
  backup_vault_name   = aws_backup_vault.main.name
  min_retention_days  = 7
  max_retention_days  = 90
  changeable_for_days = 3
}

resource "aws_backup_plan" "daily" {
  name = "${local.name}-daily"
  rule {
    rule_name         = "daily-0300-baku"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 23 * * ? *)" # 03:00 Bakı vaxtı
    lifecycle { delete_after = 35 }
  }
}

resource "aws_iam_role" "backup" {
  name = "${local.name}-backup"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "backup.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_selection" "tagged" {
  name         = "${local.name}-tagged"
  plan_id      = aws_backup_plan.daily.id
  iam_role_arn = aws_iam_role.backup.arn
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "daily"
  }
}
