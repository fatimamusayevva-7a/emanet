# KMS açarları — açar ayrılığı (key separation): hər məqsəd üçün ayrıca açar.
#
#  release — seyflərin "zaman kilidi" açarları R (GenerateDataKey / Decrypt)
#  data    — S3 obyektləri və Secrets Manager
#  logs    — CloudWatch Logs və CloudTrail

resource "aws_kms_key" "release" {
  description              = "Emanet: seyflerin zaman kilidi acarlari (R)"
  enable_key_rotation      = true
  rotation_period_in_days  = 365
  deletion_window_in_days  = 30
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        # İdarəetmə icazəsi var, amma şifrəaçma YOXDUR: admin R-i aça bilməz (vəzifələrin bölünməsi)
        Action = ["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
          "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:RotateKeyOnDemand"]
        Resource = "*"
      },
      {
        Sid       = "AppUseWithContextOnly"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.app.arn }
        Action    = ["kms:GenerateDataKey", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo"]
        Resource  = "*"
        Condition = {
          StringEquals                = { "kms:EncryptionContext:app" = "emanet", "kms:EncryptionContext:purpose" = "release-key" }
          "ForAllValues:StringEquals" = { "kms:EncryptionContextKeys" = ["app", "purpose", "vault_id"] }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "release" {
  name          = "alias/${local.name}-release"
  target_key_id = aws_kms_key.release.key_id
}

resource "aws_kms_key" "data" {
  description             = "Emanet: S3 seyf obyektleri ve Secrets Manager"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.name}-data"
  target_key_id = aws_kms_key.data.key_id
}

resource "aws_kms_key" "logs" {
  description             = "Emanet: CloudWatch Logs ve CloudTrail"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = { ArnLike = { "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${local.account_id}:*" } }
      },
      {
        Sid       = "CloudTrail"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { StringLike = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${local.account_id}:trail/*" } }
      }
    ]
  })
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.name}-logs"
  target_key_id = aws_kms_key.logs.key_id
}
