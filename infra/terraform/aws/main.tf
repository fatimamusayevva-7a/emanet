# Əmanət — AWS infrastrukturu (Infrastructure as Code)
#
#   İnternet ──443──▶ EIP ─▶ EC2 (Caddy TLS 1.3 ─▶ Emanet konteyneri)   [ictimai alt şəbəkə, SSH YOX]
#                                 │  IAM rolu (statik açar yoxdur)
#            ┌────────────────────┼───────────────────────┬──────────────────────┐
#            ▼                    ▼                       ▼                      ▼
#      KMS (R açarları)   S3 (seyf obyektləri:     Secrets Manager        SES (bildirişlər)
#      EncryptionContext  versioning + Object Lock (HMAC açarları)
#                         + SSE-KMS)
#   EventBridge Scheduler ──1 saat──▶ Lambda "tick" ──HMAC imzalı POST──▶ /internal/tick
#   CloudTrail (bütün API çağırışları, log validation) · CloudWatch (log, metric filter, alarm → SNS)
#   AWS Backup (EBS gündəlik) · GuardDuty · Budgets
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.60" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
  # İstehsalda vəziyyət faylı (state) şifrəli S3 + DynamoDB kilidi ilə saxlanılmalıdır:
  # backend "s3" { bucket = "emanet-tfstate-<hesab>" key = "prod.tfstate" region = "eu-central-1"
  #                encrypt = true dynamodb_table = "emanet-tf-lock" }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project            = "emanet"
      Environment        = var.environment
      Owner              = var.owner_tag
      DataClassification = "restricted"      # ISO 27001 A.5.12 — təsnifat etiketi
      ManagedBy          = "terraform"
    }
  }
}

data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

locals {
  name       = "emanet-${var.environment}"
  account_id = data.aws_caller_identity.me.account_id
  domain     = var.domain != "" ? var.domain : "${aws_eip.app.public_ip}.sslip.io"
  origin     = "https://${local.domain}"
}
