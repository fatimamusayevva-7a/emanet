# Seyf obyektləri: versiyalanma + Object Lock (dəyişməz ehtiyat) + SSE-KMS + yalnız TLS.
#
# Object Lock və "unudulma hüququ" ziddiyyəti crypto-shredding ilə həll olunur: silinmə zamanı
# DB-dəki sarınmış DEK/R məhv edilir, S3-də qalan köhnə versiyalar oxunmaz şifrəmətndir.

resource "aws_s3_bucket" "vaults" {
  bucket_prefix       = "${local.name}-vaults-"
  object_lock_enabled = true
  force_destroy       = false
}

resource "aws_s3_bucket_versioning" "vaults" {
  bucket = aws_s3_bucket.vaults.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "vaults" {
  bucket = aws_s3_bucket.vaults.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vaults" {
  bucket = aws_s3_bucket.vaults.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "vaults" {
  bucket                  = aws_s3_bucket.vaults.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "vaults" {
  bucket = aws_s3_bucket.vaults.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_lifecycle_configuration" "vaults" {
  bucket = aws_s3_bucket.vaults.id
  rule {
    id     = "noncurrent-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

resource "aws_s3_bucket_policy" "vaults" {
  bucket = aws_s3_bucket.vaults.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.vaults.arn, "${aws_s3_bucket.vaults.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyOldTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.vaults.arn, "${aws_s3_bucket.vaults.arn}/*"]
        Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
      },
      {
        Sid       = "DenyUnencryptedPut"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.vaults.arn}/*"
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } }
      },
      {
        Sid       = "DenyGovernanceBypassExceptBreakGlass"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:BypassGovernanceRetention"
        Resource  = "${aws_s3_bucket.vaults.arn}/*"
        Condition = { StringNotLike = { "aws:PrincipalArn" = "arn:aws:iam::${local.account_id}:role/emanet-break-glass" } }
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.vaults]
}

# ----------------------------------------------------------------- log bucket (CloudTrail)
resource "aws_s3_bucket" "trail" {
  bucket_prefix = "${local.name}-trail-"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "archive"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
    expiration { days = 2555 } # 7 il — A.5.33 qeydlərin qorunması
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}
