# IAM — ən az imtiyaz. Statik giriş açarı (access key) yoxdur: EC2 və Lambda rolları qısa ömürlü STS kredensialları alır.

resource "aws_iam_role" "app" {
  name = "${local.name}-app"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "${local.name}-app"
  role = aws_iam_role.app.name
}

resource "aws_iam_role_policy" "app" {
  name = "emanet-app-least-privilege"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReleaseKeys"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo"]
        Resource = aws_kms_key.release.arn
        Condition = {
          StringEquals = { "kms:EncryptionContext:app" = "emanet", "kms:EncryptionContext:purpose" = "release-key" }
        }
      },
      {
        Sid      = "VaultObjects"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.vaults.arn}/vaults/*"
      },
      {
        Sid       = "VaultList"
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.vaults.arn
        Condition = { StringLike = { "s3:prefix" = ["vaults/*"] } }
      },
      {
        Sid      = "S3DataKey"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.data.arn
        Condition = {
          StringEquals = { "kms:ViaService" = ["s3.${var.region}.amazonaws.com", "secretsmanager.${var.region}.amazonaws.com"] }
        }
      },
      {
        Sid      = "AppSecret"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.app.arn
      },
      {
        Sid       = "SendMail"
        Effect    = "Allow"
        Action    = ["ses:SendEmail"]
        Resource  = "*"
        Condition = { StringEquals = { "ses:FromAddress" = var.ses_sender } }
      },
      {
        Sid      = "AppLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = "${aws_cloudwatch_log_group.app.arn}:*"
      }
    ]
  })
}

# SSH əvəzinə SSM Session Manager (sessiyalar CloudTrail-də qeyd olunur)
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ----------------------------------------------------------------- Lambda (planlaşdırıcı)
resource "aws_iam_role" "tick" {
  name = "${local.name}-tick"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "tick" {
  role = aws_iam_role.tick.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = aws_secretsmanager_secret.scheduler.arn },
      {
        Effect    = "Allow", Action = "kms:Decrypt", Resource = aws_kms_key.data.arn,
        Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } }
      },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.tick.arn}:*" },
      { Effect = "Allow", Action = "cloudwatch:PutMetricData", Resource = "*", Condition = { StringEquals = { "cloudwatch:namespace" = "Emanet" } } }
    ]
  })
}

resource "aws_iam_role" "scheduler" {
  name = "${local.name}-scheduler"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "scheduler.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "lambda:InvokeFunction", Resource = aws_lambda_function.tick.arn }]
  })
}

# Hesab səviyyəsində parol siyasəti (konsol istifadəçiləri üçün, CIS AWS 1.8–1.9)
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  max_password_age               = 0
  allow_users_to_change_password = true
}
