# Hesablama: Amazon Linux 2023, IMDSv2 məcburi, şifrəli EBS, SSH açarı yoxdur, sabit IP (EIP).
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_eip" "app" {
  domain = "vpc"
  tags   = { Name = local.name }
}

resource "aws_instance" "app" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  iam_instance_profile        = aws_iam_instance_profile.app.name
  associate_public_ip_address = true
  monitoring                  = true
  disable_api_termination     = var.environment == "prod"
  # key_name YOXDUR — SSH ilə giriş mümkün deyil, yalnız SSM Session Manager

  metadata_options {
    http_tokens                 = "required" # IMDSv2 — SSRF ilə kredensial oğurluğuna qarşı
    http_put_response_hop_limit = 1          # konteynerlər IMDS-ə çata bilmir
    http_endpoint               = "enabled"
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    kms_key_id            = aws_kms_key.data.arn
    delete_on_termination = false
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    repo_url       = var.repo_url
    repo_ref       = var.repo_ref
    domain         = local.domain
    origin         = local.origin
    acme_email     = var.acme_email
    region         = var.region
    secrets_id     = aws_secretsmanager_secret.app.arn
    kms_key_id     = aws_kms_key.release.arn
    s3_bucket      = aws_s3_bucket.vaults.bucket
    ses_sender     = var.ses_sender
    log_group      = aws_cloudwatch_log_group.app.name
    operator_email = var.alert_email
  })
  user_data_replace_on_change = true

  tags       = { Name = local.name, Backup = "daily" }
  depends_on = [aws_secretsmanager_secret_version.app]
}

resource "aws_eip_association" "app" {
  instance_id   = aws_instance.app.id
  allocation_id = aws_eip.app.id
}

# Avtomatik bərpa: sistem yoxlaması uğursuz olarsa instansiya başqa hosta köçürülür (A.8.14)
resource "aws_cloudwatch_metric_alarm" "auto_recover" {
  alarm_name          = "${local.name}-auto-recover"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  dimensions          = { InstanceId = aws_instance.app.id }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = ["arn:aws:automate:${var.region}:ec2:recover", aws_sns_topic.alerts.arn]
}
