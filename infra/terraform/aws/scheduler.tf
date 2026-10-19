# "Sağam" planlaşdırıcısı: EventBridge Scheduler → Lambda → HMAC imzalı POST /internal/tick
# Server-in özündəki cron-dan fərqli olaraq, EC2 yenidən başlasa belə planlaşdırma itmir
# və Lambda xətaları CloudWatch alarmı yaradır.
data "archive_file" "tick" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/tick.py"
  output_path = "${path.module}/.build/tick.zip"
}

resource "aws_cloudwatch_log_group" "tick" {
  name              = "/aws/lambda/${local.name}-tick"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_lambda_function" "tick" {
  function_name    = "${local.name}-tick"
  role             = aws_iam_role.tick.arn
  runtime          = "python3.12"
  handler          = "tick.handler"
  filename         = data.archive_file.tick.output_path
  source_code_hash = data.archive_file.tick.output_base64sha256
  timeout          = 60
  memory_size      = 128
  architectures    = ["arm64"]
  environment {
    variables = {
      APP_URL          = local.origin
      SCHEDULER_SECRET = aws_secretsmanager_secret.scheduler.arn
      METRIC_NAMESPACE = "Emanet"
    }
  }
  tracing_config { mode = "Active" }
  depends_on = [aws_cloudwatch_log_group.tick]
}

resource "aws_scheduler_schedule" "tick" {
  name                         = "${local.name}-tick"
  schedule_expression          = "rate(1 hour)"
  schedule_expression_timezone = "Asia/Baku"
  flexible_time_window { mode = "OFF" }
  target {
    arn      = aws_lambda_function.tick.arn
    role_arn = aws_iam_role.scheduler.arn
    retry_policy {
      maximum_retry_attempts       = 3
      maximum_event_age_in_seconds = 3600
    }
  }
}
