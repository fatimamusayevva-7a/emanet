# Monitorinq və aşkarlama (NIST CSF DE, ISO 27001 A.8.15–A.8.16).
# Qeyd: alarm mesajlarında sirr yoxdur. AWS-managed "alias/aws/sns" açarı EventBridge-in
# dərc etməsinə imkan vermədiyi üçün mövzu SSE-siz saxlanılır (Checkov CKV_AWS_26 — əsaslandırılmış istisna).
resource "aws_sns_topic" "alerts" {
  name = "${local.name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/emanet/${var.environment}/app"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

locals {
  # Tətbiq strukturlaşdırılmış JSON log yazır: {"security_event": "<növ>", ...} və {"audit": "<hərəkət>", ...}
  metric_filters = {
    SecurityEvents          = { pattern = "\"security_event\"", threshold = 50, period = 300 }
    LoginFailures           = { pattern = "\"login_failed\"", threshold = 30, period = 300 }
    AccountLocked           = { pattern = "\"account_locked\"", threshold = 3, period = 900 }
    PrematureReleaseAttempt = { pattern = "\"premature_release_attempt\"", threshold = 1, period = 300 }
    VaultReleased           = { pattern = "\"switch.pending_release->released\"", threshold = 1, period = 300 }
    BolaDenied              = { pattern = "\"bola_denied\"", threshold = 5, period = 300 }
    SchedulerBadSignature   = { pattern = "\"scheduler_bad_signature\"", threshold = 1, period = 300 }
    MassAssignment          = { pattern = "\"mass_assignment_attempt\"", threshold = 1, period = 300 }
    UnhandledErrors         = { pattern = "\"unhandled error\"", threshold = 5, period = 300 }
  }
}

resource "aws_cloudwatch_log_metric_filter" "app" {
  for_each       = local.metric_filters
  name           = "${local.name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = each.value.pattern
  metric_transformation {
    name          = each.key
    namespace     = "Emanet"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "app" {
  for_each            = local.metric_filters
  alarm_name          = "${local.name}-${each.key}"
  alarm_description   = "Emanet: ${each.key} — playbook: isms/policies/incident-response.md"
  namespace           = "Emanet"
  metric_name         = each.key
  statistic           = "Sum"
  period              = each.value.period
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  depends_on          = [aws_cloudwatch_log_metric_filter.app]
}

# Planlaşdırıcı işləmirsə, "sağam" xatırlatmaları getmir — bu, biznes riskidir (R-07)
resource "aws_cloudwatch_metric_alarm" "tick_errors" {
  alarm_name          = "${local.name}-tick-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.tick.function_name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "tick_missing" {
  alarm_name          = "${local.name}-tick-missing"
  namespace           = "Emanet"
  metric_name         = "TickSucceeded"
  statistic           = "Sum"
  period              = 10800
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "cpu" {
  alarm_name          = "${local.name}-cpu"
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  dimensions          = { InstanceId = aws_instance.app.id }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = local.name
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", width = 12, height = 6, properties = {
          title   = "Tehlukesizlik hadiseleri", region = var.region, stat = "Sum", period = 300,
          metrics = [for k in ["SecurityEvents", "LoginFailures", "BolaDenied", "PrematureReleaseAttempt"] : ["Emanet", k]]
        }
      },
      {
        type = "metric", width = 12, height = 6, properties = {
          title   = "Planlasdirici", region = var.region, stat = "Sum", period = 3600,
          metrics = [["Emanet", "TickSucceeded"], ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.tick.function_name]]
        }
      }
    ]
  })
}

# ----------------------------------------------------------------- GuardDuty və büdcə
resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
}

resource "aws_budgets_budget" "monthly" {
  name         = "${local.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}

# ----------------------------------------------------------------- KMS açarına təhlükəli əməliyyatlar (R-09)
resource "aws_cloudwatch_event_rule" "kms_danger" {
  name        = "${local.name}-kms-danger"
  description = "KMS acari silinmeye planlasdirildi ve ya deaktiv edildi"
  event_pattern = jsonencode({
    source        = ["aws.kms"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName   = ["ScheduleKeyDeletion", "DisableKey", "PutKeyPolicy", "DisableKeyRotation"]
    }
  })
}

resource "aws_cloudwatch_event_target" "kms_danger" {
  rule = aws_cloudwatch_event_rule.kms_danger.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgeAndCloudWatch"
      Effect    = "Allow"
      Principal = { Service = ["events.amazonaws.com", "cloudwatch.amazonaws.com"] }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}
