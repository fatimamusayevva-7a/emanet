output "url" {
  description = "Tətbiqin ünvanı (HTTPS, Let's Encrypt)"
  value       = local.origin
}

output "public_ip" {
  value = aws_eip.app.public_ip
}

output "instance_id" {
  description = "SSM ilə qoşulmaq: aws ssm start-session --target <id>"
  value       = aws_instance.app.id
}

output "vault_bucket" {
  value = aws_s3_bucket.vaults.bucket
}

output "release_kms_key" {
  value = aws_kms_alias.release.name
}

output "app_secret_arn" {
  value = aws_secretsmanager_secret.app.arn
}

output "dashboard" {
  value = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}
