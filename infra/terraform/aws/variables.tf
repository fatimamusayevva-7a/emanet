variable "region" {
  description = "AWS regionu (Frankfurt — Azərbaycana ən yaxın AB regionu, GDPR üçün AB daxilində)"
  type        = string
  default     = "eu-central-1"
}

variable "environment" {
  type    = string
  default = "prod"
  validation {
    condition     = contains(["prod", "staging"], var.environment)
    error_message = "environment: prod və ya staging"
  }
}

variable "owner_tag" {
  type    = string
  default = "emanet-security-team"
}

variable "domain" {
  description = "Öz domeniniz (məs. emanet.az). Boş qalsa <EIP>.sslip.io istifadə olunur — Let's Encrypt yenə də işləyir."
  type        = string
  default     = ""
}

variable "acme_email" {
  description = "Let's Encrypt sertifikat bildirişləri üçün e-poçt"
  type        = string
}

variable "alert_email" {
  description = "CloudWatch alarm bildirişləri (SNS) üçün e-poçt"
  type        = string
}

variable "ses_sender" {
  description = "Bildiriş məktublarının göndərən ünvanı (SES-də təsdiqlənməlidir)"
  type        = string
}

variable "repo_url" {
  description = "Tətbiqin Git repozitoriyası"
  type        = string
  default     = "https://github.com/USERNAME/emanet.git"
}

variable "repo_ref" {
  description = "Yerləşdiriləcək commit/tag (dəyişməz versiya — supply-chain nəzarəti)"
  type        = string
  default     = "main"
}

variable "instance_type" {
  type    = string
  default = "t3.small"
}

variable "object_lock_days" {
  description = "S3 Object Lock (GOVERNANCE) saxlama müddəti — ransomware/səhv silinməyə qarşı"
  type        = number
  default     = 30
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "monthly_budget_usd" {
  type    = number
  default = 30
}

variable "enable_guardduty" {
  description = "Hesabda GuardDuty artıq aktivdirsə false edin"
  type        = bool
  default     = true
}

variable "allowed_ingress_cidrs" {
  description = "HTTPS-ə icazə verilən şəbəkələr (ictimai xidmət üçün 0.0.0.0/0)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "teardown_friendly" {
  description = "Qisa sinaq yerlesdirmesi: terraform destroy butun resurslari silə bilsin (istehsalda false)"
  type        = bool
  default     = false
}
