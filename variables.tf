variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-west-2"
}

variable "lambda_function_name" {
  description = "Name of the S3 audit Lambda function"
  type        = string
  default     = "s3-bucket-health-auditor"
}

variable "report_bucket_name" {
  description = "S3 bucket where audit reports are stored"
  type        = string
  default     = "security-test-bucket-100"
}

variable "report_prefix" {
  description = "Prefix (folder) inside the report bucket"
  type        = string
  default     = "s3-audit-reports/"
}

variable "schedule_expression" {
  description = "EventBridge schedule expression (rate or cron)"
  type        = string
  default     = "rate(1 day)"
  # Example cron: cron(0 1 * * ? *)
}

variable "alert_emails" {
  description = "Email addresses to receive HIGH/CRITICAL S3 audit alerts"
  type        = list(string)
  default     = []
}