output "lambda_function_name" {
  description = "Name of the S3 audit Lambda function"
  value       = aws_lambda_function.s3_bucket_auditor.function_name
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge schedule rule"
  value       = aws_cloudwatch_event_rule.s3_audit_schedule.name
}

output "report_bucket" {
  description = "S3 bucket where audit reports are stored"
  value       = var.report_bucket_name
}

output "report_prefix" {
  description = "Prefix used for audit reports in the bucket"
  value       = var.report_prefix
}