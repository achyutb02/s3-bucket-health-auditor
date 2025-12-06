resource "aws_sns_topic" "s3_audit_alerts" {
  name = "s3-audit-alerts"
}

# One subscription per email
resource "aws_sns_topic_subscription" "s3_audit_email" {
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.s3_audit_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}