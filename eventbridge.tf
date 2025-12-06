resource "aws_cloudwatch_event_rule" "s3_audit_schedule" {
  name                = "${var.lambda_function_name}-schedule"
  description         = "Schedule for S3 bucket health auditor"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "s3_audit_target" {
  rule      = aws_cloudwatch_event_rule.s3_audit_schedule.name
  target_id = "${var.lambda_function_name}-target"
  arn       = aws_lambda_function.s3_bucket_auditor.arn
}

resource "aws_lambda_permission" "allow_eventbridge_invoke" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_bucket_auditor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_audit_schedule.arn
}