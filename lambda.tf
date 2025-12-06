data "archive_file" "s3_audit_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda.py"
  output_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "s3_bucket_auditor" {
  function_name = var.lambda_function_name
  role          = aws_iam_role.s3_audit_lambda_role.arn
  handler       = "lambda.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.s3_audit_lambda_zip.output_path
  source_code_hash = data.archive_file.s3_audit_lambda_zip.output_base64sha256

  timeout = 60
  memory_size = 256

  environment {
    variables = {
      REPORT_BUCKET   = var.report_bucket_name
      REPORT_PREFIX   = var.report_prefix
      ALERT_TOPIC_ARN = aws_sns_topic.s3_audit_alerts.arn
    }
  }
}