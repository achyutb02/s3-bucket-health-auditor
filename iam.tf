data "aws_iam_policy_document" "s3_audit_lambda_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "s3_audit_lambda_role" {
  name               = "${var.lambda_function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.s3_audit_lambda_assume_role.json
}

data "aws_iam_policy_document" "s3_audit_lambda_policy" {
  # S3 inspection
  statement {
    sid    = "AllowS3BucketInspection"
    effect = "Allow"

    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketAcl",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketVersioning",
      "s3:GetBucketLocation",
    ]

    resources = ["arn:aws:s3:::*"]
  }

    statement {
    sid    = "AllowPublishToAlertsTopic"
    effect = "Allow"

    actions = [
      "sns:Publish",
    ]

    resources = [
      aws_sns_topic.s3_audit_alerts.arn
    ]
  }

  # Put reports into the report bucket
  statement {
    sid    = "AllowPutReports"
    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${var.report_bucket_name}/${var.report_prefix}*"
    ]
  }

  # CloudWatch Logs for Lambda
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*"
    ]
  }
}

resource "aws_iam_role_policy" "s3_audit_lambda_role_policy" {
  name   = "${var.lambda_function_name}-policy"
  role   = aws_iam_role.s3_audit_lambda_role.id
  policy = data.aws_iam_policy_document.s3_audit_lambda_policy.json
}