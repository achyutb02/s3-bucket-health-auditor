# S3 Security Guardian – S3 Bucket Health Auditor

This project is an automated security check for AWS S3.

- Uses AWS Lambda (Python) triggered by EventBridge on a schedule.
- Audits every S3 bucket for:
  - Default encryption
  - Public ACLs (flags public buckets as CRITICAL)
  - Versioning status
  - Locked-down buckets (explicit deny) without breaking
- Writes two reports to a central S3 bucket:
  - JSON (machine-readable)
  - Text (human-readable with severities like [CRITICAL 🔥], [HIGH ⚠], [MEDIUM], [INFO], [OK ✅])
- Sends SNS email alerts if any bucket is CRITICAL or HIGH.

All infrastructure (Lambda, IAM, SNS, EventBridge) is defined with Terraform and can be deployed with a single `terraform apply`.
