# 🛡️ S3 Security Guardian – S3 Bucket Health Auditor

**S3 Security Guardian** is a real-world AWS security automation project that continuously audits all S3 buckets in an account, classifies their risk level, writes JSON + human-readable reports, and sends **email alerts** when serious issues are found.

It uses:
* **AWS Lambda (Python)** – runs the S3 audit logic
* **Amazon S3** – stores the audit reports
* **Amazon EventBridge** – schedules the Lambda to run (e.g. daily)
* **Amazon SNS** – sends email alerts for HIGH / CRITICAL issues
* **Terraform** – deploys all of the above as infrastructure-as-code

---

## 🏁 Quick Start

If you already know Terraform and have AWS CLI configured, this is all you need:

```bash
git clone [https://github.com/achyutb02/s3-bucket-health-auditor.git](https://github.com/achyutb02/s3-bucket-health-auditor.git)
cd s3-bucket-health-auditor

# create terraform.tfvars with your values (see “Configure terraform.tfvars” below)

terraform init
terraform plan
terraform apply
