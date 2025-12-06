# 🛡️ S3 Security Guardian

# S3 Security Guardian – S3 Bucket Health Auditor

S3 Security Guardian is a **real-world AWS security automation** project that continuously audits all S3 buckets in an AWS account, classifies their risk level, writes JSON + human-readable reports, and sends **email alerts** for serious issues.

It uses:

- **AWS Lambda (Python)** – to scan buckets and generate reports  
- **Amazon S3** – to store audit reports  
- **Amazon EventBridge** – to run the audit on a schedule  
- **Amazon SNS** – to email alerts for HIGH/CRITICAL issues  
- **Terraform** – to deploy the entire stack with a single `terraform apply`


---

## 🚀 Key Features

* **🔍 Deep Security Scans:**
    * **Public Access Detection:** Instantly flags buckets with dangerous ACLs (`AllUsers` or `AuthenticatedUsers`) as **[CRITICAL]**.
    * **Encryption Verification:** Identifies buckets missing default server-side encryption (**[HIGH]** severity).
    * **Versioning Checks:** Warns if object versioning is disabled, vital for ransomware protection (**[MEDIUM]** severity).
    * **Policy Inspection:** Reports on buckets with restrictive policies that block auditing (**[INFO]**).

* **⚡ Real-Time Alerting:**
    * Integrates with **Amazon SNS** to send immediate email or SMS notifications for **CRITICAL** and **HIGH** severity findings.

* **📊 Comprehensive Reporting:**
    * Generates both **human-readable (.txt)** summaries and **machine-parseable (.json)** logs.
    * Reports are centrally stored in a dedicated S3 bucket for audit trails.

* **🏗️ Infrastructure as Code (IaC):**
    * Built entirely with **Terraform** for reliable, repeatable, and one-click deployments.

---

## 🏗️ Architecture

The solution leverages a serverless architecture to minimize cost and maintenance:

1.  **Amazon EventBridge:** Triggers the audit Lambda on a scheduled basis (e.g., daily).
2.  **AWS Lambda (Python):** The core engine that iterates through all buckets and applies security logic.
3.  **Amazon S3:** Stores the generated audit reports.
4.  **Amazon SNS:** Broadcasts alerts to administrators when risks are detected.

---

## 🛠️ Prerequisites

Before deploying, ensure you have the following installed:

* **[AWS CLI](https://aws.amazon.com/cli/)**: Configured with `AdministratorAccess` or appropriate permissions.
* **[Terraform](https://www.terraform.io/downloads)** (v1.0+): For provisioning infrastructure.
* **Python 3.9+**: Required only for local testing or modifications.

---

## ⚙️ Installation & Deployment

Follow these steps to deploy the S3 Security Guardian in minutes.

### 1. Clone the Repository
```bash
git clone [https://github.com/achyutb02/s3-bucket-health-auditor.git](https://github.com/achyutb02/s3-bucket-health-auditor.git)
