import json
import datetime
import os

import boto3
from botocore.exceptions import ClientError

# === CONFIG ===
# These can be overridden via Lambda environment variables.
S3_REPORT_BUCKET = os.environ.get("REPORT_BUCKET", "security-test-bucket-100")
S3_REPORT_PREFIX = os.environ.get("REPORT_PREFIX", "s3-audit-reports/")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN")
# ==============


def check_encryption(s3_client, bucket_name):
    result = {
        "enabled": False,
        "algorithm": None,
        "kms_key_arn": None,
        "error": None,
    }

    try:
        resp = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            rule = rules[0]
            sse = rule.get("ApplyServerSideEncryptionByDefault", {})
            result["enabled"] = True
            result["algorithm"] = sse.get("SSEAlgorithm")
            result["kms_key_arn"] = sse.get("KMSMasterKeyID")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            result["enabled"] = False
        else:
            result["error"] = str(e)

    return result


def check_public_acl(s3_client, bucket_name):
    result = {"has_public_acl": False, "error": None}

    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        grants = acl.get("Grants", [])
        for g in grants:
            grantee = g.get("Grantee", {})
            uri = grantee.get("URI", "")

            if uri in (
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ):
                result["has_public_acl"] = True
                break
    except ClientError as e:
        result["error"] = str(e)

    return result


def check_versioning(s3_client, bucket_name):
    result = {"status": None, "enabled": False, "error": None}

    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket_name)
        result["status"] = resp.get("Status")
        result["enabled"] = resp.get("Status") == "Enabled"
    except ClientError as e:
        result["error"] = str(e)

    return result


def assess_bucket_risk(bucket_report):
    issues = []
    severities = []

    enc = bucket_report["encryption"]
    acl = bucket_report["public_acl"]
    ver = bucket_report["versioning"]

    # Locked buckets
    phrase = "explicit deny in a resource-based policy"
    locked = [
        (acl.get("error") or ""),
        (enc.get("error") or ""),
        (ver.get("error") or ""),
    ]
    if any(phrase in err for err in locked):
        issues.append(
            "Bucket is locked down by an explicit deny in its bucket policy; "
            "current role is not allowed to inspect ACL/encryption/versioning."
        )
        return issues, "INFO"

    # Public ACL
    if acl["error"]:
        issues.append(f"ACL check error: {acl['error']}")
        severities.append("INFO")
    elif acl["has_public_acl"]:
        issues.append("Bucket ACL is PUBLIC (AllUsers/AuthenticatedUsers).")
        severities.append("CRITICAL")

    # Encryption
    if enc["error"]:
        issues.append(f"Encryption check error: {enc['error']}")
        severities.append("INFO")
    elif not enc["enabled"]:
        issues.append("Default encryption is NOT enabled.")
        severities.append("HIGH")

    # Versioning
    if ver["error"]:
        issues.append(f"Versioning check error: {ver['error']}")
        severities.append("INFO")
    elif not ver["enabled"]:
        if ver["status"] == "Suspended":
            issues.append("Versioning is SUSPENDED.")
        else:
            issues.append("Versioning is NOT configured.")
        severities.append("MEDIUM")

    if not issues:
        return [], "OK"

    levels = ["CRITICAL", "HIGH", "MEDIUM", "INFO", "OK"]
    highest = min(severities, key=lambda s: levels.index(s))

    return issues, highest


def lambda_handler(event, context):
    s3_client = boto3.client("s3")

    try:
        response = s3_client.list_buckets()
    except ClientError as e:
        print("[ERROR] Could not list buckets:", e)
        return {"statusCode": 500, "body": "Error listing buckets"}

    buckets = response.get("Buckets", [])
    print(f"[INFO] Found {len(buckets)} bucket(s)")

    full_report = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0, "OK": 0}

    for b in buckets:
        name = b["Name"]

        enc = check_encryption(s3_client, name)
        acl = check_public_acl(s3_client, name)
        ver = check_versioning(s3_client, name)

        report = {
            "bucket_name": name,
            "encryption": enc,
            "public_acl": acl,
            "versioning": ver,
        }

        issues, severity = assess_bucket_risk(report)
        report["issues"] = issues
        report["severity"] = severity
        severity_counts[severity] += 1

        

        full_report.append(report)

    # Check if we have any HIGH or CRITICAL findings
    has_critical_or_high = (
        severity_counts.get("CRITICAL", 0) > 0
        or severity_counts.get("HIGH", 0) > 0
    )

    # Optionally send an SNS alert if a topic ARN is configured
    if has_critical_or_high and ALERT_TOPIC_ARN:
        sns_client = boto3.client("sns")
        try:
            alert_subject = "S3 Bucket Audit: HIGH/CRITICAL findings detected"

            alert_lines = []
            alert_lines.append("One or more S3 buckets have HIGH or CRITICAL issues.")
            alert_lines.append("")
            alert_lines.append("Summary by severity:")
            for level in ["CRITICAL", "HIGH", "MEDIUM", "INFO", "OK"]:
                count = severity_counts.get(level, 0)
                alert_lines.append(f"- {level}: {count}")

            alert_lines.append("")
            alert_lines.append("Affected buckets:")
            for report in full_report:
                sev = report["severity"]
                if sev in ("CRITICAL", "HIGH"):
                    alert_lines.append(f"- {report['bucket_name']} [{sev}]")

            alert_message = "\n".join(alert_lines)

            sns_client.publish(
                TopicArn=ALERT_TOPIC_ARN,
                Subject=alert_subject,
                Message=alert_message,
            )
            print("[INFO] Alert notification sent via SNS.")
        except ClientError as e:
            print("[ERROR] Failed to send SNS alert:", e)

    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
    json_key = f"{S3_REPORT_PREFIX}s3_audit_report_{ts}.json"
    text_key = f"{S3_REPORT_PREFIX}s3_audit_report_{ts}.txt"

    # Build a human-readable text summary
    lines = []
    lines.append(f"S3 Bucket Health Audit Report (UTC {ts})")
    lines.append("")
    lines.append("Summary by severity:")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "INFO", "OK"]:
        count = severity_counts.get(level, 0)
        lines.append(f"- {level}: {count}")

    lines.append("")

    lines.append("Per-bucket details:")

    severity_labels = {
        "CRITICAL": "[CRITICAL 🔥]",
        "HIGH": "[HIGH ⚠]",
        "MEDIUM": "[MEDIUM]",
        "INFO": "[INFO]",
        "OK": "[OK ✅]",
    }

    for report in full_report:
        name = report["bucket_name"]
        severity = report["severity"]
        issues = report.get("issues") or []
        label = severity_labels.get(severity, f"[{severity}]")
        lines.append("")
        lines.append(f"Bucket: {name} {label}")
        if not issues:
            lines.append("  - No major issues detected.")
        else:
            for issue in issues:
                lines.append(f"  - {issue}")

    text_body = "\n".join(lines)

    # Upload JSON report
    try:
        s3_client.put_object(
            Bucket=S3_REPORT_BUCKET,
            Key=json_key,
            Body=json.dumps(full_report, indent=2),
            ContentType="application/json",
        )
    except ClientError as e:
        print("[ERROR] Failed to upload JSON report to S3:", e)
        return {"statusCode": 500, "body": "Error uploading JSON report to S3"}

    # Upload human-readable text report
    try:
        s3_client.put_object(
            Bucket=S3_REPORT_BUCKET,
            Key=text_key,
            Body=text_body,
            ContentType="text/plain",
        )
    except ClientError as e:
        print("[ERROR] Failed to upload text report to S3:", e)
        return {"statusCode": 500, "body": "Error uploading text report to S3"}

    print(f"[INFO] JSON report uploaded to s3://{S3_REPORT_BUCKET}/{json_key}")
    print(f"[INFO] Text report uploaded to s3://{S3_REPORT_BUCKET}/{text_key}")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "S3 audit completed",
                "severity_counts": severity_counts,
                "report_bucket": S3_REPORT_BUCKET,
                "json_report_key": json_key,
                "text_report_key": text_key,
            }
        ),
    }