#!/usr/bin/env python3

import json
import boto3
from botocore.exceptions import ClientError


def check_encryption(s3_client, bucket_name: str):
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


def check_public_acl(s3_client, bucket_name: str):
    result = {
        "has_public_acl": False,
        "error": None,
    }

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


def check_versioning(s3_client, bucket_name: str):
    result = {
        "status": None,
        "enabled": False,
        "error": None,
    }

    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = resp.get("Status")
        result["status"] = status
        result["enabled"] = status == "Enabled"
    except ClientError as e:
        result["error"] = str(e)

    return result


def assess_bucket_risk(bucket_report):
    """Assess risk for a bucket and return (issues, highest_severity)."""
    issues = []
    severities = []

    enc = bucket_report["encryption"]
    acl = bucket_report["public_acl"]
    ver = bucket_report["versioning"]

    # If this bucket is locked down by an explicit deny in a resource-based policy,
    # treat it as an INFO-level, non-misconfiguration and skip noisy error text.
    explicit_deny_phrase = "explicit deny in a resource-based policy"
    locked_errors = [
        (acl.get("error") or ""),
        (enc.get("error") or ""),
        (ver.get("error") or ""),
    ]
    if any(explicit_deny_phrase in err for err in locked_errors):
        issues.append(
            "Bucket is locked down by an explicit deny in its bucket policy; "
            "current user is not allowed to inspect ACL/encryption/versioning."
        )
        severities.append("INFO")
        return issues, "INFO"

    # Public ACL = CRITICAL
    if acl["error"]:
        issues.append(f"ACL check error: {acl['error']}")
        severities.append("INFO")
    elif acl["has_public_acl"]:
        issues.append("Bucket ACL is public (AllUsers/AuthenticatedUsers).")
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

    order = ["CRITICAL", "HIGH", "MEDIUM", "INFO", "OK"]
    highest = "OK"
    for s in severities:
        if order.index(s) < order.index(highest):
            highest = s

    return issues, highest


def main():
    s3_client = boto3.client("s3")
    print("[DEBUG] Starting S3 audit script...")

    try:
        response = s3_client.list_buckets()
    except ClientError as e:
        print("[ERROR] Could not list buckets:", e)
        return

    buckets = response.get("Buckets", [])
    print(f"[DEBUG] Found {len(buckets)} bucket(s)")

    if not buckets:
        print("No buckets found in this account.")
        return

    full_report = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0, "OK": 0}

    for b in buckets:
        name = b["Name"]

        enc = check_encryption(s3_client, name)
        acl = check_public_acl(s3_client, name)
        ver = check_versioning(s3_client, name)

        bucket_report = {
            "bucket_name": name,
            "encryption": enc,
            "public_acl": acl,
            "versioning": ver,
        }

        issues, severity = assess_bucket_risk(bucket_report)
        bucket_report["issues"] = issues
        bucket_report["severity"] = severity

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        full_report.append(bucket_report)

        print(f"\nBucket: {name}  [Severity: {severity}]")

        if not issues:
            print("  ✅ No major issues detected.")
        else:
            for issue in issues:
                print("  ⚠", issue)

    print("\n=== Summary by Severity ===")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "INFO", "OK"]:
        print(f"  {level}: {severity_counts.get(level, 0)}")

    with open("s3_audit_report_v1.json", "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)
    print("\n[INFO] JSON report saved to s3_audit_report_v1.json")


if __name__ == "__main__":
    main()
