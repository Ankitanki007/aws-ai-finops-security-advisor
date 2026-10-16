"""Read-only AWS cost and security checks with optional Bedrock explanations."""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017, 9200, 11211}


def _finding(category: str, severity: str, title: str, resource_type: str,
             resource_id: str, evidence: str, recommendation: str) -> dict[str, str]:
    return {"category": category, "severity": severity, "title": title,
            "resource_type": resource_type, "resource_id": resource_id,
            "evidence": evidence, "recommendation": recommendation}


def _open_sensitive_ports(ip_ranges: list[dict[str, Any]], from_port: int | None,
                          to_port: int | None) -> list[int]:
    if from_port is None or to_port is None:
        return []
    if not any(item.get("CidrIp") == "0.0.0.0/0" for item in ip_ranges):
        return []
    return sorted(port for port in SENSITIVE_PORTS if from_port <= port <= to_port)


def _metric_average(cloudwatch: Any, instance_id: str, now: datetime) -> float | None:
    response = cloudwatch.get_metric_statistics(
        Namespace="AWS/EC2", MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=now - timedelta(days=7), EndTime=now, Period=86400,
        Statistics=["Average"],
    )
    points = response.get("Datapoints", [])
    if not points:
        return None
    return round(sum(float(point["Average"]) for point in points) / len(points), 2)


def _list_items(client: Any, operation: str, result_key: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Read all pages where the SDK supports pagination; keep small fakes easy to use."""
    try:
        paginator = client.get_paginator(operation)
    except Exception:
        return getattr(client, operation)(**kwargs).get(result_key, [])
    items: list[dict[str, Any]] = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def scan_account(*, ec2: Any, cloudwatch: Any, rds: Any, s3: Any, iam: Any,
                 region: str, account_id: str, now: datetime | None = None) -> dict[str, Any]:
    """Run deterministic checks using supplied boto3 clients (easy to test)."""
    now = now or datetime.now(timezone.utc)
    findings: list[dict[str, str]] = []
    warnings: list[str] = []
    checks = [
        "EC2 average CPU over the previous 7 days",
        "Unattached EBS volumes and unassociated Elastic IPs",
        "Public ingress to selected sensitive security-group ports",
        "S3 bucket public-policy status",
        "RDS public access and storage encryption",
        "Root account MFA status",
    ]

    reservations = _list_items(ec2, "describe_instances", "Reservations")
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            if instance.get("State", {}).get("Name") != "running":
                continue
            instance_id = instance["InstanceId"]
            try:
                cpu = _metric_average(cloudwatch, instance_id, now)
            except Exception as exc:
                warnings.append(f"EC2 CPU metric unavailable for {instance_id}: {type(exc).__name__}")
                continue
            if cpu is not None and cpu < 5:
                findings.append(_finding(
                    "cost", "medium", "Low average EC2 CPU", "EC2 instance", instance_id,
                    f"Seven-day average CPU utilization was {cpu}%.",
                    "Review workload and memory/network metrics before rightsizing or scheduling this instance.",
                ))

    for volume in _list_items(ec2, "describe_volumes", "Volumes"):
        if not volume.get("Attachments"):
            findings.append(_finding(
                "cost", "medium", "Unattached EBS volume", "EBS volume", volume["VolumeId"],
                f"Volume is {volume.get('Size', 'unknown')} GiB and has no attached instance.",
                "Confirm the volume is not needed for recovery, then snapshot or delete it through an approved change.",
            ))

    for address in _list_items(ec2, "describe_addresses", "Addresses"):
        if not address.get("AssociationId"):
            findings.append(_finding(
                "cost", "low", "Unassociated Elastic IP", "Elastic IP",
                address.get("AllocationId", "unknown"), "Elastic IP has no current association.",
                "Confirm it is not reserved for a planned change, then release it if unused.",
            ))

    for group in _list_items(ec2, "describe_security_groups", "SecurityGroups"):
        for rule in group.get("IpPermissions", []):
            ports = _open_sensitive_ports(rule.get("IpRanges", []), rule.get("FromPort"), rule.get("ToPort"))
            if ports:
                findings.append(_finding(
                    "security", "high", "Sensitive port open to the internet", "Security group",
                    group.get("GroupId", "unknown"),
                    f"IPv4 ingress from 0.0.0.0/0 includes port(s): {', '.join(map(str, ports))}.",
                    "Restrict ingress to approved source CIDRs or a trusted security group after checking dependencies.",
                ))

    for bucket in _list_items(s3, "list_buckets", "Buckets"):
        name = bucket["Name"]
        try:
            status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
            if status.get("IsPublic"):
                findings.append(_finding(
                    "security", "high", "S3 bucket policy allows public access", "S3 bucket", name,
                    "S3 reports the bucket policy as public.",
                    "Review the bucket policy and account-level Block Public Access settings before changing access.",
                ))
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code not in {"NoSuchBucketPolicy", "NoSuchBucketPolicyException"}:
                warnings.append(f"S3 policy status not checked for {name}: {type(exc).__name__}")

    for db in _list_items(rds, "describe_db_instances", "DBInstances"):
        db_id = db.get("DBInstanceIdentifier", "unknown")
        if db.get("PubliclyAccessible"):
            findings.append(_finding(
                "security", "high", "RDS instance is marked publicly accessible", "RDS instance", db_id,
                "RDS PubliclyAccessible is true; this does not by itself prove the database is reachable.",
                "Review subnet routing and security groups; disable public accessibility if not required.",
            ))
        if not db.get("StorageEncrypted", False):
            findings.append(_finding(
                "security", "medium", "RDS storage encryption is disabled", "RDS instance", db_id,
                "RDS reports StorageEncrypted=false.",
                "Plan an encrypted replacement or migration that preserves backups and application availability.",
            ))

    summary = iam.get_account_summary().get("SummaryMap", {})
    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append(_finding(
            "security", "high", "Root account MFA is not enabled", "AWS account", account_id,
            "IAM account summary reports AccountMFAEnabled=0.",
            "Enable MFA for the root user and avoid using root credentials for daily work.",
        ))

    return {
        "scan_time": now.isoformat(), "account_id": account_id, "region": region,
        "checks": checks, "findings": findings, "warnings": warnings,
        "summary": {
            "finding_count": len(findings),
            "high": sum(x["severity"] == "high" for x in findings),
            "medium": sum(x["severity"] == "medium" for x in findings),
            "low": sum(x["severity"] == "low" for x in findings),
        },
    }


def _ai_safe_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    """Remove account/resource identifiers before sending findings to the model."""
    keys = ("category", "severity", "title", "resource_type", "evidence", "recommendation")
    return [{key: item[key] for key in keys} for item in findings]


def summarize_with_bedrock(bedrock: Any, findings: list[dict[str, str]], model_id: str) -> str:
    if not findings:
        return "No findings were detected by the configured checks. This is not a complete security audit."
    prompt = (
        "Summarize these AWS cost and security findings for an engineer. Use only the provided facts. "
        "Do not invent savings amounts, vulnerabilities, or remediations. Group the most important actions first. "
        "State clearly that recommendations require human review. Keep it under 250 words.\n\n"
        + json.dumps(_ai_safe_findings(findings), separators=(",", ":"))
    )
    response = bedrock.converse(
        modelId=model_id,
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig={"maxTokens": 700, "temperature": 0.2, "topP": 0.9},
    )
    return "".join(part.get("text", "") for part in response["output"]["message"]["content"])


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    # Runtime import lets unit tests run without AWS credentials or boto3 installed.
    import boto3

    region = os.environ.get("SCAN_REGION", os.environ.get("AWS_REGION", "ap-southeast-2"))
    bucket = os.environ["REPORT_BUCKET"]
    model_id = os.environ.get("BEDROCK_MODEL_ID", "amazon.nova-micro-v1:0")
    session = boto3.session.Session(region_name=region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    report = scan_account(
        ec2=session.client("ec2"), cloudwatch=session.client("cloudwatch"),
        rds=session.client("rds"), s3=session.client("s3", region_name="us-east-1"),
        iam=session.client("iam"), region=region, account_id=account_id,
    )
    if os.environ.get("ENABLE_AI_SUMMARY", "true").lower() == "true":
        try:
            report["ai_summary"] = summarize_with_bedrock(
                session.client("bedrock-runtime"), report["findings"], model_id
            )
        except Exception as exc:
            report["ai_summary"] = None
            report["warnings"].append(f"AI summary unavailable: {type(exc).__name__}; rule findings are preserved.")
    else:
        report["ai_summary"] = None

    timestamp = datetime.now(timezone.utc)
    key = f"reports/{timestamp:%Y/%m/%d}/scan-{uuid.uuid4().hex}.json"
    session.client("s3").put_object(
        Bucket=bucket, Key=key, Body=json.dumps(report, indent=2).encode("utf-8"),
        ContentType="application/json", ServerSideEncryption="AES256",
    )
    return {"statusCode": 200, "report_bucket": bucket, "report_key": key, "summary": report["summary"]}
