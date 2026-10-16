import unittest
from datetime import datetime, timezone

from src.lambda_handler import _ai_safe_findings, _open_sensitive_ports, scan_account


class FakeEC2:
    def describe_instances(self):
        return {"Reservations": []}
    def describe_volumes(self):
        return {"Volumes": [{"VolumeId": "vol-unused", "Size": 20, "Attachments": []}]}
    def describe_addresses(self):
        return {"Addresses": [{"AllocationId": "eipalloc-unused"}]}
    def describe_security_groups(self):
        return {"SecurityGroups": [{"GroupId": "sg-test", "IpPermissions": [
            {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]}]}


class FakeCloudWatch:
    def get_metric_statistics(self, **kwargs):
        return {"Datapoints": []}


class FakeRDS:
    def describe_db_instances(self):
        return {"DBInstances": []}


class FakeS3:
    def list_buckets(self):
        return {"Buckets": []}


class FakeIAM:
    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 0}}


class RuleTests(unittest.TestCase):
    def test_sensitive_port_detection_requires_public_ipv4_range(self):
        self.assertEqual(_open_sensitive_ports([{"CidrIp": "0.0.0.0/0"}], 22, 23), [22])
        self.assertEqual(_open_sensitive_ports([{"CidrIp": "10.0.0.0/8"}], 22, 23), [])
        self.assertEqual(_open_sensitive_ports([{"CidrIp": "0.0.0.0/0"}], 80, 443), [])

    def test_scan_returns_expected_findings(self):
        report = scan_account(
            ec2=FakeEC2(), cloudwatch=FakeCloudWatch(), rds=FakeRDS(), s3=FakeS3(), iam=FakeIAM(),
            region="ap-southeast-2", account_id="123456789012",
            now=datetime(2026, 10, 15, tzinfo=timezone.utc),
        )
        titles = {item["title"] for item in report["findings"]}
        self.assertTrue({"Unattached EBS volume", "Unassociated Elastic IP",
                         "Sensitive port open to the internet", "Root account MFA is not enabled"} <= titles)
        self.assertEqual(report["region"], "ap-southeast-2")

    def test_ai_payload_excludes_resource_identifiers(self):
        finding = {"category": "security", "severity": "high", "title": "Public SG",
                   "resource_type": "Security group", "resource_id": "sg-secret",
                   "evidence": "SSH open", "recommendation": "Restrict access"}
        safe = _ai_safe_findings([finding])[0]
        self.assertNotIn("resource_id", safe)
        self.assertNotIn("sg-secret", str(safe))


if __name__ == "__main__":
    unittest.main()
