# Deployment policy review

The final AWS configuration passes Terraform provider/syntax validation. It has not been planned or applied against an AWS account. Checkov 3.2.489 and Trivy 0.65.0 report the findings below; no suppression comments were added.

The VPC default security group is explicitly restricted, EBS optimization is explicit, and incomplete multipart uploads are aborted after one day. Those changes add no inbound access or retention expiry for completed artifacts.

| Scanner | Rule | Finding |
| --- | --- | --- |
| Checkov | CKV_AWS_158 | Ensure that CloudWatch Log Group is encrypted by KMS |
| Checkov | CKV_AWS_338 | Ensure CloudWatch log groups retains logs for at least 1 year |
| Checkov | CKV_AWS_88 | EC2 instance should not have public IP. |
| Checkov | CKV2_AWS_62 | Ensure S3 buckets should have event notifications enabled |
| Checkov | CKV2_AWS_11 | Ensure VPC flow logging is enabled in all VPCs |
| Checkov | CKV_AWS_18 | Ensure the S3 bucket has access logging enabled |
| Checkov | CKV_AWS_144 | Ensure that S3 bucket has cross-region replication enabled |
| Checkov | CKV_AWS_145 | Ensure that S3 buckets are encrypted with KMS by default |
| Trivy | AVD-AWS-0017 | CloudWatch log groups should be encrypted using CMK |
| Trivy | AVD-AWS-0089 | S3 Bucket Logging |
| Trivy | AVD-AWS-0104 | A security group rule should not allow unrestricted egress to any IP address. |
| Trivy | AVD-AWS-0132 | S3 encryption should use Customer Managed Keys |
| Trivy | AVD-AWS-0178 | VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet "Rejects" for VPCs. |

These are documented MVP tradeoffs, not assertions that the policies are irrelevant:

- Public IPv4 enables outbound SSM/registry access without a NAT gateway or private endpoints. There are no inbound security-group rules. IPv4 charges must be included in the credit estimate.
- Outbound TCP 443 permits software registries and AWS endpoints; it is not a domain allowlist. Uploaded remote modules are refused before scanning.
- S3 uses private SSE-S3 encryption; CloudWatch uses service-managed encryption. Customer-managed KMS keys are deferred with their costs and key policies.
- Three-day application log retention suits a short private demo. VPC flow logs and S3 access logs add retention, access and cost decisions and remain deferred.
- Cross-region replication and S3 event notifications are outside this single-region learning deployment.

Before broader deployment, review these findings against actual operational requirements and verified regional costs. Do not describe this configuration as scanner-clean or production-hardened.

Raw evidence: [Checkov](results/deployment-checkov.json), [Trivy](results/deployment-trivy.json). The commands scanned `infra/aws` without module downloads; no uploaded dataset was deployed.
