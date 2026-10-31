# Temporary AWS demo

No resources are provisioned by tests, builds, packaging, or CI. Uploaded Terraform and
synthetic fixtures are never applied. Only `infra/aws` is deployment configuration.

## Credit and account prerequisite

Check the AWS Billing console for the real account plan, remaining credit amount,
expiration and service eligibility. Estimate costs in the selected region for EC2,
EBS, public IPv4, S3 requests/storage/versions, CloudWatch, monitoring and data transfer.
Set a budget alert, but do not treat alerts or Terraform variables as a hard spending cap.
Do not upgrade an account to a paid plan to make this demo work automatically.

If the account has no applicable credits, or no eligible x86-64 instance with at least
4 GiB RAM, use the local software and stop cloud provisioning. Prefer a short demo session
and destroy the infrastructure afterward. Stopping EC2 leaves storage and potentially
other charges. See [AWS plan rules](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier-plans.html)
and [EC2 lifecycle costs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html).

The Terraform credit gate defaults to false. Its dependency graph prevents cloud resource
creation until the supplied verification conditions pass. The gate cannot independently
verify that your inputs are true; it is not a billing-enforcement service.

## Prepare a reviewed release

Run all tests and the benchmark first, then package source:

```powershell
.\.venv\Scripts\python.exe scripts/package_release.py
```

The archive, SHA256 and file manifest appear under `outputs`. The archive excludes user
uploads, .env, state, virtual environments and real infrastructure variable files.

Install the official AWS CLI, SSM Session Manager plugin and Terraform. Authenticate
using your normal AWS profile; do not paste credentials into source or container files.

```powershell
terraform -chdir=infra/aws init
terraform -chdir=infra/aws validate
```

Create `infra/aws/demo.tfvars` locally (gitignored), using actual verified values:

```hcl
region                        = "ap-south-1"
instance_type                 = "t3.medium"
credits_verified              = true
credit_balance_usd            = 0 # replace with the verified balance
verified_session_estimate_usd  = 0 # replace with the full regional estimate
credit_expires_at             = "2000-01-01T00:00:00Z" # replace with actual expiration
release_sha256                = "REPLACE_WITH_RELEASE_SHA256"
```

Review the plan before applying:

```powershell
terraform -chdir=infra/aws plan -var-file=demo.tfvars -out=demo.tfplan
terraform -chdir=infra/aws apply demo.tfplan
$bucket = terraform -chdir=infra/aws output -raw artifact_bucket
aws s3 cp outputs/iac-guard-v0.1.0.tar.gz "s3://$bucket/releases/iac-guard-v0.1.0.tar.gz" --sse AES256 --region ap-south-1
```

Upload immediately after apply: boot waits up to 15 minutes for the release. It verifies
the archive SHA256, generates a database password on the host, installs the checksum-verified
Compose plugin and starts the same containers as the local app. Building can take time.
If boot fails, use SSM to inspect `cloud-init` and the `iac-guard` systemd service; rerun
only after diagnosing the error. The source release and compose configuration must be reviewed.

The runtime role grants SSM access, reads the exact release object, reads/writes the
application's `iac-guard/` object prefix, and writes to the designated log group. No static
AWS keys are configured. CloudWatch log retention is three days.

## Connect and verify

```powershell
terraform -chdir=infra/aws output -raw connect_command
```

Run the returned SSM command and visit http://127.0.0.1:8501. Close any local server already
using that port first, or change the local port in the SSM command. No inbound application,
Redis, database or SSH ports are open.

Create a project, scan the example, request a fix, download the candidate, refresh the
page and reopen history. Confirm the VM has sufficient memory with one worker. This
deployment is a temporary private demo; public access and multi-user authentication are
outside v0.1.0.

## Teardown

Export reports and original snapshots you want to retain. PostgreSQL history is on the
instance volume and will be lost on termination. S3 is versioned and protected from
automatic removal by default.

To remove everything, explicitly allow **deletion of all S3 artifact/source versions**:

```powershell
terraform -chdir=infra/aws apply -var-file=demo.tfvars -var=allow_artifact_deletion=true
terraform -chdir=infra/aws destroy -var-file=demo.tfvars -var=allow_artifact_deletion=true
```

Review deletion prompts. Check the console afterward for remaining volumes, object
versions, log groups and addresses. Never commit state, saved plans, credentials or
your filled-in tfvars file.
