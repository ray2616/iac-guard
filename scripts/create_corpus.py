"""Materialize 30 hand-authored base cases, not randomized copies of one template."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "datasets"
CASES = []


def label(
    file="main.tf", resource="aws_ebs_volume.data", checkov="CKV_AWS_3", trivy="AVD-AWS-0026"
):
    return {
        "file": file,
        "resource_suffix": resource,
        "rules": {"checkov": checkov, "trivy": trivy},
    }


def case(name, files, labels=(), absent=(), expected="findings", note=""):
    CASES.append(
        {
            "id": name,
            "kind": "terraform",
            "files": files,
            "labels": list(labels),
            "absent": list(absent),
            "expected": expected,
            "note": note,
        }
    )


EBS = 'resource "aws_ebs_volume" "data" {\n  availability_zone = "us-east-1a"\n  size = 10\n  encrypted = false\n}\n'
RDS = 'resource "aws_db_instance" "app" {\n  engine = "postgres"\n  instance_class = "db.t3.micro"\n  allocated_storage = 20\n  username = "example_user"\n  manage_master_user_password = true\n  storage_encrypted = %s\n  publicly_accessible = %s\n}\n'
SAFE_EBS = EBS.replace(
    "encrypted = false",
    'encrypted = true\n  kms_key_id = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"',
)
case("tf01-ebs-literal", {"main.tf": EBS}, [label()])
case(
    "tf02-rds-encryption",
    {"main.tf": RDS % ("false", "false")},
    [label(resource="aws_db_instance.app", checkov="CKV_AWS_16", trivy="AVD-AWS-0080")],
)
case(
    "tf03-rds-public",
    {"main.tf": RDS % ("true", "true")},
    [label(resource="aws_db_instance.app", checkov="CKV_AWS_17", trivy="AVD-AWS-0180")],
)
case(
    "tf04-variables",
    {
        "main.tf": EBS.replace("encrypted = false", "encrypted = var.encryption"),
        "variables.tf": 'variable "encryption" {\n type = bool\n default = false\n}\n',
    },
    [label()],
    note="Variable-driven attribute must be refused by automatic fixing.",
)
case(
    "tf05-cross-file-reference",
    {
        "storage.tf": EBS.replace('"us-east-1a"', "var.zone"),
        "variables.tf": 'variable "zone" { default = "us-east-1a" }',
        "outputs.tf": 'output "disk_id" { value = aws_ebs_volume.data.id }',
    },
    [label(file="storage.tf")],
)
case(
    "tf06-local-module",
    {"main.tf": 'module "volume" { source = "./modules/volume" }', "modules/volume/main.tf": EBS},
    [label(file="modules/volume/main.tf")],
    note="Bundled module finding is scan-only.",
)
CASES[-1]["labels"][0]["resource_aliases"] = {"trivy": ["module.volume"]}
case(
    "tf07-two-root-files",
    {"storage.tf": EBS, "database.tf": RDS % ("true", "true")},
    [
        label(file="storage.tf"),
        label(
            file="database.tf",
            resource="aws_db_instance.app",
            checkov="CKV_AWS_17",
            trivy="AVD-AWS-0180",
        ),
    ],
)
case(
    "tf08-public-access-block",
    {
        "main.tf": 'resource "aws_s3_bucket_public_access_block" "access" {\n bucket = "example"\n block_public_acls = false\n block_public_policy = false\n ignore_public_acls = false\n restrict_public_buckets = false\n}'
    },
    note="Unsupported automatic fix; access policy requires review.",
)
case(
    "tf09-open-ssh",
    {
        "main.tf": 'resource "aws_security_group" "access" {\n name = "example"\n description = "Example access"\n ingress {\n description = "SSH"\n from_port = 22\n to_port = 22\n protocol = "tcp"\n cidr_blocks = ["0.0.0.0/0"]\n }\n}'
    },
    note="Requires an approved source range, not a guessed replacement.",
)
case(
    "tf10-selected-variables",
    {
        "main.tf": EBS.replace("encrypted = false", "encrypted = var.encryption"),
        "variables.tf": 'variable "encryption" { type = bool }',
        "dev.tfvars": "encryption = false",
    },
    [label()],
    note="Run with dev.tfvars explicitly selected.",
)
CASES[-1]["variables"] = ["dev.tfvars"]
case(
    "tf11-rds-two-flaws",
    {"main.tf": RDS % ("false", "true")},
    [
        label(resource="aws_db_instance.app", checkov="CKV_AWS_16", trivy="AVD-AWS-0080"),
        label(resource="aws_db_instance.app", checkov="CKV_AWS_17", trivy="AVD-AWS-0180"),
    ],
)
case(
    "tf12-external-module",
    {
        "main.tf": EBS
        + '\nmodule "unavailable" {\n source = "hashicorp/consul/aws"\n version = "0.11.0"\n}'
    },
    [label()],
    expected="unverified",
    note="Must disclose unavailable external-module coverage without downloading it.",
)
case("tf13-secure-volume", {"main.tf": SAFE_EBS}, absent=[label()], expected="secure-control")
case(
    "tf14-secure-access-block",
    {"main.tf": CASES[7]["files"]["main.tf"].replace("false", "true")},
    expected="secure-control",
)
case(
    "tf15-secure-split",
    {"storage.tf": SAFE_EBS, "outputs.tf": 'output "id" { value = aws_ebs_volume.data.id }'},
    absent=[label(file="storage.tf")],
    expected="secure-control",
)
case(
    "tf16-secure-module",
    {
        "main.tf": 'module "volume" { source = "./modules/volume" }',
        "modules/volume/main.tf": SAFE_EBS,
    },
    absent=[label(file="modules/volume/main.tf")],
    expected="secure-control",
)
case(
    "tf17-malformed",
    {"main.tf": 'resource "aws_ebs_volume" "data" {\n encrypted = '},
    expected="invalid",
)
case(
    "tf18-duplicate-root",
    {"a.tf": EBS, "b.tf": EBS},
    expected="refusal",
    note="Duplicate root addresses must not be automatically patched.",
)
case(
    "tf19-reused-module",
    {
        "main.tf": 'module "one" { source = "./modules/volume" }\nmodule "two" { source = "./modules/volume" }',
        "modules/volume/main.tf": EBS,
    },
    expected="refusal",
    note="Same source file instantiated twice; module edits are unsupported.",
)
case(
    "tf20-expression",
    {"main.tf": EBS.replace("encrypted = false", 'encrypted = length("example") < 1')},
    expected="refusal",
    note="An expression is never rewritten as a guessed literal.",
)

DOCKER_SAFE = (
    'FROM alpine:3.21.3\nWORKDIR /app\nUSER 10001\nHEALTHCHECK CMD ["true"]\nCMD ["true"]\n'
)
docker_cases = [
    ("dk01-no-user", DOCKER_SAFE.replace("USER 10001\n", ""), "CKV_DOCKER_3", "", "findings"),
    (
        "dk02-root-user",
        DOCKER_SAFE.replace("USER 10001", "USER root"),
        "CKV_DOCKER_8",
        "USER",
        "findings",
    ),
    (
        "dk03-latest",
        DOCKER_SAFE.replace("alpine:3.21.3", "alpine:latest"),
        "CKV_DOCKER_7",
        "FROM",
        "findings",
    ),
    (
        "dk04-add",
        DOCKER_SAFE.replace("WORKDIR /app", "WORKDIR /app\nADD example.txt /app/example.txt"),
        "CKV_DOCKER_4",
        "ADD",
        "findings",
    ),
    ("dk05-expose-ssh", DOCKER_SAFE + "EXPOSE 22\n", "CKV_DOCKER_1", "EXPOSE", "findings"),
    (
        "dk06-no-healthcheck",
        DOCKER_SAFE.replace('HEALTHCHECK CMD ["true"]\n', ""),
        "CKV_DOCKER_2",
        "",
        "findings",
    ),
    ("dk07-secure-control", DOCKER_SAFE, "CKV_DOCKER_8", "USER", "secure-control"),
    (
        "dk08-secure-multistage",
        "FROM alpine:3.21.3 AS builder\nRUN printf example > /example\n"
        + DOCKER_SAFE.replace(
            "WORKDIR /app", "WORKDIR /app\nCOPY --from=builder /example /app/example"
        ),
        "CKV_DOCKER_7",
        "FROM",
        "secure-control",
    ),
    ("dk09-missing-from", "RUN echo example\nUSER 10001\n", "", "", "invalid"),
    ("dk10-fenced", "```dockerfile\nFROM alpine:3.21.3\n```\n", "", "", "invalid"),
]
for name, source, rule, resource, expected in docker_cases:
    item = label(file="Dockerfile", resource=resource, checkov=rule, trivy="")
    CASES.append(
        {
            "id": name,
            "kind": "dockerfile",
            "files": {"Dockerfile": source},
            "labels": [item] if expected == "findings" else [],
            "absent": [item] if expected == "secure-control" else [],
            "expected": expected,
            "note": "Configuration controls only; image existence/build/runtime not evaluated.",
        }
    )


def main():
    ROOT.mkdir(exist_ok=True)
    manifest = []
    for item in CASES:
        folder = ROOT / item["id"]
        for name, content in item["files"].items():
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((content + "\n").encode())
        manifest.append({k: v for k, v in item.items() if k != "files"})
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Created {len(manifest)} base cases")


if __name__ == "__main__":
    main()
