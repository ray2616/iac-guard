from dataclasses import dataclass

from ..models import Finding


@dataclass(frozen=True)
class BooleanFix:
    name: str
    resource_type: str
    attribute: str
    before: bool
    after: bool
    rules: tuple[tuple[str, str], ...]
    impact: str

    def matches(self, finding: Finding) -> bool:
        return (
            (finding.scanner, finding.rule_id) in self.rules
            and finding.resource.startswith(self.resource_type + ".")
            and finding.resource.count(".") == 1
        )


FIXES = (
    BooleanFix(
        "ebs-encryption",
        "aws_ebs_volume",
        "encrypted",
        False,
        True,
        (("checkov", "CKV_AWS_3"), ("trivy", "AVD-AWS-0026")),
        "Encryption may replace an existing volume; review data migration before deployment.",
    ),
    BooleanFix(
        "rds-encryption",
        "aws_db_instance",
        "storage_encrypted",
        False,
        True,
        (("checkov", "CKV_AWS_16"), ("trivy", "AVD-AWS-0080")),
        "Encryption may require database replacement or migration; review the Terraform plan.",
    ),
    BooleanFix(
        "rds-private-access",
        "aws_db_instance",
        "publicly_accessible",
        True,
        False,
        (("checkov", "CKV_AWS_17"), ("trivy", "AVD-AWS-0180")),
        "Public clients may lose connectivity; confirm private application access first.",
    ),
)


def handler_for(finding: Finding) -> BooleanFix | None:
    return next((spec for spec in FIXES if spec.matches(finding)), None)


def guidance(finding: Finding) -> str:
    spec = handler_for(finding)
    if spec:
        return f"Supported when {spec.attribute} is an explicit literal. {spec.impact}"
    return (
        "Manual review required. Read the scanner rule and choose a change that preserves "
        "the workload's required access and behaviour. This version has no automatic handler."
    )
