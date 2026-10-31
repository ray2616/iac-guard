from dataclasses import replace

from iac_guard.benchmark import matches
from iac_guard.models import Finding


def test_module_alias_requires_the_labeled_file():
    finding = Finding(
        "trivy",
        "AVD-AWS-0026",
        "module.volume",
        "unencrypted",
        severity="HIGH",
        file="modules/volume/main.tf",
    )
    label = {
        "file": finding.file,
        "resource_suffix": "aws_ebs_volume.data",
        "resource_aliases": {"trivy": ["module.volume"]},
        "rules": {"trivy": finding.rule_id},
    }
    assert matches(finding, label, "trivy")
    assert not matches(replace(finding, file="main.tf"), label, "trivy")


def test_missing_instruction_labels_match_only_file_scope():
    finding = Finding("checkov", "CKV_DOCKER_3", "", "no USER", file="Dockerfile")
    label = {"file": "Dockerfile", "resource_suffix": "", "rules": {"checkov": finding.rule_id}}
    assert matches(finding, label, "checkov")
    assert not matches(replace(finding, resource="USER"), label, "checkov")
