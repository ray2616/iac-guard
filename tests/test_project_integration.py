import os
from pathlib import Path

import pytest

from iac_guard.projects import materialize
from iac_guard.remediation.project import fix_project
from iac_guard.scanners import scan_project

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.getenv("IAC_GUARD_INTEGRATION") != "1", reason="Live scanner opt-in"),
]


def test_live_multifile_fixes_and_paths(tmp_path):
    root = Path(__file__).resolve().parents[1]
    original = {
        "storage.tf": (root / "datasets/tf01-ebs-literal/main.tf").read_bytes(),
        "outputs.tf": b'output "id" { value = aws_ebs_volume.data.id }\n',
    }
    materialize(original, tmp_path)
    reports = scan_project(tmp_path)
    assert all(f.file == "storage.tf" for r in reports for f in r.findings)
    updated, report = fix_project(tmp_path)
    assert report.diffs
    assert updated["outputs.tf"] == original["outputs.tf"]
    assert all(attempt.status == "verified" for attempt in report.attempts)
    materialize(updated, tmp_path)
    assert not fix_project(tmp_path)[1].diffs


def test_live_automatic_and_selected_variable_precedence(tmp_path):
    files = {
        "main.tf": b'resource "aws_ebs_volume" "data" {\n availability_zone = "us-east-1a"\n size = 10\n encrypted = var.encryption\n}\n',
        "variables.tf": b'variable "encryption" {\n type = bool\n default = true\n}\n',
        "terraform.tfvars": b"encryption = true",
        "a.auto.tfvars": b"encryption = true",
        "b.auto.tfvars": b"encryption = false",
        "dev.tfvars": b"encryption = true",
    }
    materialize(files, tmp_path)
    rules = {"checkov": "CKV_AWS_3", "trivy": "AVD-AWS-0026"}
    automatic = scan_project(tmp_path)
    assert all(any(f.rule_id == rules[r.scanner] for f in r.findings) for r in automatic)
    selected = scan_project(tmp_path, var_files=("dev.tfvars",))
    assert all(not any(f.rule_id == rules[r.scanner] for f in r.findings) for r in selected)
