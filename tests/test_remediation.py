from pathlib import Path

import pytest

from iac_guard.models import Finding, ScanReport, ToolError
from iac_guard.remediation.engine import fix_file
from iac_guard.remediation.registry import FIXES
from iac_guard.remediation.terraform import (
    parse_terraform,
    propose_boolean_fix,
    resource_body,
    verify_only_intended_change,
)


def source_for(spec, value=None):
    value = str(spec.before).lower() if value is None else value
    return (
        f'resource "{spec.resource_type}" "example" {{\n'
        f"  {spec.attribute} = {value} # preserve this comment\n"
        '  tags = { Name = "données" }\n'
        "}\n"
    )


def finding_for(spec):
    return Finding(
        "checkov",
        spec.rules[0][1],
        f"{spec.resource_type}.example",
        "Test rule",
        line=1,
        end_line=4,
    )


@pytest.mark.parametrize("spec", FIXES, ids=lambda spec: spec.name)
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_targeted_edit_preserves_every_other_byte(spec, newline):
    source = source_for(spec).replace("\n", newline)
    candidate = propose_boolean_fix(source, finding_for(spec), spec)
    expected = source.replace(
        f"{spec.attribute} = {str(spec.before).lower()}",
        f"{spec.attribute} = {str(spec.after).lower()}",
    )
    assert candidate == expected
    with pytest.raises(ToolError, match="explicit literal"):
        propose_boolean_fix(candidate, finding_for(spec), spec)


@pytest.mark.parametrize("value", ["var.encrypt", "local.encrypt", '"false"', "0"])
def test_refuse_non_literal_attributes(value):
    spec = FIXES[0]
    with pytest.raises(ToolError, match="explicit literal"):
        propose_boolean_fix(source_for(spec, value), finding_for(spec), spec)


def test_missing_attribute_is_not_guessed():
    spec = FIXES[0]
    with pytest.raises(ToolError, match="explicit literal"):
        propose_boolean_fix(
            'resource "aws_ebs_volume" "example" { size = 10 }', finding_for(spec), spec
        )


def test_deleting_other_resource_is_rejected():
    spec = FIXES[0]
    source = source_for(spec) + 'resource "aws_s3_bucket" "keep" { bucket = "keep" }\n'
    candidate = source_for(spec).replace("encrypted = false", "encrypted = true")
    with pytest.raises(ToolError, match="unrelated"):
        verify_only_intended_change(source, candidate, finding_for(spec), spec)


def test_comment_literal_cannot_substitute_for_real_attribute():
    spec = FIXES[0]
    source = (
        'resource "aws_ebs_volume" "example" {\n'
        "  /*\n  encrypted = false\n  */\n"
        "  encrypted = false\n}\n"
    )
    finding = Finding("checkov", "CKV_AWS_3", "aws_ebs_volume.example", "Test", line=1, end_line=7)
    with pytest.raises(ToolError):
        propose_boolean_fix(source, finding, spec)


def reports_for(path: Path):
    spec = FIXES[0]
    body = resource_body(
        parse_terraform(path.read_text(encoding="utf-8")), "aws_ebs_volume.example"
    )
    rows = [finding_for(spec)] if not body["encrypted"][0] else []
    return [ScanReport("checkov", "test", rows), ScanReport("trivy", "test", [])]


def test_engine_accepts_verified_fix_and_is_idempotent(tmp_path):
    path = tmp_path / "input.tf"
    original = source_for(FIXES[0])
    path.write_text(original, encoding="utf-8")
    result = fix_file(path, scanner=reports_for)
    assert result.attempts[0].status == "verified"
    assert result.diff
    assert path.read_text(encoding="utf-8") == original
    path.write_bytes(result.code.encode("utf-8"))
    repeated = fix_file(path, scanner=reports_for)
    assert repeated.diff == ""
    assert repeated.attempts == []


def test_engine_rejects_regression_in_other_scanner(tmp_path):
    path = tmp_path / "input.tf"
    path.write_text(source_for(FIXES[0]), encoding="utf-8")

    def scanner(candidate):
        reports = reports_for(candidate)
        if not reports[0].findings:
            reports[1].findings.append(Finding("trivy", "NEW", "other", "New problem"))
        return reports

    result = fix_file(path, scanner=scanner)
    assert not result.diff
    assert result.attempts[0].status == "rejected"
    assert "introduced" in result.attempts[0].reason


def test_engine_rejects_duplicate_count_increase(tmp_path):
    path = tmp_path / "input.tf"
    path.write_text(source_for(FIXES[0]), encoding="utf-8")
    existing = Finding("trivy", "EXISTING", "other", "Repeated finding")

    def scanner(candidate):
        reports = reports_for(candidate)
        reports[1].findings = [existing] * (1 if reports[0].findings else 2)
        return reports

    result = fix_file(path, scanner=scanner)
    assert not result.diff
    assert "introduced" in result.attempts[0].reason


def test_engine_rejects_candidate_scanner_failure(tmp_path):
    path = tmp_path / "input.tf"
    path.write_text(source_for(FIXES[0]), encoding="utf-8")

    def scanner(candidate):
        if candidate != path:
            raise ToolError("scanner crashed")
        return reports_for(candidate)

    result = fix_file(path, scanner=scanner)
    assert not result.diff
    assert result.attempts[0].status == "rejected"
    assert "scanner crashed" in result.attempts[0].reason


def test_baseline_scanner_failure_aborts(tmp_path):
    path = tmp_path / "input.tf"
    path.write_text(source_for(FIXES[0]), encoding="utf-8")

    def broken(_):
        raise ToolError("baseline failed")

    with pytest.raises(ToolError, match="baseline failed"):
        fix_file(path, scanner=broken)


def test_one_scanner_cannot_verify_remediation(tmp_path):
    path = tmp_path / "input.tf"
    path.write_text(source_for(FIXES[0]), encoding="utf-8")
    with pytest.raises(ToolError, match="both"):
        fix_file(path, scanner=lambda p: reports_for(p)[:1])
