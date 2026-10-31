import json

import pytest

from iac_guard.models import ToolError
from iac_guard.scanners import parse_checkov, parse_trivy


def checkov_report():
    return {
        "summary": {"passed": 2, "failed": 1, "parsing_errors": 0},
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_3",
                    "check_name": "Encrypt EBS",
                    "resource": "aws_ebs_volume.a",
                    "file_line_range": [1, 4],
                }
            ]
        },
    }


def test_parse_checkov_keeps_unknown_severity():
    result = parse_checkov(json.dumps(checkov_report()), "test", "terraform")
    assert result.findings[0].severity == "UNKNOWN"
    assert result.findings[0].line == 1
    assert result.findings[0].resource == "aws_ebs_volume.a"


@pytest.mark.parametrize("raw", ["", "{}", "[]", "null", "crash", '{"summary": {}}'])
def test_invalid_checkov_reports_never_mean_clean(raw):
    with pytest.raises(ToolError):
        parse_checkov(raw, "test", "terraform")


def test_checkov_parse_error_is_failure():
    report = checkov_report()
    report["summary"]["parsing_errors"] = 1
    with pytest.raises(ToolError, match="parse"):
        parse_checkov(json.dumps(report), "test", "terraform")


def test_checkov_mismatched_count_is_failure():
    report = checkov_report()
    report["summary"]["failed"] = 0
    with pytest.raises(ToolError, match="disagree"):
        parse_checkov(json.dumps(report), "test", "terraform")


def test_checkov_no_applicable_checks_is_unverified():
    report = {"summary": {"passed": 0, "failed": 0, "parsing_errors": 0}}
    with pytest.raises(ToolError, match="no applicable"):
        parse_checkov(json.dumps(report), "test", "terraform")


@pytest.mark.parametrize("raw", ["", "{}", "[]", "null", '{"SchemaVersion": 2, "Results": []}'])
def test_invalid_trivy_reports_never_mean_clean(raw):
    with pytest.raises(ToolError):
        parse_trivy(raw, "test")


def test_valid_trivy_clean_scan_requires_checks():
    doc = {
        "SchemaVersion": 2,
        "Results": [
            {
                "MisconfSummary": {"Successes": 4, "Failures": 0, "Exceptions": 0},
            }
        ],
    }
    assert parse_trivy(json.dumps(doc), "test").findings == []


def test_trivy_keeps_duplicates_for_regression_detection():
    row = {"ID": "AVD-EXAMPLE", "Title": "Example", "Severity": "HIGH"}
    doc = {
        "SchemaVersion": 2,
        "Results": [
            {
                "MisconfSummary": {"Successes": 0, "Failures": 2, "Exceptions": 0},
                "Misconfigurations": [row, row],
            }
        ],
    }
    result = parse_trivy(json.dumps(doc), "test")
    assert result.counts()[("trivy", "AVD-EXAMPLE", "", "")] == 2


def test_trivy_rejects_malformed_empty_findings():
    doc = {
        "SchemaVersion": 2,
        "Results": [
            {
                "MisconfSummary": {"Successes": 4, "Failures": 0},
                "Misconfigurations": {},
            }
        ],
    }
    with pytest.raises(ToolError, match="disagree"):
        parse_trivy(json.dumps(doc), "test")
