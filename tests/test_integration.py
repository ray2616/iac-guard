import os
from pathlib import Path

import pytest

from iac_guard.remediation.engine import fix_file

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("IAC_GUARD_INTEGRATION") != "1", reason="Opt-in live scanners"
    ),
]


def test_live_scanners_verify_three_fixes(tmp_path):
    source = Path(__file__).resolve().parents[1] / "samples" / "review.tf"
    result = fix_file(source)
    verified = [a for a in result.attempts if a.status == "verified"]
    assert {a.handler for a in verified} == {
        "ebs-encryption",
        "rds-encryption",
        "rds-private-access",
    }, result.attempts
    assert source.read_text(encoding="utf-8") != result.code
    path = tmp_path / "corrected.tf"
    path.write_bytes(result.code.encode("utf-8"))
    assert fix_file(path).diff == ""
