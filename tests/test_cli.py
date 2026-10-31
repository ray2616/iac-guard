from pathlib import Path

from iac_guard.cli import main
from iac_guard.models import FixReport


def test_review_outputs_never_overwrite_source_or_reuse_old_candidate(tmp_path, monkeypatch):
    path = tmp_path / "input.tf"
    path.write_bytes(b"original\n")
    result = FixReport(str(path), "candidate\n", "some diff\n", [], [])
    monkeypatch.setattr("iac_guard.cli.fix_file", lambda _: result)
    assert main(["fix", str(path), "--out", str(tmp_path)]) == 0
    folders = set(tmp_path.glob("review-*"))
    assert len(folders) == 1
    assert (next(iter(folders)) / path.name).read_bytes() == b"candidate\n"
    result.code, result.diff = "original\n", ""
    assert main(["fix", str(path), "--out", str(tmp_path)]) == 0
    new_folders = set(tmp_path.glob("review-*")) - folders
    assert len(new_folders) == 1
    assert not (next(iter(new_folders)) / path.name).exists()
    assert path.read_bytes() == b"original\n"


def test_json_scan_failure_exits_unverified(tmp_path, monkeypatch, capsys):
    from iac_guard.models import ToolError

    def broken(*_):
        raise ToolError("scanner failed")

    monkeypatch.setattr("iac_guard.cli.scan_file", broken)
    assert main(["scan", str(Path(tmp_path) / "input.tf"), "--json"]) == 2
    assert '"status": "unverified"' in capsys.readouterr().out
