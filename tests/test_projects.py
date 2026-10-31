import io
import stat
import zipfile
from pathlib import Path

import pytest

from iac_guard.models import Finding, ScanReport, ToolError
from iac_guard.projects import (
    directory_files,
    effective_variable_source,
    materialize,
    project_metadata,
    read_zip,
    zip_files,
)
from iac_guard.remediation.project import fix_project

SOURCE = b'resource "aws_ebs_volume" "data" {\n  size = 10\n  encrypted = false\n}\n'


def archive(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as out:
        for name, body in entries:
            out.writestr(name.replace("\\", "/"), body)
    raw = stream.getvalue()
    for name, _ in entries:
        if "\\" in name:
            raw = raw.replace(name.replace("\\", "/").encode(), name.encode())
    return raw


@pytest.mark.parametrize(
    "name",
    [
        "../main.tf",
        "/main.tf",
        "C:/main.tf",
        "a\\main.tf",
        "foo/../../main.tf",
        "x./main.tf",
        "CON.tf",
        ".git/main.tf",
        "main.tfstate",
        "a.zip",
        "test.env",
        "x?/main.tf",
    ],
)
def test_archive_rejects_unsafe_paths(name):
    with pytest.raises(ToolError):
        read_zip(archive([(name, SOURCE)]))


def test_archive_normalizes_one_folder_and_preserves_local_modules():
    raw = archive([("repo/main.tf", SOURCE), ("repo/modules/ebs/main.tf", SOURCE)])
    assert set(read_zip(raw)) == {"main.tf", "modules/ebs/main.tf"}


def test_archive_rejects_case_collisions():
    with pytest.raises(ToolError, match="duplicate"):
        read_zip(archive([("main.tf", SOURCE), ("MAIN.tf", SOURCE)]))


def test_archive_rejects_symlinks():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as out:
        info = zipfile.ZipInfo("main.tf")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        out.writestr(info, "../../outside")
    with pytest.raises(ToolError, match="links"):
        read_zip(stream.getvalue())


@pytest.mark.parametrize(
    "entries",
    [
        [("main.tf", b"x" * 1_000_001)],
        [(f"f{i}.tf", SOURCE) for i in range(101)],
    ],
)
def test_archive_size_and_count_limits(entries):
    with pytest.raises(ToolError):
        read_zip(archive(entries))


def test_variables_and_external_module_notes():
    files = {
        "main.tf": SOURCE + b'module "external" { source = "org/module/aws" }\n',
        "terraform.tfvars": b"x = 1",
        "a.auto.tfvars": b"x = 2",
        "dev.tfvars": b"x = 3",
    }
    meta = project_metadata(files, ("dev.tfvars",))
    assert meta["variables"] == ["terraform.tfvars", "a.auto.tfvars", "dev.tfvars"]
    assert any("not downloaded" in note for note in meta["limitations"])
    with pytest.raises(ToolError):
        project_metadata(files, ("missing.tfvars",))


def test_unselected_variables_do_not_participate_in_parsing():
    files = {"main.tf": SOURCE, "dev.tfvars": b"invalid {{{"}
    assert "dev.tfvars" not in project_metadata(files)["documents"]
    with pytest.raises(ToolError, match="parse failure"):
        project_metadata(files, ("dev.tfvars",))


def test_snapshot_metadata_is_platform_independent():
    packed = zip_files({"main.tf": SOURCE})
    with zipfile.ZipFile(io.BytesIO(packed)) as archive:
        assert archive.infolist()[0].create_system == 3
    assert read_zip(packed) == {"main.tf": SOURCE}


def test_variable_normalization_replaces_assignments_without_rewriting_values():
    import hcl2

    files = {
        "terraform.tfvars": b'encryption = true\ntags = { first = "value" }\nitems = ["a", "b"]\n',
        "a.auto.tfvars": b'encryption = false # chosen\ntags = { other = "replacement" }\ntext = <<EOT\nexample\nEOT\n',
    }
    result = effective_variable_source(files, list(files))
    parsed = hcl2.loads(result.decode())
    assert parsed["encryption"] == [False]
    assert parsed["tags"] == [{"other": "replacement"}]
    assert parsed["items"] == [["a", "b"]]
    assert b"# chosen" in result
    assert b"<<EOT\nexample\nEOT" in result


@pytest.mark.parametrize("source", [b"x = true\nx = false", b'variable "x" {}'])
def test_ambiguous_or_block_variable_files_are_refused(source):
    with pytest.raises(ToolError):
        effective_variable_source({"dev.tfvars": source}, ["dev.tfvars"])


def fake_scanner(root: Path):
    findings = []
    for file in root.rglob("*.tf"):
        if b"encrypted = false" in file.read_bytes():
            relative = file.relative_to(root).as_posix()
            resource = (
                "module.child.aws_ebs_volume.data" if "/" in relative else "aws_ebs_volume.data"
            )
            findings.append(Finding("checkov", "CKV_AWS_3", resource, "Encrypt EBS", file=relative))
    return [ScanReport("checkov", "test", findings), ScanReport("trivy", "test", [])]


def test_project_fix_preserves_other_files_and_refuses_modules(tmp_path):
    files = {
        "main.tf": SOURCE,
        "outputs.tf": b'output "id" { value = aws_ebs_volume.data.id }',
        "modules/child/main.tf": SOURCE,
    }
    materialize(files, tmp_path)
    updated, report = fix_project(tmp_path, scanner=fake_scanner)
    assert set(updated) == set(files)
    assert updated["outputs.tf"] == files["outputs.tf"]
    assert updated["modules/child/main.tf"] == files["modules/child/main.tf"]
    assert updated["main.tf"] != files["main.tf"]
    assert directory_files(tmp_path) == files
    assert set(report.diffs) == {"main.tf"}
    assert len(report.after[0].findings) == 1
    materialize(updated, tmp_path)
    assert not fix_project(tmp_path, scanner=fake_scanner)[1].diffs


def test_project_regression_in_other_file_is_rejected(tmp_path):
    files = {"main.tf": SOURCE, "outputs.tf": b'output "id" { value = aws_ebs_volume.data.id }'}
    materialize(files, tmp_path)

    def scanner(root):
        reports = fake_scanner(root)
        if not reports[0].findings:
            reports[1].findings.append(
                Finding("trivy", "NEW", "aws_ebs_volume.data", "Regression", file="outputs.tf")
            )
        return reports

    updated, report = fix_project(tmp_path, scanner=scanner)
    assert updated == files
    assert report.attempts[0].status == "rejected"


def test_duplicate_root_resource_is_refused(tmp_path):
    materialize({"a.tf": SOURCE, "b.tf": SOURCE}, tmp_path)
    _updated, report = fix_project(tmp_path, scanner=fake_scanner)
    assert not report.diffs
    assert all(attempt.status == "skipped" for attempt in report.attempts)


def test_zip_roundtrip_is_deterministic():
    files = {"main.tf": SOURCE, "variables.tf": b'variable "zone" { type = string }'}
    assert read_zip(zip_files(files)) == files
    assert zip_files(files) == zip_files(dict(reversed(list(files.items()))))


def test_remote_modules_refuse_before_scanner_execution(tmp_path, monkeypatch):
    from iac_guard.scanners import scan_project

    materialize(
        {"main.tf": SOURCE + b'module "external" { source = "example/module/aws" }'}, tmp_path
    )
    calls = []
    monkeypatch.setattr("iac_guard.scanners.run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ToolError, match="cannot disable module downloads"):
        scan_project(tmp_path)
    assert not calls
