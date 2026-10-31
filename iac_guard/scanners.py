"""Run real scanner executables and refuse missing or malformed results."""

import json
import os
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from tempfile import TemporaryDirectory

from .models import Finding, ScanReport, ToolError, file_kind
from .projects import (
    canonical_scanner_path,
    directory_files,
    effective_variable_source,
    materialize,
    project_metadata,
)


def executable(name: str) -> str:
    for suffix in (".exe", "") if os.name == "nt" else ("",):
        candidate = Path(sys.executable).parent / (name + suffix)
        if candidate.is_file():
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    raise ToolError(f"{name} is not installed or is not on PATH. Run scripts/setup.ps1.")


def run(
    command: list[str],
    allowed: tuple[int, ...] = (0,),
    timeout: int = 180,
    cwd: Path | None = None,
) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            env={**os.environ, "PYTHONUTF8": "1", "CHECKOV_SKIP_PLATFORM_DOWNLOAD": "true"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"Could not complete {Path(command[0]).name}: {exc}") from exc
    if result.returncode not in allowed:
        detail = (result.stderr or result.stdout).strip()[-1200:]
        raise ToolError(f"{Path(command[0]).name} failed ({result.returncode}): {detail}")
    if "There are no runners to run" in result.stderr:
        raise ToolError("Checkov did not run an applicable scanner; the result is unverified.")
    if not result.stdout.strip():
        raise ToolError(f"{Path(command[0]).name} returned no report; this is not a clean scan.")
    return result.stdout.strip()


def json_document(raw: str) -> dict | list:
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ToolError("Scanner returned invalid JSON; results cannot be verified.") from exc
    if not isinstance(doc, (dict, list)):
        raise ToolError("Scanner report has an unexpected schema.")
    return doc


def _integer(value, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ToolError(f"Scanner report has an invalid {label}.")
    return value


def _location(value) -> tuple[int | None, int | None]:
    if not value:
        return None, None
    if not isinstance(value, list) or len(value) != 2:
        raise ToolError("Scanner returned an invalid source range.")
    start, end = value
    if type(start) is not int or type(end) is not int or not 0 < start <= end:
        raise ToolError("Scanner returned an invalid source range.")
    return start, end


def parse_checkov(raw: str, version: str, kind: str, root: Path | None = None) -> ScanReport:
    doc = json_document(raw)
    docs = doc if isinstance(doc, list) else [doc]
    if not docs:
        raise ToolError("Checkov returned an empty report list.")
    findings: list[Finding] = []
    passed = examined = 0
    for entry in docs:
        if not isinstance(entry, dict) or not isinstance(entry.get("summary"), dict):
            raise ToolError("Checkov report is missing its summary.")
        summary = entry["summary"]
        failed = _integer(summary.get("failed"), "failed count")
        pass_count = _integer(summary.get("passed"), "passed count")
        skipped = _integer(summary.get("skipped", 0), "skipped count")
        if _integer(summary.get("parsing_errors"), "parsing error count"):
            raise ToolError("Checkov could not parse the input file.")
        results = entry.get("results", {})
        if not isinstance(results, dict):
            raise ToolError("Checkov results have an unexpected schema.")
        rows = results.get("failed_checks", [])
        if not isinstance(rows, list) or len(rows) != failed:
            raise ToolError("Checkov findings disagree with the summary.")
        for row in rows:
            if not isinstance(row, dict) or not row.get("check_id") or not row.get("check_name"):
                raise ToolError("Checkov returned an incomplete finding.")
            start, end = _location(row.get("file_line_range"))
            resource = row.get("resource") or ""
            if kind == "dockerfile":
                resource = resource.rsplit(".", 1)[-1]
            findings.append(
                Finding(
                    "checkov",
                    row["check_id"],
                    resource,
                    row["check_name"],
                    str(row.get("severity") or "UNKNOWN").upper(),
                    start,
                    end,
                    row.get("guideline") or "",
                    canonical_scanner_path(row.get("file_path") or "", root),
                )
            )
        passed += pass_count
        examined += pass_count + failed + skipped
    if not examined:
        raise ToolError("Checkov ran no applicable checks; the file is unverified.")
    return ScanReport("checkov", version, findings, passed)


def parse_trivy(raw: str, version: str, root: Path | None = None) -> ScanReport:
    doc = json_document(raw)
    if not isinstance(doc, dict) or doc.get("SchemaVersion") != 2:
        raise ToolError("Trivy report has an unsupported schema version.")
    results = doc.get("Results")
    if not isinstance(results, list) or not results:
        raise ToolError("Trivy returned no applicable scan results.")
    findings: list[Finding] = []
    passed = examined = 0
    for entry in results:
        if not isinstance(entry, dict) or not isinstance(entry.get("MisconfSummary"), dict):
            raise ToolError("Trivy report is missing its misconfiguration summary.")
        summary = entry["MisconfSummary"]
        successes = _integer(summary.get("Successes"), "success count")
        failures = _integer(summary.get("Failures"), "failure count")
        exceptions = _integer(summary.get("Exceptions", 0), "exception count")
        rows = entry.get("Misconfigurations")
        if rows is None:
            rows = []
        if not isinstance(rows, list) or len(rows) != failures:
            raise ToolError("Trivy findings disagree with the summary.")
        for row in rows:
            if not isinstance(row, dict) or not row.get("ID") or not row.get("Title"):
                raise ToolError("Trivy returned an incomplete finding.")
            cause = row.get("CauseMetadata") or {}
            findings.append(
                Finding(
                    "trivy",
                    row.get("AVDID") or row["ID"],
                    cause.get("Resource") or "",
                    row["Title"],
                    str(row.get("Severity") or "UNKNOWN").upper(),
                    cause.get("StartLine") or None,
                    cause.get("EndLine") or None,
                    row.get("PrimaryURL") or "",
                    canonical_scanner_path(entry.get("Target") or "", root),
                )
            )
        passed += successes
        examined += successes + failures + exceptions
    if not examined:
        raise ToolError("Trivy ran no applicable checks; the file is unverified.")
    return ScanReport("trivy", version, findings, passed)


@lru_cache(maxsize=4)
def scanner_version(name: str) -> str:
    command = scanner_command(name)
    if name == "checkov" and Path(command[-1]).parent == Path(sys.executable).parent:
        from importlib.metadata import version

        return version("checkov")
    return run([*command, "--version"], timeout=90).splitlines()[0]


def scanner_command(name: str) -> list[str]:
    path = executable(name)
    # Checkov ships a Python console script plus a .cmd wrapper on Windows.
    # Run the script with this environment's interpreter, without a command shell.
    if name == "checkov" and Path(path).suffix == "":
        return [sys.executable, path]
    return [path]


def scan_file(path: Path, names: tuple[str, ...] = ("checkov", "trivy")) -> list[ScanReport]:
    if path.is_dir():
        return scan_project(path, names)
    path = path.resolve()
    if not path.is_file():
        raise ToolError(f"Input file does not exist: {path}")
    kind = file_kind(path)
    if path.stat().st_size > 1_000_000:
        raise ToolError("Files over 1 MB are outside this version's single-file scope.")
    if kind == "terraform" and "trivy" in names:
        metadata = project_metadata({path.name: path.read_bytes()})
        if metadata["remote_modules"]:
            raise ToolError(
                "Remote module coverage unavailable: Trivy CLI cannot disable module downloads. Bundle local modules; no scan was run."
            )
    if kind == "dockerfile":
        try:
            source = path.read_bytes().decode("utf-8-sig")
        except UnicodeError as exc:
            raise ToolError("Dockerfile must be UTF-8") from exc
        instructions = [
            line.strip()
            for line in source.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        first = next((line for line in instructions if not line.upper().startswith("ARG ")), "")
        if "```" in source or not first.upper().startswith("FROM ") or len(first.split()) < 2:
            raise ToolError(
                "Dockerfile structure invalid: an unfenced FROM instruction is required."
            )
    reports = []
    for name in names:
        version = scanner_version(name)
        if name == "checkov":
            raw = run(
                [
                    *scanner_command(name),
                    "--file",
                    str(path),
                    "--framework",
                    kind,
                    "--output",
                    "json",
                    "--quiet",
                    "--compact",
                    "--skip-download",
                    "--download-external-modules",
                    "false",
                ],
                allowed=(0, 1),
            )
            reports.append(parse_checkov(raw, version, kind))
        elif name == "trivy":
            raw = run([*scanner_command(name), "config", "--format", "json", "--quiet", str(path)])
            reports.append(parse_trivy(raw, version))
        else:
            raise ToolError(f"Unsupported scanner: {name}")
    return reports


def scan_project(
    path: Path,
    names: tuple[str, ...] = ("checkov", "trivy"),
    var_files: tuple[str, ...] = (),
) -> list[ScanReport]:
    path = path.resolve()
    files = directory_files(path)
    metadata = project_metadata(files, var_files)
    if metadata["remote_modules"] and "trivy" in names:
        raise ToolError(
            "Remote module coverage unavailable: Trivy CLI cannot disable module downloads. Bundle local modules; no scan was run."
        )
    if any(name.endswith(".tfvars") for name in files):
        # Scanner versions differ in tfvars precedence and list/bool handling.
        # The scan-only view retains every .tf path and bundled module byte-for-byte.
        # Source/candidate snapshots are never modified by this normalization.
        with TemporaryDirectory(prefix="iac-scan-") as directory:
            view = {name: data for name, data in files.items() if not name.endswith(".tfvars")}
            if metadata["variables"]:
                view["terraform.tfvars"] = effective_variable_source(files, metadata["variables"])
            materialize(view, Path(directory))
            metadata["limitations"].append(
                "Variable assignments were normalized in an isolated scan-only view; original files are preserved."
            )
            return _scan_project_directory(Path(directory), names, metadata)
    return _scan_project_directory(path, names, metadata)


def _scan_project_directory(path: Path, names: tuple[str, ...], metadata: dict) -> list[ScanReport]:
    reports = []
    for name in names:
        version = scanner_version(name)
        if name == "checkov":
            command = [
                *scanner_command(name),
                "--directory",
                str(path),
                "--framework",
                "terraform",
                "--output",
                "json",
                "--quiet",
                "--compact",
                "--skip-download",
                "--download-external-modules",
                "false",
            ]
            report = parse_checkov(run(command, (0, 1)), version, "terraform", path)
        elif name == "trivy":
            command = [
                *scanner_command(name),
                "config",
                "--format",
                "json",
                "--quiet",
                "--tf-exclude-downloaded-modules",
            ]
            if metadata["variables"]:
                # Trivy resolves variable files against its scan-root filesystem.
                command += ["--tf-vars", "terraform.tfvars"]
            command += ["."]
            report = parse_trivy(run(command, cwd=path), version, path)
        else:
            raise ToolError(f"Unsupported scanner: {name}")
        report.limitations = metadata["limitations"]
        reports.append(report)
    return reports
