"""Verified edits of root resources, with complete-project rescans."""

from collections import Counter
from dataclasses import asdict, dataclass
from difflib import unified_diff
from pathlib import Path
from tempfile import TemporaryDirectory

from ..models import Attempt, ScanReport, ToolError
from ..projects import directory_files, materialize, project_metadata
from ..scanners import scan_project
from .engine import _require_both
from .registry import handler_for
from .terraform import propose_boolean_fix, verify_only_intended_change


@dataclass
class ProjectFixReport:
    before: list[ScanReport]
    after: list[ScanReport]
    diffs: dict[str, str]
    attempts: list[Attempt]
    limitations: list[str]

    def as_dict(self):
        return asdict(self)


def fix_project(path: Path, var_files=(), max_attempts=3, scanner=None):
    original = directory_files(path)
    metadata = project_metadata(original, tuple(var_files))
    scan = scanner or (lambda p: scan_project(p, var_files=tuple(var_files)))
    before = scan(path)
    _require_both(before)
    current, after = dict(original), before
    attempts = []
    scheduled = set()
    candidates = []
    for report in before:
        for finding in report.findings:
            spec = handler_for(finding)
            if not spec:
                continue
            key = (finding.file, finding.resource, spec.name)
            if key in scheduled:
                continue
            scheduled.add(key)
            if not finding.file or "/" in finding.file or finding.file not in original:
                attempts.append(
                    Attempt(
                        spec.name,
                        finding.resource,
                        "skipped",
                        "Only root-module resources are eligible.",
                        spec.impact,
                    )
                )
                continue
            # The same resource address in two root files is ambiguous, even if a scanner picks one.
            occurrences = sum(
                finding.resource.split(".")[1] in block.get(spec.resource_type, {})
                for name, doc in metadata["documents"].items()
                if "/" not in name and name.endswith(".tf")
                for block in doc.get("resource", [])
            )
            if occurrences != 1:
                attempts.append(
                    Attempt(
                        spec.name,
                        finding.resource,
                        "skipped",
                        "Ambiguous root resource address.",
                        spec.impact,
                    )
                )
                continue
            candidates.append((finding, spec))
    for finding, spec in candidates[:max_attempts]:
        try:
            source = current[finding.file].decode("utf-8-sig")
            updated = propose_boolean_fix(source, finding, spec)
            verify_only_intended_change(source, updated, finding, spec)
            candidate = {**current, finding.file: updated.encode("utf-8")}
            if set(candidate) != set(original) or any(
                candidate[n] != current[n] for n in current if n != finding.file
            ):
                raise ToolError("Unrelated project content changed.")
            with TemporaryDirectory(prefix="iac-project-") as work:
                materialize(candidate, Path(work))
                reports = scan(Path(work))
            _require_both(reports)
            old_counts = sum((r.counts() for r in after), Counter())
            new_counts = sum((r.counts() for r in reports), Counter())
            if new_counts[finding.identity]:
                raise ToolError("Target finding remains after project rescan.")
            if new_counts - old_counts:
                raise ToolError("Project rescan introduced findings.")
        except (ToolError, OSError) as exc:
            attempts.append(Attempt(spec.name, finding.resource, "rejected", str(exc), spec.impact))
        else:
            current, after = candidate, reports
            attempts.append(
                Attempt(
                    spec.name,
                    finding.resource,
                    "verified",
                    "Target resolved; both project rescans passed regression checks.",
                    spec.impact,
                )
            )
    if len(candidates) > max_attempts:
        attempts.append(
            Attempt("attempt-limit", "", "skipped", "Patch attempt budget reached.", "")
        )
    diffs = {}
    for name in original:
        if original[name] != current[name]:
            diffs[name] = "".join(
                unified_diff(
                    original[name].decode("utf-8-sig").splitlines(True),
                    current[name].decode("utf-8-sig").splitlines(True),
                    fromfile=f"original/{name}",
                    tofile=f"candidate/{name}",
                )
            )
    return current, ProjectFixReport(before, after, diffs, attempts, metadata["limitations"])
