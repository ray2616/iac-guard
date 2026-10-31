from collections import Counter
from collections.abc import Callable
from difflib import unified_diff
from pathlib import Path
from tempfile import TemporaryDirectory

from ..models import Attempt, FixReport, ScanReport, ToolError, file_kind
from ..scanners import scan_file
from .registry import handler_for
from .terraform import parse_terraform, propose_boolean_fix, verify_only_intended_change


def _counts(reports: list[ScanReport]) -> Counter:
    return sum((report.counts() for report in reports), Counter())


def _require_both(reports: list[ScanReport]) -> None:
    if sorted(report.scanner for report in reports) != ["checkov", "trivy"]:
        raise ToolError("Remediation requires complete reports from both Checkov and Trivy.")


def fix_file(
    path: Path,
    scanner: Callable[[Path], list[ScanReport]] = scan_file,
    max_attempts: int = 20,
) -> FixReport:
    if max_attempts < 1:
        raise ToolError("max_attempts must be positive.")
    kind = file_kind(path)
    try:
        source = path.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ToolError(f"Could not read the input as UTF-8: {exc}") from exc
    if len(source) > 1_000_000:
        raise ToolError("Files over 1 MB are outside this version's single-file scope.")
    if kind == "terraform":
        parse_terraform(source)
    before = scanner(path)
    _require_both(before)
    current, after = source, before
    attempts: list[Attempt] = []
    seen: set[tuple[str, str]] = set()
    supported = []
    for report in before:
        for finding in report.findings:
            spec = handler_for(finding) if kind == "terraform" else None
            if spec and (spec.name, finding.resource) not in seen:
                seen.add((spec.name, finding.resource))
                supported.append((finding, spec))

    with TemporaryDirectory(prefix="iac-guard-") as directory:
        candidate_path = Path(directory) / ("main.tf" if kind == "terraform" else "Dockerfile")
        for finding, spec in supported[:max_attempts]:
            try:
                candidate = propose_boolean_fix(current, finding, spec)
                # Verify at the engine boundary as well, including injected handlers in tests.
                verify_only_intended_change(current, candidate, finding, spec)
                candidate_path.write_bytes(candidate.encode("utf-8"))
                reports = scanner(candidate_path)
                _require_both(reports)
                previous_counts, candidate_counts = _counts(after), _counts(reports)
                if candidate_counts[finding.identity]:
                    raise ToolError("The target finding remains after rescanning.")
                introduced = candidate_counts - previous_counts
                if introduced:
                    rules = ", ".join(f"{key[0]}:{key[1]}" for key in introduced)
                    raise ToolError(f"The candidate introduced findings: {rules}")
            except (ToolError, OSError) as exc:
                attempts.append(
                    Attempt(spec.name, finding.resource, "rejected", str(exc), spec.impact)
                )
            else:
                current, after = candidate, reports
                attempts.append(
                    Attempt(
                        spec.name,
                        finding.resource,
                        "verified",
                        "Target finding resolved; no new findings in either scanner.",
                        spec.impact,
                    )
                )
    if len(supported) > max_attempts:
        attempts.append(
            Attempt(
                "attempt-limit",
                "",
                "skipped",
                "Reached the configured patch attempt limit.",
                "",
            )
        )
    diff = "".join(
        unified_diff(
            source.splitlines(keepends=True),
            current.splitlines(keepends=True),
            fromfile=path.name,
            tofile=f"candidate/{path.name}",
        )
    )
    return FixReport(str(path.resolve()), current, diff, before, after, attempts)
