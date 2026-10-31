import argparse
import json
from dataclasses import asdict
from pathlib import Path
from tempfile import mkdtemp

from .models import ToolError
from .projects import zip_files
from .remediation.engine import fix_file
from .remediation.project import fix_project
from .remediation.registry import guidance
from .scanners import scan_file, scan_project, scanner_version


def doctor() -> int:
    import sys

    print(f"Python: {sys.version.split()[0]}")
    failed = False
    for name in ("checkov", "trivy"):
        try:
            print(f"{name}: {scanner_version(name)}")
        except ToolError as exc:
            print(f"{name}: unavailable ({exc})")
            failed = True
    print("LLM/API key: not required")
    return 2 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local IaC scanning and verified patch proposals")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="check the local runtime and scanner installation")
    scan = sub.add_parser("scan", help="scan a Terraform file or Dockerfile")
    scan.add_argument("path", type=Path)
    scan.add_argument("--scanner", choices=("checkov", "trivy", "both"), default="both")
    scan.add_argument("--json", action="store_true", help="emit a machine-readable report")
    scan.add_argument("--var-file", action="append", default=[])
    fix = sub.add_parser("fix", help="propose supported fixes and rescan with both scanners")
    fix.add_argument("path", type=Path)
    fix.add_argument("--out", type=Path, default=Path("outputs/review"))
    fix.add_argument("--var-file", action="append", default=[])
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return doctor()
    try:
        if args.command == "scan":
            names = ("checkov", "trivy") if args.scanner == "both" else (args.scanner,)
            reports = (
                scan_project(args.path, names, tuple(args.var_file))
                if args.path.is_dir()
                else scan_file(args.path, names)
            )
            if args.json:
                print(json.dumps([asdict(r) for r in reports], indent=2))
            else:
                for report in reports:
                    print(f"\n{report.scanner} ({report.version}): {len(report.findings)} findings")
                    for finding in report.findings:
                        print(
                            f"  {finding.rule_id} [{finding.severity}] {finding.file} {finding.resource}"
                        )
                        print(f"    {finding.message}")
                        print(f"    {guidance(finding)}")
            return int(any(r.findings for r in reports))
        if args.path.is_dir():
            files, report = fix_project(args.path, tuple(args.var_file))
            args.out.mkdir(parents=True, exist_ok=True)
            review_dir = Path(mkdtemp(prefix="review-", dir=args.out))
            (review_dir / "report.json").write_text(
                json.dumps(report.as_dict(), indent=2), encoding="utf-8"
            )
            (review_dir / "candidate.zip").write_bytes(zip_files(files))
            (review_dir / "changes.diff").write_bytes("\n".join(report.diffs.values()).encode())
            print(f"Project review: {review_dir.resolve()}")
            return int(any(r.findings for r in report.after))
        report = fix_file(args.path)
        args.out.mkdir(parents=True, exist_ok=True)
        review_dir = Path(mkdtemp(prefix="review-", dir=args.out))
        candidate_path = review_dir / args.path.name
        (review_dir / "report.json").write_text(
            json.dumps(report.as_dict(), indent=2),
            encoding="utf-8",
        )
        (review_dir / "changes.diff").write_bytes(report.diff.encode("utf-8"))
        if report.diff:
            candidate_path.write_bytes(report.code.encode("utf-8"))
            print(f"Verified candidate for human review: {candidate_path.resolve()}")
            print(report.diff)
        else:
            print(
                "No verified patch was produced. See report.json for findings and refusal reasons."
            )
        for attempt in report.attempts:
            print(f"{attempt.handler}: {attempt.status} — {attempt.reason}")
            if attempt.impact:
                print(f"  Review: {attempt.impact}")
        print(f"Report: {(review_dir / 'report.json').resolve()}")
        return int(any(r.findings for r in report.after))
    except (ToolError, OSError) as exc:
        if getattr(args, "json", False):
            print(json.dumps({"status": "unverified", "error": str(exc)}))
        else:
            print(f"Unverified: {exc}")
        return 2
