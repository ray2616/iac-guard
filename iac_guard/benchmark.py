"""Reproducible labeled-control measurements; incidental findings are unadjudicated."""

import argparse
import hashlib
import json
import platform
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .models import ToolError
from .remediation.project import fix_project
from .scanners import scan_file, scan_project


def matches(finding, label, scanner):
    rule = label["rules"].get(scanner)
    resources = label.get("resource_aliases", {}).get(scanner, [])
    suffix = label["resource_suffix"]
    return bool(
        rule
        and finding.rule_id == rule
        and finding.file == label["file"]
        and (
            finding.resource == suffix
            or (bool(suffix) and finding.resource.endswith(suffix))
            or finding.resource in resources
        )
    )


def run_corpus(root: Path, include_fixes=True, only=None, output=None):
    manifest = json.loads((root / "manifest.json").read_text())
    results = []
    for case in manifest:
        if only and case["id"] not in only:
            continue
        start = time.monotonic()
        item = {**case, "reports": [], "errors": [], "controls": {}, "fix": None}
        folder = root / case["id"]
        item["source_hashes"] = {
            p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob("*"))
            if p.is_file()
        }
        try:
            reports = (
                scan_project(folder, var_files=tuple(case.get("variables", [])))
                if case["kind"] == "terraform"
                else scan_file(folder / "Dockerfile")
            )
            item["reports"] = [asdict(report) for report in reports]
            for report in reports:
                # Single Dockerfile scanner identities normalize their input filename.
                from dataclasses import replace

                findings = (
                    [replace(f, file="Dockerfile") for f in report.findings]
                    if case["kind"] == "dockerfile"
                    else report.findings
                )
                labels = [label for label in case["labels"] if label["rules"].get(report.scanner)]
                absent = [
                    label for label in case.get("absent", []) if label["rules"].get(report.scanner)
                ]
                hits = sum(
                    any(matches(f, label, report.scanner) for f in findings) for label in labels
                )
                false_alarms = sum(
                    any(matches(f, label, report.scanner) for f in findings) for label in absent
                )
                unmatched = sum(
                    not any(matches(f, label, report.scanner) for label in labels) for f in findings
                )
                item["controls"][report.scanner] = {
                    "labels": len(labels),
                    "detected": hits,
                    "negative_controls": len(absent),
                    "controlled_false_alarms": false_alarms,
                    "unadjudicated_findings": unmatched,
                }
            if include_fixes and case["kind"] == "terraform" and case["expected"] != "invalid":
                _, fix = fix_project(folder, tuple(case.get("variables", [])))
                item["fix"] = fix.as_dict()
        except ToolError as exc:
            item["errors"].append(str(exc)[:1000])
        item["seconds"] = round(time.monotonic() - start, 3)
        results.append(item)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps({"complete": False, "cases": results}, indent=2), encoding="utf-8"
            )
        print(
            f"{case['id']}: {'unverified' if item['errors'] else 'measured'} ({item['seconds']}s)",
            flush=True,
        )
    return {
        "complete": True,
        "timestamp": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "method": "Planted locations scored by rule/file/resource; unadjudicated findings are not false positives. No training data or model calls.",
        "cases": results,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=Path("datasets"))
    parser.add_argument("--out", type=Path, default=Path("outputs/benchmark.json"))
    parser.add_argument("--scan-only", action="store_true")
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--verify-labels", action="store_true")
    args = parser.parse_args()
    report = run_corpus(args.corpus, not args.scan_only, args.only, args.out)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    mismatches = []
    for case in report["cases"]:
        if case["expected"] in {"invalid", "unverified"}:
            if not case["errors"]:
                mismatches.append(case["id"] + ": invalid configuration was not rejected")
        else:
            if case["errors"] and case["expected"] != "refusal":
                mismatches.append(case["id"] + ": scan failed")
            for scanner, controls in case["controls"].items():
                if (
                    controls["labels"] != controls["detected"]
                    or controls["controlled_false_alarms"]
                ):
                    mismatches.append(case["id"] + ": control mismatch for " + scanner)
    report["label_mismatches"] = mismatches
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Saved {args.out}; {len(mismatches)} control mismatches")
    return int(bool(mismatches) and args.verify_labels)


if __name__ == "__main__":
    raise SystemExit(main())
