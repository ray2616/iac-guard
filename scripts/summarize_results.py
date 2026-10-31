"""Publish measurements from a complete run; preserve raw findings for auditing."""

import argparse
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    if not report.get("complete") or report.get("label_mismatches") != []:
        raise SystemExit("A complete run with zero control mismatches is required")
    scores = defaultdict(Counter)
    outcomes = Counter()
    changed = []
    introduced = 0
    for case in report["cases"]:
        for scanner, controls in case["controls"].items():
            scores[scanner].update(controls)
        fix = case.get("fix")
        if not fix:
            continue
        outcomes.update(a["status"] for a in fix["attempts"])
        if fix["diffs"]:
            changed.append(case["id"])

        def identities(reports):
            return Counter(
                (r["scanner"], f["rule_id"], f["resource"], f["file"])
                for r in reports
                for f in r["findings"]
            )

        introduced += sum((identities(fix["after"]) - identities(fix["before"])).values())
    cases = report["cases"]
    lines = [
        "# Measured release results",
        "",
        f"Run: {report['timestamp']}; Python {report['python']}, Linux containers on Docker Desktop.",
        "",
        f"{len(cases)} versioned synthetic fixtures; {sum(not c['errors'] for c in cases)} completed dual scans; zero control mismatches.",
        "These are controlled variations and hand-authored examples, not 30 independent repositories.",
        "Detection denominators include completed scans only. Unverified inputs are listed separately.",
        "",
        "| Scanner | Detected / scored planted labels | Negative controls | Controlled false alarms | Unadjudicated findings |",
        "| --- | --- | --- | --- | --- |",
    ]
    for scanner, counts in sorted(scores.items()):
        lines.append(
            f"| {scanner} | {counts['detected']} / {counts['labels']} | {counts['negative_controls']} | {counts['controlled_false_alarms']} | {counts['unadjudicated_findings']} |"
        )
    lines += [
        "",
        f"Patch outcomes: {dict(outcomes)}. {len(changed)} project fixtures received verified changes; {introduced} introduced finding occurrences in accepted results.",
        "Skipped outcomes include module/ambiguity refusals; rejected outcomes include unsupported expressions. Rules without handlers remain manual-review findings, not attempted edits.",
        "",
        f"Total measured runtime: {sum(c['seconds'] for c in cases):.1f} seconds, including scans, repeated fix baselines and candidate rescans. This is not API latency or a cloud performance claim.",
        "",
        "Unverified inputs (excluded from detection denominators):",
        "",
    ]
    lines += [f"- `{c['id']}`: {c['errors'][0]}" for c in cases if c["errors"]]
    lines += [
        "",
        "See [raw benchmark JSON](results/benchmark.json) for scanner versions, source hashes, rule/file/resource matches, remaining findings, runtimes, refusals and diffs. Policy bundle versions were not reported by the CLIs. Unadjudicated findings are not false positives. Secure controls cover selected rules only.",
        "",
        "Reproduce with `python -m iac_guard.benchmark --verify-labels --out outputs/benchmark-release.json`, then `python scripts/summarize_results.py outputs/benchmark-release.json`.",
        "",
        "AWS execution, UI screenshots and a UI recording remain pending. An actual API walkthrough is included in docs/media. Terraform validation and local container operation do not establish cloud deployment success.",
    ]
    output = Path("docs/results")
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.report, output / "benchmark.json")
    Path("docs/RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Published docs/RESULTS.md and docs/results/benchmark.json")


if __name__ == "__main__":
    main()
