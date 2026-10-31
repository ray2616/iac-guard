# Measured release results

Run: 2026-10-31T18:51:52.538745+00:00; Python 3.12.16, Linux containers on Docker Desktop.

30 versioned synthetic fixtures; 26 completed dual scans; zero control mismatches.
These are controlled variations and hand-authored examples, not 30 independent repositories.
Detection denominators include completed scans only. Unverified inputs are listed separately.

| Scanner | Detected / scored planted labels | Negative controls | Controlled false alarms | Unadjudicated findings |
| --- | --- | --- | --- | --- |
| checkov | 17 / 17 | 5 | 0 | 58 |
| trivy | 11 / 11 | 3 | 0 | 39 |

Patch outcomes: {'verified': 8, 'rejected': 3, 'skipped': 2}. 6 project fixtures received verified changes; 0 introduced finding occurrences in accepted results.
Skipped outcomes include module/ambiguity refusals; rejected outcomes include unsupported expressions. Rules without handlers remain manual-review findings, not attempted edits.

Total measured runtime: 326.8 seconds, including scans, repeated fix baselines and candidate rescans. This is not API latency or a cloud performance claim.

Unverified inputs (excluded from detection denominators):

- `tf12-external-module`: Remote module coverage unavailable: Trivy CLI cannot disable module downloads. Bundle local modules; no scan was run.
- `tf17-malformed`: Terraform parse failure in main.tf: UnexpectedToken
- `dk09-missing-from`: Dockerfile structure invalid: an unfenced FROM instruction is required.
- `dk10-fenced`: Dockerfile structure invalid: an unfenced FROM instruction is required.

See [raw benchmark JSON](results/benchmark.json) for scanner versions, source hashes, rule/file/resource matches, remaining findings, runtimes, refusals and diffs. Policy bundle versions were not reported by the CLIs. Unadjudicated findings are not false positives. Secure controls cover selected rules only.

Reproduce with `python -m iac_guard.benchmark --verify-labels --out outputs/benchmark-release.json`, then `python scripts/summarize_results.py outputs/benchmark-release.json`.

AWS execution, UI screenshots and a UI recording remain pending. An actual API walkthrough is included in docs/media. Terraform validation and local container operation do not establish cloud deployment success.
