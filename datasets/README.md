# Synthetic corpus

Thirty hand-authored base cases: 20 Terraform projects and 10 Dockerfiles. Regenerate
with `python scripts/create_corpus.py`. The manifest is the annotation source, fixed
before benchmark execution; scanner mismatches fail `--verify-labels` instead of
silently changing labels.

All infrastructure is synthetic. Do not deploy it. The all-zero account/key ARN is a
placeholder, not a real key. Image builds and live cloud functionality are not tested.

`secure-control` describes intended configuration controls, not a certification of
security. Cases have positive labels, selected negative controls, or explicit refusal/
invalid-input expectations. Other scanner findings are unadjudicated, not automatically
classified as false positives. Module instances of the same planted source location
are not counted as independent flaws. Rules with an empty mapping are not scored for
that scanner.

Observed scanner-specific identities are explicit annotations: Trivy reports the
bundled-module EBS finding at `module.volume`, and Checkov reports missing Dockerfile
instructions with an empty (file-scope) resource. Those aliases still require an exact
file and rule match. The initial Windows run exposed these three annotation mismatches;
fresh runs verify the corrected mappings without rewriting raw scanner findings.

Run `python -m iac_guard.benchmark --scan-only --verify-labels` for detection controls,
or omit `--scan-only` to also measure the bounded remediation pipeline. JSON reports
include per-scanner versions, policy-version availability, runtime, findings, limitations,
and each attempted fix. Do not report results from this application using the original
LLM project's historical percentages.
