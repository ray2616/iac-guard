# Demo and release checklist

## Three-minute recording

An actual API walkthrough is included as [MP4](media/api-demo.mp4) and
[asciicast](media/api-demo.cast). It captures live requests, worker results, diffs,
candidate download and reopened history. [Transcript preview](media/api-demo.png).
It is an API demonstration; UI screenshots and a UI recording remain pending.
Re-record with `python scripts/record_api_demo.py`; optional `--render` needs Pillow
and imageio-ffmpeg. Browser capture was stopped during implementation.

1. Show the architecture diagram and say: “The core is scan, propose, validate and
   independently rescan. Deterministic handlers replace the original model.”
2. Open the local UI, create a project and submit the bundled multi-file Terraform ZIP.
3. Show queued/running state, then file-aware findings from both scanners.
4. Request verified fixes. Show per-file diffs, remaining findings and replacement/
   connectivity implications. Download the candidate ZIP and report.
5. Refresh and reopen the review from saved history. Explain PostgreSQL persistence,
   Redis/RQ execution, the outbox and manual retries.
6. Show the benchmark output and limitations. Separate measured results from unverified
   checks. Mention that external module jobs are refused to prevent downloads.
7. If AWS deployment was actually tested with verified credits, show SSM access and logs,
   then teardown. Otherwise describe it as prepared infrastructure, not a deployed service.

Use only synthetic inputs. Do not record credentials, account billing details, raw user
uploads or the contents of `.env`/Terraform state. A recording must reflect an actual
running app; do not substitute mocked results for a live demo.

## GitHub release

- Run unit/API/archive/migration/UI tests and the opt-in real PostgreSQL/Redis tests.
- Verify live single-file and project-level scanner tests and all benchmark controls.
- Build the application image and test Compose from a fresh database and volumes.
- Validate and scan `infra/aws`; document policy findings rather than claiming the
  deployment is scanner-clean without evidence.
- Review `git diff --cached` and run a secret scanner before publishing. Fixture fake
  identifiers are documented in `datasets/README.md`.
- Publish source to the intended GitHub account. Keep .env, state, uploads, caches and
  account-specific tfvars out of git.
- Include architecture/setup documentation, actual screenshots, demo recording and
  observed benchmark results. Attach the source archive and checksums to `v0.1.0`.
- Use only measured claims on the resume. Do not reuse the original LLM metrics.

Suggested description after verifying the corresponding features:

> Evolved an LLM-assisted IaC workflow into a deterministic security application with
> project-aware Checkov/Trivy scans, verified remediation, PostgreSQL review history,
> Redis/RQ background jobs and a private AWS deployment.

Omit “AWS deployment” until the cloud smoke test has actually passed. This repository
does not establish production maturity, compliance certification or benchmark results
on organically written infrastructure.
