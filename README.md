# IaC Guard

**Project-aware IaC scanning and verified remediation, without an LLM.**

Upload a Terraform project ZIP or Dockerfile, run Checkov and Trivy asynchronously,
reopen saved reviews, and download independently checked Terraform patches.

The core workflow remains **scan → propose → validate → rescan → human review**. This
application is a separate implementation inspired by
[llm-iac-security](https://github.com/Shlok014/llm-iac-security); it replaces model-based
detection/rewriting with scanners and explicit fix handlers. Historical LLM evaluation
numbers are not results of this application.

## Stack

| Layer | Technology |
| --- | --- |
| Interface | Streamlit, existing light theme |
| API | FastAPI, Pydantic, OpenAPI |
| Persistence | PostgreSQL 16, SQLAlchemy 2, Alembic |
| Background execution | Redis 7, RQ, transactional outbox |
| Security engine | Checkov 3.2.489, Trivy 0.65.0, bc-python-hcl2 0.4.3 |
| Runtime | Python 3.12, Docker Compose, non-root Linux containers |
| Deployment | Terraform, EC2, IAM, private S3, CloudWatch, SSM |
| Verification | pytest, Ruff, GitHub Actions, synthetic benchmark |

No API credits, model, GPU, Terraform cloud credentials, or image builds are needed
to analyze uploaded files. Kafka is outside v0.1.0.

## Start on Windows

Start Docker Desktop with the Linux engine enabled. From this folder:

```powershell
docker compose up --build -d
docker compose ps
```

- Interface: [http://127.0.0.1:8501](http://127.0.0.1:8501)
- API documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Readiness: [http://127.0.0.1:8000/health/ready](http://127.0.0.1:8000/health/ready)

The first build downloads dependencies and scanner policies. The migration job must
finish successfully before the services start. If startup fails:

```powershell
docker compose logs --tail 80 migrate api dispatcher worker
```

PostgreSQL, Redis and source/artifact storage use named volumes. `docker compose stop`
preserves them. Removing volumes destroys local history; export anything you need first.
Only the UI/API are published, and both bind to localhost. No public multi-user access
or authentication system is included in this release.

## Try the workflow

1. Create a named project in the interface.
2. Select the Terraform example (a multi-file project), upload a ZIP, or upload one `.tf`
   file. Dockerfiles are separate single-file uploads.
3. Select any additional root-level variable files. Automatic `.tfvars` files load first;
   explicitly selected variable files load afterward, in selected order.
4. Submit a scan. The API returns a job immediately; queued/running status updates in
   the interface. Refreshing does not discard the review; its URL contains the job ID.
5. Inspect scanner-specific findings with filenames, source lines, severities and coverage
   limitations. Unknown severity stays unknown.
6. Open Proposed patch and request verified fixes. Read every attempt outcome and diff.
7. Download the original snapshot, candidate project ZIP, diff and JSON report. A candidate
   ZIP is offered only when a verified edit exists. Reopen scans and fixes through Saved reviews.

Scanner failure is an **incomplete review**, never a clean result. Completed means the
tools finished, not that no issues remain.

## Supported project inputs

Project ZIPs preserve relative paths and bundled local-module directories. Accepted
files are `.tf`, `.tfvars` and `.terraform.lock.hcl`. Normalize one enclosing folder;
the resulting root must contain a `.tf` file. Auxiliary templates and other file types
are outside this version's upload format.

Limits: 100 files, 10 MB compressed, 25 MB expanded, 1 MB per file. Unsafe paths,
symlinks, special files, Windows-name collisions, duplicate normalized paths, nested
archives, hidden directories, state and environment files are rejected. Exclude `.git`
and `.terraform` before packaging a project. Files must be UTF-8.

**Remote modules are refused in both-scanner jobs.** Trivy's exclusion flag does not
disable remote downloads, so refusal enforces this application's no-download contract.
Bundle local module source instead. Checkov-only CLI scans can produce partial root
analysis without downloading external modules. Missing local references and provider
semantics remain coverage limitations. See [architecture](docs/ARCHITECTURE.md).

## Supported fixes

| Root-module resource | Explicit attribute | Candidate value | Review implication |
| --- | --- | --- | --- |
| `aws_ebs_volume` | `encrypted = false` | `true` | Existing volumes may require replacement |
| `aws_db_instance` | `storage_encrypted = false` | `true` | Databases may require migration/replacement |
| `aws_db_instance` | `publicly_accessible = true` | `false` | Public clients may lose connectivity |

Variables, expressions, missing/ambiguous assignments, duplicate root addresses and
module-internal changes require manual review. No fix is inferred for arbitrary findings.
Dockerfiles support configuration scanning and guidance, not automatic rewriting or CVE scanning.

Each fix edits an isolated copy, preserves unrelated project content, and rescans the
whole project with **both** scanners. It must resolve its target and introduce no findings
in either tool. Up to three patches are attempted per UI job. Repeated successful fixing
is idempotent. No Terraform init, validate, plan, apply, Docker build or cloud query is
executed against uploads. These checks do not prove functional correctness or compliance.

## Standalone CLI and development

Install Python 3.12 and Trivy, then prepare the project environment:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
.\.venv\Scripts\python.exe -m iac_guard doctor
.\.venv\Scripts\python.exe -m iac_guard scan .\datasets\tf05-cross-file-reference --json
.\.venv\Scripts\python.exe -m iac_guard scan .\datasets\tf10-selected-variables --var-file dev.tfvars
.\.venv\Scripts\python.exe -m iac_guard fix .\datasets\tf07-two-root-files --out .\outputs\review
```

Single `.tf` files and Dockerfiles remain supported. The CLI never needs the API,
PostgreSQL, Redis, or AWS. Exit codes: 0 = no findings remain; 1 = findings remain;
2 = input/tooling failure. A verified partial improvement can still exit 1.

```powershell
.\.venv\Scripts\python.exe -m pytest -m 'not integration'
.\.venv\Scripts\python.exe -m ruff check iac_guard tests scripts migrations app.py
$env:IAC_GUARD_INTEGRATION = "1"
.\.venv\Scripts\python.exe -m pytest -m integration
.\.venv\Scripts\python.exe -m iac_guard.benchmark --scan-only --verify-labels
```

Real PostgreSQL/Redis integration is enabled by `POSTGRES_TEST_URL` and `REDIS_URL`.
Use a disposable database migrated with Alembic; CI does this automatically. Local API
unit tests use temporary SQLite databases to exercise transactions and persistence;
they do not replace the PostgreSQL/RQ integration test.

Run all tests, including live scanners, inside Linux containers with disposable services:

```powershell
docker compose build api
docker compose -f compose.yaml -f compose.test.yaml run --rm verify
.\.venv\Scripts\python.exe scripts/smoke.py
```

The smoke command exercises the running stack and downloads a verified project.
Container tests also verify variable precedence with both actual scanners.

The core/UI/scanner versions are pinned; platform dependency constraints are in
`requirements-windows.lock.txt` and `requirements-linux.lock.txt`. Linux verification
is performed by container/CI checks. Scanner policy bundle versions are marked
unreported when the CLI does not provide them; do not assume identical policy coverage
merely because CLI versions match.

## Benchmark and learning

The corpus contains 30 hand-authored base cases: 20 Terraform projects and 10 Dockerfiles.
See [dataset methodology](datasets/README.md). Positive labels and selected negative
controls are scored separately from unadjudicated findings. Reports include source
hashes, scanner versions, runtime, limitations, and patch outcomes.

See [measured release results](docs/RESULTS.md) for the recorded run and raw evidence.

`outputs/benchmark-scan.json` is generated by a scan-only run; run the full benchmark
without `--scan-only` to measure remediation too. Check `complete` and `label_mismatches`
before citing results. Interrupted runs checkpoint partial results and must not be
presented as complete measurements. These synthetic cases do not establish performance
on real-world repositories.

Follow the [architecture and learning checkpoints](docs/ARCHITECTURE.md), then the
[AWS deployment guide](docs/AWS.md). AWS uses one server and free credits only, subject
to verified account eligibility. No cloud deployment is attempted automatically.

## Release

Follow the [demo and release checklist](docs/DEMO.md). Package a reviewed source release:

```powershell
.\.venv\Scripts\python.exe scripts/package_release.py
```

Do not publish user uploads, credentials, state, saved plans, or account-specific tfvars.
Describe cloud deployment, container startup and benchmarks as verified only after the
corresponding checks have actually passed. MIT licensed; original project attribution
is retained above.
