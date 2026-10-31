# Local verification record

Verified on 1 November 2026 using Windows PowerShell and Docker Desktop's Linux engine.

| Check | Observed outcome |
| --- | --- |
| Full Linux pytest suite | 90 passed; one upstream Starlette/httpx deprecation warning |
| Windows regression suite | 86 passed; real PostgreSQL test skipped; three live Linux tests deselected |
| PostgreSQL/Redis | Real outbox locking and RQ execution passed |
| Alembic | Empty-database upgrade; downgrade/upgrade; metadata drift check passed |
| Live scanners | Three fix handlers, project paths, idempotence, variable-file precedence passed |
| Compose | Shared image built; migration exited 0; API, dispatcher, worker and UI started |
| API workflow | ZIP upload, dual scan, fix, immutable source and candidate download passed |
| Live UI/API integration | Saved fix reopened; both scanners' remaining findings displayed |
| Real Redis outage | HTTP 202 accepted; job stayed queued with an unpublished outbox row; completed after restart |
| Duplicate delivery | Worker returned `duplicate_or_terminal`; one completed report retained |
| Persistence | Completed review reopened after PostgreSQL, Redis and API restarts |
| Corpus | All 30 fixtures evaluated; zero label mismatches; four explicitly unverified inputs |
| Terraform deployment | `fmt -check` and provider-backed `validate` passed; no plan/apply |
| Source secret scan | Trivy secret scanner reported zero findings in publishable source |
| API demo | Recorded real HTTP/worker outcomes; 32-second MP4 and asciicast included |

Reproduce the container suite:

```powershell
docker compose build api
docker compose -f compose.yaml -f compose.test.yaml run --rm verify
docker compose up -d --wait
.\.venv\Scripts\python.exe scripts/smoke.py
```

For outage recovery, stop this stack's Redis, run `scripts/recovery_probe.py submit`,
start Redis, then run `scripts/recovery_probe.py verify`. Stop only your own local
test stack. The failed/outage submission stays in history.

Raw [pytest JUnit](results/pytest-linux.xml), [benchmark](results/benchmark.json), and
[deployment review](DEPLOYMENT-REVIEW.md) accompany this record. Container tests use
disposable PostgreSQL/Redis services, separate from application history volumes.

Not verified: AWS account eligibility, credit availability, EC2 deployment/runtime,
cloud teardown, or public multi-user operation. Browser Computer Use was stopped;
UI screenshots and a UI recording remain pending. The included video shows the API.
