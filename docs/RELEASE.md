IaC Guard v0.1.0 is a local MVP with complete Terraform project uploads, bundled local
modules, explicit variable-file selection, Dockerfile scans and three deterministic
Terraform fix handlers. PostgreSQL saves immutable review history; a transactional
outbox, Redis/RQ and fenced workers provide asynchronous processing and recovery.

Verified locally:

- 90 tests pass in Linux containers, including PostgreSQL/RQ, migrations, archive safety,
  API/UI behavior, live scanner remediation and variable precedence.
- All 30 synthetic fixtures evaluated with zero label mismatches: Checkov detects 17/17
  scored labels; Trivy detects 11/11. Four inputs are explicitly unverified. These are
  selected synthetic controls, not real-world detection rates.
- Eight edits across six project fixtures are verified with zero introduced findings.
- A real Redis outage, duplicate delivery and database/API/queue restarts preserve results.
- Docker Compose builds/starts locally. AWS Terraform validates without provisioning.

See `docs/RESULTS.md` and raw results for complete measurements, limitations and refusals.
The attached 32-second API video records the running application with synthetic input.

This is a prerelease portfolio MVP. AWS execution awaits account/credit verification;
the vulnerable corpus is never deployed. UI screenshots and a UI recording remain
pending after Computer Use was stopped. Infrastructure policy findings are documented
in `docs/DEPLOYMENT-REVIEW.md`. No public multi-user authentication is included.

MIT licensed. Inspired by https://github.com/Shlok014/llm-iac-security; historical LLM
metrics are not reused. The engine makes no model calls and runs no Terraform
init/validate/plan/apply against submitted projects.
