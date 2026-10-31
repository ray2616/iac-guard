"""RQ execution adapter. Database claim tokens fence duplicate and stale workers."""

import hashlib
import io
import json
import logging
import zipfile
from dataclasses import asdict, replace
from pathlib import Path
from tempfile import TemporaryDirectory

from sqlalchemy import update

from ..models import ToolError
from ..projects import materialize, project_metadata, read_zip, validate_files, zip_files
from ..remediation.project import fix_project
from ..scanners import scan_file, scan_project
from .database import Artifact, FindingRow, Job, Snapshot, session_factory, uid, utcnow
from .storage import Storage

log = logging.getLogger("iac_guard.jobs")


def execute(job_id: str):
    token = uid()
    factory = session_factory()
    with factory.begin() as db:
        claim = db.execute(
            update(Job)
            .where(Job.id == job_id, Job.status == "queued")
            .values(
                status="running",
                stage="scanning",
                token=token,
                started_at=utcnow(),
            )
        )
        if claim.rowcount != 1:
            return "duplicate_or_terminal"
        job = db.get(Job, job_id)
        snapshot = db.get(Snapshot, job.snapshot_id)
    log.info("job_started", extra={"job_id": job_id, "kind": job.kind})
    try:
        store = Storage()
        packed = store.get(snapshot.object_key)
        if hashlib.sha256(packed).hexdigest() != snapshot.digest:
            raise ToolError("Stored source hash does not match its immutable snapshot")
        if snapshot.kind == "dockerfile":
            with zipfile.ZipFile(io.BytesIO(packed)) as archive:
                if archive.namelist() != ["Dockerfile"]:
                    raise ToolError("Invalid stored Dockerfile snapshot")
                files = validate_files({"Dockerfile": archive.read("Dockerfile")}, dockerfile=True)
        else:
            files = read_zip(packed)
        artifacts = []
        with TemporaryDirectory(prefix="iac-job-") as directory:
            root = Path(directory)
            materialize(files, root)
            if job.kind == "scan":
                if snapshot.kind == "terraform":
                    metadata = project_metadata(files, tuple(snapshot.variables))
                    reports = scan_project(root, var_files=tuple(snapshot.variables))
                    limitations = metadata["limitations"]
                else:
                    reports = scan_file(root / "Dockerfile")
                    for report in reports:
                        report.findings = [
                            replace(finding, file="Dockerfile") for finding in report.findings
                        ]
                    limitations = [
                        "Dockerfile configuration scanning only; no image build or CVE scan."
                    ]
                result = {"reports": [asdict(r) for r in reports], "limitations": limitations}
            else:
                with factory.begin() as db:
                    db.execute(
                        update(Job)
                        .where(Job.id == job_id, Job.token == token)
                        .values(stage="verifying_fixes")
                    )
                candidate, report = fix_project(root, tuple(snapshot.variables), max_attempts=3)
                result = report.as_dict()
                reports = report.after
                result["reports"] = result["after"]
                if report.diffs:
                    artifacts += [
                        ("candidate.zip", zip_files(candidate), "application/zip"),
                        ("changes.diff", "\n".join(report.diffs.values()).encode(), "text/plain"),
                    ]
        artifacts.append(("report.json", json.dumps(result, indent=2).encode(), "application/json"))
        stored = [(name, store.put(body), mime) for name, body, mime in artifacts]
        with factory.begin() as db:
            finish = db.execute(
                update(Job)
                .where(
                    Job.id == job_id,
                    Job.status == "running",
                    Job.token == token,
                )
                .values(status="completed", stage="complete", result=result, finished_at=utcnow())
            )
            if finish.rowcount != 1:
                return "stale_execution"
            for report in reports:
                for finding in report.findings:
                    db.add(FindingRow(job_id=job_id, **asdict(finding)))
            for name, key, mime in stored:
                db.add(Artifact(job_id=job_id, name=name, object_key=key, media_type=mime))
        log.info("job_completed", extra={"job_id": job_id})
        return "completed"
    except Exception as exc:
        # Never log uploaded source or raw scanner output. Details remain private in the DB.
        message = (
            str(exc)[:2000]
            if isinstance(exc, ToolError)
            else f"Execution failed ({type(exc).__name__}); check service readiness and retry."
        )
        with factory.begin() as db:
            db.execute(
                update(Job)
                .where(Job.id == job_id, Job.status == "running", Job.token == token)
                .values(
                    status="failed",
                    stage="failed",
                    error=message,
                    finished_at=utcnow(),
                )
            )
        log.warning("job_failed", extra={"job_id": job_id, "error_type": type(exc).__name__})
        # RQ must also record failed jobs, while API status remains durable in PostgreSQL.
        raise RuntimeError(f"Job {job_id} failed ({type(exc).__name__})") from None


def main():
    from redis import Redis
    from rq import Queue, Worker

    from .config import settings

    logging.basicConfig(level=logging.INFO)
    cfg = settings()
    connection = Redis.from_url(cfg.redis_url, socket_connect_timeout=5, socket_timeout=30)
    Worker([Queue(cfg.queue, connection=connection)], connection=connection).work()


if __name__ == "__main__":
    main()
