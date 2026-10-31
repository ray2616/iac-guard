import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select, text

from ..models import ToolError, file_kind
from ..projects import (
    MAX_UPLOAD,
    read_zip,
    snapshot_hash,
    validate_files,
    zip_files,
)
from .database import (
    Artifact,
    FindingRow,
    Job,
    Outbox,
    Project,
    Snapshot,
    engine,
    session_factory,
    uid,
)
from .storage import Storage


@asynccontextmanager
async def lifespan(app):
    yield


app = FastAPI(title="IaC Guard API", version="0.1.0", lifespan=lifespan)


def session():
    with session_factory()() as db:
        yield db


def get_or_404(db, model, identifier):
    value = db.get(model, identifier)
    if value is None:
        raise HTTPException(404, "Record not found")
    return value


class ProjectInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)


def job_json(job):
    return {
        "id": job.id,
        "project_id": job.project_id,
        "snapshot_id": job.snapshot_id,
        "parent_id": job.parent_id,
        "kind": job.kind,
        "status": job.status,
        "stage": job.stage,
        "error": job.error,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
    }


def create_job(db, snapshot, kind, parent=None):
    job = Job(
        id=uid(),
        project_id=snapshot.project_id,
        snapshot_id=snapshot.id,
        kind=kind,
        parent_id=parent,
    )
    db.add(job)
    db.flush()
    db.add(Outbox(job_id=job.id))
    return job


@app.get("/health/live")
def live():
    return {"status": "alive"}


@app.get("/health/ready")
def ready():
    try:
        with engine().connect() as connection:
            connection.execute(text("SELECT 1 FROM projects LIMIT 1"))
        from redis import Redis

        from .config import settings

        Redis.from_url(settings().redis_url, socket_connect_timeout=2, socket_timeout=2).ping()
    except Exception:
        raise HTTPException(503, "Database, migration or queue unavailable") from None
    return {"status": "ready"}


@app.post("/api/v1/projects", status_code=201)
def create_project(body: ProjectInput, db=Depends(session)):
    project = Project(name=body.name.strip())
    if not project.name:
        raise HTTPException(422, "Project name cannot be blank")
    db.add(project)
    db.commit()
    return {"id": project.id, "name": project.name}


@app.get("/api/v1/projects")
def projects(db=Depends(session)):
    return [
        {"id": p.id, "name": p.name}
        for p in db.scalars(select(Project).order_by(Project.created_at.desc()).limit(100))
    ]


@app.post("/api/v1/projects/{project_id}/scans", status_code=202)
def submit_scan(
    project_id: str,
    file: UploadFile = File(...),
    variable_files: str = Form("[]"),
    db=Depends(session),
):
    get_or_404(db, Project, project_id)
    body = file.file.read(MAX_UPLOAD + 1)
    if len(body) > MAX_UPLOAD:
        raise HTTPException(413, "Upload exceeds 10 MB")
    name = Path((file.filename or "").replace("\\", "/")).name
    try:
        selected = json.loads(variable_files)
        if not isinstance(selected, list) or any(not isinstance(x, str) for x in selected):
            raise ToolError("variable_files must be a JSON array of root-level filenames")
        if name.lower().endswith(".zip"):
            files, kind = read_zip(body), "terraform"
        else:
            kind = file_kind(Path(name))
            safe = "Dockerfile" if kind == "dockerfile" else name
            files = validate_files({safe: body}, dockerfile=kind == "dockerfile")
        # Syntax failures belong to scanner job outcomes, not upload validation.
        if kind == "dockerfile" and selected:
            raise ToolError("Variable files apply only to Terraform projects")
        available = {n for n in files if n.endswith(".tfvars") and "/" not in n}
        if any(n not in available for n in selected):
            raise ToolError("Selected variable file is not present at the project root")
    except (ToolError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    packed = zip_files(files)
    key = Storage().put(packed)
    snapshot = Snapshot(
        id=uid(),
        project_id=project_id,
        name=name,
        kind=kind,
        digest=snapshot_hash(files),
        object_key=key,
        variables=selected,
        manifest=[{"file": n, "bytes": len(b)} for n, b in sorted(files.items())],
    )
    db.add(snapshot)
    db.flush()
    job = create_job(db, snapshot, "scan")
    db.commit()
    return job_json(job)


@app.get("/api/v1/projects/{project_id}/jobs")
def project_history(project_id: str, limit: int = 50, db=Depends(session)):
    get_or_404(db, Project, project_id)
    query = (
        select(Job)
        .where(Job.project_id == project_id)
        .order_by(Job.created_at.desc())
        .limit(max(1, min(limit, 100)))
    )
    return [job_json(job) for job in db.scalars(query)]


@app.get("/api/v1/scans")
def scans(project_id: str | None = None, limit: int = 50, db=Depends(session)):
    query = select(Job).where(Job.kind == "scan")
    if project_id:
        query = query.where(Job.project_id == project_id)
    rows = db.scalars(query.order_by(Job.created_at.desc()).limit(max(1, min(limit, 100))))
    return [job_json(j) for j in rows]


@app.get("/api/v1/jobs/{job_id}")
@app.get("/api/v1/scans/{job_id}")
@app.get("/api/v1/fixes/{job_id}")
def job_detail(job_id: str, db=Depends(session)):
    job = get_or_404(db, Job, job_id)
    snapshot = get_or_404(db, Snapshot, job.snapshot_id)
    return {
        **job_json(job),
        "result": job.result,
        "source": {
            "name": snapshot.name,
            "kind": snapshot.kind,
            "hash": snapshot.digest,
            "files": snapshot.manifest,
            "variables": snapshot.variables,
        },
        "artifacts": [
            {"id": a.id, "name": a.name, "media_type": a.media_type}
            for a in db.scalars(select(Artifact).where(Artifact.job_id == job.id))
        ],
    }


@app.post("/api/v1/scans/{scan_id}/fixes", status_code=202)
def propose_fix(scan_id: str, db=Depends(session)):
    scan = get_or_404(db, Job, scan_id)
    snapshot = get_or_404(db, Snapshot, scan.snapshot_id)
    if scan.kind != "scan" or scan.status != "completed" or snapshot.kind != "terraform":
        raise HTTPException(409, "Fixes require a completed Terraform scan")
    job = create_job(db, snapshot, "fix", scan.id)
    db.commit()
    return job_json(job)


@app.post("/api/v1/jobs/{job_id}/retry", status_code=202)
def retry(job_id: str, db=Depends(session)):
    old = get_or_404(db, Job, job_id)
    if old.status != "failed":
        raise HTTPException(409, "Only failed jobs can be retried")
    job = create_job(db, get_or_404(db, Snapshot, old.snapshot_id), old.kind, old.id)
    db.commit()
    return job_json(job)


@app.get("/api/v1/jobs/{job_id}/findings")
def findings(job_id: str, db=Depends(session)):
    get_or_404(db, Job, job_id)
    return [
        {
            key: getattr(row, key)
            for key in (
                "scanner",
                "rule_id",
                "file",
                "resource",
                "severity",
                "line",
                "end_line",
                "message",
                "guideline",
            )
        }
        for row in db.scalars(select(FindingRow).where(FindingRow.job_id == job_id))
    ]


@app.get("/api/v1/snapshots/{snapshot_id}/download")
def download_source(snapshot_id: str, db=Depends(session)):
    snapshot = get_or_404(db, Snapshot, snapshot_id)
    return Response(
        Storage().get(snapshot.object_key),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="source.zip"'},
    )


@app.get("/api/v1/artifacts/{artifact_id}/download")
def download_artifact(artifact_id: str, db=Depends(session)):
    artifact = get_or_404(db, Artifact, artifact_id)
    return Response(
        Storage().get(artifact.object_key),
        media_type=artifact.media_type,
        headers={"Content-Disposition": f'attachment; filename="{artifact.name}"'},
    )
