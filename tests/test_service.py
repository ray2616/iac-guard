from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from iac_guard.models import Finding, ScanReport, ToolError
from iac_guard.service.api import app
from iac_guard.service.config import settings
from iac_guard.service.database import (
    Artifact,
    Base,
    FindingRow,
    Job,
    Outbox,
    engine,
    session_factory,
    utcnow,
)
from iac_guard.service.dispatcher import dispatch_once, reconcile_once
from iac_guard.service.jobs import execute

SOURCE = b'resource "aws_ebs_volume" "data" {\n encrypted = false\n}\n'


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(tmp_path / "service.sqlite"))
    monkeypatch.setenv("STORAGE_PATH", str(tmp_path / "objects"))
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    settings.cache_clear()
    engine.cache_clear()
    Base.metadata.create_all(engine())
    with TestClient(app) as client:
        yield client
    engine().dispose()
    engine.cache_clear()
    settings.cache_clear()


def submit(client):
    project = client.post("/api/v1/projects", json={"name": "Demo"}).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/scans", files={"file": ("main.tf", SOURCE)}
    )
    assert response.status_code == 202, response.text
    return response.json()


def clean_reports(_root, **kwargs):
    return [ScanReport("checkov", "test", []), ScanReport("trivy", "test", [])]


class Queue:
    def __init__(self, broken=False):
        self.broken = broken
        self.jobs = {}
        self.deliveries = 0

    def fetch_job(self, identifier):
        if self.broken:
            raise ConnectionError("offline")
        return self.jobs.get(identifier)

    def enqueue(self, function, identifier, **kwargs):
        self.deliveries += 1
        self.jobs[identifier] = SimpleNamespace(get_status=lambda: "queued")


def test_upload_and_outbox_are_transactional(service):
    job = submit(service)
    with session_factory()() as db:
        assert db.get(Job, job["id"]).status == "queued"
        assert db.scalar(select(func.count()).select_from(Outbox)) == 1
    assert service.get("/api/v1/scans").json()[0]["id"] == job["id"]


def test_redis_outage_and_duplicate_delivery(service):
    submit(service)
    offline = Queue(broken=True)
    assert dispatch_once(offline) == 0
    with session_factory()() as db:
        assert db.scalar(select(Outbox)).published_at is None
    online = Queue()
    assert dispatch_once(online) == 1
    assert dispatch_once(online) == 0
    assert online.deliveries == 1


def test_worker_is_idempotent_and_artifacts_persist(service, monkeypatch):
    monkeypatch.setattr("iac_guard.service.jobs.scan_project", clean_reports)
    job = submit(service)
    assert execute(job["id"]) == "completed"
    assert execute(job["id"]) == "duplicate_or_terminal"
    result = service.get(f"/api/v1/jobs/{job['id']}").json()
    assert result["status"] == "completed"
    assert len(result["artifacts"]) == 1
    artifact = service.get(f"/api/v1/artifacts/{result['artifacts'][0]['id']}/download")
    assert artifact.status_code == 200
    assert artifact.json()["reports"][0]["scanner"] == "checkov"
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(Artifact)) == 1


def test_saved_project_history_includes_fix_proposals(service, monkeypatch):
    monkeypatch.setattr("iac_guard.service.jobs.scan_project", clean_reports)
    scan = submit(service)
    execute(scan["id"])
    response = service.post(f"/api/v1/scans/{scan['id']}/fixes")
    assert response.status_code == 202
    fix = response.json()
    history = service.get(f"/api/v1/projects/{scan['project_id']}/jobs").json()
    assert {job["id"] for job in history} == {scan["id"], fix["id"]}
    assert {job["kind"] for job in history} == {"scan", "fix"}
    assert fix["parent_id"] == scan["id"]


def test_failure_is_not_clean_and_retry_is_linked(service, monkeypatch):
    def broken(*args, **kwargs):
        raise ToolError("Scanner failed")

    monkeypatch.setattr("iac_guard.service.jobs.scan_project", broken)
    job = submit(service)
    with pytest.raises(RuntimeError):
        execute(job["id"])
    result = service.get(f"/api/v1/jobs/{job['id']}").json()
    assert result["status"] == "failed"
    assert result["result"] is None
    retry = service.post(f"/api/v1/jobs/{job['id']}/retry")
    assert retry.status_code == 202
    assert retry.json()["parent_id"] == job["id"]
    assert retry.json()["id"] != job["id"]


def test_recovery_deadline_makes_abandoned_job_visible(service):
    job = submit(service)
    with session_factory().begin() as db:
        record = db.get(Job, job["id"])
        record.created_at = utcnow() - timedelta(days=2)
    reconcile_once(Queue())
    assert service.get(f"/api/v1/jobs/{job['id']}").json()["status"] == "failed"


def test_stale_worker_cannot_publish_after_job_is_failed(service, monkeypatch):
    job = submit(service)

    def scanner(*args, **kwargs):
        with session_factory().begin() as db:
            db.get(Job, job["id"]).status = "failed"
        return clean_reports(None)

    monkeypatch.setattr("iac_guard.service.jobs.scan_project", scanner)
    assert execute(job["id"]) == "stale_execution"
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(Artifact)) == 0
        assert db.scalar(select(func.count()).select_from(FindingRow)) == 0


def test_unselected_variable_and_path_validation(service):
    project = service.post("/api/v1/projects", json={"name": "Demo"}).json()
    result = service.post(
        f"/api/v1/projects/{project['id']}/scans",
        files={"file": ("main.tf", SOURCE)},
        data={"variable_files": '["missing.tfvars"]'},
    )
    assert result.status_code == 422
    assert service.get("/api/v1/scans").json() == []


def test_findings_preserve_file_and_duplicates(service, monkeypatch):
    def scanner(*args, **kwargs):
        finding = Finding("trivy", "EXAMPLE", "aws_ebs_volume.data", "Example", file="main.tf")
        return [ScanReport("checkov", "test", []), ScanReport("trivy", "test", [finding, finding])]

    monkeypatch.setattr("iac_guard.service.jobs.scan_project", scanner)
    job = submit(service)
    execute(job["id"])
    rows = service.get(f"/api/v1/jobs/{job['id']}/findings").json()
    assert len(rows) == 2
    assert all(row["file"] == "main.tf" for row in rows)
