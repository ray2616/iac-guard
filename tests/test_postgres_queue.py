"""Real PostgreSQL/Redis integration. CI supplies fresh, disposable services."""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from redis import Redis
from rq import Queue, SimpleWorker
from sqlalchemy import select

from iac_guard.models import ScanReport
from iac_guard.service.api import app
from iac_guard.service.config import settings
from iac_guard.service.database import Job, Outbox, engine, session_factory
from iac_guard.service.dispatcher import dispatch_once

pytestmark = pytest.mark.skipif(
    not os.getenv("POSTGRES_TEST_URL"), reason="Real PostgreSQL/Redis services are opt-in"
)


def test_postgres_outbox_locking_and_rq_execution(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", os.environ["POSTGRES_TEST_URL"])
    settings.cache_clear()
    engine.cache_clear()
    assert engine().dialect.name == "postgresql"
    monkeypatch.setattr(
        "iac_guard.service.jobs.scan_project",
        lambda *args, **kwargs: [
            ScanReport("checkov", "test", []),
            ScanReport("trivy", "test", []),
        ],
    )
    client = TestClient(app)
    project = client.post("/api/v1/projects", json={"name": "Queue integration"}).json()
    job = client.post(
        f"/api/v1/projects/{project['id']}/scans",
        files={
            "file": ("main.tf", b'resource "aws_ebs_volume" "data" { encrypted = false }'),
        },
    ).json()
    queue = Queue("test-" + uuid4().hex, connection=Redis.from_url(settings().redis_url))
    # Two dispatchers contend for the same outbox; SKIP LOCKED must avoid duplicate publication.
    with ThreadPoolExecutor(max_workers=2) as pool:
        counts = list(pool.map(lambda _: dispatch_once(queue), range(2)))
    assert sum(counts) == 1
    assert queue.count == 1
    SimpleWorker([queue], connection=queue.connection).work(burst=True)
    with session_factory()() as db:
        assert db.get(Job, job["id"]).status == "completed"
        assert db.scalar(select(Outbox).where(Outbox.job_id == job["id"])).published_at is not None
    engine().dispose()
    engine.cache_clear()
    settings.cache_clear()
