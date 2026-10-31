"""Transactional outbox delivery and bounded abandoned-job reconciliation."""

import logging
import time
from datetime import UTC, timedelta

from redis import Redis
from rq import Queue
from sqlalchemy import select

from .config import settings
from .database import Job, Outbox, session_factory, utcnow

log = logging.getLogger("iac_guard.dispatcher")


def queue():
    cfg = settings()
    return Queue(
        cfg.queue,
        connection=Redis.from_url(
            cfg.redis_url,
            socket_connect_timeout=3,
            socket_timeout=5,
        ),
    )


def dispatch_once(target_queue=None):
    target_queue = target_queue if target_queue is not None else queue()
    delivered = 0
    with session_factory().begin() as db:
        entries = list(
            db.scalars(
                select(Outbox)
                .where(
                    Outbox.published_at.is_(None),
                )
                .with_for_update(skip_locked=True)
                .limit(10)
            )
        )
        for entry in entries:
            job = db.get(Job, entry.job_id)
            if job.status != "queued":
                entry.published_at = utcnow()
                continue
            entry.attempts += 1
            try:
                existing = target_queue.fetch_job(job.id)
                if existing is None:
                    target_queue.enqueue(
                        "iac_guard.service.jobs.execute",
                        job.id,
                        job_id=job.id,
                        job_timeout=1800 if job.kind == "fix" else 600,
                        result_ttl=86400,
                        failure_ttl=604800,
                    )
                entry.published_at = utcnow()
                entry.last_error = None
                job.stage = "queued"
                delivered += 1
            except Exception as exc:
                entry.last_error = type(exc).__name__
                # Commit the durable outbox record and retry next pass.
                break
    return delivered


def reconcile_once(target_queue=None):
    cfg = settings()
    target_queue = target_queue if target_queue is not None else queue()
    now = utcnow()
    with session_factory().begin() as db:
        jobs = list(
            db.scalars(
                select(Job)
                .where(Job.status.in_(["queued", "running"]))
                .with_for_update(skip_locked=True)
            )
        )
        for job in jobs:
            origin = job.started_at if job.status == "running" else job.created_at
            if origin.tzinfo is None:
                origin = origin.replace(tzinfo=UTC)
            deadline = cfg.running_deadline if job.status == "running" else cfg.queued_deadline
            if now - origin > timedelta(seconds=deadline):
                job.status, job.stage = "failed", "failed"
                job.error = (
                    "Job exceeded its recovery deadline. Retry creates a new linked attempt."
                )
                job.finished_at = now
                continue
            try:
                queued = target_queue.fetch_job(job.id)
                state = str(queued.get_status()).lower().split(".")[-1] if queued else None
                if state in {"failed", "stopped", "canceled"}:
                    job.status, job.stage = "failed", "failed"
                    job.error = "Worker execution failed or was abandoned. Retry is available."
                    job.finished_at = now
                elif queued is None and job.status == "queued":
                    entry = db.scalar(select(Outbox).where(Outbox.job_id == job.id))
                    if entry:
                        entry.published_at = None
            except Exception as exc:
                # Redis unavailability is not evidence of scanner success or job failure.
                log.debug("queue_status_unavailable", extra={"error_type": type(exc).__name__})
                continue


def main():
    logging.basicConfig(level=logging.INFO)
    while True:
        try:
            dispatch_once()
            reconcile_once()
        except Exception as exc:
            log.warning("dispatch_unavailable", extra={"error_type": type(exc).__name__})
        time.sleep(5)


if __name__ == "__main__":
    main()
