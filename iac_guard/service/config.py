import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    database_url: str
    redis_url: str
    storage_backend: str
    storage_path: str
    s3_bucket: str
    s3_prefix: str
    queue: str
    queued_deadline: int
    running_deadline: int


@lru_cache
def settings() -> Settings:
    return Settings(
        os.getenv(
            "DATABASE_URL", "postgresql+psycopg://iac:local-development@localhost:5432/iac_guard"
        ),
        os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        os.getenv("STORAGE_BACKEND", "local"),
        os.getenv("STORAGE_PATH", "work/storage"),
        os.getenv("S3_BUCKET", ""),
        os.getenv("S3_PREFIX", "iac-guard/"),
        "iac-guard",
        int(os.getenv("QUEUED_DEADLINE_SECONDS", "86400")),
        int(os.getenv("RUNNING_DEADLINE_SECONDS", "2100")),
    )
