from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from iac_guard.service.config import settings


def test_empty_database_upgrade_downgrade_upgrade(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "migration.sqlite")
    monkeypatch.setenv("DATABASE_URL", url)
    settings.cache_clear()
    config = Config("alembic.ini")
    command.upgrade(config, "head")
    db = create_engine(url)
    assert {"projects", "snapshots", "jobs", "outbox", "findings", "artifacts"} <= set(
        inspect(db).get_table_names()
    )
    command.downgrade(config, "base")
    assert "jobs" not in inspect(db).get_table_names()
    command.upgrade(config, "head")
    assert "jobs" in inspect(db).get_table_names()
    db.dispose()
    settings.cache_clear()
