import httpx
from streamlit.testing.v1 import AppTest

from iac_guard.web import APIClient


def configure(monkeypatch, status=None, kind="terraform"):
    job = {
        "id": "job",
        "snapshot_id": "snapshot",
        "kind": "scan",
        "status": status or "completed",
        "stage": "complete",
        "source": {"name": "review.zip", "kind": kind},
        "error": "scanner failed",
        "artifacts": [],
        "result": {
            "reports": [
                {"scanner": "checkov", "version": "test", "findings": []},
                {"scanner": "trivy", "version": "test", "findings": []},
            ]
        },
    }

    def get(self, path):
        if path == "/api/v1/projects":
            return [{"id": "project", "name": "Example"}]
        if path.endswith("/jobs"):
            return []
        return job

    monkeypatch.setattr(APIClient, "get", get)
    monkeypatch.setattr(
        APIClient, "request", lambda *args, **kwargs: httpx.Response(200, content=b"example")
    )


def test_ui_loads_and_switches_source(monkeypatch):
    configure(monkeypatch)
    app = AppTest.from_file("app.py", default_timeout=20).run()
    assert not app.exception
    assert app.title[0].value == "IaC Guard"
    app.radio[0].set_value("Dockerfile example").run()
    assert not app.exception
    assert not next(b for b in app.button if b.label == "Scan project or file").disabled


def test_empty_upload_disables_submission(monkeypatch):
    configure(monkeypatch)
    app = AppTest.from_file("app.py", default_timeout=20).run()
    app.radio[0].set_value("Upload project or file").run()
    assert not app.exception
    assert next(b for b in app.button if b.label == "Scan project or file").disabled


def test_api_failure_has_no_passing_result(monkeypatch):
    def broken(*args):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(APIClient, "get", broken)
    app = AppTest.from_file("app.py", default_timeout=20).run()
    assert not app.exception
    assert "unavailable" in app.error[0].value
    assert not app.metric


def test_saved_review_and_docker_fix_restriction(monkeypatch):
    configure(monkeypatch, kind="dockerfile")
    app = AppTest.from_file("app.py", default_timeout=20)
    app.query_params["job"] = "job"
    app.run()
    assert not app.exception
    assert [m.value for m in app.metric] == ["0", "0"]
    assert next(b for b in app.button if b.label == "Propose verified fixes").disabled


def test_failed_review_offers_retry(monkeypatch):
    configure(monkeypatch, status="failed")
    app = AppTest.from_file("app.py", default_timeout=20)
    app.query_params["job"] = "job"
    app.run()
    assert not app.exception
    assert "incomplete" in app.error[0].value
    assert any(b.label == "Retry as a new job" for b in app.button)
    assert not app.metric
