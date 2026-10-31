"""API-only Streamlit UI. No scanner, database, Redis or cloud clients in the browser layer."""

import json
import os
from html import escape
from pathlib import Path

import httpx
import streamlit as st

from .models import ToolError
from .projects import read_zip, zip_files

ROOT = Path(__file__).resolve().parents[1]


class APIClient:
    def __init__(self):
        self.url = os.getenv("IAC_API_URL", "http://127.0.0.1:8000").rstrip("/")

    def request(self, method, path, **kwargs):
        with httpx.Client(timeout=20) as client:
            response = client.request(method, self.url + path, **kwargs)
        if response.is_error:
            try:
                detail = response.json().get("detail", "Request failed")
            except ValueError:
                detail = "Request failed"
            raise ToolError(f"API {response.status_code}: {str(detail)[:400]}")
        return response

    def get(self, path):
        return self.request("GET", path).json()


def activate(identifier):
    st.session_state.active_job = identifier
    st.session_state.job_status = "queued"
    st.query_params["job"] = identifier


def render_job(api, job_id):
    try:
        job = api.get(f"/api/v1/jobs/{job_id}")
    except (httpx.HTTPError, ToolError) as exc:
        st.error(f"Cannot retrieve this review: {exc}")
        return
    old = st.session_state.get("job_status")
    st.session_state.job_status = job["status"]
    st.caption(f"Review {job['id']} · {job['source']['name']} · {job['kind']}")
    if job["status"] in {"queued", "running"}:
        st.info(
            f"{job['status'].title()} · {job['stage'].replace('_', ' ')}. You can leave and reopen this review."
        )
        st.caption("Results are saved by the worker; refreshing the page does not cancel the job.")
        return
    if old in {"queued", "running"}:
        st.rerun(scope="app")
    if job["status"] == "failed":
        st.error(f"Review incomplete: {job['error']}")
        if st.button("Retry as a new job", key="retry"):
            activate(api.request("POST", f"/api/v1/jobs/{job_id}/retry").json()["id"])
            st.rerun(scope="app")
        return
    result = job["result"] or {}
    reports = result.get("reports", [])
    with st.container(key="results_card"):
        st.html('<div class="section-title">Your review, in detail.</div>')
        columns = st.columns(max(len(reports), 1))
        for column, report in zip(columns, reports):
            column.metric(f"{report['scanner'].title()} findings", len(report["findings"]))
            column.caption(f"Version: {report['version']}")
        findings_tab, patch_tab, report_tab = st.tabs(["Findings", "Proposed patch", "Downloads"])
        with findings_tab:
            for report in reports:
                st.subheader(report["scanner"].title())
                rows = report["findings"]
                if rows:
                    st.dataframe(
                        [
                            {
                                "File": f["file"],
                                "Line": f["line"],
                                "Rule": f["rule_id"],
                                "Severity": f["severity"],
                                "Resource": f["resource"],
                                "Finding": f["message"],
                            }
                            for f in rows
                        ],
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.success("No findings from this scanner's applicable checks.")
            with st.expander("Coverage and deployment notes"):
                notes = result.get("limitations", []) + [
                    n for r in reports for n in r.get("limitations", [])
                ]
                for note in dict.fromkeys(notes):
                    st.write(note)
                st.write(
                    "Completed scans do not prove that infrastructure is secure or deployable."
                )
        with patch_tab:
            if job["kind"] == "scan":
                st.write(
                    "Automatic fixes cover explicit root-module EBS/RDS encryption and RDS public access. Other findings require manual review."
                )
                if st.button(
                    "Propose verified fixes",
                    disabled=job["source"]["kind"] != "terraform",
                    key="fix",
                ):
                    activate(api.request("POST", f"/api/v1/scans/{job_id}/fixes").json()["id"])
                    st.rerun(scope="app")
            else:
                diffs = result.get("diffs", {})
                if not diffs:
                    st.info("No verified patch was produced. Review the attempt outcomes below.")
                for name, diff in diffs.items():
                    st.caption(name)
                    st.code(diff, language="diff")
                for attempt in result.get("attempts", []):
                    st.write(
                        f"**{attempt['handler']} · {attempt['status']}** — {attempt['reason']}"
                    )
                    st.caption(attempt["impact"])
                st.caption(
                    "Review connectivity and replacement implications. Terraform plan/apply were not run."
                )
        with report_tab:
            source = api.request("GET", f"/api/v1/snapshots/{job['snapshot_id']}/download").content
            st.download_button(
                "Download original snapshot", source, "source.zip", "application/zip"
            )
            for artifact in job["artifacts"]:
                body = api.request("GET", f"/api/v1/artifacts/{artifact['id']}/download").content
                st.download_button(
                    f"Download {artifact['name']}",
                    body,
                    artifact["name"],
                    artifact["media_type"],
                    key=artifact["id"],
                )


def render():
    st.set_page_config(page_title="IaC Guard", page_icon="🛡️", layout="wide")
    st.html(f"<style>{(ROOT / 'ui.css').read_text(encoding='utf-8')}</style>")
    st.html(
        '<div class="brandbar"><div class="brand"><span class="brand-icon"><span class="shield-drawing"></span></span>iac guard<span class="brand-tag">YOUR INFRASTRUCTURE WORKSPACE</span></div><div class="local-pill">Persistent reviews · No LLM</div></div>'
    )
    st.html('<div class="eyebrow intro-kicker">A LITTLE CLARITY, BEFORE YOU DEPLOY</div>')
    st.title("IaC Guard")
    st.html('<div class="intro-copy">Your project. A clearer picture. Every change verified.</div>')
    api = APIClient()
    try:
        projects = api.get("/api/v1/projects")
    except (httpx.HTTPError, ToolError) as exc:
        st.error(f"The review service is unavailable: {exc}")
        st.code("docker compose up --build -d", language="powershell")
        st.caption(
            "Start Docker Desktop first. The API and database must be running; scanner failures are never treated as clean results."
        )
        return
    left, right = st.columns([1.65, 1], gap="large")
    with right, st.container(key="workspace_card"):
        st.html('<div class="eyebrow">YOUR WORKSPACE</div>')
        names = {p["id"]: p["name"] for p in projects}
        project = st.selectbox(
            "Project", list(names), format_func=names.get, index=0 if names else None
        )
        with st.expander("Create a project", expanded=not bool(names)):
            project_name = st.text_input("Project name", value="My infrastructure", max_chars=120)
            if st.button("Create project", disabled=not project_name.strip()):
                api.request("POST", "/api/v1/projects", json={"name": project_name})
                st.rerun()
        mode = st.radio(
            "Choose input", ["Terraform example", "Dockerfile example", "Upload project or file"]
        )
        filename, content = "", b""
        if mode == "Terraform example":
            filename = "example-project.zip"
            content = zip_files(
                {
                    "main.tf": (ROOT / "samples/review.tf").read_bytes(),
                    "outputs.tf": b'output "volume_id" { value = aws_ebs_volume.data.id }\n',
                }
            )
        elif mode == "Dockerfile example":
            filename, content = "Dockerfile", (ROOT / "samples/Dockerfile").read_bytes()
        else:
            uploaded = st.file_uploader("Terraform ZIP, .tf or Dockerfile · max 10 MB")
            if uploaded:
                filename, content = uploaded.name, uploaded.getvalue()
        variables = []
        if filename.lower().endswith(".zip"):
            try:
                manifest = read_zip(content)
                choices = [
                    n
                    for n in manifest
                    if n.endswith(".tfvars")
                    and "/" not in n
                    and n != "terraform.tfvars"
                    and not n.endswith(".auto.tfvars")
                ]
                variables = st.multiselect("Additional variable files", choices)
                st.caption(f"{len(manifest)} files · relative paths preserved")
            except ToolError as exc:
                st.error(str(exc))
                content = b""
        st.caption("Examples contain deliberate misconfigurations. Do not deploy them.")
    with left, st.container(key="focus_card"):
        st.html(
            '<div class="focus-top">Today’s focus</div><div class="focus-title">A clearer view of<br>your infrastructure.</div><div class="focus-copy">Scan a complete Terraform project. Revisit saved findings. Review a targeted, independently checked patch.</div>'
        )
        st.html(
            f'<div class="file-pill">{escape(filename or "Choose a project ZIP or a file")}</div>'
        )
        if st.button(
            "Scan project or file",
            type="primary",
            use_container_width=True,
            disabled=not content or not project,
        ):
            try:
                response = api.request(
                    "POST",
                    f"/api/v1/projects/{project}/scans",
                    files={"file": (filename, content)},
                    data={"variable_files": json.dumps(variables)},
                )
                activate(response.json()["id"])
                st.rerun()
            except (httpx.HTTPError, ToolError) as exc:
                st.error(str(exc))
        st.html(
            '<div class="card-footer"><span>Checkov + Trivy</span><span>Queued · Saved · Reviewable</span></div>'
        )
        st.caption(
            "Source snapshots remain unchanged. Up to three supported root-resource patches are attempted per fix job."
        )
    if project:
        history = api.get(f"/api/v1/projects/{project}/jobs")
        lookup = {
            j["id"]: f"{j['created_at'][:19]} · {j['kind']} · {j['status']} · {j['id'][:8]}"
            for j in history
        }

        def open_saved():
            if st.session_state.saved_scan:
                activate(st.session_state.saved_scan)

        st.selectbox(
            "Saved reviews",
            list(lookup),
            format_func=lookup.get,
            index=None,
            key="saved_scan",
            on_change=open_saved,
            placeholder="Reopen a previous review",
        )
    job_id = st.session_state.get("active_job") or st.query_params.get("job")
    if job_id:
        interval = (
            2 if st.session_state.get("job_status", "queued") in {"queued", "running"} else None
        )

        @st.fragment(run_every=interval)
        def show_job():
            try:
                render_job(api, job_id)
            except (httpx.HTTPError, ToolError) as exc:
                st.error(f"Review service unavailable: {exc}")

        show_job()
    st.html(
        '<div class="page-foot">Static analysis, careful changes · No Terraform apply · Human review required</div>'
    )
