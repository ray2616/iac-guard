"""Exercise the running API and real worker; never deploy the vulnerable input."""

import argparse
import io
import json
import time
import zipfile
from pathlib import Path

import httpx

from iac_guard.projects import zip_files


def wait(client, identifier, timeout=900):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            response = client.get(f"/api/v1/jobs/{identifier}")
        except httpx.TransportError:
            time.sleep(2)
            continue
        if response.status_code in {500, 502, 503, 504}:
            time.sleep(2)
            continue
        response.raise_for_status()
        job = response.json()
        if job["status"] == "completed":
            return job
        if job["status"] == "failed":
            raise RuntimeError(job["error"])
        time.sleep(2)
    raise TimeoutError(f"Job {identifier} did not finish")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--out", type=Path, default=Path("outputs/smoke.json"))
    args = parser.parse_args()
    source = {
        "storage.tf": b'resource "aws_ebs_volume" "data" {\n availability_zone = var.zone\n size = 10\n encrypted = false\n}\n',
        "variables.tf": b'variable "zone" { default = "us-east-1a" }\n',
        "outputs.tf": b'output "volume_id" { value = aws_ebs_volume.data.id }\n',
    }
    with httpx.Client(base_url=args.api, timeout=30) as client:
        client.get("/health/ready").raise_for_status()
        response = client.post("/api/v1/projects", json={"name": "Prototype verification"})
        response.raise_for_status()
        project = response.json()
        response = client.post(
            f"/api/v1/projects/{project['id']}/scans",
            files={"file": ("project.zip", zip_files(source), "application/zip")},
        )
        assert response.status_code == 202, response.text
        scan = wait(client, response.json()["id"])
        assert {r["scanner"] for r in scan["result"]["reports"]} == {"checkov", "trivy"}
        for report in scan["result"]["reports"]:
            assert any(f["file"] == "storage.tf" for f in report["findings"])
        response = client.post(f"/api/v1/scans/{scan['id']}/fixes")
        assert response.status_code == 202, response.text
        fix = wait(client, response.json()["id"])
        candidate_artifact = next(a for a in fix["artifacts"] if a["name"] == "candidate.zip")
        response = client.get(f"/api/v1/artifacts/{candidate_artifact['id']}/download")
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            candidate = {name: archive.read(name) for name in archive.namelist()}
        assert set(candidate) == set(source)
        assert candidate["variables.tf"] == source["variables.tf"]
        assert candidate["outputs.tf"] == source["outputs.tf"]
        assert b"encrypted = true" in candidate["storage.tf"]
        response = client.get(f"/api/v1/snapshots/{scan['snapshot_id']}/download")
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            assert {name: archive.read(name) for name in archive.namelist()} == source
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"project": project, "scan": scan, "fix": fix}, indent=2))
        print(
            f"Verified upload, dual scan, queued fix, immutable source and candidate download: {args.out}"
        )


if __name__ == "__main__":
    main()
