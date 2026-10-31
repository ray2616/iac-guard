"""Run submit while Redis is stopped, then verify after Redis/services restart."""

import argparse
import json
from pathlib import Path

import httpx
from smoke import wait


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=["submit", "verify"])
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--state", type=Path, default=Path("outputs/recovery.json"))
    args = parser.parse_args()
    with httpx.Client(base_url=args.api, timeout=30) as client:
        if args.stage == "submit":
            response = client.post("/api/v1/projects", json={"name": "Queue outage recovery"})
            response.raise_for_status()
            project = response.json()
            response = client.post(
                f"/api/v1/projects/{project['id']}/scans",
                files={
                    "file": ("main.tf", b'resource "aws_ebs_volume" "data" { encrypted = false }')
                },
            )
            assert response.status_code == 202, response.text
            job = response.json()
            assert client.get(f"/api/v1/jobs/{job['id']}").json()["status"] == "queued"
            args.state.parent.mkdir(parents=True, exist_ok=True)
            args.state.write_text(json.dumps({"project": project, "job": job}, indent=2))
            print("Submission accepted during queue outage:", job["id"])
        else:
            state = json.loads(args.state.read_text())
            job = wait(client, state["job"]["id"])
            history = client.get(f"/api/v1/scans?project_id={state['project']['id']}").json()
            assert sum(j["id"] == job["id"] for j in history) == 1
            assert len(job["artifacts"]) == 1
            state["verified"] = job
            args.state.write_text(json.dumps(state, indent=2))
            print("Recovered exactly one completed review and report:", job["id"])


if __name__ == "__main__":
    main()
