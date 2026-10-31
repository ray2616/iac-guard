"""Record actual synthetic API requests as an asciicast and optional MP4 transcript."""

import argparse
import io
import json
import time
import zipfile
from pathlib import Path

import httpx
from smoke import wait

from iac_guard.projects import zip_files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--render", action="store_true")
    args = parser.parse_args()
    folder = Path("docs/media")
    folder.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    events = []

    def emit(message):
        text = message + "\r\n"
        events.append([round(time.monotonic() - started, 3), "o", text])
        print(message, flush=True)

    emit("IaC Guard v0.1.0 | LIVE API WALKTHROUGH | Synthetic input only")
    emit("Scan -> targeted fix -> structural checks -> dual rescan -> human review")
    source = {
        "storage.tf": Path("datasets/tf01-ebs-literal/main.tf").read_bytes(),
        "outputs.tf": b'output "disk_id" { value = aws_ebs_volume.data.id }\n',
    }
    with httpx.Client(base_url=args.api, timeout=30) as client:
        response = client.post("/api/v1/projects", json={"name": "Live API demonstration"})
        response.raise_for_status()
        project = response.json()
        emit(f"POST /api/v1/projects -> {response.status_code}")
        response = client.post(
            f"/api/v1/projects/{project['id']}/scans",
            files={"file": ("project.zip", zip_files(source))},
        )
        assert response.status_code == 202, response.text
        emit("POST project/scans -> 202 Accepted; two-file snapshot saved")
        emit("PostgreSQL outbox -> Redis/RQ -> isolated scanner worker")
        scan = wait(client, response.json()["id"])
        emit(f"GET job -> {scan['status']}")
        for report in scan["result"]["reports"]:
            emit(f"  {report['scanner']} {report['version']}: {len(report['findings'])} findings")
            for finding in report["findings"]:
                emit(
                    f"    {finding['file']}:{finding['line']} {finding['rule_id']} {finding['resource']}"
                )
        response = client.post(f"/api/v1/scans/{scan['id']}/fixes")
        assert response.status_code == 202, response.text
        emit("POST scan/fixes -> 202 Accepted; original snapshot remains immutable")
        fix = wait(client, response.json()["id"])
        for attempt in fix["result"]["attempts"]:
            emit(f"PATCH {attempt['handler']}: {attempt['status']}")
        for name, diff in fix["result"]["diffs"].items():
            emit(f"File: {name}\n{diff}")
        candidate = next(a for a in fix["artifacts"] if a["name"] == "candidate.zip")
        response = client.get(f"/api/v1/artifacts/{candidate['id']}/download")
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            assert set(archive.namelist()) == set(source)
            assert archive.read("outputs.tf") == source["outputs.tf"]
        emit("DOWNLOAD candidate.zip -> 200; file set and unrelated output verified")
        history = client.get(f"/api/v1/projects/{project['id']}/jobs")
        history.raise_for_status()
        emit(f"REOPEN history -> {len(history.json())} saved reviews (scan + fix)")
        emit("No LLM calls. No Terraform init/validate/plan/apply. No cloud deployment.")
        emit("Review replacement/connectivity implications before adopting any patch.")
    header = {"version": 2, "width": 100, "height": 32, "timestamp": int(time.time())}
    (folder / "api-demo.cast").write_text(
        "\n".join(json.dumps(item) for item in [header, *events]) + "\n", encoding="utf-8"
    )
    if args.render:
        render_video(events, folder / "api-demo.mp4")


def render_video(events, output):
    import textwrap

    import imageio_ffmpeg
    from PIL import Image, ImageDraw, ImageFont

    font_path = Path("C:/Windows/Fonts/consola.ttf")
    font = (
        ImageFont.truetype(str(font_path), 19)
        if font_path.exists()
        else ImageFont.load_default(size=19)
    )
    writer = imageio_ffmpeg.write_frames(
        str(output), (1280, 800), fps=2, codec="libx264", output_params=["-movflags", "+faststart"]
    )
    writer.send(None)
    duration = int(events[-1][0]) + 6
    for frame in range(duration * 2):
        elapsed = frame / 2
        text = "".join(e[2] for e in events if e[0] <= elapsed)
        lines = [part for line in text.splitlines() for part in (textwrap.wrap(line, 96) or [""])]
        canvas = Image.new("RGB", (1280, 800), "#f5f7fa")
        draw = ImageDraw.Draw(canvas)
        draw.text((36, 22), "IaC Guard | Actual API run | No LLM", fill="#111827", font=font)
        draw.line((36, 58, 1244, 58), fill="#cbd5e1", width=2)
        draw.multiline_text((36, 80), "\n".join(lines[-27:]), fill="#172033", font=font, spacing=5)
        draw.text(
            (36, 756),
            f"API transcript playback  {elapsed:.1f}s  |  UI capture pending",
            fill="#64748b",
            font=font,
        )
        writer.send(canvas.tobytes())
    writer.close()
    print(output)


if __name__ == "__main__":
    main()
