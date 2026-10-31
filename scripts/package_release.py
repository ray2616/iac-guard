"""Build a source release without credentials, state, virtualenvs or user uploads."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = [
    ".github",
    ".gitignore",
    ".gitattributes",
    "iac_guard",
    "migrations",
    "samples",
    "scripts",
    "tests",
    "datasets",
    ".streamlit",
    "docs",
    "infra",
    "app.py",
    "ui.css",
    "pyproject.toml",
    "requirements-windows.lock.txt",
    "requirements-linux.lock.txt",
    "README.md",
    "LICENSE",
    "Dockerfile",
    "compose.yaml",
    "compose.aws.yaml",
    "compose.test.yaml",
    "alembic.ini",
    ".dockerignore",
    ".env.example",
]


def main():
    out = ROOT / "outputs" / "iac-guard-v0.1.0.tar.gz"
    out.parent.mkdir(exist_ok=True)
    manifest = {}
    with tarfile.open(out, "w:gz") as archive:
        for entry in INCLUDE:
            path = ROOT / entry
            if not path.exists():
                continue
            for file in sorted(path.rglob("*")) if path.is_dir() else [path]:
                name = file.relative_to(ROOT).as_posix()
                if (
                    file.is_symlink()
                    or not file.is_file()
                    or any(part in {"__pycache__", ".terraform"} for part in file.parts)
                ):
                    continue
                if file.suffix in {".pyc", ".tfstate", ".tfvars"} and name.startswith("infra/"):
                    continue
                if name.startswith("infra/") and (
                    file.name.endswith(".tfstate.backup") or file.name.endswith(".tfplan")
                ):
                    continue
                data = file.read_bytes()
                manifest[name] = hashlib.sha256(data).hexdigest()
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
    checksum = hashlib.sha256(out.read_bytes()).hexdigest()
    out.with_suffix(out.suffix + ".sha256").write_text(f"{checksum}  {out.name}\n")
    (out.parent / "release-manifest.json").write_text(json.dumps(manifest, indent=2))
    print(out)
    print("SHA256:", checksum)


if __name__ == "__main__":
    main()
