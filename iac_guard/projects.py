"""Bounded, platform-independent project snapshots. Never extract an untrusted ZIP."""

import hashlib
import io
import re
import stat
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath

import hcl2

from .models import ToolError

MAX_FILES = 100
MAX_FILE = 1_000_000
MAX_UPLOAD = 10_000_000
MAX_EXPANDED = 25_000_000


def safe_name(name: str) -> str:
    name = unicodedata.normalize("NFC", name)
    parts = name.rstrip("/").split("/")
    if (
        not name
        or "\\" in name
        or ":" in name
        or name.startswith("/")
        or any(p in ("", ".", "..") or p.endswith((" ", ".")) for p in parts)
        or any(any(ord(c) < 32 or c in '<>"|?*' for c in p) for p in parts)
    ):
        raise ToolError("Unsafe project path.")
    for part in parts:
        if part.split(".")[0].upper() in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *[f"COM{i}" for i in range(10)],
            *[f"LPT{i}" for i in range(10)],
        }:
            raise ToolError("Reserved Windows project path.")
        if part.startswith(".") and part != ".terraform.lock.hcl":
            raise ToolError("Hidden directories, state and environment files are not accepted.")
    return "/".join(parts)


def allowed(name: str) -> bool:
    return name.endswith((".tf", ".tfvars")) or PurePosixPath(name).name == ".terraform.lock.hcl"


def validate_files(files: dict[str, bytes], dockerfile: bool = False) -> dict[str, bytes]:
    if not files or len(files) > MAX_FILES:
        raise ToolError("Submit between 1 and 100 files.")
    seen = set()
    total = 0
    for name, data in files.items():
        if safe_name(name) != name or name.casefold() in seen:
            raise ToolError("Duplicate or non-canonical project path.")
        seen.add(name.casefold())
        if not allowed(name) and not (dockerfile and name == "Dockerfile" and len(files) == 1):
            raise ToolError(
                f"Unsupported file: {name}. Only Terraform source/variables/lock files are accepted."
            )
        if len(data) > MAX_FILE:
            raise ToolError(f"File exceeds 1 MB: {name}")
        total += len(data)
        try:
            data.decode("utf-8-sig")
        except UnicodeError as exc:
            raise ToolError(f"File is not UTF-8: {name}") from exc
    if total > MAX_EXPANDED:
        raise ToolError("Project exceeds 25 MB expanded.")
    if not dockerfile and not any("/" not in name and name.endswith(".tf") for name in files):
        raise ToolError("The project root must contain at least one .tf file.")
    return files


def read_zip(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_UPLOAD:
        raise ToolError("ZIP exceeds 10 MB compressed.")
    files: dict[str, bytes] = {}
    seen = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > 300:
                raise ToolError("Archive contains too many entries.")
            for entry in entries:
                # ZipInfo normalizes Windows separators and truncates NULs in filename.
                # Validate the original archive name before those transformations.
                name = safe_name(entry.orig_filename)
                if name.casefold() in seen:
                    raise ToolError("Archive contains duplicate normalized paths.")
                seen.add(name.casefold())
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                    raise ToolError("Archive links and special files are not accepted.")
                if entry.is_dir():
                    continue
                if not allowed(name):
                    raise ToolError(f"Unsupported archive entry: {name}")
                if entry.flag_bits & 1 or entry.file_size > MAX_FILE:
                    raise ToolError("Encrypted or oversized archive entry.")
                with archive.open(entry) as stream:
                    body = stream.read(MAX_FILE + 1)
                total += len(body)
                if len(body) > MAX_FILE or total > MAX_EXPANDED or len(files) >= MAX_FILES:
                    raise ToolError("Archive expansion exceeds project limits.")
                files[name] = body
    except ToolError:
        raise
    except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError) as exc:
        raise ToolError("Invalid or unsupported ZIP archive.") from exc
    # Normalize a single enclosing folder, not arbitrary nested module roots.
    first = {name.split("/")[0] for name in files}
    if len(first) == 1 and all("/" in name for name in files):
        files = {name.split("/", 1)[1]: body for name, body in files.items()}
    return validate_files(files)


def zip_files(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3  # Stable Unix metadata on Windows and Linux.
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, data)
    return stream.getvalue()


def snapshot_hash(files: dict[str, bytes]) -> str:
    return hashlib.sha256(zip_files(files)).hexdigest()


def directory_files(root: Path) -> dict[str, bytes]:
    files = {}
    total = 0
    for entries, path in enumerate(root.rglob("*"), start=1):
        if entries > 300:
            raise ToolError("Project contains too many directory entries.")
        if path.is_symlink():
            raise ToolError("Project symlinks are not accepted.")
        relative = path.relative_to(root).as_posix()
        if path.is_file():
            safe_name(relative)
            if not allowed(relative):
                raise ToolError(f"Unsupported project file: {relative}")
            if path.stat().st_size > MAX_FILE or len(files) >= MAX_FILES:
                raise ToolError("Project exceeds file size/count limits.")
            files[relative] = path.read_bytes()
            total += len(files[relative])
            if total > MAX_EXPANDED:
                raise ToolError("Project exceeds 25 MB expanded.")
    return validate_files(files)


def materialize(files: dict[str, bytes], root: Path) -> None:
    for name, data in files.items():
        target = root / safe_name(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def project_metadata(files: dict[str, bytes], selected: tuple[str, ...] = ()) -> dict:
    available = sorted(n for n in files if n.endswith(".tfvars") and "/" not in n)
    if any(name not in available for name in selected):
        raise ToolError("Selected variable files must exist at the project root.")
    automatic = (["terraform.tfvars"] if "terraform.tfvars" in available else []) + [
        n for n in available if n.endswith(".auto.tfvars")
    ]
    effective = list(dict.fromkeys([*automatic, *selected]))
    limitations = [
        "Static scanner analysis only; Terraform init/validate/plan/apply were not run.",
        "Variable values and references may remain unresolved; coverage is not proof of deployability.",
    ]
    docs = {}
    remote_modules = []
    for name, data in files.items():
        if name.endswith(".tf") or name in effective:
            try:
                docs[name] = hcl2.loads(data.decode("utf-8-sig"))
            except Exception as exc:
                raise ToolError(f"Terraform parse failure in {name}: {type(exc).__name__}") from exc
    for name, doc in docs.items():
        for module in doc.get("module", []):
            for label, body in module.items():
                sources = body.get("source", [])
                source = sources[0] if len(sources) == 1 else ""
                if not isinstance(source, str) or not source.startswith(("./", "../")):
                    remote_modules.append(f"{name}:{label}")
                    limitations.append(f"External module {label} in {name} was not downloaded.")
                else:
                    from posixpath import normpath

                    target = normpath(str(PurePosixPath(name).parent / source))
                    if target.startswith("../") or target == "..":
                        raise ToolError("Local module source escapes the project.")
                    prefix = "" if target == "." else target + "/"
                    if not any(n.startswith(prefix) and n.endswith(".tf") for n in files):
                        limitations.append(f"Local module {label} in {name} has no bundled source.")
    for name in set(available) - set(effective):
        limitations.append(f"Variable file {name} was not selected.")
    return {
        "variables": effective,
        "limitations": limitations,
        "documents": docs,
        "remote_modules": remote_modules,
    }


def canonical_scanner_path(value: str, root: Path | None) -> str:
    if root is None or not value:
        return ""
    value = value.replace("\\", "/")
    absolute = root.resolve().as_posix().rstrip("/")
    if value.casefold().startswith(absolute.casefold() + "/"):
        value = value[len(absolute) + 1 :]
    elif re.match(r"^[A-Za-z]:", value):
        raise ToolError("Scanner returned a path outside the project.")
    value = value.removeprefix("./").lstrip("/")
    value = safe_name(value)
    if not (root / value).is_file():
        raise ToolError(f"Scanner finding has no matching project file: {value}")
    return value


def effective_variable_source(files: dict[str, bytes], names: list[str]) -> bytes:
    """Keep original assignment syntax while applying last-file-wins precedence.

    Pinned bc-python-hcl2 supplies source spans. Never serialize parsed expressions
    into strings or merge object values: Terraform replaces the whole assignment.
    """
    from hcl2.parser import Hcl2

    assignments = {}
    expected = {}
    for name in names:
        source = files[name].decode("utf-8-sig") + "\n"
        body = Hcl2.lark_parser.parse(source).children[0]
        seen = set()
        for node in body.children:
            if node.data != "attribute":
                raise ToolError(f"Variable file contains a block instead of assignments: {name}")
            key = str(node.children[0].children[0])
            if key in seen:
                raise ToolError(f"Variable assigned more than once in {name}: {key}")
            seen.add(key)
            assignments[key] = source[node.meta.start_pos : node.meta.end_pos].rstrip() + "\n"
        expected.update(hcl2.loads(source))
    merged = "".join(assignments.values())
    if hcl2.loads(merged) != expected:
        raise ToolError("Variable normalization changed parsed assignment values")
    return merged.encode("utf-8")
