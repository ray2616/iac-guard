from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path


class ToolError(RuntimeError):
    """The tool did not establish a valid result."""


def file_kind(path: Path) -> str:
    if path.suffix.lower() == ".tf":
        return "terraform"
    name = path.name.lower()
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return "dockerfile"
    raise ToolError("Choose a .tf file or a Dockerfile.")


@dataclass(frozen=True)
class Finding:
    scanner: str
    rule_id: str
    resource: str
    message: str
    severity: str = "UNKNOWN"
    line: int | None = None
    end_line: int | None = None
    guideline: str = ""
    file: str = ""

    @property
    def identity(self) -> tuple[str, str, str, str]:
        # Path-independent Terraform resource addresses; scanners remain separate.
        return self.scanner, self.rule_id, self.resource, self.file


@dataclass
class ScanReport:
    scanner: str
    version: str
    findings: list[Finding]
    checks_passed: int = 0
    limitations: list[str] = field(default_factory=list)
    policy_version: str = "not reported by scanner CLI"

    def counts(self) -> Counter:
        return Counter(f.identity for f in self.findings)


@dataclass
class Attempt:
    handler: str
    resource: str
    status: str
    reason: str
    impact: str


@dataclass
class FixReport:
    source: str
    code: str
    diff: str
    before: list[ScanReport]
    after: list[ScanReport]
    attempts: list[Attempt] = field(default_factory=list)
    limitations: list[str] = field(
        default_factory=lambda: [
            "Single-file analysis; Terraform modules and references are not resolved.",
            "Parse and scanner checks only; terraform validate/plan/apply were not run.",
            "Review deployment and connectivity implications before using any patch.",
        ]
    )

    def as_dict(self) -> dict:
        return asdict(self)
