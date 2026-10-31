import copy
import re

import hcl2

from ..models import Finding, ToolError
from .registry import BooleanFix


def parse_terraform(source: str) -> dict:
    if not source.strip():
        raise ToolError("Terraform input is empty.")
    try:
        doc = hcl2.loads(source)
    except Exception as exc:
        raise ToolError(f"Terraform could not be parsed: {exc}") from exc
    if not isinstance(doc, dict) or not doc:
        raise ToolError("Terraform input contains no configuration blocks.")
    return doc


def resource_body(doc: dict, address: str) -> dict:
    resource_type, name = address.split(".", 1)
    matches = [
        entry[resource_type][name]
        for entry in doc.get("resource", [])
        if resource_type in entry and name in entry[resource_type]
    ]
    if len(matches) != 1:
        raise ToolError("The resource could not be uniquely located in this file.")
    return matches[0]


def has_literal(body: dict, spec: BooleanFix) -> bool:
    # bc-python-hcl2 preserves assignments as lists, including literal scalars.
    values = body.get(spec.attribute)
    return (
        isinstance(values, list)
        and len(values) == 1
        and type(values[0]) is bool
        and values[0] == spec.before
    )


def verify_only_intended_change(
    original: str,
    candidate: str,
    finding: Finding,
    spec: BooleanFix,
) -> None:
    expected = copy.deepcopy(parse_terraform(original))
    body = resource_body(expected, finding.resource)
    if not has_literal(body, spec):
        raise ToolError("The target attribute is absent, an expression, or already corrected.")
    body[spec.attribute] = [spec.after]
    if parse_terraform(candidate) != expected:
        raise ToolError("The candidate changed unrelated configuration or resource structure.")


def propose_boolean_fix(source: str, finding: Finding, spec: BooleanFix) -> str:
    doc = parse_terraform(source)
    body = resource_body(doc, finding.resource)
    if not has_literal(body, spec):
        raise ToolError(
            "An explicit literal is required; variables and missing attributes need review."
        )
    lines = source.splitlines(keepends=True)
    start, end = body.get("__start_line__"), body.get("__end_line__")
    if not start or not end or not 0 < start <= end <= len(lines):
        raise ToolError("The scanner did not provide a usable resource source range.")
    segment = "".join(lines[start - 1 : end])
    literal = str(spec.before).lower()
    pattern = re.compile(
        rf"(?m)^([ \t]*{re.escape(spec.attribute)}[ \t]*=[ \t]*)"
        rf"{literal}([ \t]*(?:(?:#|//)[^\r\n]*)?\r?)$"
    )
    matches = list(pattern.finditer(segment))
    if len(matches) != 1:
        raise ToolError("The literal assignment is ambiguous or uses unsupported formatting.")
    updated = pattern.sub(lambda m: m[1] + str(spec.after).lower() + m[2], segment, count=1)
    candidate = "".join(lines[: start - 1]) + updated + "".join(lines[end:])
    verify_only_intended_change(source, candidate, finding, spec)
    return candidate
