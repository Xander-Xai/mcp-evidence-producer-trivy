"""Fail-closed validation for external GitHub Action references."""

from __future__ import annotations

import re
import sys
from pathlib import Path


_USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<value>.+?)\s*$")
_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


def _target_from_value(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if value[0] in {"'", '"'}:
        quote = value[0]
        end = value.find(quote, 1)
        if end < 0 or value[end + 1 :].strip().startswith("#") is False and value[end + 1 :].strip():
            return None
        return value[1:end]
    return value.split("#", 1)[0].strip() or None


def action_targets(text: str) -> list[tuple[int, str | None]]:
    """Return active YAML ``uses`` targets as (line number, target)."""
    targets: list[tuple[int, str | None]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        match = _USES_LINE.match(line)
        if match:
            targets.append((line_number, _target_from_value(match.group("value"))))
    return targets


def violations(text: str, source: str = "<text>") -> list[str]:
    errors: list[str] = []
    for line_number, target in action_targets(text):
        if target is None:
            errors.append(f"{source}:{line_number}: malformed uses target")
            continue
        if target.startswith("./") or target.startswith("../"):
            continue
        if "${{" in target or "@" not in target:
            errors.append(f"{source}:{line_number}: external uses must pin a full commit SHA: {target!r}")
            continue
        ref = target.rsplit("@", 1)[1]
        if not _FULL_SHA.fullmatch(ref):
            errors.append(f"{source}:{line_number}: external uses must pin a full commit SHA: {target!r}")
    return errors


def workflow_files(root: Path) -> list[Path]:
    workflow_root = root / ".github" / "workflows"
    return sorted([*workflow_root.rglob("*.yml"), *workflow_root.rglob("*.yaml")])


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = [error for path in workflow_files(root) for error in violations(path.read_text(encoding="utf-8"), str(path))]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("all external Action references use full 40-character commit SHAs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
