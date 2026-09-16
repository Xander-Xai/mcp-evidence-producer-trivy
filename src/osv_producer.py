from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .osv_adapter import inconclusive_receipt, map_report, validate_report
from .scanner_execution import component_for_error, make_execution_evidence

PRODUCER_VERSION = "0.1.0"
PINNED_OSV_VERSION = "2.5.1"
PINNED_OSV_SHA256 = {
    "linux": "f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be",
}
OSV_REQUIRED_COMPONENTS = (
    "scanner_process",
    "scanner_output",
    "result_sections",
    "source_binding",
    "result_semantics",
)
OSV_SCANNER_CONTRACT = "osv-scanner-v2-lockfile-json-v1"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _platform_key() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


def osv_version(binary: str) -> str:
    proc = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True)
    text = "\n".join(part for part in (proc.stdout, proc.stderr) if part).strip()
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)", text)
    if not match:
        raise ValueError("unparseable_osv_version")
    return match.group(1)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _raw_report_metadata(raw_path: Path) -> dict[str, Any]:
    exists = raw_path.exists()
    size: int | None = None
    digest: str | None = None
    if exists:
        try:
            size = raw_path.stat().st_size
            digest = sha256(raw_path)
        except OSError:
            exists = False
    return {
        "path": str(raw_path),
        "present": exists and bool(size),
        "exists": exists,
        "size": size,
        "sha256": digest,
    }


def _write_evidence(
    *,
    out: Path,
    artifact: Path,
    artifact_hash: str,
    binary_hash: str | None,
    scanner_version: str,
    argv: list[str],
    started: str | None,
    completed: str | None,
    exit_code: int | None,
    raw_path: Path,
    execution: dict[str, Any],
) -> Path:
    evidence = {
        "schema_version": "project-defined-evidence-manifest-v1",
        "schema_extensions": ["project-defined-scanner-execution-v1"],
        "artifact": {"ref": str(artifact), "sha256": artifact_hash, "size": artifact.stat().st_size},
        "scanner": {
            "name": "osv-scanner",
            "version": scanner_version,
            "binary_sha256": binary_hash,
        },
        "scanner_database": {
            "source": "https://osv.dev",
            "mode": "remote-query",
            "snapshot": "unavailable",
        },
        "invocation": {
            "argv": argv,
            "started_at": started,
            "completed_at": completed,
            "exit_code": exit_code,
        },
        "scanner_execution": execution,
        "raw_report": _raw_report_metadata(raw_path),
        "producer": {
            "name": "mcp-evidence-producer-osv",
            "version": PRODUCER_VERSION,
            "repository": "yandexuanxuan/mcp-evidence-producer-trivy",
        },
    }
    evidence_path = out / "evidence.json"
    _write_json(evidence_path, evidence)
    return evidence_path


def _finish_inconclusive(
    *,
    out: Path,
    artifact: Path,
    artifact_hash: str,
    binary_hash: str | None,
    scanner_version: str,
    argv: list[str],
    started: str | None,
    completed: str | None,
    exit_code: int | None,
    raw_path: Path,
    execution: dict[str, Any],
) -> int:
    evidence_path = _write_evidence(
        out=out,
        artifact=artifact,
        artifact_hash=artifact_hash,
        binary_hash=binary_hash,
        scanner_version=scanner_version,
        argv=argv,
        started=started,
        completed=completed,
        exit_code=exit_code,
        raw_path=raw_path,
        execution=execution,
    )
    receipt = inconclusive_receipt(
        artifact_ref=str(artifact),
        artifact_sha256=artifact_hash,
        scanner_version=scanner_version,
        scanned_at=completed,
        evidence_digest=f"sha256:{sha256(evidence_path)}",
    )
    _write_json(out / "receipt.json", receipt)
    return 1


def _preflight_execution(reason: str) -> dict[str, Any]:
    return make_execution_evidence(
        invocation_started=False,
        process_completed=False,
        exit_code=None,
        exit_state_valid=False,
        output_present=False,
        output_parseable=False,
        output_exists=False,
        output_size=None,
        required_components=OSV_REQUIRED_COMPONENTS,
        failed_components=["scanner_process"],
        result_semantics_consistent=None,
        completeness_reason=reason,
        scanner_contract=OSV_SCANNER_CONTRACT,
        fatal_failure=True,
    )


def run(binary: str, artifact: Path, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    raw_path = out / "osv.raw.json"
    stderr_path = out / "osv.stderr.log"
    raw_path.unlink(missing_ok=True)
    artifact_hash = sha256(artifact)

    try:
        binary_hash = sha256(Path(binary))
    except OSError:
        binary_hash = None
    expected_binary_hash = PINNED_OSV_SHA256.get(_platform_key())
    if expected_binary_hash is None or binary_hash != expected_binary_hash:
        execution = _preflight_execution("scanner_binary_not_verified")
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version="unverified",
            argv=[],
            started=None,
            completed=None,
            exit_code=None,
            raw_path=raw_path,
            execution=execution,
        )

    try:
        version = osv_version(binary)
    except (OSError, subprocess.SubprocessError, ValueError):
        execution = _preflight_execution("scanner_version_unavailable")
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version="unavailable",
            argv=[],
            started=None,
            completed=None,
            exit_code=None,
            raw_path=raw_path,
            execution=execution,
        )
    if version != PINNED_OSV_VERSION:
        execution = _preflight_execution("scanner_version_mismatch")
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version=version,
            argv=[],
            started=None,
            completed=None,
            exit_code=None,
            raw_path=raw_path,
            execution=execution,
        )

    started = _now()
    argv = [binary, "scan", "--format", "json", "-L", str(artifact)]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True)
    except Exception as exc:  # fail closed for platform-specific subprocess failures
        completed = _now()
        raw_path.write_text("", encoding="utf-8")
        stderr_path.write_text(str(exc), encoding="utf-8")
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=False,
            exit_code=None,
            exit_state_valid=False,
            output_present=False,
            output_parseable=False,
            output_exists=True,
            output_size=0,
            required_components=OSV_REQUIRED_COMPONENTS,
            failed_components=["scanner_process"],
            result_semantics_consistent=None,
            completeness_reason="scanner_process_failed",
            scanner_contract=OSV_SCANNER_CONTRACT,
            fatal_failure=True,
        )
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version=version,
            argv=argv,
            started=started,
            completed=completed,
            exit_code=None,
            raw_path=raw_path,
            execution=execution,
        )

    completed = _now()
    stdout_value = getattr(proc, "stdout", "") or ""
    stdout = stdout_value.decode("utf-8", errors="replace") if isinstance(stdout_value, bytes) else str(stdout_value)
    stderr_value = getattr(proc, "stderr", "") or ""
    stderr = stderr_value.decode("utf-8", errors="replace") if isinstance(stderr_value, bytes) else str(stderr_value)
    stderr_path.write_text(stderr, encoding="utf-8")
    raw_path.write_text(stdout, encoding="utf-8")
    exit_code = getattr(proc, "returncode", None)
    exists = raw_path.exists()
    size = raw_path.stat().st_size if exists else None
    output_present = bool(exists and size)
    raw: Any = None
    output_parseable = False
    if output_present:
        try:
            raw = json.loads(stdout)
            output_parseable = True
        except (UnicodeError, json.JSONDecodeError):
            raw = None

    if not isinstance(exit_code, int) or exit_code not in (0, 1):
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=exit_code if isinstance(exit_code, int) else None,
            exit_state_valid=False,
            output_present=output_present,
            output_parseable=output_parseable,
            output_exists=exists,
            output_size=size,
            required_components=OSV_REQUIRED_COMPONENTS,
            failed_components=["scanner_process"],
            result_semantics_consistent=None,
            completeness_reason="scanner_exit_state_invalid",
            scanner_contract=OSV_SCANNER_CONTRACT,
            fatal_failure=True,
        )
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version=version,
            argv=argv,
            started=started,
            completed=completed,
            exit_code=exit_code if isinstance(exit_code, int) else None,
            raw_path=raw_path,
            execution=execution,
        )

    if not output_present:
        reason = "scanner_output_empty" if exists else "scanner_output_missing"
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=exit_code,
            exit_state_valid=True,
            output_present=False,
            output_parseable=False,
            output_exists=exists,
            output_size=size,
            required_components=OSV_REQUIRED_COMPONENTS,
            failed_components=["scanner_output"],
            result_semantics_consistent=None,
            completeness_reason=reason,
            scanner_contract=OSV_SCANNER_CONTRACT,
        )
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version=version,
            argv=argv,
            started=started,
            completed=completed,
            exit_code=exit_code,
            raw_path=raw_path,
            execution=execution,
        )

    if not output_parseable:
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=exit_code,
            exit_state_valid=True,
            output_present=True,
            output_parseable=False,
            output_exists=True,
            output_size=size,
            required_components=OSV_REQUIRED_COMPONENTS,
            failed_components=["scanner_output"],
            result_semantics_consistent=None,
            completeness_reason="scanner_output_unparseable",
            scanner_contract=OSV_SCANNER_CONTRACT,
        )
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version=version,
            argv=argv,
            started=started,
            completed=completed,
            exit_code=exit_code,
            raw_path=raw_path,
            execution=execution,
        )

    if not isinstance(raw, dict):
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=exit_code,
            exit_state_valid=True,
            output_present=True,
            output_parseable=True,
            output_exists=True,
            output_size=size,
            required_components=OSV_REQUIRED_COMPONENTS,
            failed_components=["result_sections"],
            result_semantics_consistent=False,
            completeness_reason="scanner_result_not_object",
            scanner_contract=OSV_SCANNER_CONTRACT,
        )
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version=version,
            argv=argv,
            started=started,
            completed=completed,
            exit_code=exit_code,
            raw_path=raw_path,
            execution=execution,
        )

    try:
        validate_report(
            raw,
            artifact_ref=str(artifact),
            scanner_version=version,
            scanner_exit_code=exit_code,
        )
    except ValueError as exc:
        error = str(exc)
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=exit_code,
            exit_state_valid=True,
            output_present=True,
            output_parseable=True,
            output_exists=True,
            output_size=size,
            required_components=OSV_REQUIRED_COMPONENTS,
            failed_components=[component_for_error(error)],
            result_semantics_consistent=False,
            completeness_reason=error,
            scanner_contract=OSV_SCANNER_CONTRACT,
        )
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version=version,
            argv=argv,
            started=started,
            completed=completed,
            exit_code=exit_code,
            raw_path=raw_path,
            execution=execution,
        )

    execution = make_execution_evidence(
        invocation_started=True,
        process_completed=True,
        exit_code=exit_code,
        exit_state_valid=True,
        output_present=True,
        output_parseable=True,
        output_exists=True,
        output_size=size,
        required_components=OSV_REQUIRED_COMPONENTS,
        completed_components=OSV_REQUIRED_COMPONENTS,
        result_semantics_consistent=True,
        scanner_contract=OSV_SCANNER_CONTRACT,
    )
    evidence_path = _write_evidence(
        out=out,
        artifact=artifact,
        artifact_hash=artifact_hash,
        binary_hash=binary_hash,
        scanner_version=version,
        argv=argv,
        started=started,
        completed=completed,
        exit_code=exit_code,
        raw_path=raw_path,
        execution=execution,
    )
    try:
        receipt = map_report(
            raw,
            artifact_ref=str(artifact),
            artifact_sha256=artifact_hash,
            scanner_version=version,
            scanner_exit_code=exit_code,
            scanner_execution=execution,
            scanned_at=completed,
            evidence_digest=f"sha256:{sha256(evidence_path)}",
        )
    except ValueError as exc:
        error = str(exc)
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=exit_code,
            exit_state_valid=True,
            output_present=True,
            output_parseable=True,
            output_exists=True,
            output_size=size,
            required_components=OSV_REQUIRED_COMPONENTS,
            failed_components=[component_for_error(error)],
            result_semantics_consistent=False,
            completeness_reason=error,
            scanner_contract=OSV_SCANNER_CONTRACT,
        )
        return _finish_inconclusive(
            out=out,
            artifact=artifact,
            artifact_hash=artifact_hash,
            binary_hash=binary_hash,
            scanner_version=version,
            argv=argv,
            started=started,
            completed=completed,
            exit_code=exit_code,
            raw_path=raw_path,
            execution=execution,
        )

    _write_json(out / "receipt.json", receipt)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--osv", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return run(args.osv, args.artifact, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
