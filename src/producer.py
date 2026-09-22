from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapter import inconclusive_receipt, map_report, validate_report
from .artifact_snapshot import ArtifactSnapshot
from .scanner_execution import component_for_error, make_execution_evidence
from .package_archive import ArchiveValidationError, PackageArchiveView, POLICY, determine_scan_coverage, is_npm_archive

PRODUCER_VERSION = "0.1.0"
PINNED_TRIVY_VERSION = "0.74.0"
PINNED_TRIVY_SHA256 = {
    "win32": "4c532e1f28f53282dc364671e87381cd77760fa9cafab143f576449c2207cdd5",
    "linux": "d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791",
}
TRIVY_REQUIRED_COMPONENTS = (
    "scanner_process",
    "scanner_output",
    "result_sections",
    "artifact_binding",
    "result_semantics",
)
TRIVY_SCANNER_CONTRACT = "trivy-fs-json-v1"
TRIVY_PACKAGE_SCANNER_CONTRACT = "trivy-fs-npm-package-view-v1"
TRIVY_ARCHIVE_REQUIRED_COMPONENTS = (
    "artifact_snapshot", "archive_validation", "archive_extraction", "derived_view_binding",
    "scanner_process", "scanner_output", "coverage_determination", "result_semantics",
)
_SNAPSHOT_META: ContextVar[dict[str, Any]] = ContextVar("trivy_snapshot_meta", default={})


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def trivy_version(binary: str) -> str:
    p = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True)
    first = p.stdout.strip().splitlines()[0]
    return first.split(":", 1)[1].strip() if ":" in first else first


def database_metadata() -> dict[str, Any]:
    cache = Path(os.environ.get("TRIVY_CACHE_DIR", Path.home() / ".cache" / "trivy")) / "db"
    metadata: dict[str, Any] = {}
    metadata_path = cache / "metadata.json"
    db_path = cache / "trivy.db"
    if metadata_path.exists():
        try:
            metadata["metadata"] = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            metadata["metadata_read_error"] = True
    if db_path.exists():
        metadata["trivy_db_path"] = str(db_path)
        metadata["trivy_db_sha256"] = sha256(db_path)
        metadata["trivy_db_size"] = db_path.stat().st_size
    return metadata


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
        "artifact": {"ref": str(artifact), "sha256": artifact_hash, "size": _SNAPSHOT_META.get().get("size", 0)},
        "scan_input": {
            "kind": _SNAPSHOT_META.get().get("scan_input_kind", "producer-owned-file-snapshot"),
            "source_ref": str(artifact),
            "sha256": artifact_hash,
            "size": _SNAPSHOT_META.get().get("size", 0),
            "retained": False,
        },
        "scanner": {
            "name": "trivy",
            "version": scanner_version,
            "binary_sha256": binary_hash,
        },
        "scanner_database": database_metadata(),
        "invocation": {
            "argv": argv,
            "started_at": started,
            "completed_at": completed,
            "exit_code": exit_code,
        },
        "scanner_execution": execution,
        "scan_coverage": _SNAPSHOT_META.get().get("scan_coverage"),
        "raw_report": _raw_report_metadata(raw_path),
        "producer": {"name": "mcp-evidence-producer-trivy", "version": PRODUCER_VERSION},
    }
    archive_view = _SNAPSHOT_META.get().get("archive_view")
    if archive_view:
        evidence["scan_input"] = {
            "kind": "producer-owned-package-archive-view",
            "source_ref": str(artifact),
            "source_sha256": artifact_hash,
            "source_size": _SNAPSHOT_META.get().get("size", 0),
            "archive": archive_view["archive"],
            "derived_view": archive_view["derived_view"],
            "extraction": archive_view["extraction"],
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
    if not artifact_hash:
        return 1
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
        required_components=TRIVY_REQUIRED_COMPONENTS,
        failed_components=["scanner_process"],
        result_semantics_consistent=None,
        completeness_reason=reason,
        scanner_contract=TRIVY_SCANNER_CONTRACT,
        fatal_failure=True,
    )


def run(binary: str, artifact: Path, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    raw_path, stderr_path = out / "trivy.raw.json", out / "trivy.stderr.log"
    # A previous valid report must never be reused after a new invocation fails.
    raw_path.unlink(missing_ok=True)
    try:
        snapshot = ArtifactSnapshot.create(artifact)
    except OSError:
        _SNAPSHOT_META.set({})
        execution = _preflight_execution("artifact_snapshot_failed")
        return _finish_inconclusive(out=out, artifact=artifact, artifact_hash="", binary_hash=None,
                                    scanner_version="unavailable", argv=[], started=None,
                                    completed=None, exit_code=None, raw_path=raw_path,
                                    execution=execution)
    _SNAPSHOT_META.set({"size": snapshot.size, "source_ref": snapshot.source_ref,
                        "scan_path": str(snapshot.scan_path), "sha256": snapshot.sha256})
    artifact_hash = snapshot.sha256
    scan_target = snapshot.scan_path
    required_components = TRIVY_REQUIRED_COMPONENTS
    scanner_contract = TRIVY_SCANNER_CONTRACT
    archive_view = None
    if is_npm_archive(artifact):
        try:
            archive_view = PackageArchiveView.create(snapshot.scan_path)
        except ArchiveValidationError as exc:
            execution = make_execution_evidence(
                invocation_started=False, process_completed=False, exit_code=None,
                exit_state_valid=False, output_present=False, output_parseable=False,
                output_exists=False, output_size=None,
                required_components=TRIVY_ARCHIVE_REQUIRED_COMPONENTS,
                failed_components=["archive_validation"], result_semantics_consistent=None,
                completeness_reason=exc.reason, scanner_contract=TRIVY_PACKAGE_SCANNER_CONTRACT,
                fatal_failure=True,
            )
            return _finish_inconclusive(out=out, artifact=artifact, artifact_hash=artifact_hash,
                                        binary_hash=None, scanner_version="unavailable", argv=[],
                                        started=None, completed=None, exit_code=None, raw_path=raw_path,
                                        execution=execution)
        scan_target = archive_view.root
        required_components = TRIVY_ARCHIVE_REQUIRED_COMPONENTS
        scanner_contract = TRIVY_PACKAGE_SCANNER_CONTRACT
        coverage = determine_scan_coverage(archive_view.root)
        _SNAPSHOT_META.set({**_SNAPSHOT_META.get(), "scan_coverage": coverage})
        _SNAPSHOT_META.set({**_SNAPSHOT_META.get(), "scan_input_kind": "producer-owned-package-archive-view",
                            "archive_view": {
                                "archive": {"format": "npm-tgz", "compression": "gzip", "member_count": archive_view.member_count},
                                "derived_view": {"root": str(archive_view.root), "manifest_sha256": archive_view.manifest_sha256,
                                                  "file_count": len(archive_view.manifest_entries),
                                                  "total_regular_file_bytes": archive_view.total_regular_file_bytes},
                                "extraction": {"completed": True, "policy": POLICY},
                            }})
        if coverage["status"] == "indeterminate":
            execution = make_execution_evidence(
                invocation_started=False, process_completed=False, exit_code=None, exit_state_valid=False,
                output_present=False, output_parseable=False, output_exists=False, output_size=None,
                required_components=TRIVY_ARCHIVE_REQUIRED_COMPONENTS, failed_components=["coverage_determination"],
                result_semantics_consistent=None, completeness_reason="coverage_inventory_failed",
                scanner_contract=TRIVY_PACKAGE_SCANNER_CONTRACT, fatal_failure=True)
            return _finish_inconclusive(out=out, artifact=artifact, artifact_hash=artifact_hash, binary_hash=None,
                                        scanner_version="unavailable", argv=[], started=None, completed=None,
                                        exit_code=None, raw_path=raw_path, execution=execution)

    try:
        binary_hash = sha256(Path(binary))
    except OSError:
        binary_hash = None
    expected_binary_hash = PINNED_TRIVY_SHA256.get(sys.platform)
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
        version = trivy_version(binary)
    except (OSError, subprocess.SubprocessError, IndexError):
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
    if version != PINNED_TRIVY_VERSION:
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
    argv = [
        binary,
        "fs",
        "--format",
        "json",
        "--output",
        str(raw_path),
        "--scanners",
        "vuln",
        "--exit-code",
        "0",
        str(scan_target),
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True)
    except Exception as exc:  # subprocess failure must fail closed, including platform-specific errors
        completed = _now()
        stderr_path.write_text(str(exc), encoding="utf-8")
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=False,
            exit_code=None,
            exit_state_valid=False,
            output_present=False,
            output_parseable=False,
            output_exists=raw_path.exists(),
            output_size=raw_path.stat().st_size if raw_path.exists() else None,
            required_components=required_components,
            failed_components=["scanner_process"],
            result_semantics_consistent=None,
            completeness_reason="scanner_process_failed",
            scanner_contract=scanner_contract,
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
    stderr_path.write_text(getattr(proc, "stderr", "") or "", encoding="utf-8")
    exit_code = getattr(proc, "returncode", None)
    exists = raw_path.exists()
    size = raw_path.stat().st_size if exists else None
    output_present = bool(exists and size)
    raw: Any = None
    output_parseable = False
    if output_present:
        try:
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            output_parseable = True
        except (OSError, UnicodeError, json.JSONDecodeError):
            raw = None

    if not isinstance(exit_code, int) or exit_code != 0:
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=exit_code if isinstance(exit_code, int) else None,
            exit_state_valid=False,
            output_present=output_present,
            output_parseable=output_parseable,
            output_exists=exists,
            output_size=size,
            required_components=required_components,
            failed_components=["scanner_process"],
            result_semantics_consistent=None,
            completeness_reason="scanner_exit_state_invalid",
            scanner_contract=scanner_contract,
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

    if not exists:
        reason = "scanner_output_missing"
    elif not output_present:
        reason = "scanner_output_empty"
    elif not output_parseable:
        reason = "scanner_output_unparseable"
    elif not isinstance(raw, dict):
        reason = "scanner_result_not_object"
    else:
        reason = ""

    if reason:
        failed_component = (
            "scanner_output"
            if reason in {"scanner_output_missing", "scanner_output_empty", "scanner_output_unparseable"}
            else "result_semantics"
        )
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=0,
            exit_state_valid=True,
            output_present=output_present,
            output_parseable=output_parseable,
            output_exists=exists,
            output_size=size,
            required_components=required_components,
            failed_components=[failed_component],
            result_semantics_consistent=False if isinstance(raw, dict) else None,
            completeness_reason=reason,
            scanner_contract=scanner_contract,
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
            exit_code=0,
            raw_path=raw_path,
            execution=execution,
        )

    try:
        validate_report(raw, artifact_ref=str(scan_target), scanner_version=version, scanner_exit_code=0)
    except ValueError as exc:
        error = str(exc)
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=0,
            exit_state_valid=True,
            output_present=True,
            output_parseable=True,
            output_exists=True,
            output_size=size,
            required_components=required_components,
            failed_components=[component_for_error(error)],
            result_semantics_consistent=False,
            completeness_reason=error,
            scanner_contract=scanner_contract,
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
            exit_code=0,
            raw_path=raw_path,
            execution=execution,
        )

    execution = make_execution_evidence(
        invocation_started=True,
        process_completed=True,
        exit_code=0,
        exit_state_valid=True,
        output_present=True,
        output_parseable=True,
        output_exists=True,
        output_size=size,
        required_components=required_components,
        completed_components=required_components,
        result_semantics_consistent=True,
        scanner_contract=scanner_contract,
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
        exit_code=0,
        raw_path=raw_path,
        execution=execution,
    )
    try:
        receipt = map_report(
            raw,
            artifact_ref=str(artifact),
            scan_target_ref=str(scan_target),
            artifact_sha256=artifact_hash,
            scanner_version=version,
            scanner_exit_code=0,
            scanner_execution=execution,
            scanned_at=completed,
            evidence_digest=f"sha256:{sha256(evidence_path)}",
        )
    except ValueError as exc:
        error = str(exc)
        execution = make_execution_evidence(
            invocation_started=True,
            process_completed=True,
            exit_code=0,
            exit_state_valid=True,
            output_present=True,
            output_parseable=True,
            output_exists=True,
            output_size=size,
            required_components=required_components,
            failed_components=[component_for_error(error)],
            result_semantics_consistent=False,
            completeness_reason=error,
            scanner_contract=scanner_contract,
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
            exit_code=0,
            raw_path=raw_path,
            execution=execution,
        )

    if scanner_contract == TRIVY_PACKAGE_SCANNER_CONTRACT and not isinstance(raw.get("Results"), list):
        coverage = _SNAPSHOT_META.get().get("scan_coverage") or {}
        if coverage.get("status") == "no_supported_targets":
            execution = make_execution_evidence(
                invocation_started=True, process_completed=True, exit_code=0, exit_state_valid=True,
                output_present=True, output_parseable=True, output_exists=True, output_size=size,
                required_components=required_components, completed_components=required_components,
                result_semantics_consistent=True, completeness_reason="no_supported_dependency_targets",
                scanner_contract=scanner_contract)
            return _finish_inconclusive(out=out, artifact=artifact, artifact_hash=artifact_hash,
                                        binary_hash=binary_hash, scanner_version=version, argv=argv,
                                        started=started, completed=completed, exit_code=0, raw_path=raw_path,
                                        execution=execution)
        execution = make_execution_evidence(
            invocation_started=True, process_completed=True, exit_code=0, exit_state_valid=True,
            output_present=True, output_parseable=True, output_exists=True, output_size=size,
            required_components=required_components, failed_components=["result_semantics"],
            result_semantics_consistent=False, completeness_reason="supported_target_result_missing",
            scanner_contract=scanner_contract)
        return _finish_inconclusive(out=out, artifact=artifact, artifact_hash=artifact_hash,
                                    binary_hash=binary_hash, scanner_version=version, argv=argv,
                                    started=started, completed=completed, exit_code=0, raw_path=raw_path,
                                    execution=execution)

    try:
        if archive_view is not None:
            archive_view.verify_unchanged()
        snapshot.verify_unchanged()
    except (OSError, ValueError):
        execution = make_execution_evidence(
            invocation_started=True, process_completed=True, exit_code=0,
            exit_state_valid=True, output_present=True, output_parseable=True,
            output_exists=True, output_size=raw_path.stat().st_size,
            required_components=required_components,
            completed_components=["scanner_process", "scanner_output", "result_sections"],
            failed_components=["artifact_binding"], result_semantics_consistent=True,
            completeness_reason="artifact_snapshot_changed",
            scanner_contract=scanner_contract, fatal_failure=True,
        )
        return _finish_inconclusive(out=out, artifact=artifact, artifact_hash=artifact_hash,
                                    binary_hash=binary_hash, scanner_version=version,
                                    argv=argv, started=started, completed=completed,
                                    exit_code=0, raw_path=raw_path, execution=execution)
    _write_json(out / "receipt.json", receipt)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--trivy", required=True)
    p.add_argument("--artifact", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    return run(args.trivy, args.artifact, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
