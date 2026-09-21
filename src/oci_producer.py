from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .oci_adapter import inconclusive_receipt, map_image_report, validate_image_report
from .oci_identity import OciIdentityError, RegistryClient, parse_reference, resolve_oci_identity
from .producer import (
    PINNED_TRIVY_SHA256,
    PINNED_TRIVY_VERSION,
    PRODUCER_VERSION,
    database_metadata,
    sha256,
    trivy_version,
)
from .scanner_execution import component_for_error, make_execution_evidence

OCI_REQUIRED_COMPONENTS = (
    "scanner_process",
    "scanner_output",
    "result_sections",
    "artifact_binding",
    "result_semantics",
)
OCI_SCANNER_CONTRACT = "trivy-oci-image-json-v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _fail(out: Path, code: str, detail: str) -> int:
    out.mkdir(parents=True, exist_ok=True)
    _write_json(out / "oci-error.json", {"error": code, "detail": detail})
    return 1


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
    image: str,
    exact_ref: str,
    manifest_digest: str,
    manifest_path: Path,
    identity_path: Path,
    index_path: Path,
    root_digest: str,
    platform: Any,
    artifact_size: int,
    binary_hash: str | None,
    scanner_version: str,
    argv: list[str],
    started: str | None,
    completed: str | None,
    exit_code: int | None,
    raw_path: Path,
    execution: dict[str, Any],
) -> Path:
    artifact: dict[str, Any] = {
        "kind": "oci-image-manifest",
        "requested_ref": image,
        "exact_ref": exact_ref,
        "sha256": manifest_digest.removeprefix("sha256:"),
        "manifest_path": str(manifest_path),
        "manifest_size": artifact_size,
        "identity_path": str(identity_path),
        "identity_sha256": sha256(identity_path),
        "root_digest": root_digest,
        "platform": platform,
    }
    if index_path.exists():
        artifact["index_path"] = str(index_path)
        artifact["index_sha256"] = sha256(index_path)
    evidence: dict[str, Any] = {
        "schema_version": "project-defined-evidence-manifest-v1",
        "schema_extensions": ["project-defined-scanner-execution-v1"],
        "artifact": artifact,
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
            "target_exact_ref": exact_ref,
        },
        "scanner_execution": execution,
        "raw_report": _raw_report_metadata(raw_path),
        "producer": {
            "name": "mcp-evidence-producer-trivy",
            "version": PRODUCER_VERSION,
            "mode": "oci-image",
        },
    }
    evidence_path = out / "evidence.json"
    _write_json(evidence_path, evidence)
    return evidence_path


def _finish_inconclusive(
    *,
    out: Path,
    image: str,
    exact_ref: str,
    manifest_digest: str,
    manifest_path: Path,
    identity_path: Path,
    index_path: Path,
    root_digest: str,
    platform: Any,
    artifact_size: int,
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
        image=image,
        exact_ref=exact_ref,
        manifest_digest=manifest_digest,
        manifest_path=manifest_path,
        identity_path=identity_path,
        index_path=index_path,
        root_digest=root_digest,
        platform=platform,
        artifact_size=artifact_size,
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
        exact_ref=exact_ref,
        manifest_digest=manifest_digest,
        scanner_version=scanner_version,
        scanned_at=completed,
        evidence_digest="sha256:" + sha256(evidence_path),
    )
    _write_json(out / "receipt.json", receipt)
    return 1


def run(
    binary: str,
    image: str,
    out: Path,
    *,
    os_name: str,
    architecture: str,
    variant: str | None = None,
) -> int:
    out.mkdir(parents=True, exist_ok=True)
    # A reused output directory must never expose artifacts from a prior run.
    for stale_name in (
        "receipt.json",
        "evidence.json",
        "oci-error.json",
        "oci-identity.json",
        "oci.index.json",
        "oci.manifest.json",
        "trivy.raw.json",
        "trivy.stderr.log",
    ):
        (out / stale_name).unlink(missing_ok=True)

    try:
        requested = parse_reference(image)
    except OciIdentityError as exc:
        return _fail(out, "oci_reference_invalid", str(exc))
    if requested.reference_kind != "digest":
        return _fail(out, "mutable_oci_reference_rejected", "real OCI producer requires an @sha256 digest reference")

    expected_binary_hash = PINNED_TRIVY_SHA256.get(sys.platform)
    try:
        binary_hash = sha256(Path(binary))
    except OSError as exc:
        return _fail(out, "trivy_binary_unavailable", str(exc))
    if expected_binary_hash is None or binary_hash != expected_binary_hash:
        return _fail(out, "trivy_binary_digest_mismatch", binary_hash)
    try:
        version = trivy_version(binary)
    except (OSError, subprocess.SubprocessError, IndexError) as exc:
        return _fail(out, "trivy_version_unavailable", str(exc))
    if version != PINNED_TRIVY_VERSION:
        return _fail(out, "trivy_version_mismatch", version)

    client = RegistryClient()
    try:
        resolved = resolve_oci_identity(
            image,
            os_name=os_name,
            architecture=architecture,
            variant=variant,
            fetch_manifest=client.fetch_manifest,
        )
    except OciIdentityError as exc:
        return _fail(out, "oci_identity_resolution_failed", str(exc))

    identity_path = out / "oci-identity.json"
    manifest_path = out / "oci.manifest.json"
    index_path = out / "oci.index.json"
    raw_path = out / "trivy.raw.json"
    stderr_path = out / "trivy.stderr.log"
    _write_json(identity_path, resolved.record)
    manifest_path.write_bytes(resolved.manifest_body)
    index_path.unlink(missing_ok=True)
    if resolved.root_body != resolved.manifest_body:
        index_path.write_bytes(resolved.root_body)

    selected = resolved.record["selected"]
    if not isinstance(selected, dict):
        return _fail(out, "oci_identity_internal_error", "selected identity is not an object")
    exact_ref = selected.get("exact_ref")
    manifest_digest = selected.get("manifest_digest")
    if not isinstance(exact_ref, str) or not isinstance(manifest_digest, str):
        return _fail(out, "oci_identity_internal_error", "selected identity fields missing")
    if "sha256:" + sha256(manifest_path) != manifest_digest:
        return _fail(out, "oci_manifest_persistence_mismatch", manifest_digest)

    # Never let a previous report satisfy a new scan after a crash.
    raw_path.unlink(missing_ok=True)
    started = utc_now()
    argv = [
        binary,
        "image",
        "--format",
        "json",
        "--output",
        str(raw_path),
        "--scanners",
        "vuln",
        "--exit-code",
        "0",
        exact_ref,
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True)
    except Exception as exc:  # fail closed for platform-specific subprocess failures
        completed = utc_now()
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
            required_components=OCI_REQUIRED_COMPONENTS,
            failed_components=["scanner_process"],
            result_semantics_consistent=None,
            completeness_reason="scanner_process_failed",
            scanner_contract=OCI_SCANNER_CONTRACT,
            fatal_failure=True,
        )
        return _finish_inconclusive(
            out=out,
            image=image,
            exact_ref=exact_ref,
            manifest_digest=manifest_digest,
            manifest_path=manifest_path,
            identity_path=identity_path,
            index_path=index_path,
            root_digest=resolved.record["root"]["digest"],
            platform=selected["platform"],
            artifact_size=manifest_path.stat().st_size,
            binary_hash=binary_hash,
            scanner_version=version,
            argv=argv,
            started=started,
            completed=completed,
            exit_code=None,
            raw_path=raw_path,
            execution=execution,
        )

    completed = utc_now()
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

    common = {
        "out": out,
        "image": image,
        "exact_ref": exact_ref,
        "manifest_digest": manifest_digest,
        "manifest_path": manifest_path,
        "identity_path": identity_path,
        "index_path": index_path,
        "root_digest": resolved.record["root"]["digest"],
        "platform": selected["platform"],
        "artifact_size": manifest_path.stat().st_size,
        "binary_hash": binary_hash,
        "scanner_version": version,
        "argv": argv,
        "started": started,
        "completed": completed,
        "raw_path": raw_path,
    }

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
            required_components=OCI_REQUIRED_COMPONENTS,
            failed_components=["scanner_process"],
            result_semantics_consistent=None,
            completeness_reason="scanner_exit_state_invalid",
            scanner_contract=OCI_SCANNER_CONTRACT,
            fatal_failure=True,
        )
        return _finish_inconclusive(**common, exit_code=exit_code if isinstance(exit_code, int) else None, execution=execution)

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
            else "result_sections"
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
            required_components=OCI_REQUIRED_COMPONENTS,
            failed_components=[failed_component],
            result_semantics_consistent=False if isinstance(raw, dict) else None,
            completeness_reason=reason,
            scanner_contract=OCI_SCANNER_CONTRACT,
        )
        return _finish_inconclusive(**common, exit_code=0, execution=execution)

    try:
        validate_image_report(
            raw,
            exact_ref=exact_ref,
            manifest_digest=manifest_digest,
            scanner_version=version,
            scanner_exit_code=0,
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
            required_components=OCI_REQUIRED_COMPONENTS,
            failed_components=[component_for_error(error)],
            result_semantics_consistent=False,
            completeness_reason=error,
            scanner_contract=OCI_SCANNER_CONTRACT,
        )
        return _finish_inconclusive(**common, exit_code=0, execution=execution)

    execution = make_execution_evidence(
        invocation_started=True,
        process_completed=True,
        exit_code=0,
        exit_state_valid=True,
        output_present=True,
        output_parseable=True,
        output_exists=True,
        output_size=size,
        required_components=OCI_REQUIRED_COMPONENTS,
        completed_components=OCI_REQUIRED_COMPONENTS,
        result_semantics_consistent=True,
        scanner_contract=OCI_SCANNER_CONTRACT,
    )
    evidence_path = _write_evidence(**common, exit_code=0, execution=execution)
    try:
        receipt = map_image_report(
            raw,
            exact_ref=exact_ref,
            manifest_digest=manifest_digest,
            scanner_version=version,
            scanner_exit_code=0,
            scanner_execution=execution,
            scanned_at=completed,
            evidence_digest="sha256:" + sha256(evidence_path),
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
            required_components=OCI_REQUIRED_COMPONENTS,
            failed_components=[component_for_error(error)],
            result_semantics_consistent=False,
            completeness_reason=error,
            scanner_contract=OCI_SCANNER_CONTRACT,
        )
        return _finish_inconclusive(**common, exit_code=0, execution=execution)

    _write_json(out / "receipt.json", receipt)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--platform-os", required=True)
    parser.add_argument("--platform-arch", required=True)
    parser.add_argument("--platform-variant")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return run(
        args.trivy,
        args.image,
        args.out,
        os_name=args.platform_os,
        architecture=args.platform_arch,
        variant=args.platform_variant,
    )


if __name__ == "__main__":
    raise SystemExit(main())
