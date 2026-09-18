from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from .scanner_execution import execution_is_complete

SCOPE = "dependency-vulnerabilities"
PROFILE = "registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22"
ALLOWED_LOCKFILE_RESULT_SOURCE_TYPES = {"lockfile", "unknown"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_report(
    raw: dict[str, Any],
    *,
    artifact_ref: str,
    scanner_version: str,
    scanner_exit_code: int,
) -> int:
    """Validate an OSV-Scanner v2 result and return its finding count."""

    if not isinstance(raw, dict):
        raise ValueError("malformed_osv_report")
    results = raw.get("results")
    if not isinstance(results, list):
        raise ValueError("malformed_osv_report")

    expected_artifact = Path(artifact_ref).resolve()
    saw_primary_lockfile_source = False
    package_count = 0
    finding_count = 0

    for result in results:
        if not isinstance(result, dict):
            raise ValueError("malformed_osv_report")

        source = result.get("source")
        if not isinstance(source, dict):
            raise ValueError("malformed_osv_report")
        source_path = source.get("path")
        source_type = source.get("type")
        if not isinstance(source_path, str) or not source_path:
            raise ValueError("malformed_osv_report")
        if Path(source_path).resolve() != expected_artifact:
            raise ValueError("artifact_ref_mismatch")
        if source_type not in ALLOWED_LOCKFILE_RESULT_SOURCE_TYPES:
            raise ValueError("unexpected_osv_source_type")
        if source_type == "lockfile":
            saw_primary_lockfile_source = True

        packages = result.get("packages")
        if not isinstance(packages, list):
            raise ValueError("malformed_osv_report")
        for entry in packages:
            if not isinstance(entry, dict):
                raise ValueError("malformed_osv_report")
            package = entry.get("package")
            if not isinstance(package, dict):
                raise ValueError("malformed_osv_report")
            if not all(isinstance(package.get(key), str) and package.get(key) for key in ("name", "version", "ecosystem")):
                raise ValueError("malformed_osv_report")
            package_count += 1

            vulnerabilities = entry.get("vulnerabilities", [])
            if vulnerabilities is None:
                vulnerabilities = []
            if not isinstance(vulnerabilities, list):
                raise ValueError("malformed_osv_report")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise ValueError("malformed_osv_report")
                if not isinstance(vulnerability.get("id"), str) or not vulnerability["id"]:
                    raise ValueError("malformed_osv_report")
                finding_count += 1

    if not saw_primary_lockfile_source or package_count == 0:
        # OSV-Scanner reserves exit 128 for no packages. A 0/1 report that does
        # not contain at least one primary lockfile source and parsed package is
        # not admissible as evidence of a clean/findings verdict. OSV v2.5.1 may
        # additionally emit same-path `unknown` records for resolved packages.
        raise ValueError("osv_no_packages_in_report")

    if scanner_exit_code not in (0, 1):
        raise ValueError("unexpected_osv_exit_code")
    if scanner_exit_code == 0 and finding_count != 0:
        raise ValueError("osv_exit_verdict_mismatch")
    if scanner_exit_code == 1 and finding_count == 0:
        raise ValueError("osv_exit_verdict_mismatch")
    return finding_count


def map_report(
    raw: dict[str, Any],
    *,
    artifact_ref: str,
    scan_target_ref: str | None = None,
    artifact_sha256: str,
    scanner_version: str,
    scanner_exit_code: int | None = None,
    scanner_execution: Mapping[str, Any] | None = None,
    scanned_at: str | None = None,
    evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Map one OSV result only after execution completeness is proven."""

    if scanner_exit_code is None and isinstance(scanner_execution, Mapping):
        candidate = scanner_execution.get("exit_code")
        if isinstance(candidate, int):
            scanner_exit_code = candidate
    if not isinstance(scanner_exit_code, int):
        raise ValueError("unexpected_osv_exit_code")
    finding_count = validate_report(
        raw,
        artifact_ref=scan_target_ref or artifact_ref,
        scanner_version=scanner_version,
        scanner_exit_code=scanner_exit_code,
    )
    if not execution_is_complete(scanner_execution, expected_exit_codes=(0, 1)):
        raise ValueError("scanner_execution_incomplete")

    receipt: dict[str, Any] = {
        "scanner": "osv-scanner",
        "scanner_version": scanner_version,
        "scanned_artifact_ref": artifact_ref,
        "scanned_artifact_digest": f"sha256:{artifact_sha256}",
        "scan_scope": [SCOPE],
        "verdict": "findings" if finding_count else "clean",
        "scanned_at": scanned_at or _now(),
        "attestation": "publisher-asserted",
        "policy_profile": PROFILE,
    }
    if evidence_digest:
        receipt["evidence_digest"] = evidence_digest
    return receipt


def inconclusive_receipt(
    *,
    artifact_ref: str,
    artifact_sha256: str,
    scanner_version: str,
    reason: str = "evidence_unavailable",
    scanned_at: str | None = None,
    evidence_digest: str | None = None,
) -> dict[str, Any]:
    receipt = {
        "scanner": "osv-scanner",
        "scanner_version": scanner_version,
        "scanned_artifact_ref": artifact_ref,
        "scanned_artifact_digest": f"sha256:{artifact_sha256}",
        "scan_scope": [SCOPE],
        "verdict": "inconclusive",
        "inconclusive_reason": reason,
        "scanned_at": scanned_at or _now(),
        "attestation": "publisher-asserted",
        "policy_profile": PROFILE,
    }
    if evidence_digest:
        receipt["evidence_digest"] = evidence_digest
    return receipt
