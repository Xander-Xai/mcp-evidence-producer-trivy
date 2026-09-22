from __future__ import annotations

from datetime import datetime, timezone
from collections.abc import Mapping
from typing import Any

from .adapter import PROFILE, SCOPE, validate_vulnerability_severity
from .scanner_execution import execution_is_complete


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _report_binds_exact_ref(raw: dict[str, Any], exact_ref: str, manifest_digest: str) -> bool:
    artifact_name = raw.get("ArtifactName")
    if artifact_name == exact_ref:
        return True
    metadata = raw.get("Metadata")
    if not isinstance(metadata, dict):
        return False
    repo_digests = metadata.get("RepoDigests")
    if not isinstance(repo_digests, list):
        return False
    expected_suffix = "@" + manifest_digest
    return any(isinstance(value, str) and (value == exact_ref or value.endswith(expected_suffix)) for value in repo_digests)


def validate_image_report(
    raw: dict[str, Any],
    *,
    exact_ref: str,
    manifest_digest: str,
    scanner_version: str,
    scanner_exit_code: int | None = None,
) -> int:
    """Validate a parsed Trivy image report and return its finding count."""

    if not isinstance(raw, dict):
        raise ValueError("malformed_trivy_image_report")
    results = raw.get("Results")
    if not isinstance(results, list) or any(not isinstance(item, dict) for item in results):
        raise ValueError("malformed_trivy_image_report")
    if not results:
        # A parseable empty result array does not prove that the requested image
        # manifest was evaluated, so it must remain inconclusive.
        raise ValueError("trivy_result_sections_missing")
    trivy = raw.get("Trivy")
    if not isinstance(trivy, dict) or trivy.get("Version") != scanner_version:
        raise ValueError("trivy_version_mismatch")
    if not _report_binds_exact_ref(raw, exact_ref, manifest_digest):
        raise ValueError("oci_artifact_ref_mismatch")

    findings = 0
    for item in results:
        if not all(isinstance(item.get(key), str) and item.get(key) for key in ("Target", "Class", "Type")):
            raise ValueError("malformed_trivy_image_report")
        vulnerabilities = item.get("Vulnerabilities")
        if vulnerabilities is not None and not isinstance(vulnerabilities, list):
            raise ValueError("malformed_trivy_image_report")
        for vulnerability in vulnerabilities or []:
            validate_vulnerability_severity(vulnerability)
        findings += len(vulnerabilities or [])
    if scanner_exit_code is not None and scanner_exit_code != 0:
        raise ValueError("trivy_exit_code_invalid")
    return findings


def map_image_report(
    raw: dict[str, Any],
    *,
    exact_ref: str,
    manifest_digest: str,
    scanner_version: str,
    scanner_exit_code: int | None = None,
    scanner_execution: Mapping[str, Any] | None = None,
    scanned_at: str | None = None,
    evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Map one Trivy image report only after execution completeness is proven."""

    if scanner_exit_code is None and isinstance(scanner_execution, Mapping):
        candidate = scanner_execution.get("exit_code")
        if isinstance(candidate, int):
            scanner_exit_code = candidate
    findings = validate_image_report(
        raw,
        exact_ref=exact_ref,
        manifest_digest=manifest_digest,
        scanner_version=scanner_version,
        scanner_exit_code=scanner_exit_code,
    )
    if not execution_is_complete(scanner_execution, expected_exit_codes=(0,)):
        raise ValueError("scanner_execution_incomplete")

    receipt: dict[str, Any] = {
        "scanner": "trivy",
        "scanner_version": scanner_version,
        "scanned_artifact_ref": exact_ref,
        "scanned_artifact_digest": manifest_digest,
        "scan_scope": [SCOPE],
        "verdict": "findings" if findings else "clean",
        "scanned_at": scanned_at or _now(),
        "attestation": "publisher-asserted",
        "policy_profile": PROFILE,
    }
    if evidence_digest:
        receipt["evidence_digest"] = evidence_digest
    return receipt


def inconclusive_receipt(
    *,
    exact_ref: str,
    manifest_digest: str,
    scanner_version: str,
    scanned_at: str | None = None,
    evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Return the unchanged v1 receipt shape for an unusable image scan."""

    receipt = {
        "scanner": "trivy",
        "scanner_version": scanner_version,
        "scanned_artifact_ref": exact_ref,
        "scanned_artifact_digest": manifest_digest,
        "scan_scope": [SCOPE],
        "verdict": "inconclusive",
        "inconclusive_reason": "evidence_unavailable",
        "scanned_at": scanned_at or _now(),
        "attestation": "publisher-asserted",
        "policy_profile": PROFILE,
    }
    if evidence_digest:
        receipt["evidence_digest"] = evidence_digest
    return receipt
