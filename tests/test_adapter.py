import json
from pathlib import Path

import pytest

from src.adapter import map_report
from src.scanner_execution import make_execution_evidence


def complete_execution() -> dict:
    components = ["scanner_process", "scanner_output", "result_sections", "artifact_binding", "result_semantics"]
    return make_execution_evidence(
        invocation_started=True,
        process_completed=True,
        exit_code=0,
        exit_state_valid=True,
        output_present=True,
        output_parseable=True,
        output_exists=True,
        output_size=1,
        required_components=components,
        completed_components=components,
        result_semantics_consistent=True,
        scanner_contract="trivy-fs-json-v1",
    )


def test_clean_and_findings_are_deterministic():
    base = {"Trivy": {"Version": "0.74.0"}, "ArtifactName": str((Path(__file__).parents[1] / "artifacts/requirements.txt").resolve()), "Results": [{"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "python"}]}
    clean = map_report(base, artifact_ref="artifacts/requirements.txt", artifact_sha256="a" * 64, scanner_version="0.74.0", scanner_execution=complete_execution(), scanned_at="2026-08-31T00:00:00Z")
    assert clean["verdict"] == "clean"
    raw = {"Trivy": {"Version": "0.74.0"}, "ArtifactName": "a", "Results": [{"Target": "a", "Class": "lang-pkgs", "Type": "python", "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST"}]}]}
    found = map_report(raw, artifact_ref="a", artifact_sha256="b" * 64, scanner_version="0.74.0", scanner_execution=complete_execution(), scanned_at="2026-08-31T00:00:00Z")
    assert found["verdict"] == "findings"


def test_malformed_report_is_rejected():
    try:
        map_report({}, artifact_ref="a", artifact_sha256="a" * 64, scanner_version="0.74.0")
    except ValueError as exc:
        assert str(exc) == "malformed_trivy_report"
    else:
        raise AssertionError("malformed report must not become clean")


def test_empty_results_are_rejected_as_inconclusive():
    raw = {
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": "artifact.txt",
        "Results": [],
    }
    with pytest.raises(ValueError, match="trivy_result_sections_missing"):
        map_report(
            raw,
            artifact_ref="artifact.txt",
            artifact_sha256="a" * 64,
            scanner_version="0.74.0",
            scanner_exit_code=0,
            scanner_execution=complete_execution(),
        )
