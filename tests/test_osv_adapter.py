from __future__ import annotations

from pathlib import Path

import pytest

from src.osv_adapter import map_report
from src.scanner_execution import make_execution_evidence


def complete_execution(exit_code: int = 0) -> dict:
    components = ["scanner_process", "scanner_output", "result_sections", "source_binding", "result_semantics"]
    return make_execution_evidence(
        invocation_started=True,
        process_completed=True,
        exit_code=exit_code,
        exit_state_valid=True,
        output_present=True,
        output_parseable=True,
        required_components=components,
        completed_components=components,
        result_semantics_consistent=True,
        scanner_contract="osv-scanner-v2-lockfile-json-v1",
    )


def raw_report(path: str, vulnerabilities: list[dict] | None = None) -> dict:
    return {
        "results": [
            {
                "source": {"path": path, "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.31.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": vulnerabilities or [],
                    }
                ],
            }
        ]
    }


def test_clean_exit_maps_clean(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    receipt = map_report(
        raw_report(str(artifact)),
        artifact_ref=str(artifact),
        artifact_sha256="a" * 64,
        scanner_version="2.5.1",
        scanner_exit_code=0,
        scanner_execution=complete_execution(0),
        scanned_at="2026-09-01T00:00:00Z",
        evidence_digest=f"sha256:{'b' * 64}",
    )
    assert receipt["scanner"] == "osv-scanner"
    assert receipt["verdict"] == "clean"
    assert receipt["scan_scope"] == ["dependency-vulnerabilities"]
    assert receipt["evidence_digest"] == f"sha256:{'b' * 64}"


def test_valid_clean_report_without_execution_evidence_is_rejected(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="scanner_execution_incomplete"):
        map_report(
            raw_report(str(artifact)),
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=0,
        )


def test_findings_exit_maps_findings(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    receipt = map_report(
        raw_report(str(artifact), [{"id": "GHSA-example-1234"}]),
        artifact_ref=str(artifact),
        artifact_sha256="a" * 64,
        scanner_version="2.5.1",
        scanner_exit_code=1,
        scanner_execution=complete_execution(1),
    )
    assert receipt["verdict"] == "findings"


def test_same_path_unknown_transitive_source_is_admissible_with_primary_lockfile(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    raw = raw_report(str(artifact), [{"id": "GHSA-direct"}])
    raw["results"].append(
        {
            "source": {"path": str(artifact), "type": "unknown"},
            "packages": [
                {
                    "package": {"name": "idna", "version": "3.9.0", "ecosystem": "PyPI"},
                    "vulnerabilities": [{"id": "GHSA-transitive"}],
                }
            ],
        }
    )
    receipt = map_report(
        raw,
        artifact_ref=str(artifact),
        artifact_sha256="a" * 64,
        scanner_version="2.5.1",
        scanner_exit_code=1,
        scanner_execution=complete_execution(1),
    )
    assert receipt["verdict"] == "findings"


@pytest.mark.parametrize(
    ("exit_code", "vulns"),
    [(0, [{"id": "GHSA-example-1234"}]), (1, [])],
)
def test_exit_code_and_json_verdict_must_agree(tmp_path: Path, exit_code: int, vulns: list[dict]) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="osv_exit_verdict_mismatch"):
        map_report(
            raw_report(str(artifact), vulns),
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=exit_code,
        )


def test_report_must_bind_every_source_to_requested_lockfile(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    raw = raw_report(str(artifact))
    raw["results"].append(
        {
            "source": {"path": str(tmp_path / "other.txt"), "type": "unknown"},
            "packages": [
                {
                    "package": {"name": "idna", "version": "3.9.0", "ecosystem": "PyPI"},
                    "vulnerabilities": [],
                }
            ],
        }
    )
    with pytest.raises(ValueError, match="artifact_ref_mismatch"):
        map_report(
            raw,
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=0,
        )


def test_empty_results_cannot_be_clean(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="osv_no_packages_in_report"):
        map_report(
            {"results": []},
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=0,
        )


def test_unknown_only_sources_cannot_establish_primary_lockfile_binding(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    raw = raw_report(str(artifact))
    raw["results"][0]["source"]["type"] = "unknown"
    with pytest.raises(ValueError, match="osv_no_packages_in_report"):
        map_report(
            raw,
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=0,
        )


def test_unrelated_source_type_is_rejected(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    raw = raw_report(str(artifact))
    raw["results"][0]["source"]["type"] = "git"
    with pytest.raises(ValueError, match="unexpected_osv_source_type"):
        map_report(
            raw,
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=0,
        )
