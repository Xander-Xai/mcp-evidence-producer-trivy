from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import producer
from src.adapter import map_report


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _setup_verified_trivy(monkeypatch, tmp_path: Path) -> tuple[Path, Path]:
    binary = tmp_path / "trivy"
    binary.write_bytes(b"pinned-trivy-binary")
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    monkeypatch.setitem(producer.PINNED_TRIVY_SHA256, sys.platform, _sha(binary))
    monkeypatch.setattr(producer, "trivy_version", lambda _: "0.74.0")
    return binary, artifact


def _report(artifact: Path, *, findings: int = 0, include_results: bool = True) -> dict:
    report = {
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": str(artifact.resolve()),
    }
    if include_results:
        report["Results"] = [
            {
                "Target": "artifact.txt",
                "Class": "lang-pkgs",
                "Type": "python",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST"} for _ in range(findings)],
            }
        ]
    return report


def _stub_scan(monkeypatch, artifact: Path, *, mode: str, exit_code: int = 0) -> None:
    def fake_run(argv, **_kwargs):
        output_path = Path(argv[argv.index("--output") + 1])
        if mode == "crash":
            raise RuntimeError("fake scanner crashed")
        if mode == "missing":
            pass
        elif mode == "empty":
            output_path.write_text("", encoding="utf-8")
        elif mode == "malformed":
            output_path.write_text('{"Results":', encoding="utf-8")
        elif mode == "missing-section":
            output_path.write_text(json.dumps(_report(artifact, include_results=False)), encoding="utf-8")
        elif mode == "clean":
            output_path.write_text(json.dumps(_report(artifact)), encoding="utf-8")
        elif mode == "findings":
            output_path.write_text(json.dumps(_report(artifact, findings=1)), encoding="utf-8")
        else:  # pragma: no cover - keeps fixture failures explicit
            raise AssertionError(mode)
        return SimpleNamespace(returncode=exit_code, stdout="", stderr="")

    monkeypatch.setattr(producer.subprocess, "run", fake_run)


def _run_case(monkeypatch, tmp_path: Path, *, mode: str, exit_code: int = 0) -> tuple[int, dict, dict]:
    binary, artifact = _setup_verified_trivy(monkeypatch, tmp_path)
    _stub_scan(monkeypatch, artifact, mode=mode, exit_code=exit_code)
    out = tmp_path / "out"
    code = producer.run(str(binary), artifact, out)
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    return code, receipt, evidence


@pytest.mark.parametrize("mode", ["crash", "missing", "empty", "malformed", "missing-section"])
def test_trivy_incomplete_execution_is_never_clean(monkeypatch, tmp_path: Path, mode: str) -> None:
    code, receipt, evidence = _run_case(monkeypatch, tmp_path, mode=mode)
    execution = evidence["scanner_execution"]
    assert code == 1
    assert receipt["verdict"] == "inconclusive"
    assert execution["completeness_status"] in {"incomplete", "failed"}
    assert execution["required_work_completed"] is False
    assert receipt["verdict"] != "clean"


def test_trivy_exit_state_contradiction_is_fail_closed(monkeypatch, tmp_path: Path) -> None:
    code, receipt, evidence = _run_case(monkeypatch, tmp_path, mode="clean", exit_code=1)
    assert code == 1
    assert receipt["verdict"] == "inconclusive"
    assert evidence["scanner_execution"]["completeness_reason"] == "scanner_exit_state_invalid"


@pytest.mark.parametrize(("mode", "expected"), [("clean", "clean"), ("findings", "findings")])
def test_complete_trivy_execution_preserves_result_semantics(monkeypatch, tmp_path: Path, mode: str, expected: str) -> None:
    code, receipt, evidence = _run_case(monkeypatch, tmp_path, mode=mode)
    execution = evidence["scanner_execution"]
    assert code == 0
    assert receipt["verdict"] == expected
    assert execution["completeness_status"] == "complete"
    assert execution["required_work_completed"] is True
    assert execution["result_semantics_consistent"] is True


def test_stale_valid_output_cannot_survive_a_scanner_crash(monkeypatch, tmp_path: Path) -> None:
    binary, artifact = _setup_verified_trivy(monkeypatch, tmp_path)
    out = tmp_path / "out"
    _stub_scan(monkeypatch, artifact, mode="clean")
    assert producer.run(str(binary), artifact, out) == 0
    _stub_scan(monkeypatch, artifact, mode="crash")
    assert producer.run(str(binary), artifact, out) == 1
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    assert evidence["raw_report"]["exists"] is False


def test_false_clean_regression_fixture_requires_complete_execution() -> None:
    fixture = Path(__file__).parent / "fixtures" / "false-clean" / "trivy-zero-findings-incomplete.json"
    value = json.loads(fixture.read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="scanner_execution_incomplete"):
        map_report(
            value["raw_report"],
            artifact_ref="fixture-artifact.txt",
            artifact_sha256="a" * 64,
            scanner_version="0.74.0",
            scanner_exit_code=0,
            scanner_execution=value["scanner_execution"],
        )
    assert value["expected"]["verdict"] == "inconclusive"


def test_valid_report_without_execution_evidence_cannot_be_clean() -> None:
    raw = {
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": "artifact.txt",
        "Results": [{"Target": "artifact.txt", "Class": "lang-pkgs", "Type": "python", "Vulnerabilities": []}],
    }
    with pytest.raises(ValueError, match="scanner_execution_incomplete"):
        map_report(
            raw,
            artifact_ref="artifact.txt",
            artifact_sha256="a" * 64,
            scanner_version="0.74.0",
            scanner_exit_code=0,
        )
