from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from src import osv_producer


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _report(path: Path, vulnerable: bool) -> str:
    vulnerabilities = [{"id": "GHSA-example-1234"}] if vulnerable else []
    return json.dumps(
        {
            "results": [
                {
                    "source": {"path": str(path.resolve()), "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "requests",
                                "version": "2.31.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": vulnerabilities,
                        }
                    ],
                }
            ]
        }
    )


def _setup_verified_binary(monkeypatch, tmp_path: Path) -> tuple[Path, Path]:
    binary = tmp_path / "osv-scanner"
    binary.write_bytes(b"pinned-osv-binary")
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    monkeypatch.setattr(osv_producer, "_platform_key", lambda: "linux")
    monkeypatch.setitem(osv_producer.PINNED_OSV_SHA256, "linux", _sha(binary))
    monkeypatch.setattr(osv_producer, "osv_version", lambda _: "2.5.1")
    return binary, artifact


def test_valid_findings_are_successful_evidence_production(monkeypatch, tmp_path: Path) -> None:
    binary, artifact = _setup_verified_binary(monkeypatch, tmp_path)
    monkeypatch.setattr(
        osv_producer.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=_report(artifact, True), stderr=""),
    )
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), artifact, out) == 0
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    evidence = (out / "evidence.json").read_bytes()
    evidence_value = json.loads(evidence)
    assert receipt["verdict"] == "findings"
    assert receipt["scanner_version"] == "2.5.1"
    assert receipt["evidence_digest"] == f"sha256:{hashlib.sha256(evidence).hexdigest()}"
    assert evidence_value["scanner_execution"]["completeness_status"] == "complete"


def test_valid_clean_scan_is_successful_evidence_production(monkeypatch, tmp_path: Path) -> None:
    binary, artifact = _setup_verified_binary(monkeypatch, tmp_path)
    monkeypatch.setattr(
        osv_producer.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=_report(artifact, False), stderr=""),
    )
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), artifact, out) == 0
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "clean"
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["scanner_execution"]["completeness_status"] == "complete"


def test_no_packages_exit_128_is_inconclusive(monkeypatch, tmp_path: Path) -> None:
    binary, artifact = _setup_verified_binary(monkeypatch, tmp_path)
    monkeypatch.setattr(
        osv_producer.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=128, stdout='{"results":[]}', stderr="no packages"),
    )
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), artifact, out) == 1
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    assert receipt["inconclusive_reason"] == "evidence_unavailable"
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["scanner_execution"]["completeness_status"] != "complete"


def test_malformed_json_is_inconclusive(monkeypatch, tmp_path: Path) -> None:
    binary, artifact = _setup_verified_binary(monkeypatch, tmp_path)
    monkeypatch.setattr(
        osv_producer.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="not-json", stderr=""),
    )
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), artifact, out) == 1
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["scanner_execution"]["completeness_reason"] == "scanner_output_unparseable"


def test_exit_and_raw_result_contradiction_is_inconclusive(monkeypatch, tmp_path: Path) -> None:
    binary, artifact = _setup_verified_binary(monkeypatch, tmp_path)
    monkeypatch.setattr(
        osv_producer.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=_report(artifact, False), stderr=""),
    )
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), artifact, out) == 1
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    assert evidence["scanner_execution"]["completeness_status"] == "incomplete"
    assert evidence["scanner_execution"]["completeness_reason"] == "osv_exit_verdict_mismatch"


def test_source_path_mismatch_is_classified_as_source_binding(monkeypatch, tmp_path: Path) -> None:
    binary, artifact = _setup_verified_binary(monkeypatch, tmp_path)
    wrong_source = tmp_path / "other-requirements.txt"
    wrong_source.write_text("requests==2.31.0\n", encoding="utf-8")
    monkeypatch.setattr(
        osv_producer.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=_report(wrong_source, False), stderr=""),
    )
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), artifact, out) == 1
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    assert evidence["scanner_execution"]["completeness_reason"] == "artifact_ref_mismatch"
    assert evidence["scanner_execution"]["failed_components"] == ["source_binding"]


def test_valid_exit_with_unmappable_report_is_inconclusive(monkeypatch, tmp_path: Path) -> None:
    binary, artifact = _setup_verified_binary(monkeypatch, tmp_path)
    malformed_but_json = json.dumps(
        {
            "results": [
                {
                    "source": {"path": str(artifact.resolve()), "type": "lockfile"},
                    "packages": [],
                }
            ]
        }
    )
    monkeypatch.setattr(
        osv_producer.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=malformed_but_json, stderr=""),
    )
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), artifact, out) == 1
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    assert (out / "evidence.json").exists()


def test_verified_binary_with_wrong_version_is_inconclusive(monkeypatch, tmp_path: Path) -> None:
    binary, artifact = _setup_verified_binary(monkeypatch, tmp_path)
    monkeypatch.setattr(osv_producer, "osv_version", lambda _: "2.5.0")
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), artifact, out) == 1
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    assert receipt["scanner_version"] == "2.5.0"
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["scanner_execution"]["invocation_started"] is False


def test_unverified_binary_is_inconclusive(tmp_path: Path) -> None:
    binary = tmp_path / "osv-scanner"
    binary.write_bytes(b"wrong-binary")
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), artifact, out) == 1
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    assert receipt["scanner_version"] == "unverified"
