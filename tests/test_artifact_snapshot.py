from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from src import osv_producer, producer


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _trivy_report(target: Path) -> str:
    return json.dumps({
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": str(target.resolve()),
        "Results": [{"Target": target.name, "Class": "lang-pkgs", "Type": "python", "Vulnerabilities": []}],
    })


def _osv_report(target: Path) -> str:
    return json.dumps({
        "results": [{
            "source": {"path": str(target.resolve()), "type": "lockfile"},
            "packages": [{"package": {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}, "vulnerabilities": []}],
        }],
    })


def test_trivy_scans_snapshot_when_subject_is_replaced(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "trivy"
    binary.write_bytes(b"trivy")
    subject = tmp_path / "requirements.txt"
    subject.write_bytes(b"A\n")
    monkeypatch.setitem(producer.PINNED_TRIVY_SHA256, sys.platform, _sha(binary))
    monkeypatch.setattr(producer, "trivy_version", lambda _: "0.74.0")
    seen: dict[str, bytes] = {}

    def fake_run(argv, **_kwargs):
        target = Path(argv[-1])
        seen["target"] = target.read_bytes()
        subject.write_bytes(b"B\n")
        Path(argv[argv.index("--output") + 1]).write_text(_trivy_report(target), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(producer.subprocess, "run", fake_run)
    out = tmp_path / "out"
    assert producer.run(str(binary), subject, out) == 0
    receipt = json.loads((out / "receipt.json").read_text())
    evidence = json.loads((out / "evidence.json").read_text())
    digest = hashlib.sha256(b"A\n").hexdigest()
    assert seen["target"] == b"A\n"
    assert seen["target"] != subject
    assert receipt["scanned_artifact_ref"] == str(subject)
    assert receipt["scanned_artifact_digest"] == f"sha256:{digest}"
    assert evidence["artifact"] == {"ref": str(subject), "sha256": digest, "size": 2}
    assert evidence["scan_input"]["sha256"] == digest
    assert evidence["scan_input"]["size"] == 2


def test_osv_scans_snapshot_when_subject_is_replaced(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "osv-scanner"
    binary.write_bytes(b"osv")
    subject = tmp_path / "requirements.txt"
    subject.write_bytes(b"A\n")
    monkeypatch.setattr(osv_producer, "_platform_key", lambda: "linux")
    monkeypatch.setitem(osv_producer.PINNED_OSV_SHA256, "linux", _sha(binary))
    monkeypatch.setattr(osv_producer, "osv_version", lambda _: "2.5.1")
    seen: dict[str, bytes] = {}

    def fake_run(argv, **_kwargs):
        target = Path(argv[-1])
        seen["target"] = target.read_bytes()
        subject.write_bytes(b"B\n")
        return SimpleNamespace(returncode=0, stdout=_osv_report(target), stderr="")

    monkeypatch.setattr(osv_producer.subprocess, "run", fake_run)
    out = tmp_path / "out"
    assert osv_producer.run(str(binary), subject, out) == 0
    receipt = json.loads((out / "receipt.json").read_text())
    evidence = json.loads((out / "evidence.json").read_text())
    digest = hashlib.sha256(b"A\n").hexdigest()
    assert seen["target"] == b"A\n"
    assert seen["target"] != subject
    assert receipt["scanned_artifact_ref"] == str(subject)
    assert receipt["scanned_artifact_digest"] == f"sha256:{digest}"
    assert evidence["artifact"]["size"] == 2
    assert evidence["scan_input"]["sha256"] == digest


def test_snapshot_mutation_fails_closed_for_trivy(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "trivy"
    binary.write_bytes(b"trivy")
    subject = tmp_path / "artifact.txt"
    subject.write_bytes(b"A")
    monkeypatch.setitem(producer.PINNED_TRIVY_SHA256, sys.platform, _sha(binary))
    monkeypatch.setattr(producer, "trivy_version", lambda _: "0.74.0")

    def fake_run(argv, **_kwargs):
        target = Path(argv[-1])
        Path(argv[argv.index("--output") + 1]).write_text(_trivy_report(target), encoding="utf-8")
        target.write_bytes(b"B")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(producer.subprocess, "run", fake_run)
    out = tmp_path / "out"
    assert producer.run(str(binary), subject, out) == 1
    receipt = json.loads((out / "receipt.json").read_text())
    evidence = json.loads((out / "evidence.json").read_text())
    assert receipt["verdict"] == "inconclusive"
    assert evidence["scanner_execution"]["completeness_reason"] == "artifact_snapshot_changed"

