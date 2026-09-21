from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from src import oci_producer
from src.oci_identity import ResolvedOciIdentity, sha256_bytes


def _setup(monkeypatch, tmp_path: Path) -> tuple[Path, str, str, bytes]:
    binary = tmp_path / "trivy"
    binary.write_bytes(b"pinned-trivy-binary")
    manifest = json.dumps(
        {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {}, "layers": []},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    digest = sha256_bytes(manifest)
    image = f"ghcr.io/example/tool@{digest}"
    monkeypatch.setitem(oci_producer.PINNED_TRIVY_SHA256, sys.platform, hashlib.sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setattr(oci_producer, "trivy_version", lambda _: "0.74.0")
    monkeypatch.setattr(
        oci_producer,
        "resolve_oci_identity",
        lambda *_args, **_kwargs: ResolvedOciIdentity(
            record={
                "requested_ref": image,
                "requested_reference_kind": "digest",
                "root": {"digest": digest},
                "selected": {
                    "exact_ref": image,
                    "manifest_digest": digest,
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
            },
            root_body=manifest,
            manifest_body=manifest,
        ),
    )
    return binary, image, digest, manifest


def _stub_scan(monkeypatch, exact_ref: str, *, output: bool, empty_results: bool = False) -> None:
    def fake_run(argv, **_kwargs):
        path = Path(argv[argv.index("--output") + 1])
        if output:
            path.write_text(
                json.dumps(
                    {
                        "Trivy": {"Version": "0.74.0"},
                        "ArtifactName": exact_ref,
                        "Results": []
                        if empty_results
                        else [{"Target": "image", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": []}],
                    }
                ),
                encoding="utf-8",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(oci_producer.subprocess, "run", fake_run)


def test_oci_complete_execution_preserves_exact_manifest_identity(monkeypatch, tmp_path: Path) -> None:
    binary, image, digest, _manifest = _setup(monkeypatch, tmp_path)
    _stub_scan(monkeypatch, image, output=True)
    out = tmp_path / "out"
    assert oci_producer.run(binary.as_posix(), image, out, os_name="linux", architecture="amd64") == 0
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "clean"
    assert receipt["scanned_artifact_digest"] == digest
    assert evidence["scanner_execution"]["completeness_status"] == "complete"
    assert evidence["artifact"]["exact_ref"] == image
    assert evidence["artifact"]["root_digest"] == digest


def test_oci_missing_output_is_inconclusive(monkeypatch, tmp_path: Path) -> None:
    binary, image, _digest, _manifest = _setup(monkeypatch, tmp_path)
    _stub_scan(monkeypatch, image, output=False)
    out = tmp_path / "out"
    assert oci_producer.run(binary.as_posix(), image, out, os_name="linux", architecture="amd64") == 1
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    assert evidence["scanner_execution"]["completeness_reason"] == "scanner_output_missing"


def test_oci_empty_results_are_inconclusive(monkeypatch, tmp_path: Path) -> None:
    binary, image, _digest, _manifest = _setup(monkeypatch, tmp_path)
    _stub_scan(monkeypatch, image, output=True, empty_results=True)
    out = tmp_path / "out"
    assert oci_producer.run(binary.as_posix(), image, out, os_name="linux", architecture="amd64") == 1
    receipt = json.loads((out / "receipt.json").read_text(encoding="utf-8"))
    evidence = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert receipt["verdict"] == "inconclusive"
    assert evidence["scanner_execution"]["completeness_reason"] == "trivy_result_sections_missing"
    assert evidence["scanner_execution"]["failed_components"] == ["result_sections"]


def test_oci_reused_output_directory_clears_prior_success(monkeypatch, tmp_path: Path) -> None:
    binary, image, _digest, _manifest = _setup(monkeypatch, tmp_path)
    _stub_scan(monkeypatch, image, output=True)
    out = tmp_path / "out"
    assert oci_producer.run(binary.as_posix(), image, out, os_name="linux", architecture="amd64") == 0
    assert (out / "receipt.json").exists()
    assert (out / "evidence.json").exists()

    assert oci_producer.run(
        binary.as_posix(),
        "ghcr.io/example/tool:latest",
        out,
        os_name="linux",
        architecture="amd64",
    ) == 1
    assert not (out / "receipt.json").exists()
    assert not (out / "evidence.json").exists()
    assert json.loads((out / "oci-error.json").read_text(encoding="utf-8"))["error"] == "mutable_oci_reference_rejected"
