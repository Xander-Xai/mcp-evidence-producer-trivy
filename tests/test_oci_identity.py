from __future__ import annotations

import http.client
import json

import pytest

from src.oci_identity import (
    OCI_INDEX,
    OCI_MANIFEST,
    ManifestResponse,
    OciIdentityError,
    RegistryClient,
    parse_reference,
    resolve_oci_identity,
    sha256_bytes,
)


def encoded(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def response(body: bytes, media_type: str, *, digest_header: str | None = None) -> ManifestResponse:
    return ManifestResponse(
        body=body,
        content_type=media_type,
        docker_content_digest=digest_header or sha256_bytes(body),
    )


def fixture_documents():
    amd64 = encoded({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + "1" * 64, "size": 2},
        "layers": [],
    })
    arm64 = encoded({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + "2" * 64, "size": 2},
        "layers": [],
    })
    index = encoded({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [
            {
                "mediaType": OCI_MANIFEST,
                "digest": sha256_bytes(amd64),
                "size": len(amd64),
                "platform": {"os": "linux", "architecture": "amd64"},
            },
            {
                "mediaType": OCI_MANIFEST,
                "digest": sha256_bytes(arm64),
                "size": len(arm64),
                "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"},
            },
        ],
    })
    return index, amd64, arm64


def test_parse_reference_requires_explicit_identity():
    digest = "sha256:" + "a" * 64
    parsed = parse_reference(f"ghcr.io/example/tool@{digest}")
    assert parsed.registry == "ghcr.io"
    assert parsed.repository == "example/tool"
    assert parsed.reference == digest
    assert parsed.reference_kind == "digest"
    assert parsed.canonical == f"ghcr.io/example/tool@{digest}"

    tagged = parse_reference("ghcr.io/example/tool:1.2.3")
    assert tagged.reference_kind == "tag"
    assert tagged.canonical == "ghcr.io/example/tool:1.2.3"

    with pytest.raises(OciIdentityError, match="requires_explicit"):
        parse_reference("ghcr.io/example/tool")


def test_index_digest_resolves_exact_linux_amd64_manifest():
    index, amd64, _ = fixture_documents()
    root_digest = sha256_bytes(index)
    amd64_digest = sha256_bytes(amd64)
    calls: list[str] = []

    def fetch(_registry: str, _repository: str, reference: str) -> ManifestResponse:
        calls.append(reference)
        if reference == root_digest:
            return response(index, OCI_INDEX)
        if reference == amd64_digest:
            return response(amd64, OCI_MANIFEST)
        raise AssertionError(reference)

    resolved = resolve_oci_identity(
        f"ghcr.io/example/tool@{root_digest}",
        os_name="linux",
        architecture="amd64",
        fetch_manifest=fetch,
    )

    assert calls == [root_digest, amd64_digest]
    assert resolved.root_body == index
    assert resolved.manifest_body == amd64
    assert resolved.record["root"]["digest"] == root_digest
    selected = resolved.record["selected"]
    assert selected["selection_source"] == "image-index"
    assert selected["manifest_digest"] == amd64_digest
    assert selected["descriptor_digest"] == amd64_digest
    assert selected["exact_ref"] == f"ghcr.io/example/tool@{amd64_digest}"
    assert selected["platform"] == {"os": "linux", "architecture": "amd64"}
    assert root_digest != amd64_digest


def test_variant_selection_is_exact_and_fail_closed():
    index, _, arm64 = fixture_documents()
    root_digest = sha256_bytes(index)
    arm64_digest = sha256_bytes(arm64)

    def fetch(_registry: str, _repository: str, reference: str) -> ManifestResponse:
        if reference == root_digest:
            return response(index, OCI_INDEX)
        if reference == arm64_digest:
            return response(arm64, OCI_MANIFEST)
        raise AssertionError(reference)

    resolved = resolve_oci_identity(
        f"ghcr.io/example/tool@{root_digest}",
        os_name="linux",
        architecture="arm64",
        variant="v8",
        fetch_manifest=fetch,
    )
    assert resolved.record["selected"]["manifest_digest"] == arm64_digest

    with pytest.raises(OciIdentityError, match="platform_manifest_not_found"):
        resolve_oci_identity(
            f"ghcr.io/example/tool@{root_digest}",
            os_name="linux",
            architecture="arm64",
            fetch_manifest=fetch,
        )


def test_requested_digest_must_match_root_manifest_bytes():
    index, _, _ = fixture_documents()
    wrong_digest = "sha256:" + "0" * 64

    def fetch(_registry: str, _repository: str, _reference: str) -> ManifestResponse:
        return response(index, OCI_INDEX)

    with pytest.raises(OciIdentityError, match="manifest_body_digest_mismatch"):
        resolve_oci_identity(
            f"ghcr.io/example/tool@{wrong_digest}",
            os_name="linux",
            architecture="amd64",
            fetch_manifest=fetch,
        )


def test_registry_digest_header_must_match_exact_body():
    index, _, _ = fixture_documents()
    root_digest = sha256_bytes(index)

    def fetch(_registry: str, _repository: str, _reference: str) -> ManifestResponse:
        return response(index, OCI_INDEX, digest_header="sha256:" + "f" * 64)

    with pytest.raises(OciIdentityError, match="docker_content_digest_mismatch"):
        resolve_oci_identity(
            f"ghcr.io/example/tool@{root_digest}",
            os_name="linux",
            architecture="amd64",
            fetch_manifest=fetch,
        )


def test_platform_descriptor_size_and_media_type_are_verified():
    index, amd64, _ = fixture_documents()
    root_digest = sha256_bytes(index)
    amd64_digest = sha256_bytes(amd64)
    broken = json.loads(index)
    broken["manifests"][0]["size"] += 1
    broken_index = encoded(broken)
    broken_root_digest = sha256_bytes(broken_index)

    def fetch(_registry: str, _repository: str, reference: str) -> ManifestResponse:
        if reference == broken_root_digest:
            return response(broken_index, OCI_INDEX)
        if reference == amd64_digest:
            return response(amd64, OCI_MANIFEST)
        raise AssertionError(reference)

    with pytest.raises(OciIdentityError, match="platform_manifest_size_mismatch"):
        resolve_oci_identity(
            f"ghcr.io/example/tool@{broken_root_digest}",
            os_name="linux",
            architecture="amd64",
            fetch_manifest=fetch,
        )


def test_direct_manifest_digest_remains_exact_manifest_identity():
    _, amd64, _ = fixture_documents()
    digest = sha256_bytes(amd64)

    def fetch(_registry: str, _repository: str, reference: str) -> ManifestResponse:
        assert reference == digest
        return response(amd64, OCI_MANIFEST)

    resolved = resolve_oci_identity(
        f"ghcr.io/example/tool@{digest}",
        os_name="linux",
        architecture="amd64",
        fetch_manifest=fetch,
    )
    assert resolved.root_body == resolved.manifest_body == amd64
    assert resolved.record["root"]["digest"] == digest
    assert resolved.record["selected"]["manifest_digest"] == digest
    assert resolved.record["selected"]["selection_source"] == "direct-manifest"


def test_platform_descriptor_requires_media_type() -> None:
    index, amd64, _ = fixture_documents()
    broken = json.loads(index)
    del broken["manifests"][0]["mediaType"]
    broken_index = encoded(broken)
    root_digest = sha256_bytes(broken_index)
    amd64_digest = sha256_bytes(amd64)

    def fetch(_registry: str, _repository: str, reference: str) -> ManifestResponse:
        if reference == root_digest:
            return response(broken_index, OCI_INDEX)
        if reference == amd64_digest:
            return response(amd64, OCI_MANIFEST)
        raise AssertionError(reference)

    with pytest.raises(OciIdentityError, match="platform_manifest_media_type_mismatch"):
        resolve_oci_identity(
            f"ghcr.io/example/tool@{root_digest}",
            os_name="linux",
            architecture="amd64",
            fetch_manifest=fetch,
        )


def test_registry_transport_failure_is_structured(monkeypatch) -> None:
    client = RegistryClient()

    def fail_open(_url: str, _headers) -> None:
        raise OSError("network unavailable")

    monkeypatch.setattr(client, "_open", fail_open)
    with pytest.raises(OciIdentityError, match="registry_manifest_transport_failed"):
        client.fetch_manifest("ghcr.io", "example/tool", "sha256:" + "a" * 64)


def test_registry_truncated_manifest_read_is_structured(monkeypatch) -> None:
    client = RegistryClient()

    class TruncatedResponse:
        headers = {}

        def read(self):
            raise http.client.IncompleteRead(b"partial", 10)

        def close(self) -> None:
            pass

    monkeypatch.setattr(client, "_open", lambda _url, _headers: TruncatedResponse())
    with pytest.raises(OciIdentityError, match="registry_manifest_transport_failed"):
        client.fetch_manifest("ghcr.io", "example/tool", "sha256:" + "a" * 64)
