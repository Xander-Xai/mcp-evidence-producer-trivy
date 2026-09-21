from __future__ import annotations

import hashlib
import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
INDEX_MEDIA_TYPES = {OCI_INDEX, DOCKER_INDEX}
MANIFEST_MEDIA_TYPES = {OCI_MANIFEST, DOCKER_MANIFEST}
ACCEPT = ", ".join([OCI_INDEX, DOCKER_INDEX, OCI_MANIFEST, DOCKER_MANIFEST])
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BEARER_RE = re.compile(r"^Bearer\s+(.*)$", re.IGNORECASE)
PARAM_RE = re.compile(r'(\w+)="([^"]*)"')


class OciIdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class OciReference:
    registry: str
    repository: str
    reference: str
    reference_kind: str

    @property
    def canonical(self) -> str:
        separator = "@" if self.reference_kind == "digest" else ":"
        return f"{self.registry}/{self.repository}{separator}{self.reference}"


@dataclass(frozen=True)
class ManifestResponse:
    body: bytes
    content_type: str | None
    docker_content_digest: str | None


@dataclass(frozen=True)
class ResolvedOciIdentity:
    record: dict[str, object]
    root_body: bytes
    manifest_body: bytes


ManifestFetcher = Callable[[str, str, str], ManifestResponse]


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def parse_reference(value: str) -> OciReference:
    raw = value.removeprefix("oci://")
    if "/" not in raw:
        raise OciIdentityError("oci_reference_requires_registry_and_repository")
    registry, remainder = raw.split("/", 1)
    if not registry or not remainder:
        raise OciIdentityError("malformed_oci_reference")

    if "@" in remainder:
        repository, digest = remainder.rsplit("@", 1)
        if not repository or not DIGEST_RE.fullmatch(digest):
            raise OciIdentityError("malformed_oci_digest_reference")
        return OciReference(registry, repository, digest, "digest")

    leaf = remainder.rsplit("/", 1)[-1]
    if ":" not in leaf:
        raise OciIdentityError("oci_reference_requires_explicit_tag_or_digest")
    repository, tag = remainder.rsplit(":", 1)
    if not repository or not tag:
        raise OciIdentityError("malformed_oci_tag_reference")
    return OciReference(registry, repository, tag, "tag")


def _media_type(response: ManifestResponse, document: Mapping[str, object]) -> str:
    header = response.content_type.split(";", 1)[0].strip() if response.content_type else None
    body_value = document.get("mediaType")
    body_type = body_value if isinstance(body_value, str) else None
    if header and body_type and header != body_type:
        raise OciIdentityError("manifest_content_type_mismatch")
    media_type = header or body_type
    if media_type not in INDEX_MEDIA_TYPES | MANIFEST_MEDIA_TYPES:
        raise OciIdentityError("unsupported_manifest_media_type")
    return media_type


def _validate_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise OciIdentityError(f"{label}_digest_invalid")
    return value


def _decode_document(
    response: ManifestResponse,
    *,
    expected_digest: str | None = None,
) -> tuple[dict[str, object], str, str]:
    actual_digest = sha256_bytes(response.body)
    if expected_digest is not None and actual_digest != expected_digest:
        raise OciIdentityError("manifest_body_digest_mismatch")
    if response.docker_content_digest is not None:
        header_digest = _validate_digest(response.docker_content_digest, label="registry_header")
        if header_digest != actual_digest:
            raise OciIdentityError("docker_content_digest_mismatch")
    try:
        document = json.loads(response.body)
    except json.JSONDecodeError as exc:
        raise OciIdentityError("manifest_json_invalid") from exc
    if not isinstance(document, dict):
        raise OciIdentityError("manifest_json_not_object")
    return document, _media_type(response, document), actual_digest


def _select_platform_descriptor(
    index: Mapping[str, object],
    *,
    os_name: str,
    architecture: str,
    variant: str | None,
) -> Mapping[str, object]:
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise OciIdentityError("image_index_manifests_missing")

    matches: list[Mapping[str, object]] = []
    for item in manifests:
        if not isinstance(item, dict):
            raise OciIdentityError("image_index_descriptor_invalid")
        platform = item.get("platform")
        if not isinstance(platform, dict):
            continue
        if platform.get("os") != os_name or platform.get("architecture") != architecture:
            continue
        item_variant = platform.get("variant")
        if variant is not None and item_variant != variant:
            continue
        if variant is None and item_variant not in (None, ""):
            continue
        matches.append(item)

    if not matches:
        raise OciIdentityError("platform_manifest_not_found")
    if len(matches) != 1:
        raise OciIdentityError("platform_manifest_ambiguous")
    return matches[0]


def resolve_oci_identity(
    requested_ref: str,
    *,
    os_name: str,
    architecture: str,
    variant: str | None = None,
    fetch_manifest: ManifestFetcher,
) -> ResolvedOciIdentity:
    reference = parse_reference(requested_ref)
    expected_root = reference.reference if reference.reference_kind == "digest" else None
    root_response = fetch_manifest(reference.registry, reference.repository, reference.reference)
    root_document, root_media_type, root_digest = _decode_document(
        root_response,
        expected_digest=expected_root,
    )

    requested_platform: dict[str, str] = {"os": os_name, "architecture": architecture}
    if variant is not None:
        requested_platform["variant"] = variant

    selected_descriptor: Mapping[str, object] | None = None
    if root_media_type in INDEX_MEDIA_TYPES:
        selected_descriptor = _select_platform_descriptor(
            root_document,
            os_name=os_name,
            architecture=architecture,
            variant=variant,
        )
        selected_digest = _validate_digest(selected_descriptor.get("digest"), label="platform_descriptor")
        selected_response = fetch_manifest(reference.registry, reference.repository, selected_digest)
        _, selected_media_type, selected_actual_digest = _decode_document(
            selected_response,
            expected_digest=selected_digest,
        )
        if selected_media_type not in MANIFEST_MEDIA_TYPES:
            raise OciIdentityError("platform_descriptor_did_not_resolve_to_manifest")
        descriptor_size = selected_descriptor.get("size")
        if not isinstance(descriptor_size, int) or descriptor_size != len(selected_response.body):
            raise OciIdentityError("platform_manifest_size_mismatch")
        descriptor_media_type = selected_descriptor.get("mediaType")
        if (
            not isinstance(descriptor_media_type, str)
            or descriptor_media_type not in MANIFEST_MEDIA_TYPES
            or descriptor_media_type != selected_media_type
        ):
            raise OciIdentityError("platform_manifest_media_type_mismatch")
        manifest_body = selected_response.body
        manifest_digest = selected_actual_digest
        manifest_media_type = selected_media_type
        selection_source = "image-index"
        platform_verified = True
        platform_source = "index-descriptor"
    else:
        manifest_body = root_response.body
        manifest_digest = root_digest
        manifest_media_type = root_media_type
        selection_source = "direct-manifest"
        platform_verified = False
        platform_source = "caller-requested-unverified"

    exact_ref = f"{reference.registry}/{reference.repository}@{manifest_digest}"
    selected_record: dict[str, object] = {
        "selection_source": selection_source,
        "platform": requested_platform,
        "platform_verified": platform_verified,
        "platform_source": platform_source,
        "manifest_digest": manifest_digest,
        "manifest_media_type": manifest_media_type,
        "manifest_size": len(manifest_body),
        "exact_ref": exact_ref,
    }
    if selected_descriptor is not None:
        selected_record["descriptor_digest"] = selected_descriptor["digest"]
        selected_record["descriptor_size"] = selected_descriptor["size"]
        if "mediaType" in selected_descriptor:
            selected_record["descriptor_media_type"] = selected_descriptor["mediaType"]

    record: dict[str, object] = {
        "schema_version": "project-defined-oci-artifact-identity-v1",
        "requested_ref": reference.canonical,
        "registry": reference.registry,
        "repository": reference.repository,
        "requested_reference_kind": reference.reference_kind,
        "root": {
            "digest": root_digest,
            "media_type": root_media_type,
            "size": len(root_response.body),
        },
        "selected": selected_record,
    }
    return ResolvedOciIdentity(record=record, root_body=root_response.body, manifest_body=manifest_body)


class RegistryClient:
    def __init__(self, *, timeout: float = 30.0):
        self.timeout = timeout
        self._tokens: dict[tuple[str, str, str], str] = {}

    def _open(self, url: str, headers: Mapping[str, str]):
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        return urllib.request.urlopen(request, timeout=self.timeout)

    def _bearer_token(self, challenge: str, registry: str, repository: str) -> str:
        match = BEARER_RE.match(challenge)
        if not match:
            raise OciIdentityError("unsupported_registry_auth_challenge")
        params = dict(PARAM_RE.findall(match.group(1)))
        realm = params.get("realm")
        if not realm or not realm.startswith("https://"):
            raise OciIdentityError("registry_auth_realm_invalid")
        service = params.get("service") or ""
        scope = params.get("scope") or f"repository:{repository}:pull"
        cache_key = (realm, service, scope)
        if cache_key in self._tokens:
            return self._tokens[cache_key]
        query = {"scope": scope}
        if service:
            query["service"] = service
        token_url = realm + ("&" if "?" in realm else "?") + urllib.parse.urlencode(query)
        try:
            with self._open(token_url, {"User-Agent": "mcp-evidence-producer-oci/0.1"}) as response:
                payload = json.loads(response.read())
        except (OSError, json.JSONDecodeError) as exc:
            raise OciIdentityError("registry_token_request_failed") from exc
        if not isinstance(payload, dict):
            raise OciIdentityError("registry_token_missing")
        token = payload.get("token") or payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise OciIdentityError("registry_token_missing")
        self._tokens[cache_key] = token
        return token

    def fetch_manifest(self, registry: str, repository: str, reference: str) -> ManifestResponse:
        quoted_reference = urllib.parse.quote(reference, safe=":")
        url = f"https://{registry}/v2/{repository}/manifests/{quoted_reference}"
        headers = {"Accept": ACCEPT, "User-Agent": "mcp-evidence-producer-oci/0.1"}
        try:
            response = self._open(url, headers)
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise OciIdentityError(f"registry_manifest_http_{error.code}") from error
            challenge = error.headers.get("WWW-Authenticate")
            if not challenge:
                raise OciIdentityError("registry_auth_challenge_missing") from error
            token = self._bearer_token(challenge, registry, repository)
            headers["Authorization"] = f"Bearer {token}"
            try:
                response = self._open(url, headers)
            except urllib.error.HTTPError as retry_error:
                raise OciIdentityError(f"registry_manifest_http_{retry_error.code}") from retry_error
            except OSError as retry_error:
                raise OciIdentityError("registry_manifest_transport_failed") from retry_error
        except OSError as error:
            raise OciIdentityError("registry_manifest_transport_failed") from error
        try:
            try:
                body = response.read()
                content_type = response.headers.get("Content-Type")
                docker_digest = response.headers.get("Docker-Content-Digest")
            except (OSError, http.client.HTTPException) as error:
                raise OciIdentityError("registry_manifest_transport_failed") from error
        finally:
            response.close()
        return ManifestResponse(
            body=body,
            content_type=content_type,
            docker_content_digest=docker_digest,
        )
