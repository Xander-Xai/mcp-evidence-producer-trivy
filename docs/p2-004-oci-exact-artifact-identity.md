# P2-004 OCI Exact Artifact Identity — Source Freeze

Status: experimental project evidence for exact OCI artifact identity.

## Decision objective

Prove that one scanner receipt can bind the exact OCI platform image manifest
that Trivy actually scans, without turning `mcp-evidence-gate` Core into a
registry client.

The required chain is:

```text
digest-pinned root reference
-> exact root bytes
-> platform descriptor selection
-> exact platform manifest bytes
-> Trivy scan of repo@platform-manifest-digest
-> SecurityScanReceipt
-> evidence_digest
-> existing offline Core artifact/evidence verification
```

## Frozen runtime example

The real CI target is a public digest-pinned image from
`ghcr.io/containers/kubernetes-mcp-server`.

- root reference:
  `ghcr.io/containers/kubernetes-mcp-server@sha256:7cba55569933e79d8b877607a0413c62faa23f0b281a99144ebb07f853539c82`
- root media type: `application/vnd.oci.image.index.v1+json`
- root index digest:
  `sha256:7cba55569933e79d8b877607a0413c62faa23f0b281a99144ebb07f853539c82`
- selected platform: `linux/amd64`
- selected platform manifest digest:
  `sha256:a60d068656fa8b57fb6f55565e439813aca7f44219e3239575c2e749d5f60bf7`

The index digest and selected manifest digest are intentionally different. A
consumer that substitutes the parent index digest for the scanned platform
manifest digest fails this acceptance contract.

## Identity rules

1. Real scanning accepts only an explicit `@sha256:<64 hex>` root reference.
2. Tags may be parsed for deterministic resolver tests but are rejected by the
   real producer because they are mutable lookup names, not frozen identities.
3. Every fetched manifest/index response is SHA-256 hashed from the exact body
   bytes.
4. If `Docker-Content-Digest` is present, it must equal the body digest.
5. A digest-pinned request must resolve to bytes whose digest equals the
   requested digest.
6. Response Content-Type and the JSON `mediaType`, when both present, must agree.
7. For an image index, platform selection is exact on OS, architecture and
   optional variant. Missing or ambiguous matches fail closed.
8. The selected descriptor digest, size and media type must match the fetched
   platform image manifest.
9. Trivy is invoked against `registry/repository@selected-manifest-digest`, not
   the parent index digest and not a tag.
10. The Trivy raw report must itself bind that exact digest through its
    `ArtifactName` or `Metadata.RepoDigests`; otherwise no clean/findings receipt
    is emitted.
11. The selected manifest bytes are retained as `oci.manifest.json`; the receipt
    `scanned_artifact_digest` equals SHA-256 of those exact bytes.
12. Existing Core verifies `oci.manifest.json` locally. Registry networking is
    producer/adapter responsibility and is not added to Core.

## Evidence outputs

A successful indexed-image runtime retains:

```text
out-oci/
  oci-identity.json
  oci.index.json
  oci.manifest.json
  trivy.raw.json
  trivy.stderr.log
  evidence.json
  receipt.json
```

`oci-identity.json` is a project-defined audit record, not an OCI or MCP standard
schema. `evidence.json` binds the identity record, root index, selected manifest,
raw scanner report, scanner binary identity, scanner database state and exact
invocation. It also carries the project-defined `scanner_execution` record;
zero image findings are not enough for a clean candidate unless that record is
`complete`. `receipt.json` keeps scanner verdict semantics independent from
admission policy.

## Consumer acceptance

The real runtime must demonstrate all of the following relational invariants:

- saved root index SHA == frozen root digest;
- saved selected manifest SHA == selected descriptor digest;
- root index digest != selected platform manifest digest for the frozen fixture;
- Trivy target == exact selected digest reference;
- Trivy raw report binds the same digest reference;
- receipt `scanned_artifact_digest` == saved selected manifest SHA;
- receipt `evidence_digest` == exact retained evidence bytes;
- existing Core `artifact_binding` == PASS using `oci.manifest.json`;
- existing Core `evidence_binding` == PASS;
- downstream decision corresponds to the original scanner verdict.

A scanner result containing findings may correctly cause Gate FAIL while the
end-to-end acceptance test itself passes.

## Non-goals

P2-004 does not establish:

- publisher identity or name custody;
- provenance/SLSA correctness;
- signature or PKI verification;
- Registry trust or official MCP adoption;
- scanner trust/reputation/quorum;
- cross-registry feature completeness;
- mutable-tag monitoring;
- vulnerability-free or server-safe status;
- a Core network resolver.

Those are separate trust, provenance, policy or compatibility phases.
