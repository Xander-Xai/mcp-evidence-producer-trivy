# MCP Evidence Producers — Trivy + OSV Incubation

Scanner-specific producers for `mcp-evidence-gate`.

The repository was created for the Trivy producer and still preserves that
implementation. P2-002B incubates a second, logically independent OSV-Scanner
producer here. P2-004 adds an OCI image identity adapter around Trivy while
keeping registry resolution out of Core.

All producer modes map evidence to the pinned
`registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22` receipt profile.
They do not claim server safety, provenance/name custody, cryptographic
attestation, signatures, PKI, scanner reputation, or Registry adoption.
Admission remains the downstream gate's job.

## Scanner execution completeness

Zero findings does not prove that the scanner completed. A scanner can crash,
write no output, or leave a structurally incomplete report that looks empty.
Every producer therefore records a project-defined `scanner_execution` object
inside `evidence.json`. It records the invocation, process and exit state,
required output, parseability, required/completed/failed components, and a
deterministic `completeness_status` of `complete`, `incomplete`, or `failed`.
The record also states the producer's bounded reason for that status; it is not
a scanner attestation or an MCP Registry field.

Producer clean requires both:

1. scanner-result semantics (the parsed report consistently says there are no
   findings); and
2. scanner-execution completeness (all required scanner work, output, binding,
   and consistency checks completed).

If any required condition is missing, the producer emits an `inconclusive`
receipt (or the existing producer runtime failure) and never `clean`. Findings
remain findings when execution is complete. This additive evidence extension
keeps the v1 receipt shape and does not change the pinned Registry profile.
Existing v1 evidence manifests without `scanner_execution` are legacy records;
they must be regenerated before a producer can make a clean claim rather than
being silently reinterpreted as complete.

## Trivy — exact local file

```powershell
python -m pytest -q
python -m src.producer --trivy .\vendor\trivy.exe --artifact .\artifacts\requirements.txt --out .\out
```

This mode writes `trivy.raw.json`, `trivy.stderr.log`, `evidence.json`, and
`receipt.json`. The receipt binds the exact local artifact bytes.

## Trivy — exact OCI platform manifest

P2-004 treats an OCI image index and its platform image manifest as distinct
content-addressed objects. A real OCI scan must start from an immutable digest
reference; a tag is rejected by `src.oci_producer` rather than silently treated
as immutable identity.

For an image index, the resolver selects exactly one requested platform
descriptor, verifies the descriptor digest, size and media type, fetches the
selected image manifest, verifies the registry digest against the exact response
bytes, and invokes Trivy against the selected manifest digest:

```text
repo@root-index-digest
  -> exact platform descriptor
  -> repo@platform-manifest-digest
  -> trivy image repo@platform-manifest-digest
```

Example:

```bash
python -m src.oci_producer \
  --trivy ./trivy \
  --image ghcr.io/containers/kubernetes-mcp-server@sha256:7cba55569933e79d8b877607a0413c62faa23f0b281a99144ebb07f853539c82 \
  --platform-os linux \
  --platform-arch amd64 \
  --out out-oci
```

The producer retains:

- `oci-identity.json` — project-defined root-to-platform resolution record;
- `oci.index.json` — exact root index bytes when the root is an index;
- `oci.manifest.json` — exact selected platform manifest bytes;
- `trivy.raw.json` and `trivy.stderr.log`;
- `evidence.json` and `receipt.json`.

`receipt.scanned_artifact_digest` is the selected platform manifest digest, not
the parent image-index digest. Core remains offline: it verifies the receipt
against the retained `oci.manifest.json` bytes and does not fetch registries.
This establishes exact OCI artifact identity only; it does not establish who
published the image or whether the name/digest relationship should be trusted.

## OSV-Scanner

The OSV producer is pinned to OSV-Scanner `v2.5.1`. On Linux CI its release
binary is admitted only when its SHA-256 is
`f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be`.

```bash
python -m src.osv_producer \
  --osv ./osv-scanner \
  --artifact artifacts/requirements.txt \
  --out out-osv
```

OSV writes `osv.raw.json`, `osv.stderr.log`, `evidence.json`, and `receipt.json`.
The exact invocation uses `scan --format json -L <artifact>`. Scanner exit codes
`0` (packages found, no findings) and `1` (findings) are valid result states;
no-package/error states are fail-closed as inconclusive. The adapter requires
every reported source path to bind to the requested artifact, at least one
primary `lockfile` source, and consistency between scanner exit code and raw
vulnerability data.

OSV vulnerability data is queried remotely. The evidence manifest therefore
records `scanner_database.snapshot = "unavailable"` instead of inventing an
immutable database/rule-set identity.

For all modes, `scan_scope` remains `dependency-vulnerabilities`, and
`evidence_digest` binds the retained producer evidence manifest.
