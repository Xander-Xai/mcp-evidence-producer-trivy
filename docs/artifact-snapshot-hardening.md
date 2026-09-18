# Producer artifact snapshot hardening

File-based Trivy and OSV producers distinguish the consumer subject path from
the producer scan target:

```text
source artifact
  -> producer-owned snapshot
  -> digest(snapshot) and size(snapshot)
  -> scanner(snapshot)
  -> receipt subject ref + snapshot digest
```

The snapshot is created in a unique temporary directory, flushed and closed
before scanner invocation, and removed when the producer run ends. The scanner
never receives the original source path. Evidence includes:

```json
{
  "artifact": {"ref": "<subject>", "sha256": "<snapshot>", "size": 123},
  "scan_input": {
    "kind": "producer-owned-file-snapshot",
    "source_ref": "<subject>",
    "sha256": "<snapshot>",
    "size": 123,
    "retained": false
  }
}
```

Trivy reports bind to the exact snapshot path supplied in the scanner argv;
OSV source binding follows the same rule. A post-scan snapshot digest/size
mismatch produces an inconclusive result with
`artifact_snapshot_changed`, never a clean or findings receipt.

This prevents source-path replacement between hashing and scanner open. It is
not a claim against a fully privileged attacker modifying producer-private
files during execution. Core and Dogfood retain independent consumer distrust
and artifact-binding checks. OCI is not changed: it scans a digest-addressed
image reference and its existing exact manifest/platform identity tests remain
the applicable protection.
