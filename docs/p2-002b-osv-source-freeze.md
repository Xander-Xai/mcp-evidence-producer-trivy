# P2-002B OSV-Scanner source freeze

This document freezes the scanner inputs and semantic boundaries used by the
P2-002B OSV producer.

## Scanner identity

- Upstream: `google/osv-scanner`
- Release: `v2.5.1`
- Release published: 2026-08-17
- Linux amd64 asset: `osv-scanner_linux_amd64`
- Linux amd64 SHA-256:
  `f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be`
- Producer accepts version string: `2.5.1`

The binary digest is checked before invoking `--version` or a scan. A binary or
version mismatch produces only an inconclusive receipt.

## Invocation contract

The exact source-lockfile invocation is:

```text
osv-scanner scan --format json -L <artifact>
```

OSV-Scanner v2 documents JSON as its machine-readable automation output. For the
scan result codes used here:

- `0`: packages found and no known vulnerabilities/findings;
- `1`: packages found and vulnerabilities/findings exist;
- `128`: no packages found.

Only result codes `0` and `1` can produce clean/findings evidence. No-package,
malformed-output, binary/version mismatch, or other runtime errors fail closed as
inconclusive. The producer additionally records explicit `scanner_execution`
completeness evidence; a valid-looking empty result cannot override an
incomplete process/output/source/consistency check.

## Artifact and report binding

The P2-002B real runtime fixture is `artifacts/requirements.txt`, passed explicitly
with `-L`.

The adapter requires:

1. every result source path resolves to the requested artifact;
2. source types are limited to `lockfile` and same-path `unknown` records observed
   for resolved/transitive packages in OSV-Scanner v2.5.1;
3. at least one primary `lockfile` source exists;
4. at least one package is parsed;
5. package identity fields are structurally present;
6. vulnerability entries carry an OSV identifier;
7. exit `0` agrees with zero vulnerability entries and exit `1` agrees with one or
   more vulnerability entries.

The real v2.5.1 run on this fixture demonstrated both a primary `lockfile` result
and a same-path `unknown` result. The latter is admitted only while the path still
binds to the exact requested artifact and a primary lockfile source is present.

## Database boundary

The default scan queries OSV vulnerability data remotely. P2-002B does not invent
a stable database snapshot or rule-set identifier. The evidence manifest records:

```json
{
  "scanner_database": {
    "source": "https://osv.dev",
    "mode": "remote-query",
    "snapshot": "unavailable"
  }
}
```

The retained raw JSON report is the scan-time evidence. Database snapshotting,
offline DB pinning, SLSA verification, and cryptographic scanner provenance are
separate future trust/provenance work.

## Consumer pin

The real OSV producer CI consumes Core at immutable SHA:

`f736023aa23c48e9f667325f84282c8546c4aa57`

This is the post-P2-002A Core `main` merge commit whose main CI passed before
P2-002B development began.
