# Scanner execution completeness closure record

Task: implement and independently validate the producer invariant
`absence of findings != evidence that the scanner completed successfully`.

## Repository and boundary

- Repository: `https://github.com/Xander-Xai/mcp-evidence-producer-trivy`
- Branch: `feat/scanner-execution-completeness`
- Baseline `main` SHA: `4c4d9bd476396cd7e34e9d4182900ac00b03d17b`
- Exact implementation-validation head SHA: `54ca534dac9e66702ee2d7de39d01821367eb2cc`
- Pull request: `#4` (open; no automatic merge)
- Registry compatibility profile: `registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22` (unchanged)

The implementation-validation SHA is the exact PR head whose local and PR CI
checks were inspected before this closure record was added. The final PR head
including this record is reported in the delivery record/PR metadata.

## Baseline and identified gap

Baseline `main` had 37 passing tests. Trivy mapped a parsed report with zero
findings to `clean` when process/output checks happened to look successful, but
there was no machine-readable producer-owned completeness record. OSV had
scanner-specific fail-closed mapping (valid exit 0/1, package/source binding,
primary lockfile, and exit/data consistency) but no shared explicit execution
evidence. OCI retained exact identity only on its successful scan path.

## Implemented invariant and evidence schema

All producer paths now write an additive project-defined
`scanner_execution` extension in `evidence.json`. Its deterministic status is
`complete`, `incomplete`, or `failed`, derived from invocation start, process
completion, scanner-valid exit state, non-empty/parseable output, required and
completed components, failed components, and result-semantic consistency.
Adapters refuse to map a clean/findings receipt without a complete execution
record. Incomplete execution produces the existing v1 `inconclusive` receipt
(`inconclusive_reason: evidence_unavailable`) with detailed project-defined
reason/component evidence. Stale raw output is removed before each invocation.

The manifest records what was expected and what actually completed, including
the bounded reason. Legacy v1 manifests without the extension are not silently
treated as complete; they must be regenerated.

## Producer results

- Trivy filesystem: crash, invalid exit, missing/empty/truncated output,
  missing sections, identity mismatch, and semantic contradictions cannot emit
  clean. Complete zero-findings emits clean; complete findings preserves
  findings.
- OSV: existing v2.5.1 semantics are preserved and now accompanied by
  completeness evidence. No-package/error and exit/data contradictions remain
  inconclusive.
- OCI: P2-004 root-index -> exact platform descriptor -> exact manifest bytes
  -> selected immutable digest binding is unchanged. Completeness evidence is
  added without changing `scanned_artifact_digest`, platform identity, or Core's
  offline verification boundary.

## Adversarial cases and fixture

`tests/test_scanner_completeness.py` covers T1-T8: process crash, missing
output, empty output, malformed/truncated JSON, missing semantic section,
invalid exit/semantic contradiction, partial execution, complete zero findings,
and complete findings. The deterministic fixture
`tests/fixtures/false-clean/trivy-zero-findings-incomplete.json` contains a
zero-finding-looking report paired with failed execution evidence and proves it
cannot map to clean. OCI producer tests cover exact-manifest success and
missing-output failure.

## Validation evidence

- Baseline: `python -m pytest -q` -> 37 passed (exit 0).
- Final implementation head: `python -m pytest -q` -> 53 passed (exit 0).
- `python -m compileall -q src tests` -> exit 0.
- CLI smoke: `python -m src.producer --help`, `python -m src.osv_producer --help`,
  and `python -m src.oci_producer --help` -> exit 0.
- Packaging smoke: `python -m pip wheel --no-deps .` -> exit 0; wheel contains
  `scanner_execution.py`.
- Real Windows Trivy (pinned 0.74.0, DB update explicitly skipped): exit 0,
  report parsed, all required components `complete`, receipt `findings`.
  Local Core alpha.3 independently returned artifact/evidence binding `pass`
  and the expected admission `fail` for findings.
- Exact PR head `54ca534dac9e66702ee2d7de39d01821367eb2cc` CI: `producer-ci`
  success (deterministic harness, real Trivy consumer, real OSV consumer) and
  `oci-exact-identity` success (deterministic OCI identity, real OCI Trivy
  consumer).

## Known limitations

The model proves the producer-observable process/output/result boundary; it
does not invent scanner-internal component coverage unavailable from the
scanner. OSV database snapshot remains `unavailable` by design. The first
real Windows Trivy run without skipping an expired DB update was stopped after
waiting and is not counted as evidence; the deterministic tests and the
successful skip-update run are the bounded local evidence. Registry networking
and real OSV/OCI runs are represented by exact-head CI. This work does not
standardize `install_time_execution`, change Registry schema/profile semantics,
claim Registry adoption, or prove server safety/name custody/publisher
identity/cryptographic attestation.

Closure predicate at the implementation-validation head: baseline audited;
zero findings not equated with completion; machine-readable completeness;
Trivy and OSV fail-closed; OCI exact identity preserved; partial execution
cannot emit clean; adversarial fixture passes; full relevant tests green;
exact head and Registry profile verified.
