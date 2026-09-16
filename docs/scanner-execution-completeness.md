# Scanner execution completeness

Status: project-defined producer invariant; it is not an MCP Registry schema
extension.

## Invariant

`absence of findings != evidence that the scanner completed successfully`.

The producer can emit a `clean` candidate only when both scanner-result
semantics and scanner-execution completeness hold:

```text
CLEAN_ELIGIBLE =
    scanner_invocation_started
AND scanner_process_completed
AND scanner_exit_state_is_valid_for_this_scanner
AND required_output_exists_and_is_non_empty
AND required_output_is_parseable
AND required_scanner_work_completed
AND result_semantics_are_consistent
```

The project-defined `evidence.json` extension is additive to
`project-defined-evidence-manifest-v1`:

```json
{
  "schema_extensions": ["project-defined-scanner-execution-v1"],
  "scanner_execution": {
    "scanner_contract": "trivy-fs-json-v1",
    "invocation_started": true,
    "process_completed": true,
    "exit_code": 0,
    "exit_state_valid": true,
    "output_present": true,
    "output_parseable": true,
    "required_components": [
      "scanner_process",
      "scanner_output",
      "result_sections",
      "artifact_binding",
      "result_semantics"
    ],
    "completed_components": [
      "scanner_process",
      "scanner_output",
      "result_sections",
      "artifact_binding",
      "result_semantics"
    ],
    "failed_components": [],
    "completeness_status": "complete",
    "completeness_reason": "all_required_scanner_work_completed",
    "required_work_completed": true,
    "result_semantics_consistent": true
  }
}
```

`output_present` means a non-empty output artifact; `output_exists` and
`output_size` preserve the distinction between missing and empty output. The
status is derived from the observed booleans and component lists, so a caller
cannot force `complete` by writing a status string.

## Scanner-specific contracts

- Trivy filesystem and OCI image producers invoke pinned Trivy with
  `--exit-code 0`. A normal process exit, non-empty parseable JSON, required
  Trivy sections, exact artifact binding, and the adapter's semantic checks are
  all required. A non-zero/negative exit, missing/empty/truncated JSON, missing
  sections, or identity mismatch is not complete.
- OSV-Scanner keeps its existing v2.5.1 contract: only exit `0` (packages with
  no findings) and exit `1` (packages with findings) are valid; a primary
  lockfile source, package data, source-path binding, and exit/data consistency
  remain required. No-package/error states remain fail-closed.

The producer records only the boundary it can verify. It does not invent
component-level completion that a scanner does not expose.

## Compatibility and boundaries

The `SecurityScanReceipt` v1 shape and
`registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22` profile remain
unchanged. `scanner_execution` is project-defined producer evidence and is not
stuffed into Registry standard fields, `scan_scope`, or a new standard
vocabulary. The producer does not prove global server safety, package/name
custody, publisher identity, or cryptographic attestation; the consumer/gate
still owns admission policy. Registry #1404 adoption is not claimed.

Legacy evidence manifests without the extension are not silently considered
complete. Regenerate them with the producer before using them to support a
clean claim.
