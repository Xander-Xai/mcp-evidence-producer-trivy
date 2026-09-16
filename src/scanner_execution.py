"""Project-defined scanner execution completeness evidence.

The MCP Registry receipt remains scanner-result focused.  This module keeps
the producer-owned execution contract separate from that receipt so a parsed
empty result can never, by itself, establish a clean verdict.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


SCHEMA_VERSION = "project-defined-scanner-execution-v1"
COMPLETENESS_STATUSES = frozenset({"complete", "incomplete", "failed"})


def _unique(values: Iterable[str]) -> list[str]:
    """Return stable, de-duplicated component names."""

    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def make_execution_evidence(
    *,
    invocation_started: bool,
    process_completed: bool,
    exit_code: int | None,
    exit_state_valid: bool,
    output_present: bool,
    output_parseable: bool,
    output_exists: bool | None = None,
    output_size: int | None = None,
    required_components: Iterable[str],
    completed_components: Iterable[str] = (),
    failed_components: Iterable[str] = (),
    result_semantics_consistent: bool | None = None,
    completeness_reason: str | None = None,
    scanner_contract: str,
    fatal_failure: bool = False,
) -> dict[str, Any]:
    """Build a deterministic execution record from observed facts.

    ``complete`` is derived only when every required component is present and
    no process/exit/output/semantic condition failed.  A caller cannot mark a
    record complete by supplying a status string alone.
    """

    required = _unique(required_components)
    completed = _unique(completed_components)
    failed = _unique(failed_components)

    all_required_completed = all(component in completed for component in required)
    if not invocation_started or not process_completed or fatal_failure:
        status = "failed"
    elif not (
        exit_state_valid
        and output_present
        and output_parseable
        and all_required_completed
        and not failed
        and result_semantics_consistent is True
    ):
        status = "incomplete"
    else:
        status = "complete"

    if completeness_reason is None:
        completeness_reason = "all_required_scanner_work_completed" if status == "complete" else "required_scanner_work_not_completed"

    return {
        "schema_version": SCHEMA_VERSION,
        "scanner_contract": scanner_contract,
        "invocation_started": invocation_started,
        "process_completed": process_completed,
        "exit_code": exit_code,
        "exit_state_valid": exit_state_valid,
        # ``output_present`` means a non-empty required output artifact exists.
        # ``output_exists`` and ``output_size`` retain the distinction between
        # missing and empty output for audit and regression diagnosis.
        "output_present": output_present,
        "output_exists": output_exists if output_exists is not None else output_present,
        "output_size": output_size,
        "output_parseable": output_parseable,
        "required_components": required,
        "completed_components": completed,
        "failed_components": failed,
        "completeness_status": status,
        "completeness_reason": completeness_reason,
        "required_work_completed": status == "complete",
        "result_semantics_consistent": result_semantics_consistent,
    }


def execution_is_complete(
    execution: Mapping[str, Any] | None,
    *,
    expected_exit_codes: Iterable[int] | None = None,
) -> bool:
    """Return whether an execution record is safe to use for a clean claim."""

    if not isinstance(execution, Mapping):
        return False
    if execution.get("completeness_status") != "complete":
        return False
    if execution.get("required_work_completed") is not True:
        return False
    if execution.get("invocation_started") is not True or execution.get("process_completed") is not True:
        return False
    if execution.get("exit_state_valid") is not True:
        return False
    if execution.get("output_present") is not True or execution.get("output_parseable") is not True:
        return False
    if execution.get("result_semantics_consistent") is not True:
        return False

    required = execution.get("required_components")
    completed = execution.get("completed_components")
    failed = execution.get("failed_components")
    if not isinstance(required, list) or not isinstance(completed, list) or not isinstance(failed, list):
        return False
    if failed or any(component not in completed for component in required):
        return False

    if expected_exit_codes is not None:
        exit_code = execution.get("exit_code")
        if not isinstance(exit_code, int) or exit_code not in set(expected_exit_codes):
            return False
    return True


def component_for_error(error: str, *, scanner: str | None = None) -> str:
    """Map scanner-specific validation errors to a stable evidence component.

    ``artifact_ref_mismatch`` is emitted by both Trivy and OSV validation, but
    the bound object differs: Trivy binds a report to an artifact while OSV
    binds each result source to the requested lockfile.  Keep the existing
    error reason and select the canonical component with scanner context.
    """

    if scanner == "osv" and error == "artifact_ref_mismatch":
        return "source_binding"

    if "artifact" in error or "oci_" in error:
        return "artifact_binding"
    if "exit" in error or "version" in error:
        return "result_semantics"
    if "source" in error or "lockfile" in error or "package" in error:
        return "source_binding"
    return "result_sections"
