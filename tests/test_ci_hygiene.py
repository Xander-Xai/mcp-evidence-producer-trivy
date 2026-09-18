from __future__ import annotations

from scripts.check_action_pins import violations


FULL_SHA = "11d5960a326750d5838078e36cf38b85af677262"


def test_immutable_list_action_passes() -> None:
    assert violations(f"- uses: actions/checkout@{FULL_SHA}\n") == []


def test_job_level_remote_reusable_workflow_passes() -> None:
    assert violations(f"uses: owner/repo/.github/workflows/test.yml@{FULL_SHA}\n") == []


def test_local_action_and_workflow_pass() -> None:
    assert violations("- uses: ./my-action\nuses: ./.github/workflows/example.yml\n") == []


def test_list_form_v4_is_rejected() -> None:
    assert violations("- uses: actions/checkout@v4\n")


def test_job_level_v1_is_rejected() -> None:
    assert violations("uses: owner/action@v1\n")


def test_symbolic_refs_are_rejected() -> None:
    for ref in ("main", "master", "latest", "stable", "release"):
        assert violations(f"- uses: owner/action@{ref}\n")


def test_short_sha_is_rejected() -> None:
    assert violations("- uses: owner/action@abcdef1\n")


def test_dynamic_external_ref_is_rejected() -> None:
    assert violations("- uses: owner/action@${{ inputs.ref }}\n")


def test_remote_reusable_workflow_tag_is_rejected() -> None:
    assert violations("uses: owner/repo/.github/workflows/test.yml@v1\n")


def test_comments_are_not_active_references() -> None:
    assert violations("# - uses: actions/checkout@v4\n") == []


def test_quoted_target_and_trailing_comment_pass() -> None:
    assert violations(f'- uses: "actions/checkout@{FULL_SHA}" # audited\n') == []
