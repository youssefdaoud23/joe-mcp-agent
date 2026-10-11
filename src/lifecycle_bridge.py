from __future__ import annotations

from typing import Any

from src.bridge_client import request


def git_restore_to_commit(
    path: str,
    target_commit: str,
    expected_head: str,
    confirm: bool = False,
) -> dict[str, Any]:
    return request(
        "git_reset_to_commit",
        path=path,
        target_commit=target_commit,
        expected_head=expected_head,
        confirm=confirm,
    )


def git_restore_previous(path: str, expected_head: str, confirm: bool = False) -> dict[str, Any]:
    return request(
        "git_rollback_last",
        path=path,
        expected_head=expected_head,
        confirm=confirm,
    )
