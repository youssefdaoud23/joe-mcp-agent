from __future__ import annotations

import posixpath
from typing import Any

FULL_HOST_MODE = "full_host"
RESTRICTED_MODE = "restricted"
READ_ONLY = "read_only"
READ_WRITE = "read_write"
MAX_SCOPE_ROOTS = 8
MAX_PATH_CHARS = 4096


class FilesystemScopeError(ValueError):
    pass


def default_filesystem_policy() -> dict[str, Any]:
    return {"mode": FULL_HOST_MODE, "roots": []}


def _normalize_path(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw or not raw.startswith("/"):
        raise FilesystemScopeError("Filesystem scope paths must be absolute")
    if len(raw) > MAX_PATH_CHARS or any(ch in raw for ch in "\x00\r\n"):
        raise FilesystemScopeError("Filesystem scope path is invalid or too long")
    normalized = posixpath.normpath(raw)
    if not normalized.startswith("/"):
        raise FilesystemScopeError("Filesystem scope path is invalid")
    return normalized.rstrip("/") or "/"


def normalize_filesystem_policy(value: Any) -> dict[str, Any]:
    if value is None:
        return default_filesystem_policy()
    if not isinstance(value, dict):
        raise FilesystemScopeError("Filesystem policy must be an object")
    mode = str(value.get("mode") or FULL_HOST_MODE).strip().lower()
    if mode == FULL_HOST_MODE:
        return default_filesystem_policy()
    if mode != RESTRICTED_MODE:
        raise FilesystemScopeError("Filesystem policy mode must be full_host or restricted")
    raw_roots = value.get("roots")
    if not isinstance(raw_roots, list) or not raw_roots:
        raise FilesystemScopeError("Restricted filesystem policy requires at least one root")
    if len(raw_roots) > MAX_SCOPE_ROOTS:
        raise FilesystemScopeError(f"Filesystem policy supports at most {MAX_SCOPE_ROOTS} roots")
    roots: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in raw_roots:
        if not isinstance(raw, dict):
            raise FilesystemScopeError("Each filesystem root must be an object")
        path = _normalize_path(raw.get("path"))
        if path == "/":
            raise FilesystemScopeError("Use full_host mode instead of restricted root /")
        if path in seen:
            raise FilesystemScopeError(f"Duplicate filesystem root: {path}")
        access = str(raw.get("access") or READ_ONLY).strip().lower()
        if access not in {READ_ONLY, READ_WRITE}:
            raise FilesystemScopeError("Filesystem root access must be read_only or read_write")
        seen.add(path)
        roots.append({"path": path, "access": access})
    roots.sort(key=lambda item: (len(item["path"]), item["path"]))
    return {"mode": RESTRICTED_MODE, "roots": roots}


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def access_for_path(policy: Any, path: str) -> str | None:
    normalized_policy = normalize_filesystem_policy(policy)
    normalized_path = _normalize_path(path)
    if normalized_policy["mode"] == FULL_HOST_MODE:
        return READ_WRITE
    matches = [root for root in normalized_policy["roots"] if _within(normalized_path, root["path"])]
    if not matches:
        return None
    most_specific = max(matches, key=lambda item: len(item["path"]))
    return str(most_specific["access"])


def can_read(policy: Any, path: str) -> bool:
    return access_for_path(policy, path) in {READ_ONLY, READ_WRITE}


def can_write(policy: Any, path: str) -> bool:
    return access_for_path(policy, path) == READ_WRITE
