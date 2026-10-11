from __future__ import annotations

import os
from pathlib import Path

from src.security import AccessDenied, normalize_host_path, safe_host_path


class WriteDenied(PermissionError):
    """Raised when a path is outside Joe MCP's writable policy."""


PROJECT_ROOT = os.getenv("JOE_PROJECT_ROOT", "/opt/joe-mcp-server").rstrip("/") or "/opt/joe-mcp-server"
DEFAULT_WRITE_ROOTS = (PROJECT_ROOT, "/var/lib/joe-mcp-work")
PROTECTED_PREFIXES = (
    f"{PROJECT_ROOT}/.git", f"{PROJECT_ROOT}/.secrets", f"{PROJECT_ROOT}/data/auth",
    f"{PROJECT_ROOT}/data/audit", f"{PROJECT_ROOT}/data/devices", f"{PROJECT_ROOT}/data/sessions",
    "/var/lib/joe-mcp-work/actions.json",
    "/var/lib/joe-mcp-work/workspaces.json",
    "/var/lib/joe-mcp-work/persistent-sessions",
    "/var/lib/joe-mcp-work/controller-state",
    "/var/lib/joe-mcp-work/trash",
)


def writable_roots() -> tuple[str, ...]:
    raw = os.getenv("JOE_WRITE_ROOTS", "").strip()
    roots = [item.strip() for item in raw.split(",") if item.strip()] if raw else list(DEFAULT_WRITE_ROOTS)
    normalized: list[str] = []
    for root in roots:
        value = normalize_host_path(root)
        if value == "/":
            raise WriteDenied("The filesystem root cannot be configured as a writable root")
        normalized.append(value.rstrip("/") or "/")
    return tuple(dict.fromkeys(normalized))


def mutation_roots() -> tuple[str, ...]:
    roots = list(writable_roots())
    try:
        from src.workspace_policy import WorkspaceDenied, workspace_mutation_roots
        roots.extend(workspace_mutation_roots())
    except (WorkspaceDenied, OSError, ValueError):
        pass
    return tuple(dict.fromkeys(roots))


def _is_within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def _protected(path: str) -> str | None:
    lowered = path.lower().rstrip("/") or "/"
    for prefix in PROTECTED_PREFIXES:
        p = prefix.lower().rstrip("/")
        if lowered == p or lowered.startswith(p + "/"):
            return prefix
    try:
        from src.workspace_policy import WorkspaceDenied, workspace_path_protected
        workspace_protected = workspace_path_protected(path)
        if workspace_protected:
            return workspace_protected
    except (WorkspaceDenied, OSError, ValueError):
        pass
    return None


def safe_write_path(path: str, *, must_exist: bool | None = None) -> Path:
    normalized = normalize_host_path(path)
    protected = _protected(normalized)
    if protected:
        raise WriteDenied(f"Write denied for {normalized}: protected area {protected}")
    try:
        candidate = safe_host_path(normalized, Path("/"))
    except (AccessDenied, ValueError, OSError) as exc:
        raise WriteDenied(str(exc)) from exc
    if candidate.is_symlink():
        raise WriteDenied(f"Write denied for {normalized}: target symlinks are not writable")
    resolved = candidate.resolve(strict=False)
    protected_resolved = _protected(str(resolved))
    if protected_resolved:
        raise WriteDenied(f"Write denied for {normalized}: resolved target is protected ({protected_resolved})")
    roots = [Path(root).resolve(strict=False) for root in mutation_roots()]
    if not any(_is_within(resolved, root) for root in roots):
        raise WriteDenied(f"Write denied for {normalized}: path is outside configured writable/workspace roots")
    if must_exist is True and not candidate.exists():
        raise FileNotFoundError(normalized)
    if must_exist is False and candidate.exists():
        raise FileExistsError(normalized)
    return candidate


def writable_policy_info() -> dict[str, object]:
    return {
        "roots": list(writable_roots()),
        "workspace_mutation_roots": [root for root in mutation_roots() if root not in writable_roots()],
        "protected_prefixes": list(PROTECTED_PREFIXES),
        "workspace_secret_protection": True,
        "target_symlinks_allowed": False,
    }
