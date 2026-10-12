from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.security import is_host_path_allowed, normalize_host_path, safe_host_path

MAX_COMMAND_BYTES = 64 * 1024
MAX_WRITE_ROOTS = 8
MAX_RUNTIME_SECONDS = 600
MAX_SCAN_ENTRIES = 20_000
PROFILES = ("inspect", "scoped-write")


class ManagedTerminalDenied(PermissionError):
    pass


def _safe_path(value: str, *, allow_root: bool = True) -> str:
    try:
        path = normalize_host_path(str(value or "/").strip() or "/")
    except ValueError as exc:
        raise ManagedTerminalDenied(str(exc)) from exc
    if not allow_root and path == "/":
        raise ManagedTerminalDenied("Managed terminal write root cannot be /")
    if any(ch.isspace() for ch in path) or any(ch in path for ch in "\x00\r\n"):
        raise ManagedTerminalDenied("Managed terminal paths cannot contain whitespace or control characters")
    if not is_host_path_allowed(path, Path("/")):
        raise ManagedTerminalDenied(f"Managed terminal path is restricted: {path}")
    return path


def normalize_write_roots(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > MAX_WRITE_ROOTS:
        raise ManagedTerminalDenied(f"Managed terminal supports at most {MAX_WRITE_ROOTS} write roots")
    roots: list[str] = []
    seen: set[str] = set()
    for value in values:
        root = _safe_path(str(value), allow_root=False)
        if root not in seen:
            roots.append(root)
            seen.add(root)
    return roots


def discover_scope_protections(cwd: str, host_root: Path, max_entries: int = MAX_SCAN_ENTRIES) -> dict[str, Any]:
    working_directory = _safe_path(cwd, allow_root=False)
    target = safe_host_path(working_directory, host_root)
    if not target.exists() or not target.is_dir():
        raise ManagedTerminalDenied("Managed terminal working directory must be an existing directory")
    resolved_root = target.resolve(strict=True)
    limit = max(100, min(int(max_entries), MAX_SCAN_ENTRIES))
    hidden: list[str] = []
    read_only: list[str] = []
    scanned = 0
    stack: list[tuple[Path, str]] = [(target, working_directory)]
    while stack:
        directory, host_directory = stack.pop()
        try:
            children = list(os.scandir(directory))
        except OSError as exc:
            raise ManagedTerminalDenied(f"Unable to inspect managed terminal scope: {host_directory}") from exc
        for entry in children:
            scanned += 1
            if scanned > limit:
                raise ManagedTerminalDenied("Managed terminal scope is too broad to verify safely; choose a narrower working directory")
            host_path = (host_directory.rstrip("/") + "/" + entry.name) if host_directory != "/" else "/" + entry.name
            path = Path(entry.path)
            if not is_host_path_allowed(host_path, host_root):
                hidden.append(host_path)
                continue
            try:
                if entry.is_symlink():
                    resolved = path.resolve(strict=False)
                    if resolved != resolved_root and not resolved.is_relative_to(resolved_root):
                        hidden.append(host_path)
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                hidden.append(host_path)
                continue
            if entry.name == ".git" and is_dir:
                read_only.append(host_path)
            parts = Path(host_path).parts
            if ".git" in parts:
                git_index = parts.index(".git")
                git_tail = parts[git_index + 1:]
                if git_tail and git_tail[0] in {"config", "config.worktree", "hooks", "credentials"}:
                    hidden.append(host_path)
                    continue
            if is_dir:
                stack.append((path, host_path))
    protected = sorted(set(hidden))
    readonly = sorted(set(read_only))
    combined = [*protected, *readonly]
    if len(combined) > 512 or sum(len(item) + 1 for item in combined) > 60_000:
        raise ManagedTerminalDenied("Managed terminal scope has too many protected paths; choose a narrower working directory")
    if any(any(ch.isspace() for ch in item) for item in combined):
        raise ManagedTerminalDenied("Managed terminal scope contains a protected path with whitespace that cannot be masked safely")
    return {
        "cwd": working_directory,
        "hidden_paths": protected,
        "read_only_paths": readonly,
        "scanned_entries": scanned,
    }


def profiles_info(write_roots: Any = None) -> dict[str, Any]:
    roots = normalize_write_roots(write_roots)
    return {
        "default_profile": "inspect",
        "network": "isolated",
        "profiles": [
            {
                "name": "inspect",
                "enabled": True,
                "host_read": True,
                "host_write": False,
                "write_roots": [],
                "description": "Selected-directory terminal mounted read-only inside an empty network-isolated filesystem namespace.",
            },
            {
                "name": "scoped-write",
                "enabled": bool(roots),
                "host_read": True,
                "host_write": bool(roots),
                "write_roots": roots,
                "description": "Selected-directory terminal with writes limited to explicit Joe-approved roots inside that directory.",
            },
        ],
    }


def build_managed_terminal_spec(
    profile: str,
    command: str,
    cwd: str = "/opt",
    write_roots: Any = None,
) -> dict[str, Any]:
    mode = str(profile or "inspect").strip().lower()
    if mode not in PROFILES:
        raise ManagedTerminalDenied("Managed terminal profile must be inspect or scoped-write")
    payload = str(command or "")
    encoded = payload.encode("utf-8")
    if not payload.strip() or len(encoded) > MAX_COMMAND_BYTES or "\x00" in payload:
        raise ManagedTerminalDenied("Managed terminal command must be non-empty, NUL-free, and at most 64 KiB")
    working_directory = _safe_path(cwd or "/", allow_root=False)
    roots = normalize_write_roots(write_roots)
    if mode == "inspect":
        roots = []
    elif not roots:
        raise ManagedTerminalDenied("scoped-write requires at least one explicit writable root")
    shell = Path("/bin/bash")
    if not shell.exists() or not shell.is_file():
        shell = Path("/bin/sh")
    if not shell.exists() or not shell.is_file():
        raise FileNotFoundError("No approved system shell is available")
    return {
        "profile": mode,
        "cwd": working_directory,
        "argv": [str(shell), "-s"],
        "display": f"{shell.name} -s [managed terminal command via stdin]",
        "stdin_payload": payload,
        "write_roots": roots,
        "network": "isolated",
        "max_runtime_seconds": MAX_RUNTIME_SECONDS,
    }
