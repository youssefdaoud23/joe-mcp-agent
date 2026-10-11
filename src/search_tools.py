from __future__ import annotations

import fnmatch
from collections import deque
from pathlib import Path
from typing import Any

from src.security import is_host_path_allowed, normalize_host_path, redact_text, safe_host_path

SEARCH_DENIED_PREFIXES = ("/proc", "/sys", "/dev", "/run")
SKIP_DIR_NAMES = {".git", ".cache", "node_modules", ".venv", "venv", "__pycache__"}
MAX_SCAN_ENTRIES = 50_000
MAX_RESULTS = 500
MAX_DEPTH = 20
MAX_CONTENT_FILE_BYTES = 1_000_000


def _display_child(parent: str, name: str) -> str:
    base = parent.rstrip("/") or "/"
    return f"/{name}" if base == "/" else f"{base}/{name}"


def _search_prefix_denied(path: str) -> bool:
    normalized = normalize_host_path(path)
    return any(normalized == prefix or normalized.startswith(prefix + "/") for prefix in SEARCH_DENIED_PREFIXES)


def _limits(max_results: int, max_depth: int, max_scanned: int) -> tuple[int, int, int]:
    results = max(1, min(int(max_results), MAX_RESULTS))
    depth = max(0, min(int(max_depth), MAX_DEPTH))
    scanned = max(1, min(int(max_scanned), MAX_SCAN_ENTRIES))
    return results, depth, scanned


def _walk(root: str, host_root: Path, max_depth: int, max_scanned: int, include_hidden: bool):
    normalized = normalize_host_path(root)
    if _search_prefix_denied(normalized):
        raise PermissionError(f"Search root is restricted: {normalized}")
    target = safe_host_path(normalized, host_root)
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(normalized)

    queue: deque[tuple[Path, str, int]] = deque([(target, normalized, 0)])
    scanned = 0
    while queue and scanned < max_scanned:
        directory, display_dir, depth = queue.popleft()
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name.lower())
        except OSError:
            continue
        for child in entries:
            if scanned >= max_scanned:
                break
            scanned += 1
            name = child.name
            if not include_hidden and name.startswith("."):
                continue
            display = _display_child(display_dir, name)
            if _search_prefix_denied(display):
                continue
            if not is_host_path_allowed(display, host_root):
                continue
            try:
                if child.is_symlink():
                    continue
                is_dir = child.is_dir()
                is_file = child.is_file()
            except OSError:
                continue
            yield child, display, depth, scanned, is_dir, is_file
            if is_dir and depth < max_depth and name not in SKIP_DIR_NAMES:
                queue.append((child, display, depth + 1))


def search_files(
    root: str,
    pattern: str,
    host_root: Path,
    max_results: int = 200,
    max_depth: int = 8,
    max_scanned: int = 10_000,
    include_hidden: bool = False,
) -> dict[str, Any]:
    if not pattern or len(pattern) > 512:
        raise ValueError("pattern must contain 1 to 512 characters")
    result_limit, depth_limit, scan_limit = _limits(max_results, max_depth, max_scanned)
    needle = pattern.lower()
    results: list[dict[str, Any]] = []
    scanned = 0
    for child, display, _depth, scanned_now, is_dir, is_file in _walk(
        root, host_root, depth_limit, scan_limit, bool(include_hidden)
    ):
        scanned = scanned_now
        if fnmatch.fnmatchcase(child.name.lower(), needle):
            try:
                size = child.stat().st_size if is_file else None
            except OSError:
                size = None
            results.append({"path": display, "type": "directory" if is_dir else "file", "size": size})
            if len(results) >= result_limit:
                break
    return {
        "root": normalize_host_path(root),
        "pattern": pattern,
        "results": results,
        "result_count": len(results),
        "scanned_entries": scanned,
        "truncated": len(results) >= result_limit or scanned >= scan_limit,
    }


def search_content(
    root: str,
    query: str,
    host_root: Path,
    file_glob: str = "*",
    max_results: int = 100,
    max_depth: int = 8,
    max_scanned: int = 10_000,
    case_sensitive: bool = False,
    include_hidden: bool = False,
) -> dict[str, Any]:
    if not query or len(query) > 512:
        raise ValueError("query must contain 1 to 512 characters")
    if not file_glob or len(file_glob) > 512:
        raise ValueError("file_glob must contain 1 to 512 characters")
    result_limit, depth_limit, scan_limit = _limits(max_results, max_depth, max_scanned)
    match_query = query if case_sensitive else query.lower()
    glob = file_glob if case_sensitive else file_glob.lower()
    results: list[dict[str, Any]] = []
    scanned = 0
    files_examined = 0

    for child, display, _depth, scanned_now, _is_dir, is_file in _walk(
        root, host_root, depth_limit, scan_limit, bool(include_hidden)
    ):
        scanned = scanned_now
        if not is_file:
            continue
        name = child.name if case_sensitive else child.name.lower()
        if not fnmatch.fnmatchcase(name, glob):
            continue
        try:
            size = child.stat().st_size
        except OSError:
            continue
        if size > MAX_CONTENT_FILE_BYTES:
            continue
        try:
            raw = child.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        files_examined += 1
        text = raw.decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            haystack = line if case_sensitive else line.lower()
            if match_query in haystack:
                results.append({"path": display, "line": line_number, "text": redact_text(line, 500)})
                if len(results) >= result_limit:
                    return {
                        "root": normalize_host_path(root),
                        "query": query,
                        "file_glob": file_glob,
                        "results": results,
                        "result_count": len(results),
                        "scanned_entries": scanned,
                        "files_examined": files_examined,
                        "truncated": True,
                    }

    return {
        "root": normalize_host_path(root),
        "query": query,
        "file_glob": file_glob,
        "results": results,
        "result_count": len(results),
        "scanned_entries": scanned,
        "files_examined": files_examined,
        "truncated": scanned >= scan_limit,
    }
