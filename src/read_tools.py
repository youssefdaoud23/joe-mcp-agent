from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any

from src.security import safe_host_path

MAX_READ_LINES = 1000
MAX_READ_BYTES = 1_000_000
MAX_MULTI_FILES = 20


def _limits(offset: int, length: int, max_bytes: int) -> tuple[int, int, int]:
    clean_offset = int(offset)
    clean_length = max(1, min(int(length), MAX_READ_LINES))
    clean_bytes = max(1, min(int(max_bytes), MAX_READ_BYTES))
    if clean_offset < -MAX_READ_LINES:
        clean_offset = -MAX_READ_LINES
    return clean_offset, clean_length, clean_bytes


def _bounded_text(lines: list[str], max_bytes: int) -> tuple[str, int, bool]:
    output: list[str] = []
    used = 0
    truncated = False
    for line in lines:
        raw = line.encode("utf-8", errors="replace")
        if used + len(raw) > max_bytes:
            remaining = max_bytes - used
            if remaining > 0:
                output.append(raw[:remaining].decode("utf-8", errors="replace"))
                used = max_bytes
            truncated = True
            break
        output.append(line)
        used += len(raw)
    return "".join(output), used, truncated


def read_text_page(
    path: str,
    host_root: Path,
    offset: int = 0,
    length: int = 200,
    max_bytes: int = 100_000,
) -> dict[str, Any]:
    target = safe_host_path(path, host_root)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(path)

    clean_offset, clean_length, clean_bytes = _limits(offset, length, max_bytes)

    if clean_offset < 0:
        tail_count = abs(clean_offset)
        tail: deque[str] = deque(maxlen=tail_count)
        total_lines = 0
        with target.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                total_lines += 1
                tail.append(line)
        selected = list(tail)
        content, bytes_returned, byte_truncated = _bounded_text(selected, clean_bytes)
        start_line = max(0, total_lines - len(selected))
        return {
            "path": path,
            "content": content,
            "offset": clean_offset,
            "length": tail_count,
            "start_line": start_line,
            "lines_returned": len(selected),
            "total_lines": total_lines,
            "bytes_returned": bytes_returned,
            "has_more": False,
            "truncated": byte_truncated,
            "tail": True,
        }

    selected: list[str] = []
    has_more = False
    total_seen = 0
    with target.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            total_seen = index + 1
            if index < clean_offset:
                continue
            if len(selected) < clean_length:
                selected.append(line)
                continue
            has_more = True
            break

    content, bytes_returned, byte_truncated = _bounded_text(selected, clean_bytes)
    if byte_truncated:
        has_more = True

    return {
        "path": path,
        "content": content,
        "offset": clean_offset,
        "length": clean_length,
        "start_line": clean_offset,
        "lines_returned": len(selected),
        "total_lines": total_seen if not has_more else None,
        "bytes_returned": bytes_returned,
        "has_more": has_more,
        "truncated": byte_truncated,
        "tail": False,
    }


def read_multiple_text_files(
    paths: list[str],
    host_root: Path,
    offset: int = 0,
    length: int = 200,
    max_bytes_per_file: int = 100_000,
) -> dict[str, Any]:
    if not isinstance(paths, list) or not paths:
        raise ValueError("paths must contain at least one absolute path")
    if len(paths) > MAX_MULTI_FILES:
        raise ValueError(f"at most {MAX_MULTI_FILES} files may be read at once")

    results: list[dict[str, Any]] = []
    for path in paths:
        try:
            result = read_text_page(str(path), host_root, offset, length, max_bytes_per_file)
            result["ok"] = True
            results.append(result)
        except (FileNotFoundError, PermissionError, ValueError, OSError) as exc:
            results.append({"path": str(path), "ok": False, "error": str(exc)})

    return {
        "files": results,
        "requested_count": len(paths),
        "success_count": sum(1 for item in results if item.get("ok")),
        "error_count": sum(1 for item in results if not item.get("ok")),
    }
