from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any

from src.security import redact_text
from src.systemd_ops import normalize_unit


JOURNAL_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/", "PAGER": "cat",
    "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0", "NO_COLOR": "1",
}
MAX_LINES = 500
MAX_SCAN_LINES = 2500
MAX_SINCE_MINUTES = 43_200
MAX_OUTPUT_BYTES = 2_000_000
MAX_MESSAGE_CHARS = 4000
MAX_TEXT_FILTER = 500


class JournalError(RuntimeError):
    pass


def _run_journal(args: list[str], timeout: float = 10.0) -> str:
    try:
        completed = subprocess.run(
            ["journalctl", *args], env=JOURNAL_ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise JournalError("journalctl is unavailable on the host") from exc
    except subprocess.TimeoutExpired as exc:
        raise JournalError("journalctl operation timed out") from exc
    if completed.returncode != 0:
        error = completed.stderr[:4000].decode("utf-8", errors="replace").strip()
        raise JournalError(error or f"journalctl exited with status {completed.returncode}")
    raw = completed.stdout[:MAX_OUTPUT_BYTES]
    return raw.decode("utf-8", errors="replace")


def _timestamp(value: Any) -> str | None:
    try:
        micros = int(str(value))
        return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _integer(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _iso_bound(value: str, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) > 64 or "\x00" in text:
        raise JournalError(f"Invalid journal {label} time")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise JournalError(f"Journal {label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def journal_logs(
    unit: str,
    lines: int = 200,
    since_minutes: int = 0,
    text: str = "",
    since: str = "",
    until: str = "",
) -> dict[str, Any]:
    normalized = normalize_unit(unit)
    line_limit = max(1, min(int(lines), MAX_LINES))
    since_window = max(0, min(int(since_minutes), MAX_SINCE_MINUTES))
    needle = str(text or "").strip()
    if len(needle) > MAX_TEXT_FILTER or "\x00" in needle or "\n" in needle or "\r" in needle:
        raise JournalError("Journal text filter is invalid or too long")
    since_bound = _iso_bound(since, "since")
    until_bound = _iso_bound(until, "until")
    if since_bound and since_window:
        raise JournalError("Use either since_minutes or since, not both")

    scan_lines = min(MAX_SCAN_LINES, max(line_limit, line_limit * 5 if needle else line_limit))
    args = ["--unit", normalized, "--no-pager", "--output=json", f"--lines={scan_lines}"]
    if since_bound:
        args.extend(["--since", since_bound])
    elif since_window:
        args.extend(["--since", f"{since_window} minutes ago"])
    if until_bound:
        args.extend(["--until", until_bound])

    output = _run_journal(args)
    entries: list[dict[str, Any]] = []
    parse_errors = 0
    matched_total = 0
    needle_lower = needle.lower()
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        if not isinstance(record, dict):
            continue
        raw_message = record.get("MESSAGE", "")
        message = redact_text(raw_message, MAX_MESSAGE_CHARS) if isinstance(raw_message, str) else "[BINARY OR NON-TEXT JOURNAL MESSAGE OMITTED]"
        identifier = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM")
        if needle_lower and needle_lower not in message.lower() and needle_lower not in str(identifier or "").lower():
            continue
        matched_total += 1
        if len(entries) < line_limit:
            entries.append({
                "timestamp": _timestamp(record.get("__REALTIME_TIMESTAMP")),
                "priority": _integer(record.get("PRIORITY")),
                "pid": _integer(record.get("_PID")),
                "identifier": str(identifier)[:256] if identifier is not None else None,
                "message": message,
            })

    return {
        "unit": normalized, "requested_lines": line_limit, "since_minutes": since_window,
        "since": since_bound or None, "until": until_bound or None, "text_filter": needle or None,
        "entries": entries, "entry_count": len(entries), "matched_total": matched_total,
        "scan_lines": scan_lines, "parse_errors": parse_errors, "redaction": "enabled",
        "truncated": matched_total > len(entries),
    }

def journal_diagnostics(
    lines: int = 200,
    since_minutes: int = 60,
    priority_max: int = 3,
    text: str = "",
    current_boot: bool = True,
    kernel_only: bool = False,
) -> dict[str, Any]:
    line_limit = max(1, min(int(lines), MAX_LINES))
    since_window = max(0, min(int(since_minutes), MAX_SINCE_MINUTES))
    priority = max(0, min(int(priority_max), 7))
    needle = str(text or "").strip()
    if len(needle) > MAX_TEXT_FILTER or any(ch in needle for ch in "\x00\r\n"):
        raise JournalError("Journal text filter is invalid or too long")
    scan_lines = min(MAX_SCAN_LINES, max(line_limit, line_limit * 5 if needle else line_limit))
    args = ["--no-pager", "--output=json", f"--lines={scan_lines}", f"--priority=0..{priority}"]
    if current_boot:
        args.append("--boot")
    if kernel_only:
        args.append("--dmesg")
    if since_window:
        args.extend(["--since", f"{since_window} minutes ago"])
    output = _run_journal(args)
    entries: list[dict[str, Any]] = []
    parse_errors = 0
    matched_total = 0
    needle_lower = needle.lower()
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        if not isinstance(record, dict):
            continue
        raw_message = record.get("MESSAGE", "")
        message = redact_text(raw_message, MAX_MESSAGE_CHARS) if isinstance(raw_message, str) else "[BINARY OR NON-TEXT JOURNAL MESSAGE OMITTED]"
        identifier = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or record.get("_KERNEL_SUBSYSTEM")
        if needle_lower and needle_lower not in message.lower() and needle_lower not in str(identifier or "").lower():
            continue
        matched_total += 1
        if len(entries) < line_limit:
            entries.append({
                "timestamp": _timestamp(record.get("__REALTIME_TIMESTAMP")),
                "priority": _integer(record.get("PRIORITY")),
                "pid": _integer(record.get("_PID")),
                "identifier": str(identifier)[:256] if identifier is not None else None,
                "message": message,
            })
    return {
        "scope": "kernel" if kernel_only else "system",
        "current_boot": bool(current_boot), "priority_max": priority,
        "requested_lines": line_limit, "since_minutes": since_window, "text_filter": needle or None,
        "entries": entries, "entry_count": len(entries), "matched_total": matched_total,
        "scan_lines": scan_lines, "parse_errors": parse_errors, "redaction": "enabled",
        "truncated": matched_total > len(entries),
    }


def kernel_diagnostics(lines: int = 200, since_minutes: int = 0, priority_max: int = 4, text: str = "") -> dict[str, Any]:
    return journal_diagnostics(lines=lines, since_minutes=since_minutes, priority_max=priority_max, text=text, current_boot=True, kernel_only=True)

