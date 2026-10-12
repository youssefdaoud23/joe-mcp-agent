from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from typing import Any

from src.action_policy import authorize_service_action, authorize_systemd_unit_action
from src.security import redact_text


SYSTEMD_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "HOME": "/",
    "PAGER": "cat",
    "SYSTEMD_PAGER": "cat",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_LOG_LEVEL": "warning",
    "NO_COLOR": "1",
}
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,256}$")
MAX_OUTPUT_BYTES = 500_000
MAX_RESULTS = 500
UNIT_TEXT_BYTES = 200_000
ENV_LINE_RE = re.compile(r"(?im)^(\s*Environment(?:File)?\s*=).*$")


class SystemdError(RuntimeError):
    pass


def _run(args: list[str], timeout: float = 8.0, max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    try:
        completed = subprocess.run(
            ["systemctl", *args],
            env=SYSTEMD_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SystemdError("systemctl is unavailable on the host") from exc
    except subprocess.TimeoutExpired as exc:
        raise SystemdError("systemctl operation timed out") from exc
    if completed.returncode != 0:
        error = completed.stderr[:4000].decode("utf-8", errors="replace").strip()
        raise SystemdError(error or f"systemctl exited with status {completed.returncode}")
    raw = completed.stdout
    truncated = len(raw) > max_bytes
    text = raw[:max_bytes].decode("utf-8", errors="replace")
    if truncated:
        text += "\n[TRUNCATED]"
    return text


def normalize_systemd_unit(unit: str, allowed_types: set[str] | None = None) -> str:
    value = str(unit or "").strip()
    if not value:
        raise ValueError("unit cannot be empty")
    allowed = allowed_types or {"service"}
    if "." not in value:
        default_type = "service" if "service" in allowed else sorted(allowed)[0]
        value += f".{default_type}"
    if not UNIT_RE.fullmatch(value):
        raise ValueError("unit contains unsupported characters")
    suffix = value.rsplit(".", 1)[-1]
    if suffix not in allowed:
        raise ValueError(f"only {', '.join(sorted(allowed))} systemd units are supported")
    return value


def normalize_unit(unit: str) -> str:
    return normalize_systemd_unit(unit, {"service"})


def _list_units(kind: str, pattern: str, max_results: int) -> dict[str, Any]:
    if not pattern or len(pattern) > 256:
        raise ValueError("pattern must contain 1 to 256 characters")
    if kind not in {"service", "timer"}:
        raise ValueError("unsupported systemd unit type")
    limit = max(1, min(int(max_results), MAX_RESULTS))
    output = _run([
        "list-units",
        f"--type={kind}",
        "--all",
        "--no-legend",
        "--no-pager",
        "--plain",
    ])
    needle = pattern.lower()
    rows: list[dict[str, str]] = []
    matched_total = 0
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line == "[TRUNCATED]":
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[:4]
        description = parts[4] if len(parts) == 5 else ""
        if not unit.endswith(f".{kind}") or not fnmatch.fnmatchcase(unit.lower(), needle):
            continue
        matched_total += 1
        if len(rows) < limit:
            rows.append({
                "unit": unit,
                "load": load,
                "active": active,
                "sub": sub,
                "description": description[:500],
            })
    return {
        "pattern": pattern,
        f"{kind}s": rows,
        "result_count": len(rows),
        "matched_total": matched_total,
        "truncated": matched_total > len(rows),
    }


def list_services(pattern: str = "*", max_results: int = 200) -> dict[str, Any]:
    return _list_units("service", pattern, max_results)


def list_timers(pattern: str = "*", max_results: int = 200) -> dict[str, Any]:
    return _list_units("timer", pattern, max_results)


def failed_units(max_results: int = 200) -> dict[str, Any]:
    limit = max(1, min(int(max_results), MAX_RESULTS))
    output = _run(["list-units", "--failed", "--all", "--no-legend", "--no-pager", "--plain"])
    rows: list[dict[str, str]] = []
    total = 0
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line == "[TRUNCATED]":
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[:4]
        description = parts[4] if len(parts) == 5 else ""
        total += 1
        if len(rows) < limit:
            rows.append({"unit": unit, "load": load, "active": active, "sub": sub, "description": description[:500]})
    return {"units": rows, "result_count": len(rows), "matched_total": total, "truncated": total > len(rows)}


STATUS_PROPERTIES = (
    "Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "Result",
    "MainPID", "ExecMainCode", "ExecMainStatus", "NRestarts", "TasksCurrent", "MemoryCurrent",
    "CPUUsageNSec", "ActiveEnterTimestamp", "InactiveEnterTimestamp",
)
TIMER_PROPERTIES = (
    "Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "Result",
    "NextElapseUSecRealtime", "NextElapseUSecMonotonic", "LastTriggerUSec", "Triggers", "Persistent",
    "RemainAfterElapse", "AccuracyUSec", "RandomizedDelayUSec",
)


def _show(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    args = ["show", unit, "--no-pager"]
    for prop in properties:
        args.append(f"--property={prop}")
    output = _run(args, max_bytes=64_000)
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in properties:
            values[key] = value[:4000]
    if not values.get("Id"):
        raise SystemdError(f"Systemd unit not found: {unit}")
    return values


def service_status(unit: str) -> dict[str, Any]:
    normalized = normalize_unit(unit)
    values = _show(normalized, STATUS_PROPERTIES)
    return {
        "unit": normalized,
        "description": values.get("Description") or None,
        "load_state": values.get("LoadState") or None,
        "active_state": values.get("ActiveState") or None,
        "sub_state": values.get("SubState") or None,
        "unit_file_state": values.get("UnitFileState") or None,
        "result": values.get("Result") or None,
        "main_pid": _to_int(values.get("MainPID")),
        "exec_main_code": _to_int(values.get("ExecMainCode")),
        "exec_main_status": _to_int(values.get("ExecMainStatus")),
        "restarts": _to_int(values.get("NRestarts")),
        "tasks_current": _to_int(values.get("TasksCurrent")),
        "memory_current": _to_int(values.get("MemoryCurrent")),
        "cpu_usage_nsec": _to_int(values.get("CPUUsageNSec")),
        "active_enter_timestamp": values.get("ActiveEnterTimestamp") or None,
        "inactive_enter_timestamp": values.get("InactiveEnterTimestamp") or None,
    }


def timer_status(unit: str) -> dict[str, Any]:
    normalized = normalize_systemd_unit(unit, {"timer"})
    values = _show(normalized, TIMER_PROPERTIES)
    return {
        "unit": normalized,
        "description": values.get("Description") or None,
        "load_state": values.get("LoadState") or None,
        "active_state": values.get("ActiveState") or None,
        "sub_state": values.get("SubState") or None,
        "unit_file_state": values.get("UnitFileState") or None,
        "result": values.get("Result") or None,
        "next_elapse_realtime": values.get("NextElapseUSecRealtime") or None,
        "next_elapse_monotonic": values.get("NextElapseUSecMonotonic") or None,
        "last_trigger": values.get("LastTriggerUSec") or None,
        "triggers": values.get("Triggers") or None,
        "persistent": values.get("Persistent") == "yes",
        "remain_after_elapse": values.get("RemainAfterElapse") == "yes",
        "accuracy_usec": _to_int(values.get("AccuracyUSec")),
        "randomized_delay_usec": _to_int(values.get("RandomizedDelayUSec")),
    }


def unit_file(unit: str) -> dict[str, Any]:
    normalized = normalize_systemd_unit(unit, {"service", "timer"})
    props = _run([
        "show", normalized, "--no-pager",
        "--property=Id", "--property=FragmentPath", "--property=DropInPaths", "--property=UnitFileState",
    ], max_bytes=64_000)
    values: dict[str, str] = {}
    for line in props.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value[:8000]
    if not values.get("Id"):
        raise SystemdError(f"Systemd unit not found: {normalized}")
    content = _run(["cat", normalized, "--no-pager"], max_bytes=UNIT_TEXT_BYTES)
    content = ENV_LINE_RE.sub(r"\1[REDACTED]", content)
    content = redact_text(content, 16_000)
    return {
        "unit": normalized,
        "fragment_path": values.get("FragmentPath") or None,
        "drop_in_paths": values.get("DropInPaths") or None,
        "unit_file_state": values.get("UnitFileState") or None,
        "content": content,
        "redaction": "environment values and common credentials hidden",
    }


def service_action(unit: str, action: str) -> dict[str, Any]:
    normalized = normalize_unit(unit)
    normalized_action = str(action or "").strip().lower()
    authorize_service_action(normalized, normalized_action)
    before = service_status(normalized)
    _run([normalized_action, normalized], timeout=30.0, max_bytes=4_000)
    after = service_status(normalized)
    return {
        "unit": normalized,
        "action": normalized_action,
        "before": {"active_state": before.get("active_state"), "sub_state": before.get("sub_state"), "main_pid": before.get("main_pid")},
        "after": {"active_state": after.get("active_state"), "sub_state": after.get("sub_state"), "main_pid": after.get("main_pid")},
    }


def unit_action(unit: str, action: str, confirm: bool = False) -> dict[str, Any]:
    normalized = normalize_systemd_unit(unit, {"service", "timer"})
    normalized_action = str(action or "").strip().lower()
    authorize_systemd_unit_action(normalized, normalized_action)
    if normalized_action in {"enable", "disable", "enable_now", "disable_now"} and confirm is not True:
        raise SystemdError("Changing systemd enablement requires confirm=true")
    before = service_status(normalized) if normalized.endswith(".service") else timer_status(normalized)
    if normalized_action == "enable_now":
        command = ["enable", "--now", normalized]
    elif normalized_action == "disable_now":
        command = ["disable", "--now", normalized]
    else:
        command = [normalized_action, normalized]
    _run(command, timeout=30.0, max_bytes=4_000)
    after = service_status(normalized) if normalized.endswith(".service") else timer_status(normalized)
    fields = ("active_state", "sub_state", "unit_file_state")
    return {
        "unit": normalized,
        "action": normalized_action,
        "before": {key: before.get(key) for key in fields},
        "after": {key: after.get(key) for key in fields},
    }


def _to_int(value: str | None) -> int | None:
    if value is None or value in {"", "[not set]", "infinity"}:
        return None
    try:
        return int(value)
    except ValueError:
        return None
