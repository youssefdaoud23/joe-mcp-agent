from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from src.action_policy import authorize_service_action, authorize_systemd_unit_action
from src.git_ops import GitError, git_status
from src.security import redact_argv, redact_text


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


SERVICE_IDENTITY_FILE = Path(os.getenv("JOE_SERVICE_IDENTITY_FILE", "/var/lib/joe-mcp-work/service-code-identity.json"))


def _service_working_directory(unit: str) -> str | None:
    try:
        values = _show(unit, ("Id", "WorkingDirectory"))
    except SystemdError:
        return None
    value = str(values.get("WorkingDirectory") or "").strip()
    if not value or not value.startswith("/"):
        return None
    return str(Path(value).resolve(strict=False))


def _git_identity_for_path(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        status = git_status(path)
    except (GitError, FileNotFoundError, PermissionError, ValueError, OSError):
        return None
    return {
        "worktree": status.get("repository"),
        "branch": status.get("branch"),
        "head": status.get("head"),
        "clean": status.get("clean"),
        "worktree_matches_head": status.get("worktree_matches_head"),
        "common_git_directory": status.get("common_git_directory"),
        "worktree_kind": status.get("worktree_kind"),
    }


def _read_service_identity_state() -> dict[str, Any]:
    try:
        data = json.loads(SERVICE_IDENTITY_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": 1, "units": {}}
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "units": {}}
    if not isinstance(data, dict) or not isinstance(data.get("units"), dict):
        return {"version": 1, "units": {}}
    return data


def _write_service_identity_state(data: dict[str, Any]) -> None:
    SERVICE_IDENTITY_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = SERVICE_IDENTITY_FILE.with_name(f".{SERVICE_IDENTITY_FILE.name}.tmp")
    temp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, SERVICE_IDENTITY_FILE)


def _snapshot_service_runtime(unit: str, expected: dict[str, Any] | None = None) -> dict[str, Any]:
    status = service_status(unit)
    pid = int(status.get("main_pid") or 0)
    cwd: str | None = None
    executable: str | None = None
    argv: list[str] = []
    start_ticks: int | None = None
    if pid > 0:
        proc = Path("/proc") / str(pid)
        try:
            cwd = str((proc / "cwd").resolve(strict=True))
        except OSError:
            cwd = None
        try:
            executable = str((proc / "exe").resolve(strict=True))
        except OSError:
            executable = None
        try:
            raw = (proc / "cmdline").read_bytes()[:64_000]
            argv = [item.decode("utf-8", errors="replace") for item in raw.split(b"\x00") if item][:32]
        except OSError:
            argv = []
        try:
            fields = (proc / "stat").read_text(encoding="utf-8", errors="replace").split()
            start_ticks = int(fields[21]) if len(fields) > 21 else None
        except (OSError, ValueError):
            start_ticks = None
    working_directory = cwd or _service_working_directory(unit)
    actual_git = _git_identity_for_path(working_directory)
    captured = expected or {}
    runtime_commit = captured.get("head") if captured and actual_git and captured.get("worktree") == actual_git.get("worktree") else None
    runtime_verified = bool(runtime_commit and actual_git and actual_git.get("head") == runtime_commit)
    result = {
        "unit": unit,
        "pid": pid or None,
        "process_start_time": status.get("active_enter_timestamp"),
        "process_start_ticks": start_ticks,
        "working_directory": working_directory,
        "executable": executable,
        "argv": redact_argv(argv) if argv else None,
        "git_worktree": actual_git.get("worktree") if actual_git else None,
        "git_branch": actual_git.get("branch") if actual_git else None,
        "git_head": actual_git.get("head") if actual_git else None,
        "git_clean": actual_git.get("clean") if actual_git else None,
        "worktree_matches_head": actual_git.get("worktree_matches_head") if actual_git else None,
        "common_git_directory": actual_git.get("common_git_directory") if actual_git else None,
        "worktree_kind": actual_git.get("worktree_kind") if actual_git else None,
        "runtime_commit": runtime_commit,
        "runtime_commit_verified": runtime_verified,
        "captured_at": time.time(),
    }
    return result


def _record_service_runtime(unit: str, expected: dict[str, Any] | None = None) -> dict[str, Any]:
    identity = _snapshot_service_runtime(unit, expected)
    data = _read_service_identity_state()
    data["version"] = 1
    data.setdefault("units", {})[unit] = identity
    _write_service_identity_state(data)
    return identity


def service_code_identity(unit: str) -> dict[str, Any]:
    normalized = normalize_unit(unit)
    stored = _read_service_identity_state().get("units", {}).get(normalized, {})
    current = _snapshot_service_runtime(normalized)
    if isinstance(stored, dict):
        same_process = bool(stored.get("pid") and stored.get("pid") == current.get("pid") and stored.get("process_start_ticks") == current.get("process_start_ticks"))
        if same_process:
            current["runtime_commit"] = stored.get("runtime_commit") or stored.get("git_head")
            current["runtime_commit_verified"] = bool(current.get("runtime_commit") and current.get("git_head") == current.get("runtime_commit"))
            current["runtime_snapshot_at"] = stored.get("captured_at")
    return current


def service_action(unit: str, action: str) -> dict[str, Any]:
    normalized = normalize_unit(unit)
    normalized_action = str(action or "").strip().lower()
    authorize_service_action(normalized, normalized_action)
    before = service_status(normalized)
    expected_runtime = _git_identity_for_path(_service_working_directory(normalized)) if normalized_action in {"start", "restart"} else None
    _run([normalized_action, normalized], timeout=30.0, max_bytes=4_000)
    after = service_status(normalized)
    identity = _record_service_runtime(normalized, expected_runtime) if expected_runtime and normalized_action in {"start", "restart"} and after.get("active_state") == "active" else None
    if expected_runtime and identity and not identity.get("runtime_commit_verified"):
        raise SystemdError("Service started but runtime Git identity does not match the commit captured before launch")
    return {
        "unit": normalized,
        "action": normalized_action,
        "before": {"active_state": before.get("active_state"), "sub_state": before.get("sub_state"), "main_pid": before.get("main_pid")},
        "after": {"active_state": after.get("active_state"), "sub_state": after.get("sub_state"), "main_pid": after.get("main_pid")},
        "code_identity": identity,
    }


def unit_action(unit: str, action: str, confirm: bool = False) -> dict[str, Any]:
    normalized = normalize_systemd_unit(unit, {"service", "timer"})
    normalized_action = str(action or "").strip().lower()
    authorize_systemd_unit_action(normalized, normalized_action)
    if normalized_action in {"enable", "disable", "enable_now", "disable_now"} and confirm is not True:
        raise SystemdError("Changing systemd enablement requires confirm=true")
    before = service_status(normalized) if normalized.endswith(".service") else timer_status(normalized)
    expected_runtime = _git_identity_for_path(_service_working_directory(normalized)) if normalized.endswith(".service") and normalized_action in {"start", "restart", "enable_now"} else None
    if normalized_action == "enable_now":
        command = ["enable", "--now", normalized]
    elif normalized_action == "disable_now":
        command = ["disable", "--now", normalized]
    else:
        command = [normalized_action, normalized]
    _run(command, timeout=30.0, max_bytes=4_000)
    after = service_status(normalized) if normalized.endswith(".service") else timer_status(normalized)
    identity = _record_service_runtime(normalized, expected_runtime) if expected_runtime and normalized.endswith(".service") and normalized_action in {"start", "restart", "enable_now"} and after.get("active_state") == "active" else None
    if expected_runtime and identity and not identity.get("runtime_commit_verified"):
        raise SystemdError("Service started but runtime Git identity does not match the commit captured before launch")
    fields = ("active_state", "sub_state", "unit_file_state")
    return {
        "unit": normalized,
        "action": normalized_action,
        "before": {key: before.get(key) for key in fields},
        "after": {key: after.get(key) for key in fields},
        "code_identity": identity,
    }


def _to_int(value: str | None) -> int | None:
    if value is None or value in {"", "[not set]", "infinity"}:
        return None
    try:
        return int(value)
    except ValueError:
        return None
