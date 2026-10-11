from __future__ import annotations

import json
import os
import re
import resource
import signal
import socketserver
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.action_policy import ActionDenied, action_policy_info, update_action_capabilities, update_action_policy
from src.command_policy import CommandDenied, allowed_commands, validate_command
from src.docker_ops import DockerError, docker_action, docker_container_status, docker_containers, docker_logs
from src.file_ops import copy_file, create_directory, edit_file, list_trash, move_file, purge_trash, restore_trash, trash_path, write_file
from src.rich_write import create_pdf, edit_xlsx_range
from src.git_ops import (GitError, git_branch_create, git_branch_switch, git_branches, git_commit, git_credentials_info, git_diff, git_log, git_push, git_reset_to_commit, git_rollback_last, git_stage, git_status)
from src.http_ops import LocalHTTPError, localhost_http
from src.journal_ops import JournalError, journal_logs
from src.persistent_sessions import (
    PersistentSessionError,
    backend_info as persistent_backend_info,
    interact as persistent_interact,
    kill as persistent_kill,
    list_sessions as list_persistent_sessions,
    read_output as persistent_read_output,
    reap_expired as reap_persistent_sessions,
    start as start_persistent_session,
)
from src.security import redact_argv
from src.sqlite_ops import SQLiteReadError, sqlite_query, sqlite_schema, sqlite_table_stats, sqlite_tables
from src.systemd_ops import SystemdError, list_services, list_timers, service_action, service_status, timer_status, unit_file
from src.workspace_exec import build_node_check_command, build_pytest_command, build_python_code_command, build_python_command
from src.workspace_policy import WorkspaceDenied, update_workspace_capabilities, workspace_profiles
from src.write_policy import PROJECT_ROOT, WriteDenied, writable_policy_info

SOCKET_PATH = Path(os.getenv("JOE_BRIDGE_SOCKET", "/run/joe-mcp/bridge.sock"))
MAX_OUTPUT_BYTES = int(os.getenv("JOE_BRIDGE_MAX_OUTPUT_BYTES", "1048576"))
MAX_INPUT_BYTES = int(os.getenv("JOE_BRIDGE_MAX_INPUT_BYTES", "65536"))
MAX_REQUEST_BYTES = int(os.getenv("JOE_BRIDGE_MAX_REQUEST_BYTES", "2000000"))
MAX_SESSION_SECONDS = int(os.getenv("JOE_BRIDGE_MAX_SESSION_SECONDS", "120"))
SESSION_RETENTION_SECONDS = int(os.getenv("JOE_BRIDGE_SESSION_RETENTION_SECONDS", "3600"))
MAX_SESSIONS = int(os.getenv("JOE_BRIDGE_MAX_SESSIONS", "100"))
NODE_ROLE = str(os.getenv("JOE_NODE_ROLE", "controller") or "controller").strip().lower()


def _require_controller_role() -> None:
    if NODE_ROLE != "controller":
        raise RuntimeError("Controller-only bridge operation is unavailable on managed nodes")


SAFE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
    "PAGER": "cat",
    "SYSTEMD_PAGER": "cat",
    "GIT_PAGER": "cat",
    "NO_COLOR": "1",
    "HOME": "/",
}


@dataclass
class Session:
    id: str
    command: str
    argv: list[str]
    cwd: str
    process: subprocess.Popen[str]
    started_at: float
    lines: list[str] = field(default_factory=list)
    output_bytes: int = 0
    output_truncated: bool = False
    completed_at: float | None = None
    returncode: int | None = None
    max_runtime_seconds: int = MAX_SESSION_SECONDS
    systemd_unit: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def state(self) -> str:
        return "running" if self.returncode is None else "completed"


SESSIONS: dict[str, Session] = {}
SESSIONS_LOCK = threading.Lock()


def _apply_limits(
    pid: int,
    cpu_seconds: int = 15,
    file_bytes: int = 2 * 1024 * 1024,
    nofile: int = 64,
    memory_bytes: int = 512 * 1024 * 1024,
) -> None:
    cpu = max(1, min(int(cpu_seconds), 3600))
    limits = (
        (resource.RLIMIT_CPU, (cpu, cpu)),
        (resource.RLIMIT_FSIZE, (file_bytes, file_bytes)),
        (resource.RLIMIT_NOFILE, (nofile, nofile)),
        (resource.RLIMIT_AS, (memory_bytes, memory_bytes)),
    )
    for which, value in limits:
        try:
            resource.prlimit(pid, which, value)
        except (AttributeError, PermissionError, ProcessLookupError, OSError):
            pass


def _session_summary(session: Session) -> dict[str, Any]:
    with session.lock:
        now = session.completed_at or time.time()
        runtime_seconds = max(0.0, now - session.started_at)
        stdin_open = bool(session.process.stdin is not None and not session.process.stdin.closed and session.returncode is None)
        return {
            "session_id": session.id,
            "backend": "process",
            "persistent": False,
            "pid": session.process.pid,
            "command": redact_argv(session.argv),
            "current_command": Path(session.argv[0]).name if session.argv else None,
            "cwd": session.cwd,
            "state": session.state,
            "returncode": session.returncode,
            "started_at": session.started_at,
            "completed_at": session.completed_at,
            "runtime_seconds": round(runtime_seconds, 3),
            "max_runtime_seconds": session.max_runtime_seconds,
            "remaining_runtime_seconds": max(0, int(session.max_runtime_seconds - runtime_seconds)) if session.returncode is None else 0,
            "output_lines": len(session.lines),
            "output_bytes": session.output_bytes,
            "output_truncated": session.output_truncated,
            "stdin_open": stdin_open,
            "input_state": "available" if stdin_open else "closed",
            "waiting_for_input": False,
            "sandbox": "systemd-transient" if session.systemd_unit else None,
            "systemd_unit": session.systemd_unit,
        }


def _reader(session: Session) -> None:
    assert session.process.stdout is not None
    try:
        for line in session.process.stdout:
            encoded = line.encode("utf-8", errors="replace")
            with session.lock:
                if session.output_bytes + len(encoded) <= MAX_OUTPUT_BYTES:
                    session.lines.append(line.rstrip("\n"))
                    session.output_bytes += len(encoded)
                else:
                    session.output_truncated = True
    finally:
        returncode = session.process.wait()
        with session.lock:
            session.returncode = returncode
            session.completed_at = time.time()


def _reserve_session_slot() -> None:
    with SESSIONS_LOCK:
        if len(SESSIONS) < MAX_SESSIONS:
            return
        completed = sorted(
            (session for session in SESSIONS.values() if session.returncode is not None),
            key=lambda session: session.completed_at or 0,
        )
        while len(SESSIONS) >= MAX_SESSIONS and completed:
            old = completed.pop(0)
            SESSIONS.pop(old.id, None)
        if len(SESSIONS) >= MAX_SESSIONS:
            raise RuntimeError("Maximum active session count reached")


def _workspace_systemd_command(spec: dict[str, Any], unit: str) -> list[str]:
    root = str(spec["cwd"])
    if any(ch.isspace() for ch in root) or any(ch in root for ch in "\x00\r\n"):
        raise WorkspaceDenied("Workspace roots with whitespace/control characters are not supported for sandboxed execution")
    inaccessible = [
        "-/etc/shadow", "-/etc/gshadow", "-/etc/ssl/private",
        "-/var/lib/joe-mcp-work/.secrets", "-/var/lib/joe-mcp-agent",
        f"-{PROJECT_ROOT}/.secrets", f"-{PROJECT_ROOT}/data/auth",
        f"-{PROJECT_ROOT}/data/audit", f"-{PROJECT_ROOT}/data/devices", f"-{PROJECT_ROOT}/data/sessions",
        f"-{root}/.secrets", f"-{root}/.env", f"-{root}/.git/config",
        f"-{root}/.git/config.worktree", f"-{root}/.git/hooks", f"-{root}/data/auth",
        f"-{root}/data/audit", f"-{root}/data/devices", f"-{root}/data/sessions",
    ]
    workspace_access = str(spec.get("workspace_access", "write") or "write").strip().lower()
    if workspace_access not in {"read", "write"}:
        raise WorkspaceDenied("Unsupported workspace access mode")
    read_only = [f"-{root}/.git"]
    if workspace_access == "read":
        read_only.append(root)
    properties = [
        "ProtectSystem=strict",
        "ProtectHome=tmpfs",
        *([f"ReadWritePaths={root}"] if workspace_access == "write" else []),
        "ReadOnlyPaths=" + " ".join(read_only),
        "InaccessiblePaths=" + " ".join(inaccessible),
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "SystemCallArchitectures=native",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes",
        "ProtectClock=yes",
        "ProtectHostname=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "RestrictRealtime=yes",
        "RestrictNamespaces=yes",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "UMask=0077",
        f"RuntimeMaxSec={int(spec['max_runtime_seconds'])}s",
        "MemoryMax=2G",
        "TasksMax=256",
        "LimitNOFILE=256",
        "LimitFSIZE=100M",
    ]
    if root == "/root" or root.startswith("/root/") or root == "/home" or root.startswith("/home/") or root.startswith("/run/user/"):
        properties.append(f"{'BindPaths' if workspace_access == 'write' else 'BindReadOnlyPaths'}={root}")
    if str(spec.get("network", "isolated")) == "isolated":
        properties.append("PrivateNetwork=yes")
    argv = [
        "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        f"--unit={unit}", f"--working-directory={root}",
        "--setenv=HOME=/", "--setenv=LANG=C.UTF-8", "--setenv=LC_ALL=C.UTF-8",
        "--setenv=PYTHONUNBUFFERED=1", "--",
    ]
    property_args: list[str] = []
    for item in properties:
        property_args.extend(["--property", item])
    return argv[:-1] + property_args + ["--", *list(spec["argv"])]


def _start_workspace_process(
    kind: str,
    workspace: str,
    script: str = "",
    code: str = "",
    targets: list[str] | None = None,
    args: list[str] | None = None,
) -> dict[str, Any]:
    if kind == "python":
        spec = build_python_command(workspace, script, args)
    elif kind == "python_code":
        spec = build_python_code_command(workspace, code, args)
    elif kind == "pytest":
        spec = build_pytest_command(workspace, targets, args)
    elif kind == "node_check":
        spec = build_node_check_command(workspace, script)
    else:
        raise ValueError("Unsupported workspace execution type")
    _reserve_session_slot()
    session_id = uuid.uuid4().hex
    unit = f"joe-mcp-workspace-{session_id[:20]}.service"
    sandbox_argv = _workspace_systemd_command(spec, unit)
    process = subprocess.Popen(
        sandbox_argv,
        cwd="/",
        env=SAFE_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    runtime = int(spec["max_runtime_seconds"])
    session = Session(
        id=session_id,
        command=str(spec["display"]),
        argv=list(spec["argv"]),
        cwd=str(spec["cwd"]),
        process=process,
        started_at=time.time(),
        max_runtime_seconds=runtime,
        systemd_unit=unit,
    )
    with SESSIONS_LOCK:
        SESSIONS[session.id] = session
    threading.Thread(target=_reader, args=(session,), daemon=True).start()
    result = _session_summary(session)
    result["workspace"] = workspace
    result["execution_type"] = kind
    result["max_runtime_seconds"] = runtime
    result["network"] = spec.get("network", "isolated")
    return result


def _start_sqlite_diagnostic(workspace: str, database: str, query: str, max_rows: int) -> dict[str, Any]:
    statement = str(query or "").strip().rstrip(";").strip()
    if not re.fullmatch(r"PRAGMA\s+(quick_check|integrity_check)", statement, flags=re.IGNORECASE):
        raise SQLiteReadError("Only PRAGMA quick_check or PRAGMA integrity_check can run as a diagnostic session")
    limit = max(1, min(int(max_rows), 500))
    _reserve_session_slot()
    argv = [
        "/usr/bin/python3",
        "-m",
        "src.sqlite_diagnostic_worker",
        str(workspace),
        str(database),
        statement,
        str(limit),
    ]
    worker_env = dict(SAFE_ENV)
    for key in ("JOE_WORKSPACES_FILE", "JOE_PROJECT_ROOT"):
        if os.environ.get(key):
            worker_env[key] = os.environ[key]
    process = subprocess.Popen(
        argv,
        cwd=PROJECT_ROOT,
        env=worker_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    _apply_limits(process.pid, cpu_seconds=360, memory_bytes=1024 * 1024 * 1024)
    session = Session(
        id=uuid.uuid4().hex,
        command=f"sqlite diagnostic {workspace}/{database}",
        argv=argv,
        cwd=PROJECT_ROOT,
        process=process,
        started_at=time.time(),
        max_runtime_seconds=360,
    )
    with SESSIONS_LOCK:
        SESSIONS[session.id] = session
    threading.Thread(target=_reader, args=(session,), daemon=True).start()
    result = _session_summary(session)
    result["workspace"] = str(workspace)
    result["database"] = str(database)
    result["execution_type"] = "sqlite_diagnostic"
    result["diagnostic"] = statement
    result["max_runtime_seconds"] = 360
    return result


def _start_process(command: str, cwd: str, persistent: bool = False) -> dict[str, Any]:
    if persistent:
        return start_persistent_session(command, cwd)
    argv = validate_command(command, cwd, Path("/"))
    with SESSIONS_LOCK:
        if len(SESSIONS) >= MAX_SESSIONS:
            completed = sorted(
                (s for s in SESSIONS.values() if s.returncode is not None),
                key=lambda s: s.completed_at or 0,
            )
            while len(SESSIONS) >= MAX_SESSIONS and completed:
                old = completed.pop(0)
                SESSIONS.pop(old.id, None)
            if len(SESSIONS) >= MAX_SESSIONS:
                raise RuntimeError("Maximum active session count reached")

    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=SAFE_ENV,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    _apply_limits(process.pid)
    session = Session(
        id=uuid.uuid4().hex,
        command=command,
        argv=argv,
        cwd=cwd,
        process=process,
        started_at=time.time(),
    )
    with SESSIONS_LOCK:
        SESSIONS[session.id] = session
    threading.Thread(target=_reader, args=(session,), daemon=True).start()
    return _session_summary(session)


def _read_output(session_id: str, offset: int, max_lines: int) -> dict[str, Any]:
    if str(session_id).startswith("ps_"):
        return persistent_read_output(session_id, offset, max_lines)
    with SESSIONS_LOCK:
        session = SESSIONS.get(session_id)
    if session is None:
        raise KeyError("Unknown session_id")
    limit = max(1, min(int(max_lines), 1000))
    requested = int(offset)
    with session.lock:
        start = max(0, len(session.lines) + requested) if requested < 0 else max(0, requested)
        start = min(start, len(session.lines))
        chunk = session.lines[start:start + limit]
        next_offset = start + len(chunk)
        now = session.completed_at or time.time()
        runtime_seconds = max(0.0, now - session.started_at)
        stdin_open = bool(session.process.stdin is not None and not session.process.stdin.closed and session.returncode is None)
        return {
            "session_id": session.id,
            "backend": "process",
            "persistent": False,
            "pid": session.process.pid,
            "state": session.state,
            "returncode": session.returncode,
            "current_command": Path(session.argv[0]).name if session.argv else None,
            "runtime_seconds": round(runtime_seconds, 3),
            "input_state": "available" if stdin_open else "closed",
            "waiting_for_input": False,
            "lines": chunk,
            "offset": start,
            "next_offset": next_offset,
            "has_more": next_offset < len(session.lines),
            "output_lines": len(session.lines),
            "output_bytes": session.output_bytes,
            "output_truncated": session.output_truncated,
        }


def _interact(session_id: str, input_text: str, append_newline: bool) -> dict[str, Any]:
    if str(session_id).startswith("ps_"):
        return persistent_interact(session_id, input_text, append_newline)
    with SESSIONS_LOCK:
        session = SESSIONS.get(session_id)
    if session is None:
        raise KeyError("Unknown session_id")
    if "\x00" in input_text:
        raise ValueError("NUL bytes are not allowed")
    payload = input_text + ("\n" if append_newline else "")
    encoded = payload.encode("utf-8")
    if len(encoded) > MAX_INPUT_BYTES:
        raise ValueError(f"Input exceeds {MAX_INPUT_BYTES} byte limit")
    with session.lock:
        if session.returncode is not None:
            raise RuntimeError("Session is already completed")
        stdin = session.process.stdin
        if stdin is None or stdin.closed:
            raise RuntimeError("Session stdin is not available")
        try:
            stdin.write(payload)
            stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise RuntimeError("Session stdin is no longer writable") from exc
    return {
        "session_id": session.id,
        "backend": "process",
        "persistent": False,
        "pid": session.process.pid,
        "state": session.state,
        "current_command": Path(session.argv[0]).name if session.argv else None,
        "input_state": "available",
        "waiting_for_input": False,
        "bytes_written": len(encoded),
        "append_newline": bool(append_newline),
    }


def _terminate_owned_session(session: Session, force: bool) -> None:
    if session.systemd_unit and session.systemd_unit.startswith("joe-mcp-workspace-"):
        signal_name = "KILL" if force else "TERM"
        subprocess.run(
            ["systemctl", "kill", "--kill-whom=all", f"--signal={signal_name}", session.systemd_unit],
            env=SAFE_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
        subprocess.run(
            ["systemctl", "stop", session.systemd_unit],
            env=SAFE_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10, check=False,
        )
        return
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.killpg(session.process.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        raise RuntimeError("Unable to terminate Joe-owned session") from exc


def _kill_process(session_id: str, force: bool) -> dict[str, Any]:
    if str(session_id).startswith("ps_"):
        return persistent_kill(session_id, force)
    with SESSIONS_LOCK:
        session = SESSIONS.get(session_id)
    if session is None:
        raise KeyError("Unknown session_id")
    with session.lock:
        completed = session.returncode is not None
        pid = session.process.pid
    if completed:
        result = _session_summary(session)
        result["already_completed"] = True
        return result
    _terminate_owned_session(session, force)
    return {
        "session_id": session.id,
        "backend": "process",
        "persistent": False,
        "pid": pid,
        "signal": "SIGKILL" if force else "SIGTERM",
        "requested": True,
        "joe_owned": True,
    }


def _list_sessions() -> dict[str, Any]:
    with SESSIONS_LOCK:
        sessions = list(SESSIONS.values())
    legacy = [_session_summary(s) for s in sessions]
    persistent = list_persistent_sessions()
    combined = legacy + list(persistent.get("sessions", []))
    combined.sort(key=lambda item: float(item.get("started_at", 0)), reverse=True)
    return {
        "sessions": combined,
        "allowed_commands": allowed_commands(),
        "max_runtime_seconds": MAX_SESSION_SECONDS,
        "persistent_backend": persistent.get("backend", persistent_backend_info()),
    }


def _reaper() -> None:
    last_persistent_reap = 0.0
    while True:
        now = time.time()
        if now - last_persistent_reap >= 30:
            try:
                reap_persistent_sessions()
            except (PersistentSessionError, OSError):
                pass
            last_persistent_reap = now
        with SESSIONS_LOCK:
            sessions = list(SESSIONS.values())
        for session in sessions:
            with session.lock:
                running = session.returncode is None
                started_at = session.started_at
                completed_at = session.completed_at
            if running and now - started_at > session.max_runtime_seconds:
                try:
                    _terminate_owned_session(session, False)
                except (RuntimeError, OSError, subprocess.SubprocessError):
                    pass
            elif completed_at and now - completed_at > SESSION_RETENTION_SECONDS:
                with SESSIONS_LOCK:
                    SESSIONS.pop(session.id, None)
        time.sleep(2)


def handle_request(request: dict[str, Any]) -> dict[str, Any]:
    op = str(request.get("op", ""))
    if op == "ping":
        return {
            "ok": True,
            "result": {
                "status": "ok",
                "node_role": NODE_ROLE,
                "allowed_commands": allowed_commands(),
                "write_policy": writable_policy_info(),
                "action_policy": action_policy_info(),
                "git_credentials": git_credentials_info(),
                "persistent_sessions": persistent_backend_info(),
                "workspace_policy": workspace_profiles(),
            },
        }
    if op == "workspace_profiles":
        return {"ok": True, "result": workspace_profiles()}
    if op == "update_workspace_capabilities":
        return {
            "ok": True,
            "result": update_workspace_capabilities(
                str(request.get("workspace", "")),
                request.get("permissions"),
                request.get("features"),
            ),
        }
    if op == "sqlite_tables":
        return {"ok": True, "result": sqlite_tables(str(request.get("workspace", "")), str(request.get("database", "")))}
    if op == "sqlite_schema":
        return {"ok": True, "result": sqlite_schema(str(request.get("workspace", "")), str(request.get("database", "")), str(request.get("table", "")))}
    if op == "start_sqlite_diagnostic":
        return {
            "ok": True,
            "result": _start_sqlite_diagnostic(
                str(request.get("workspace", "")),
                str(request.get("database", "")),
                str(request.get("query", "")),
                int(request.get("max_rows", 100)),
            ),
        }
    if op == "sqlite_query":
        return {"ok": True, "result": sqlite_query(str(request.get("workspace", "")), str(request.get("database", "")), str(request.get("query", "")), int(request.get("max_rows", 100)))}
    if op == "sqlite_table_stats":
        return {"ok": True, "result": sqlite_table_stats(str(request.get("workspace", "")), str(request.get("database", "")), str(request.get("table", "")), str(request.get("timestamp_column", "")))}
    if op == "localhost_http":
        return {"ok": True, "result": localhost_http(str(request.get("workspace", "")), str(request.get("url", "")), str(request.get("method", "GET")), str(request.get("body", "")), float(request.get("timeout_seconds", 5.0)))}
    if op == "controller_deploy_request":
        _require_controller_role()
        from src.controller_deploy_request import request_controller_deploy
        return {
            "ok": True,
            "result": request_controller_deploy(
                str(request.get("expected_head", "")),
                bool(request.get("confirm", False)),
            ),
        }
    if op == "controller_deploy_status":
        _require_controller_role()
        from src.controller_deploy_request import controller_deploy_status
        return {"ok": True, "result": controller_deploy_status()}
    if op == "controller_rollback_request":
        _require_controller_role()
        from src.controller_deploy_request import request_controller_rollback
        return {
            "ok": True,
            "result": request_controller_rollback(
                str(request.get("deployment_request_id", "")),
                bool(request.get("confirm", False)),
            ),
        }
    if op == "host_runtime_update_request":
        _require_controller_role()
        from src.host_runtime_update_request import request_host_runtime_update
        return {
            "ok": True,
            "result": request_host_runtime_update(
                str(request.get("expected_head", "")),
                bool(request.get("confirm", False)),
            ),
        }
    if op == "host_runtime_update_status":
        _require_controller_role()
        from src.host_runtime_update_request import host_runtime_update_status
        return {"ok": True, "result": host_runtime_update_status()}
    if op == "host_runtime_rollback_request":
        _require_controller_role()
        from src.host_runtime_update_request import request_host_runtime_rollback
        return {
            "ok": True,
            "result": request_host_runtime_rollback(
                str(request.get("update_request_id", "")),
                bool(request.get("confirm", False)),
            ),
        }
    if op == "public_agent_export_request":
        _require_controller_role()
        from src.public_agent_release import export_public_agent_release
        return {
            "ok": True,
            "result": export_public_agent_release(
                str(request.get("expected_head", "")),
                bool(request.get("confirm", False)),
            ),
        }
    if op == "public_agent_publish_request":
        _require_controller_role()
        from src.public_agent_publish import publish_public_agent
        return {
            "ok": True,
            "result": publish_public_agent(
                str(request.get("expected_head", "")),
                bool(request.get("confirm", False)),
            ),
        }
    if op == "action_policy_status":
        return {"ok": True, "result": action_policy_info()}
    if op == "update_action_capabilities":
        return {
            "ok": True,
            "result": update_action_capabilities(
                request.get("service_enabled"),
                request.get("docker_enabled"),
                request.get("git_enabled"),
                request.get("git_push_enabled"),
                bool(request.get("confirm_push", False)),
            ),
        }
    if op == "update_action_policy":
        return {
            "ok": True,
            "result": update_action_policy(
                request.get("service_control"),
                request.get("docker_control"),
                request.get("git_write"),
            ),
        }
    if op == "start_process":
        result = _start_process(
            str(request.get("command", "")),
            str(request.get("cwd", "/")),
            bool(request.get("persistent", False)),
        )
        return {"ok": True, "result": result}
    if op == "start_workspace_python":
        result = _start_workspace_process(
            "python", str(request.get("workspace", "")),
            script=str(request.get("script", "")), args=request.get("args", []),
        )
        return {"ok": True, "result": result}
    if op == "start_workspace_python_code":
        result = _start_workspace_process(
            "python_code", str(request.get("workspace", "")),
            code=str(request.get("code", "")), args=request.get("args", []),
        )
        return {"ok": True, "result": result}
    if op == "start_workspace_pytest":
        result = _start_workspace_process(
            "pytest", str(request.get("workspace", "")),
            targets=request.get("targets", None), args=request.get("args", []),
        )
        return {"ok": True, "result": result}
    if op == "start_workspace_node_check":
        result = _start_workspace_process(
            "node_check", str(request.get("workspace", "")),
            script=str(request.get("script", "")),
        )
        return {"ok": True, "result": result}
    if op == "read_process_output":
        result = _read_output(
            str(request.get("session_id", "")),
            int(request.get("offset", 0)),
            int(request.get("max_lines", 200)),
        )
        return {"ok": True, "result": result}
    if op == "interact_with_process":
        result = _interact(
            str(request.get("session_id", "")),
            str(request.get("input_text", "")),
            bool(request.get("append_newline", True)),
        )
        return {"ok": True, "result": result}
    if op == "kill_process":
        result = _kill_process(
            str(request.get("session_id", "")),
            bool(request.get("force", False)),
        )
        return {"ok": True, "result": result}
    if op == "write_file":
        result = write_file(
            str(request.get("path", "")),
            str(request.get("content", "")),
            str(request.get("mode", "rewrite")),
        )
        return {"ok": True, "result": result}
    if op == "edit_file":
        result = edit_file(
            str(request.get("path", "")),
            str(request.get("old_text", "")),
            str(request.get("new_text", "")),
            int(request.get("expected_replacements", 1)),
        )
        return {"ok": True, "result": result}
    if op == "edit_spreadsheet_range":
        result = edit_xlsx_range(
            str(request.get("path", "")),
            str(request.get("cell_range", "")),
            request.get("values", []),
        )
        return {"ok": True, "result": result}
    if op == "write_pdf":
        return {"ok": True, "result": create_pdf(str(request.get("path", "")), str(request.get("content", "")))}
    if op == "create_directory":
        result = create_directory(
            str(request.get("path", "")),
            bool(request.get("parents", True)),
        )
        return {"ok": True, "result": result}
    if op == "move_file":
        result = move_file(
            str(request.get("source", "")),
            str(request.get("destination", "")),
        )
        return {"ok": True, "result": result}
    if op == "copy_file":
        return {"ok": True, "result": copy_file(str(request.get("source", "")), str(request.get("destination", "")))}
    if op == "trash_path":
        return {"ok": True, "result": trash_path(str(request.get("path", "")))}
    if op == "list_trash":
        return {"ok": True, "result": list_trash(int(request.get("max_results", 200)))}
    if op == "restore_trash":
        return {"ok": True, "result": restore_trash(str(request.get("trash_id", "")), str(request.get("destination", "")))}
    if op == "purge_trash":
        return {"ok": True, "result": purge_trash(str(request.get("trash_id", "")), bool(request.get("confirm", False)))}
    if op == "git_status":
        return {"ok": True, "result": git_status(str(request.get("path", "")))}
    if op == "git_diff":
        return {
            "ok": True,
            "result": git_diff(
                str(request.get("path", "")),
                bool(request.get("staged", False)),
                int(request.get("max_bytes", 200000)),
            ),
        }
    if op == "git_log":
        return {
            "ok": True,
            "result": git_log(
                str(request.get("path", "")),
                int(request.get("max_count", 20)),
            ),
        }
    if op == "git_branches":
        return {"ok": True, "result": git_branches(str(request.get("path", "")), int(request.get("max_count", 200)))}
    if op == "git_branch_create":
        return {"ok": True, "result": git_branch_create(str(request.get("path", "")), str(request.get("name", "")), str(request.get("start_commit", "")))}
    if op == "git_branch_switch":
        return {"ok": True, "result": git_branch_switch(str(request.get("path", "")), str(request.get("name", "")))}
    if op == "git_reset_to_commit":
        return {"ok": True, "result": git_reset_to_commit(str(request.get("path", "")), str(request.get("target_commit", "")), str(request.get("expected_head", "")), bool(request.get("confirm", False)))}
    if op == "git_rollback_last":
        return {"ok": True, "result": git_rollback_last(str(request.get("path", "")), str(request.get("expected_head", "")), bool(request.get("confirm", False)))}
    if op == "git_stage":
        return {
            "ok": True,
            "result": git_stage(
                str(request.get("path", "")),
                request.get("paths", []),
            ),
        }
    if op == "git_commit":
        return {
            "ok": True,
            "result": git_commit(
                str(request.get("path", "")),
                str(request.get("message", "")),
            ),
        }
    if op == "git_push":
        return {
            "ok": True,
            "result": git_push(
                str(request.get("path", "")),
                str(request.get("expected_branch", "")),
                str(request.get("remote", "origin")),
            ),
        }
    if op == "list_services":
        return {
            "ok": True,
            "result": list_services(
                str(request.get("pattern", "*")),
                int(request.get("max_results", 200)),
            ),
        }
    if op == "list_timers":
        return {"ok": True, "result": list_timers(str(request.get("pattern", "*")), int(request.get("max_results", 200)))}
    if op == "timer_status":
        return {"ok": True, "result": timer_status(str(request.get("unit", "")))}
    if op == "unit_file":
        return {"ok": True, "result": unit_file(str(request.get("unit", "")))}
    if op == "service_status":
        return {
            "ok": True,
            "result": service_status(str(request.get("unit", ""))),
        }
    if op == "service_action":
        return {
            "ok": True,
            "result": service_action(
                str(request.get("unit", "")),
                str(request.get("action", "")),
            ),
        }
    if op == "journal_logs":
        return {
            "ok": True,
            "result": journal_logs(
                str(request.get("unit", "")),
                int(request.get("lines", 200)),
                int(request.get("since_minutes", 0)),
                str(request.get("text", "")),
                str(request.get("since", "")),
                str(request.get("until", "")),
            ),
        }
    if op == "docker_containers":
        return {
            "ok": True,
            "result": docker_containers(
                str(request.get("pattern", "*")),
                int(request.get("max_results", 200)),
            ),
        }
    if op == "docker_container_status":
        return {
            "ok": True,
            "result": docker_container_status(str(request.get("container", ""))),
        }
    if op == "docker_action":
        return {
            "ok": True,
            "result": docker_action(
                str(request.get("container", "")),
                str(request.get("action", "")),
            ),
        }
    if op == "docker_logs":
        return {
            "ok": True,
            "result": docker_logs(
                str(request.get("container", "")),
                int(request.get("lines", 200)),
                int(request.get("since_minutes", 0)),
            ),
        }
    if op == "list_sessions":
        return {"ok": True, "result": _list_sessions()}
    raise ValueError(f"Unsupported bridge operation: {op}")


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(MAX_REQUEST_BYTES + 1)
        if not raw:
            return
        if len(raw) > MAX_REQUEST_BYTES:
            response = {"ok": False, "error": "Request too large"}
        else:
            try:
                request = json.loads(raw.decode("utf-8"))
                if not isinstance(request, dict):
                    raise ValueError("Request must be an object")
                response = handle_request(request)
            except (
                ActionDenied,
                CommandDenied,
                WriteDenied,
                DockerError,
                GitError,
                JournalError,
                LocalHTTPError,
                SQLiteReadError,
                WorkspaceDenied,
                PersistentSessionError,
                SystemdError,
                KeyError,
                RuntimeError,
                ValueError,
                FileNotFoundError,
                FileExistsError,
                json.JSONDecodeError,
            ) as exc:
                response = {"ok": False, "error": str(exc), "error_type": type(exc).__name__}
            except Exception:
                response = {"ok": False, "error": "Internal bridge error", "error_type": "InternalError"}
        self.wfile.write((json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8"))


class ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main() -> None:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass
    threading.Thread(target=_reaper, daemon=True).start()
    with ThreadedUnixServer(str(SOCKET_PATH), Handler) as server:
        os.chmod(SOCKET_PATH, 0o660)
        server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
