from __future__ import annotations

import json
import os
import queue
import re
import resource
import shlex
import signal
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# When launched with `python -m src.host_bridge`, this module initially exists as `__main__`.
# Privileged operations import `src.host_bridge` later; alias the canonical name to this live
# module so both paths share the same in-memory session registry and locks.
if __name__ == "__main__":
    sys.modules.setdefault("src.host_bridge", sys.modules[__name__])

from src.action_policy import ActionDenied, action_policy_info, update_action_capabilities, update_action_policy, update_systemd_unit_policy
from src.admin_terminal import AdminTerminalDenied, MAX_RUNTIME_SECONDS as ADMIN_TERMINAL_MAX_RUNTIME_SECONDS, masked_paths as admin_terminal_masked_paths, set_enabled as set_admin_terminal_enabled, status as admin_terminal_status, validate_request as validate_admin_terminal_request
from src.command_policy import CommandDenied, allowed_commands, validate_command
from src.dc_compat import enabled as dc_compat_enabled, validate_shell_command
from src.developer_access import (
    DeveloperAccessDenied,
    MAX_RUNTIME_SECONDS as DEVELOPER_MAX_RUNTIME_SECONDS,
    ROOT_USER as DEVELOPER_ROOT_USER,
    build_terminal_argv as developer_terminal_argv,
    load_policy as developer_load_policy,
    normalize_policy as developer_normalize_policy,
    normalize_sudo_ttl as developer_normalize_ttl,
    public_status as developer_public_status,
    resolve_linux_user as developer_resolve_user,
    sandbox_properties as developer_sandbox_properties,
    save_policy as developer_save_policy,
    validate_password_shape as developer_validate_password,
    validate_terminal_request as developer_validate_request,
)
from src.docker_ops import DockerError, docker_action, docker_container_status, docker_containers, docker_logs, recover_joe_tunnel
from src.file_ops import copy_file, create_directory, edit_file, install_staged_pdf, list_trash, move_file, purge_trash, restore_trash, trash_path, write_file
from src.rich_write import create_pdf, edit_xlsx_range
from src.git_ops import (GitError, git_branch_create, git_branch_switch, git_branches, git_commit, git_compare_branches, git_credentials_info, git_diff, git_log, git_merge_branches, git_merge_preview, git_push, git_reset_to_commit, git_restore_paths, git_rollback_last, git_stage, git_status)
from src.http_ops import LocalHTTPError, localhost_http
from src.journal_ops import JournalError, journal_diagnostics, journal_logs, kernel_diagnostics
from src.managed_terminal import ManagedTerminalDenied, build_managed_terminal_spec
from src.linux_diagnostics import LinuxDiagnosticError, firewall_status, proc_snapshot, routing_diagnostics, sysctl_read, tailscale_status
from src.process_ops import ProcessControlDenied, process_info as host_process_info, terminate_host_process
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
from src.sap_ops import SAPError, abap_activate, abap_adt_change, abap_adt_get, abap_atc_run, abap_object_search, abap_source_read, abap_source_update, configure_sap_profile, remove_sap_profile, sap_host_discover, sap_instance_action, sap_process_list, sap_profiles, sap_rfc_status, sap_system_info
from src.systemd_ops import SystemdError, failed_units, list_services, list_timers, service_action, service_code_identity, service_status, timer_status, unit_action, unit_file
from src.workspace_exec import build_node_check_command, build_pytest_command, build_python_code_command, build_python_command, build_shell_command
from src.workspace_policy import WorkspaceDenied, discover_git_worktrees, register_linked_git_worktree_workspace, remove_workspace, set_workspace_http_ports, update_workspace_capabilities, workspace_for_host_path, workspace_profiles
from src.write_policy import PROJECT_ROOT, WriteDenied, safe_write_path, writable_policy_info

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


def _workspace_git_metadata(root: str) -> dict[str, str] | None:
    marker = Path(root) / ".git"
    if marker.is_dir() and not marker.is_symlink():
        resolved = marker.resolve(strict=True)
        return {"git_directory": str(resolved), "common_git_directory": str(resolved), "kind": "main"}
    if not marker.is_file() or marker.is_symlink() or marker.stat().st_size > 4096:
        return None
    line = marker.read_text(encoding="utf-8").strip()
    if not line.startswith("gitdir: "):
        return None
    raw = line[8:].strip()
    git_dir = Path(raw)
    if not git_dir.is_absolute():
        git_dir = (Path(root) / git_dir).resolve(strict=False)
    else:
        git_dir = git_dir.resolve(strict=False)
    if not git_dir.is_dir():
        raise WorkspaceDenied("Linked worktree Git metadata directory is unavailable")
    allowed_common: Path | None = None
    for profile in workspace_profiles().get("workspaces", []):
        base = Path(str(profile.get("root") or "")).resolve(strict=False)
        primary = base / ".git"
        worktrees = primary / "worktrees"
        if primary.is_dir() and (git_dir == worktrees or git_dir.is_relative_to(worktrees)):
            allowed_common = primary.resolve(strict=False)
            break
    if allowed_common is None:
        raise WorkspaceDenied("Linked worktree Git metadata is outside registered workspace repositories")
    return {"git_directory": str(git_dir), "common_git_directory": str(allowed_common), "kind": "linked"}


def _schedule_workspace_mount_refresh(delay_seconds: float = 2.0) -> dict[str, Any]:
    _require_controller_role()
    runtime_root = Path(__file__).resolve().parents[1]
    unit = f"joe-mcp-workspace-refresh-{uuid.uuid4().hex[:16]}.service"
    argv = [
        "/usr/bin/systemd-run",
        "--quiet",
        "--collect",
        f"--unit={unit}",
        f"--working-directory={runtime_root}",
        "--setenv=JOE_WORKSPACES_FILE=/var/lib/joe-mcp-work/workspaces.json",
        f"--setenv=JOE_PROJECT_ROOT={PROJECT_ROOT}",
        "--",
        "/usr/bin/python3",
        "-m",
        "src.workspace_mounts",
        "--delay-seconds",
        str(max(0.5, min(float(delay_seconds), 10.0))),
        "--restart-bridge",
    ]
    try:
        completed = subprocess.run(
            argv,
            cwd="/",
            env=SAFE_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise WorkspaceDenied("Unable to schedule workspace mount-policy refresh") from exc
    if completed.returncode != 0:
        error = completed.stderr[:2000].decode("utf-8", errors="replace").strip()
        raise WorkspaceDenied(error or "Unable to schedule workspace mount-policy refresh")
    return {"scheduled": True, "unit": unit, "delay_seconds": max(0.5, min(float(delay_seconds), 10.0))}


def _workspace_systemd_command(spec: dict[str, Any], unit: str) -> list[str]:
    root = str(spec["cwd"])
    if any(ch.isspace() for ch in root) or any(ch in root for ch in "\x00\r\n"):
        raise WorkspaceDenied("Workspace roots with whitespace/control characters are not supported for sandboxed execution")
    inaccessible = [
        "-/etc/shadow", "-/etc/gshadow", "-/etc/ssl/private", "-/etc/ssh", "-/etc/sudoers", "-/etc/sudoers.d",
        "-/etc/polkit-1", "-/etc/NetworkManager/system-connections", "-/etc/netplan", "-/etc/letsencrypt", "-/etc/cloud",
        "-/etc/apt/auth.conf", "-/etc/apt/auth.conf.d", "-/etc/crypttab", "-/etc/systemd",
        "-/run/systemd/private", "-/run/dbus/system_bus_socket", "-/run/docker.sock", "-/var/run/docker.sock",
        "-/run/containerd/containerd.sock", "-/run/joe-mcp/bridge.sock", "-/run/joe-mcp-session/tmux.sock",
        "-/var/lib/docker", "-/var/lib/containerd", "-/var/lib/joe-mcp-work", "-/var/lib/joe-mcp-agent", "-/var/log", "-/var/backups", "-/var/spool",
        f"-{PROJECT_ROOT}/.secrets", f"-{PROJECT_ROOT}/data/auth",
        f"-{PROJECT_ROOT}/data/audit", f"-{PROJECT_ROOT}/data/devices", f"-{PROJECT_ROOT}/data/sessions",
        f"-{root}/.secrets", f"-{root}/.env", f"-{root}/data/auth",
        f"-{root}/data/audit", f"-{root}/data/devices", f"-{root}/data/sessions",
    ]
    workspace_access = str(spec.get("workspace_access", "write") or "write").strip().lower()
    if workspace_access not in {"read", "write"}:
        raise WorkspaceDenied("Unsupported workspace access mode")
    git_meta = _workspace_git_metadata(root)
    read_only: list[str] = []
    bind_paths: list[str] = []
    bind_read_only: list[str] = []
    if workspace_access == "read":
        read_only.append(root)
    if git_meta:
        git_dir = git_meta["git_directory"]
        common_dir = git_meta["common_git_directory"]
        if git_meta["kind"] == "linked":
            (bind_paths if workspace_access == "write" else bind_read_only).append(common_dir)
        for protected_git_path in (
            str(Path(common_dir) / "config"),
            str(Path(common_dir) / "config.worktree"),
            str(Path(common_dir) / "hooks"),
            str(Path(git_dir) / "config.worktree"),
        ):
            read_only.append(f"-{protected_git_path}")
    properties = [
        "ProtectSystem=strict",
        "ProtectHome=tmpfs",
        *([f"ReadWritePaths={root}"] if workspace_access == "write" else []),
        *(["BindPaths=" + " ".join(bind_paths)] if bind_paths else []),
        *(["BindReadOnlyPaths=" + " ".join(bind_read_only)] if bind_read_only else []),
        *(["ReadOnlyPaths=" + " ".join(read_only)] if read_only else []),
        "InaccessiblePaths=" + " ".join(inaccessible),
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "SystemCallArchitectures=native",
        "SystemCallFilter=~kill tkill tgkill pidfd_send_signal ptrace process_vm_readv process_vm_writev reboot kexec_load kexec_file_load init_module finit_module delete_module mount umount2 pivot_root swapon swapoff keyctl add_key request_key",
        "SystemCallErrorNumber=EPERM",
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
        "--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--setenv=PYTHONUNBUFFERED=1", "--",
    ]
    property_args: list[str] = []
    for item in properties:
        property_args.extend(["--property", item])
    return argv[:-1] + property_args + ["--", *list(spec["argv"])]


def _managed_terminal_systemd_command(spec: dict[str, Any], unit: str) -> list[str]:
    cwd = str(spec["cwd"])
    write_roots = [str(item) for item in spec.get("write_roots", [])]
    hidden_paths = [str(item) for item in spec.get("hidden_paths", [])]
    read_only_paths = [str(item) for item in spec.get("read_only_paths", [])]
    runtime_paths = [
        "-/usr", "-/bin", "-/sbin", "-/lib", "-/lib64", "-/etc/alternatives",
        "-/etc/ld.so.cache", "-/etc/passwd", "-/etc/group", "-/etc/nsswitch.conf", "-/etc/localtime",
    ]
    properties = [
        "TemporaryFileSystem=/:ro",
        "BindReadOnlyPaths=" + " ".join([*runtime_paths, cwd]),
        *(["BindPaths=" + " ".join(write_roots)] if write_roots else []),
        *(["ReadOnlyPaths=" + " ".join(read_only_paths)] if read_only_paths else []),
        *(["InaccessiblePaths=" + " ".join(hidden_paths)] if hidden_paths else []),
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "PrivateNetwork=yes",
        "MountAPIVFS=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "SystemCallArchitectures=native",
        "SystemCallFilter=~kill tkill tgkill pidfd_send_signal ptrace process_vm_readv process_vm_writev reboot kexec_load kexec_file_load init_module finit_module delete_module mount umount2 pivot_root swapon swapoff keyctl add_key request_key",
        "SystemCallErrorNumber=EPERM",
        "RestrictAddressFamilies=AF_UNIX",
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
    argv = [
        "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        f"--unit={unit}", f"--working-directory={cwd}",
        "--setenv=HOME=/tmp", "--setenv=LANG=C.UTF-8", "--setenv=LC_ALL=C.UTF-8",
        "--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--setenv=PYTHONUNBUFFERED=1", "--",
    ]
    property_args: list[str] = []
    for item in properties:
        property_args.extend(["--property", item])
    return argv[:-1] + property_args + ["--", *list(spec["argv"])]


def _start_managed_terminal(
    profile: str,
    command: str,
    cwd: str,
    write_roots: list[str] | None = None,
    hidden_paths: list[str] | None = None,
    read_only_paths: list[str] | None = None,
) -> dict[str, Any]:
    if NODE_ROLE != "managed":
        raise ManagedTerminalDenied("Managed terminal is available only on enrolled managed nodes")
    if not Path(cwd).is_dir():
        raise ManagedTerminalDenied("Managed terminal working directory must be an existing directory")
    validated_write_roots: list[str] = []
    for raw in write_roots or []:
        try:
            candidate = safe_write_path(str(raw), must_exist=True)
        except (WriteDenied, OSError, ValueError) as exc:
            raise ManagedTerminalDenied(str(exc)) from exc
        if not candidate.is_dir():
            raise ManagedTerminalDenied("Managed terminal write roots must be existing directories")
        normalized = str(candidate)
        if normalized != cwd and not normalized.startswith(cwd.rstrip("/") + "/"):
            raise ManagedTerminalDenied("Managed terminal write roots must stay inside the selected working directory")
        validated_write_roots.append(normalized)

    def scoped_paths(values: list[str] | None, label: str) -> list[str]:
        if values is None:
            return []
        if not isinstance(values, list) or len(values) > 512:
            raise ManagedTerminalDenied(f"Managed terminal {label} paths exceed the bounded limit")
        result: list[str] = []
        for raw in values:
            value = str(raw or "")
            if not value.startswith("/") or any(ch.isspace() for ch in value) or any(ch in value for ch in "\x00\r\n"):
                raise ManagedTerminalDenied(f"Managed terminal {label} path is invalid")
            if value != cwd and not value.startswith(cwd.rstrip("/") + "/"):
                raise ManagedTerminalDenied(f"Managed terminal {label} paths must stay inside the selected working directory")
            result.append(value)
        return result

    spec = build_managed_terminal_spec(profile, command, cwd, validated_write_roots)
    spec["hidden_paths"] = scoped_paths(hidden_paths, "hidden")
    spec["read_only_paths"] = scoped_paths(read_only_paths, "read-only")
    _reserve_session_slot()
    session_id = uuid.uuid4().hex
    unit = f"joe-mcp-terminal-{session_id[:20]}.service"
    sandbox_argv = _managed_terminal_systemd_command(spec, unit)
    process = subprocess.Popen(
        sandbox_argv,
        cwd="/",
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
    if process.stdin is not None:
        try:
            process.stdin.write(str(spec["stdin_payload"]))
            if not str(spec["stdin_payload"]).endswith("\n"):
                process.stdin.write("\n")
            process.stdin.close()
        except BrokenPipeError:
            pass
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
    result["execution_type"] = "managed_terminal"
    result["terminal_profile"] = str(spec["profile"])
    result["network"] = "isolated"
    result["write_roots"] = list(spec.get("write_roots", []))
    return result


def _start_admin_terminal(command: str, cwd: str, confirm: bool = False) -> dict[str, Any]:
    payload, working_directory = validate_admin_terminal_request(command, cwd, confirm)
    _reserve_session_slot()
    session_id = uuid.uuid4().hex
    unit = f"joe-mcp-admin-{session_id[:20]}.service"
    properties = [
        "User=root",
        "Group=root",
        "UMask=0077",
        "InaccessiblePaths=" + " ".join(admin_terminal_masked_paths(PROJECT_ROOT)),
        f"RuntimeMaxSec={ADMIN_TERMINAL_MAX_RUNTIME_SECONDS}s",
    ]
    argv = [
        "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        f"--unit={unit}", f"--working-directory={working_directory}",
        "--setenv=HOME=/root", "--setenv=LANG=C.UTF-8", "--setenv=LC_ALL=C.UTF-8",
        "--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ]
    for item in properties:
        argv.extend(["--property", item])
    argv.extend(["--", "/bin/bash", "-s"])
    process = subprocess.Popen(
        argv,
        cwd="/",
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
    if process.stdin is not None:
        try:
            process.stdin.write(payload)
            if not payload.endswith("\n"):
                process.stdin.write("\n")
            process.stdin.close()
        except BrokenPipeError:
            pass
    session = Session(
        id=session_id,
        command="bash -s [approved host admin command]",
        argv=["/bin/bash", "-s"],
        cwd=working_directory,
        process=process,
        started_at=time.time(),
        max_runtime_seconds=ADMIN_TERMINAL_MAX_RUNTIME_SECONDS,
        systemd_unit=unit,
    )
    with SESSIONS_LOCK:
        SESSIONS[session.id] = session
    threading.Thread(target=_reader, args=(session,), daemon=True).start()
    result = _session_summary(session)
    result.update({
        "execution_type": "admin_terminal",
        "host_admin": True,
        "joe_credentials_masked": True,
        "network": "host",
        "max_runtime_seconds": ADMIN_TERMINAL_MAX_RUNTIME_SECONDS,
    })
    return result


# ---------------------------------------------------------------------------------------------
# Developer Access (opt-in privileged developer terminal for managed nodes)
# ---------------------------------------------------------------------------------------------
DEVELOPER_ANCHOR_SOURCE_FILE = Path(__file__).with_name("developer_access_anchor.py")
DEVELOPER_SUDO_BINARY = "/usr/bin/sudo"
DEVELOPER_PYTHON_BINARY = "/usr/bin/python3"
DEVELOPER_ANCHOR_HANDSHAKE_SECONDS = 20
_DEV_LOCK = threading.RLock()


class AnchoredProcess:
    """Popen-shaped view of one privileged command running under the sudo anchor."""

    stdin = None

    def __init__(self, run_id: str, anchor: "SudoAnchor") -> None:
        self.run_id = run_id
        self.anchor = anchor
        self.pid = 0
        self.returncode: int | None = None
        self.reauth_required = False
        self.start_error = ""
        self._lines: "queue.Queue[str | None]" = queue.Queue()
        self._started = threading.Event()
        self._done = threading.Event()

    @property
    def stdout(self):
        def generate():
            while True:
                item = self._lines.get()
                if item is None:
                    return
                yield item
        return generate()

    def feed(self, line: str) -> None:
        self._lines.put(line + "\n")

    def mark_started(self, pid: int) -> None:
        self.pid = int(pid or 0)
        self._started.set()

    def fail_start(self, message: str) -> None:
        self.start_error = str(message or "privileged command could not be started")[:200]
        self._started.set()
        self.finish(-1)

    def finish(self, returncode: int, reauth_required: bool = False) -> None:
        if self._done.is_set():
            return
        self.returncode = int(returncode)
        self.reauth_required = bool(reauth_required)
        self._lines.put(None)
        self._done.set()
        self._started.set()

    def wait(self, timeout: float | None = None) -> int | None:
        self._done.wait(timeout)
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode


class SudoAnchor:
    """Bridge-side handle for one authorized sudo anchor unit (one per device, one user)."""

    def __init__(self, user: str, unit: str, ttl_seconds: int, process: "subprocess.Popen[str]") -> None:
        self.user = user
        self.unit = unit
        self.process = process
        self.expires_at = time.time() + ttl_seconds
        self.closed = threading.Event()
        self.state_events: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self.runs: dict[str, AnchoredProcess] = {}
        self.runs_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self.reauth_required = False

    def send(self, message: dict[str, Any]) -> None:
        stdin = self.process.stdin
        if stdin is None or self.closed.is_set():
            raise DeveloperAccessDenied("Developer Access sudo authorization is not active")
        data = json.dumps(message, separators=(",", ":")) + "\n"
        with self._send_lock:
            try:
                stdin.write(data)
                stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                raise DeveloperAccessDenied("Developer Access sudo authorization is no longer active") from exc

    def read_events(self) -> None:
        stdout = self.process.stdout
        try:
            if stdout is not None:
                for raw in stdout:
                    try:
                        event = json.loads(raw)
                    except ValueError:
                        continue
                    if isinstance(event, dict):
                        self._dispatch(event)
        finally:
            self.closed.set()
            try:
                self.process.wait(timeout=2)
            except Exception:
                pass
            with self.runs_lock:
                pending = list(self.runs.values())
                self.runs.clear()
            for run in pending:
                run.finish(-1)
            self.state_events.put({"event": "closed"})
            _forget_anchor(self)

    def _dispatch(self, event: dict[str, Any]) -> None:
        kind = str(event.get("event") or "")
        if kind in {"authorized", "denied", "expired", "revoked"}:
            if kind == "authorized":
                self.state_events.put({"event": "authorized"})
            else:
                self.state_events.put({"event": kind, "reason": str(event.get("reason") or "")[:64]})
            return
        run_id = str(event.get("id") or "")
        with self.runs_lock:
            run = self.runs.get(run_id)
        if run is None:
            return
        if kind == "started":
            run.mark_started(int(event.get("pid") or 0))
        elif kind == "output":
            run.feed(str(event.get("line", "")))
        elif kind == "error":
            run.fail_start(str(event.get("message") or ""))
            with self.runs_lock:
                self.runs.pop(run_id, None)
        elif kind == "exit":
            if bool(event.get("reauth_required")):
                self.reauth_required = True
                self.expires_at = 0.0
            run.finish(int(event.get("returncode", -1)), bool(event.get("reauth_required")))
            with self.runs_lock:
                self.runs.pop(run_id, None)

    def wait_state(self, timeout: float) -> dict[str, Any]:
        try:
            return self.state_events.get(timeout=timeout)
        except queue.Empty:
            return {"event": "timeout"}

    @property
    def active(self) -> bool:
        return not self.closed.is_set() and time.time() < self.expires_at and self.process.poll() is None

    def start_run(self, run_id: str, payload: str, cwd: str, max_seconds: int) -> AnchoredProcess:
        handle = AnchoredProcess(run_id, self)
        with self.runs_lock:
            self.runs[run_id] = handle
        try:
            self.send({"op": "run", "id": run_id, "cwd": cwd, "payload": payload, "max_seconds": max_seconds})
        except DeveloperAccessDenied:
            with self.runs_lock:
                self.runs.pop(run_id, None)
            raise
        if not handle._started.wait(15) or handle.start_error:
            with self.runs_lock:
                self.runs.pop(run_id, None)
            raise DeveloperAccessDenied(handle.start_error or "Privileged command did not start")
        return handle

    def kill_run(self, run_id: str, force: bool) -> None:
        try:
            self.send({"op": "kill", "id": run_id, "force": bool(force)})
        except DeveloperAccessDenied:
            pass


_DEV_ANCHOR: SudoAnchor | None = None


def _forget_anchor(anchor: SudoAnchor) -> None:
    global _DEV_ANCHOR
    with _DEV_LOCK:
        if _DEV_ANCHOR is anchor:
            _DEV_ANCHOR = None


def _developer_require_managed() -> None:
    if NODE_ROLE != "managed":
        raise DeveloperAccessDenied("Developer Access is available only on enrolled managed nodes")


def _developer_active_anchor() -> SudoAnchor | None:
    with _DEV_LOCK:
        anchor = _DEV_ANCHOR
    if anchor is None:
        return None
    if not anchor.active:
        _developer_revoke_sudo("expired")
        return None
    return anchor


def _developer_sudo_state(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    anchor = _developer_active_anchor()
    if anchor is None:
        return {"authorized": False}
    current = policy if policy is not None else developer_load_policy()
    if not (current["enabled"] and current["sudo_allowed"] and current["run_as_user"] == anchor.user):
        _developer_revoke_sudo("policy_mismatch")
        return {"authorized": False}
    return {
        "authorized": True,
        "user": anchor.user,
        "remaining_seconds": max(0, int(anchor.expires_at - time.time())),
        "expires_at": anchor.expires_at,
    }


def _developer_revoke_sudo(reason: str = "revoked") -> bool:
    """Terminate the anchor (running `sudo -k` inside it) and drop its handle. Idempotent."""
    global _DEV_ANCHOR
    with _DEV_LOCK:
        anchor = _DEV_ANCHOR
        _DEV_ANCHOR = None
    if anchor is None:
        return False
    try:
        anchor.send({"op": "revoke"})
    except DeveloperAccessDenied:
        pass
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and not anchor.closed.is_set():
        time.sleep(0.05)
    if not anchor.closed.is_set():
        subprocess.run(
            ["systemctl", "stop", anchor.unit],
            env=SAFE_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
        try:
            anchor.process.kill()
        except OSError:
            pass
    return True


def _developer_status() -> dict[str, Any]:
    _developer_require_managed()
    policy = developer_load_policy()
    return developer_public_status(policy, _developer_sudo_state(policy))


def _developer_configure(policy_value: Any) -> dict[str, Any]:
    _developer_require_managed()
    candidate = developer_normalize_policy(policy_value)
    if candidate["enabled"]:
        developer_resolve_user(candidate["run_as_user"])
    with _DEV_LOCK:
        previous = developer_load_policy()
        if candidate != previous:
            # Any change (disable, different user, sudo no longer allowed...) ends temporary sudo first.
            _developer_revoke_sudo("policy_changed")
            developer_save_policy(candidate)
    return _developer_status()


def _developer_authorize_sudo(password: Any, ttl_minutes: Any, confirm: Any) -> dict[str, Any]:
    _developer_require_managed()
    if confirm is not True:
        raise DeveloperAccessDenied("Authorizing sudo requires confirm=true")
    policy = developer_load_policy()
    if not policy["enabled"]:
        raise DeveloperAccessDenied("Developer Access is disabled for this device")
    if policy["run_as_user"] == DEVELOPER_ROOT_USER:
        raise DeveloperAccessDenied("root runs directly and never uses sudo")
    if not policy["sudo_allowed"]:
        raise DeveloperAccessDenied("sudo is not allowed by this device's Developer Access policy")
    account = developer_resolve_user(policy["run_as_user"])
    ttl = developer_normalize_ttl(ttl_minutes)
    secret = developer_validate_password(password)
    password = None
    if not Path(DEVELOPER_SUDO_BINARY).is_file():
        raise DeveloperAccessDenied("sudo is not installed on this device")
    try:
        anchor_source = DEVELOPER_ANCHOR_SOURCE_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise DeveloperAccessDenied("Developer Access sudo helper is unavailable") from exc
    global _DEV_ANCHOR
    with _DEV_LOCK:
        _developer_revoke_sudo("reauthorize")
        session_id = uuid.uuid4().hex
        unit = f"joe-mcp-devsudo-{session_id[:20]}.service"
        properties = developer_sandbox_properties(
            account["name"], is_root=False, runtime_seconds=ttl * 60 + 120,
            project_root=PROJECT_ROOT, allow_privilege_gain=True,
        )
        argv = [
            "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
            f"--unit={unit}", "--working-directory=/",
            "--setenv=LANG=C.UTF-8", "--setenv=LC_ALL=C.UTF-8",
            "--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ]
        for item in properties:
            argv.extend(["--property", item])
        # The password is written to the anchor's private stdin pipe below; it is never part of argv/env.
        argv.extend(["--", DEVELOPER_PYTHON_BINARY, "-I", "-c", anchor_source, DEVELOPER_SUDO_BINARY])
        process = subprocess.Popen(
            argv, cwd="/", env=SAFE_ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", bufsize=1, start_new_session=True,
        )
        anchor = SudoAnchor(account["name"], unit, ttl * 60, process)
        threading.Thread(target=anchor.read_events, daemon=True).start()
        try:
            anchor.send({"op": "authorize", "password": secret, "ttl_seconds": ttl * 60})
        except DeveloperAccessDenied:
            secret = ""
            _developer_kill_anchor(anchor)
            raise DeveloperAccessDenied("sudo authorization could not be started")
        secret = ""
        outcome = anchor.wait_state(DEVELOPER_ANCHOR_HANDSHAKE_SECONDS)
        if outcome.get("event") != "authorized":
            _developer_kill_anchor(anchor)
            reason = str(outcome.get("reason") or outcome.get("event") or "")
            if reason == "ticket_not_retained":
                raise DeveloperAccessDenied("sudo accepted the password but would not keep a ticket (check sudoers timestamp_timeout); authorization was not granted")
            raise DeveloperAccessDenied("sudo authorization failed (wrong password, or this user is not permitted to use sudo)")
        anchor.expires_at = time.time() + ttl * 60
        _DEV_ANCHOR = anchor
    return developer_public_status(policy, _developer_sudo_state(policy))


def _developer_kill_anchor(anchor: SudoAnchor) -> None:
    try:
        anchor.send({"op": "revoke"})
    except DeveloperAccessDenied:
        pass
    try:
        anchor.process.wait(timeout=5)
    except Exception:
        subprocess.run(
            ["systemctl", "stop", anchor.unit],
            env=SAFE_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
        try:
            anchor.process.kill()
        except OSError:
            pass


def _developer_revoke_request(reason: str = "revoked") -> dict[str, Any]:
    _developer_require_managed()
    revoked = _developer_revoke_sudo(reason)
    result = _developer_status()
    result["sudo_revoked"] = bool(revoked)
    return result


def _start_developer_terminal(command: Any, cwd: Any, confirm: Any, privileged: Any) -> dict[str, Any]:
    _developer_require_managed()
    policy = developer_load_policy()
    if not policy["enabled"]:
        raise DeveloperAccessDenied("Developer Access is disabled for this device")
    payload, working_directory, wants_privileged = developer_validate_request(command, cwd, confirm, privileged, PROJECT_ROOT)
    account = developer_resolve_user(policy["run_as_user"])
    is_root = bool(account["is_root"])
    if wants_privileged and is_root:
        raise DeveloperAccessDenied("root already runs as root; privileged must be false")
    if wants_privileged and not policy["sudo_allowed"]:
        raise DeveloperAccessDenied("sudo is not allowed by this device's Developer Access policy")
    _reserve_session_slot()
    session_id = uuid.uuid4().hex
    if wants_privileged:
        anchor = _developer_active_anchor()
        if anchor is None or anchor.user != account["name"]:
            raise DeveloperAccessDenied("sudo authorization is required or has expired; authorize sudo again")
        handle = anchor.start_run(session_id, payload, working_directory, DEVELOPER_MAX_RUNTIME_SECONDS)
        session = Session(
            id=session_id,
            command="bash -s [privileged developer terminal command via the sudo anchor]",
            # The command really runs as `sudo -n` inside the retained anchor; the summary must not suggest
            # a standalone sudo process exists on the bridge side.
            argv=["/bin/bash", "-s"],
            cwd=working_directory,
            process=handle,  # type: ignore[arg-type]
            started_at=time.time(),
            max_runtime_seconds=DEVELOPER_MAX_RUNTIME_SECONDS,
            systemd_unit=None,
        )
    else:
        unit = f"joe-mcp-devaccess-{session_id[:20]}.service"
        properties = developer_sandbox_properties(
            account["name"], is_root=is_root, runtime_seconds=DEVELOPER_MAX_RUNTIME_SECONDS, project_root=PROJECT_ROOT,
        )
        process = subprocess.Popen(
            developer_terminal_argv(unit, working_directory, properties),
            cwd="/", env=SAFE_ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1, start_new_session=True,
        )
        if process.stdin is not None:
            try:
                process.stdin.write(payload)
                if not payload.endswith("\n"):
                    process.stdin.write("\n")
                process.stdin.close()
            except BrokenPipeError:
                pass
        session = Session(
            id=session_id,
            command="bash -s [developer terminal command]",
            argv=["/bin/bash", "-s"],
            cwd=working_directory,
            process=process,
            started_at=time.time(),
            max_runtime_seconds=DEVELOPER_MAX_RUNTIME_SECONDS,
            systemd_unit=unit,
        )
    with SESSIONS_LOCK:
        SESSIONS[session.id] = session
    threading.Thread(target=_reader, args=(session,), daemon=True).start()
    result = _session_summary(session)
    result.update({
        "execution_type": "developer_terminal",
        "run_as_user": account["name"],
        "run_as_root": bool(is_root or False),
        "privileged": bool(wants_privileged),
        "via_sudo_anchor": bool(wants_privileged),
        "network": "host",
        "joe_credentials_masked": True,
        "max_runtime_seconds": DEVELOPER_MAX_RUNTIME_SECONDS,
    })
    return result


def _start_workspace_process(
    kind: str,
    workspace: str,
    script: str = "",
    code: str = "",
    command: str = "",
    targets: list[str] | None = None,
    args: list[str] | None = None,
) -> dict[str, Any]:
    if kind == "python":
        spec = build_python_command(workspace, script, args)
    elif kind == "python_code":
        spec = build_python_code_command(workspace, code, args)
    elif kind == "shell":
        spec = build_shell_command(workspace, command)
        if dc_compat_enabled():
            spec["network"] = "host"
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
    stdin_payload = spec.get("stdin_payload")
    process = subprocess.Popen(
        sandbox_argv,
        cwd="/",
        env=SAFE_ENV,
        stdin=subprocess.PIPE if stdin_payload is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    if stdin_payload is not None and process.stdin is not None:
        try:
            process.stdin.write(str(stdin_payload))
            if not str(stdin_payload).endswith("\n"):
                process.stdin.write("\n")
            process.stdin.close()
        except BrokenPipeError:
            pass
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
    if dc_compat_enabled():
        if persistent:
            raise CommandDenied("Desktop Commander compatibility shell currently supports non-persistent sessions only")
        payload = validate_shell_command(command)
        selected = workspace_for_host_path(cwd, "modify")
        if selected is None:
            raise CommandDenied("Desktop Commander compatibility shell is limited to approved Joe workspaces")
        root = Path(str(selected["root"])).resolve(strict=False)
        wanted = Path(cwd).resolve(strict=False)
        if wanted != root and not wanted.is_relative_to(root):
            raise CommandDenied("Working directory is outside the selected workspace")
        if not wanted.exists() or not wanted.is_dir():
            raise CommandDenied("Working directory does not exist or is not a directory")
        wrapped = f"cd -- {shlex.quote(str(wanted))}\n{payload}"
        return _start_workspace_process("shell", str(selected["name"]), command=wrapped)
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
    if isinstance(session.process, AnchoredProcess):
        session.process.anchor.kill_run(session.process.run_id, force)
        return
    if session.systemd_unit and session.systemd_unit.startswith(("joe-mcp-workspace-", "joe-mcp-terminal-", "joe-mcp-devaccess-")):
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


def _dc_equivalence_self_test() -> dict[str, Any]:
    import shutil
    import sqlite3
    import tempfile

    checks: dict[str, dict[str, Any]] = {}

    def record(name: str, status: str, detail: str = "") -> None:
        checks[name] = {"status": status, "detail": detail[:500]}

    scratch = Path(tempfile.mkdtemp(prefix=".joe-dc-selftest-", dir=PROJECT_ROOT))
    try:
        # Filesystem write/copy/move through Joe's own guarded file layer.
        try:
            first = scratch / "first.txt"
            second = scratch / "second.txt"
            third = scratch / "third.txt"
            write_file(str(first), "joe-dc-selftest\n", "rewrite")
            copy_file(str(first), str(second))
            move_file(str(second), str(third))
            if first.read_text(encoding="utf-8") == "joe-dc-selftest\n" and third.read_text(encoding="utf-8") == "joe-dc-selftest\n":
                record("filesystem_read_write", "PASS")
                record("file_copy_move", "PASS")
            else:
                record("filesystem_read_write", "FAIL", "round-trip content mismatch")
                record("file_copy_move", "FAIL", "copy/move content mismatch")
        except Exception as exc:
            record("filesystem_read_write", "FAIL", str(exc))
            record("file_copy_move", "FAIL", str(exc))

        # Temporary repository + linked worktree proves that Git metadata and actual files move together.
        try:
            base = scratch / "git-main"
            linked = scratch / "git-linked"
            base.mkdir()
            def git(cwd: Path, *args: str) -> str:
                completed = subprocess.run(["git", *args], cwd=cwd, env=SAFE_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
                if completed.returncode != 0:
                    raise RuntimeError(completed.stderr.decode("utf-8", errors="replace")[:500])
                return completed.stdout.decode("utf-8", errors="replace").strip()
            git(base, "init", "-q", "-b", "main")
            git(base, "config", "user.name", "Joe Self Test")
            git(base, "config", "user.email", "joe-selftest@example.invalid")
            (base / "proof.txt").write_text("one\n", encoding="utf-8")
            git(base, "add", "proof.txt")
            git(base, "commit", "-q", "-m", "one")
            git(base, "branch", "alt")
            (base / "proof.txt").write_text("two\n", encoding="utf-8")
            git(base, "add", "proof.txt")
            git(base, "commit", "-q", "-m", "two")
            git(base, "branch", "candidate", "HEAD")
            git(base, "worktree", "add", "-q", str(linked), "alt")
            before = git_status(str(linked))
            before_text = (linked / "proof.txt").read_text(encoding="utf-8")
            git(linked, "switch", "--no-guess", "candidate")
            after = git_status(str(linked))
            after_text = (linked / "proof.txt").read_text(encoding="utf-8")
            candidate = git(base, "rev-parse", "candidate")
            forward_ok = bool(after.get("head") == candidate and after.get("clean") and after.get("worktree_matches_head") and before_text != after_text)
            git(linked, "switch", "--no-guess", "alt")
            restored = git_status(str(linked))
            rollback_ok = bool(restored.get("head") == before.get("head") and restored.get("clean") and restored.get("worktree_matches_head") and (linked / "proof.txt").read_text(encoding="utf-8") == before_text)
            record("linked_git_worktree", "PASS" if before.get("linked_worktree") and forward_ok and rollback_ok else "FAIL", f"forward={forward_ok} rollback={rollback_ok}")
            record("git_branch_switch_rollback", "PASS" if forward_ok and rollback_ok else "FAIL", f"forward={forward_ok} rollback={rollback_ok}")
        except Exception as exc:
            record("linked_git_worktree", "FAIL", str(exc))
            record("git_branch_switch_rollback", "FAIL", str(exc))

        try:
            status = service_status("joe-mcp-host-bridge.service")
            record("service_status", "PASS" if status.get("load_state") == "loaded" else "FAIL", str(status.get("active_state")))
        except Exception as exc:
            record("service_status", "FAIL", str(exc))

        try:
            policy = action_policy_info().get("service_control", {})
            capable = bool(policy.get("enabled") and policy.get("allowed_units") and policy.get("allowed_actions"))
            record("service_control", "PASS" if capable else "POLICY BLOCKED", "No lifecycle action is executed by this diagnostic")
        except Exception as exc:
            record("service_control", "FAIL", str(exc))

        try:
            logs = journal_logs("joe-mcp-host-bridge.service", 5, 0, "", "", "")
            record("journal_access", "PASS" if isinstance(logs.get("entries"), list) else "FAIL")
        except Exception as exc:
            record("journal_access", "FAIL", str(exc))

        try:
            proc = host_process_info(Path("/"), os.getpid())
            record("process_inspection", "PASS" if proc.get("pid") == os.getpid() else "FAIL")
        except Exception as exc:
            record("process_inspection", "FAIL", str(exc))

        try:
            db_path = Path(PROJECT_ROOT) / ".joe-dc-selftest.db"
            with sqlite3.connect(db_path) as conn:
                conn.execute("CREATE TABLE proof(id INTEGER PRIMARY KEY, value TEXT)")
                conn.execute("INSERT INTO proof(value) VALUES ('ok')")
                conn.commit()
            sql = sqlite_query("joe-mcp", ".joe-dc-selftest.db", "SELECT value FROM proof", 10)
            record("sqlite", "PASS" if sql.get("rows") == [["ok"]] else "FAIL", f"rows={sql.get('row_count')}")
            db_path.unlink(missing_ok=True)
        except Exception as exc:
            record("sqlite", "FAIL", str(exc))
            try:
                (Path(PROJECT_ROOT) / ".joe-dc-selftest.db").unlink(missing_ok=True)
            except OSError:
                pass

        try:
            shell = _start_workspace_process("shell", "joe-mcp", command="printf 'joe-shell-pass\\n'")
            session_id = str(shell.get("session_id") or "")
            deadline = time.time() + 5
            while time.time() < deadline:
                result = _read_output(session_id, 0, 50)
                if result.get("state") != "running":
                    break
                time.sleep(0.05)
            record("workspace_shell", "PASS" if result.get("returncode") == 0 and "joe-shell-pass" in result.get("lines", []) else "FAIL", str(result.get("returncode")))
        except Exception as exc:
            record("workspace_shell", "FAIL", str(exc))

        try:
            http = localhost_http("joe-mcp", "http://127.0.0.1:8765/health", "GET", "", 3.0)
            record("localhost_http", "PASS" if int(http.get("status", 0)) == 200 else "FAIL", str(http.get("status")))
        except Exception as exc:
            record("localhost_http", "FAIL", str(exc))

        try:
            timers = list_timers("*", 5)
            record("timers", "PASS" if isinstance(timers.get("timers"), list) else "FAIL")
        except Exception as exc:
            record("timers", "FAIL", str(exc))

        try:
            routing = routing_diagnostics()
            record("networking", "PASS" if isinstance(routing, dict) else "FAIL")
        except Exception as exc:
            record("networking", "FAIL", str(exc))

        try:
            backend = persistent_backend_info()
            if not backend.get("available"):
                record("persistent_sessions", "POLICY BLOCKED", "persistent session backend unavailable")
            else:
                session = start_persistent_session("pwd", PROJECT_ROOT)
                time.sleep(0.15)
                output = persistent_read_output(str(session["session_id"]), 0, 20)
                try:
                    persistent_kill(str(session["session_id"]), False)
                except Exception:
                    pass
                record("persistent_sessions", "PASS" if output.get("session_id") else "FAIL")
        except Exception as exc:
            record("persistent_sessions", "FAIL", str(exc))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        try:
            (Path(PROJECT_ROOT) / ".joe-dc-selftest.db").unlink(missing_ok=True)
        except OSError:
            pass

    counts = {key: sum(1 for item in checks.values() if item.get("status") == key) for key in ("PASS", "FAIL", "POLICY BLOCKED")}
    return {"status": "PASS" if counts["FAIL"] == 0 else "FAIL", "checks": checks, "counts": counts, "destructive_changes": False}


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
    if op == "dc_equivalence_self_test":
        return {"ok": True, "result": _dc_equivalence_self_test()}
    if op == "workspace_discover_git_worktrees":
        return {"ok": True, "result": discover_git_worktrees(str(request.get("base_workspace", "")))}
    if op == "workspace_remove":
        name = str(request.get("workspace", ""))
        existing = next((item for item in workspace_profiles().get("workspaces", []) if item.get("name") == name), None)
        if not isinstance(existing, dict):
            raise WorkspaceDenied(f"Unknown workspace: {name}")
        root = os.path.normpath(str(existing.get("root", "")))
        workspace_result = remove_workspace(name, bool(request.get("confirm", False)))
        policy = action_policy_info()
        git = policy.get("git_write", {}) if isinstance(policy.get("git_write", {}), dict) else {}
        repositories = [item for item in (git.get("allowed_repositories", []) if isinstance(git.get("allowed_repositories", []), list) else []) if os.path.normpath(str(item)) != root]
        action_result = update_action_policy(git_write={
            "enabled": bool(git.get("enabled", False)),
            "allowed_repositories": repositories,
            "allowed_actions": list(git.get("allowed_actions", [])) if isinstance(git.get("allowed_actions", []), list) else [],
            "push_enabled": bool(git.get("push_enabled", False)),
        })
        refresh = _schedule_workspace_mount_refresh()
        return {"ok": True, "result": {"workspace": workspace_result, "action_policy": action_result, "mount_refresh": refresh}}
    if op == "workspace_update":
        if request.get("confirm") is not True:
            raise WorkspaceDenied("Updating workspace capabilities requires confirm=true")
        result = update_workspace_capabilities(str(request.get("workspace", "")), request.get("permissions"), request.get("features"))
        return {"ok": True, "result": {"workspace": result, "mount_refresh": _schedule_workspace_mount_refresh()}}
    if op == "set_workspace_http_ports":
        return {"ok": True, "result": set_workspace_http_ports(str(request.get("workspace", "")), request.get("ports", []), bool(request.get("confirm", False)))}
    if op == "update_workspace_capabilities":
        result = update_workspace_capabilities(
            str(request.get("workspace", "")),
            request.get("permissions"),
            request.get("features"),
        )
        return {"ok": True, "result": {"workspace": result, "mount_refresh": _schedule_workspace_mount_refresh()}}
    if op == "sap_profiles":
        return {"ok": True, "result": sap_profiles()}
    if op == "sap_profile_configure":
        return {"ok": True, "result": configure_sap_profile(
            str(request.get("name", "")), str(request.get("base_url", "")), str(request.get("client", "")),
            str(request.get("username", "")), str(request.get("password", "")), str(request.get("bearer_token", "")),
            bool(request.get("verify_tls", True)), bool(request.get("allow_insecure_http", False)), bool(request.get("confirm", False)),
        )}
    if op == "sap_profile_remove":
        return {"ok": True, "result": remove_sap_profile(str(request.get("name", "")), bool(request.get("confirm", False)))}
    if op == "sap_host_discover":
        return {"ok": True, "result": sap_host_discover()}
    if op == "sap_process_list":
        return {"ok": True, "result": sap_process_list(str(request.get("instance_number", "")), str(request.get("host", "")))}
    if op == "sap_system_info":
        return {"ok": True, "result": sap_system_info(str(request.get("instance_number", "")), str(request.get("host", "")))}
    if op == "sap_instance_action":
        return {"ok": True, "result": sap_instance_action(str(request.get("instance_number", "")), str(request.get("action", "")), str(request.get("host", "")), bool(request.get("confirm", False)))}
    if op == "sap_rfc_status":
        return {"ok": True, "result": sap_rfc_status()}
    if op == "abap_adt_get":
        return {"ok": True, "result": abap_adt_get(str(request.get("profile", "")), str(request.get("path", "")), str(request.get("accept", "")))}
    if op == "abap_object_search":
        return {"ok": True, "result": abap_object_search(str(request.get("profile", "")), str(request.get("query", "")), str(request.get("object_type", "")), int(request.get("max_results", 50)))}
    if op == "abap_source_read":
        return {"ok": True, "result": abap_source_read(str(request.get("profile", "")), str(request.get("source_uri", "")))}
    if op == "abap_adt_change":
        return {"ok": True, "result": abap_adt_change(str(request.get("profile", "")), str(request.get("method", "")), str(request.get("path", "")), str(request.get("body", "")), str(request.get("content_type", "application/xml; charset=utf-8")), bool(request.get("confirm", False)))}
    if op == "abap_source_update":
        return {"ok": True, "result": abap_source_update(str(request.get("profile", "")), str(request.get("source_uri", "")), str(request.get("source", "")), str(request.get("lock_handle", "")), str(request.get("transport_request", "")), bool(request.get("confirm", False)))}
    if op == "abap_activate":
        return {"ok": True, "result": abap_activate(str(request.get("profile", "")), str(request.get("object_uri", "")), str(request.get("object_name", "")), bool(request.get("confirm", False)))}
    if op == "abap_atc_run":
        return {"ok": True, "result": abap_atc_run(str(request.get("profile", "")), str(request.get("path", "")), str(request.get("body", "")), bool(request.get("confirm", False)))}
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
    if op == "admin_terminal_status":
        return {"ok": True, "result": admin_terminal_status()}
    if op == "set_admin_terminal_enabled":
        return {"ok": True, "result": set_admin_terminal_enabled(bool(request.get("enabled", False)), bool(request.get("confirm", False)))}
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
    if op == "update_systemd_unit_policy":
        return {"ok": True, "result": update_systemd_unit_policy(request.get("allowed_units", []), request.get("allowed_actions", []), request.get("enabled"), bool(request.get("confirm", False)))}
    if op == "register_git_worktree_workspace":
        _require_controller_role()
        if request.get("confirm") is not True:
            raise WorkspaceDenied("Registering a linked Git worktree requires confirm=true")
        base_workspace = str(request.get("base_workspace", ""))
        workspace = str(request.get("workspace", ""))
        root = str(request.get("root", ""))
        workspace_result = register_linked_git_worktree_workspace(base_workspace, workspace, root, True)
        policy = action_policy_info()
        git = policy.get("git_write", {}) if isinstance(policy.get("git_write", {}), dict) else {}
        repositories = list(git.get("allowed_repositories", [])) if isinstance(git.get("allowed_repositories", []), list) else []
        normalized_root = os.path.normpath(root)
        if normalized_root not in repositories:
            repositories.append(normalized_root)
        action_result = update_action_policy(git_write={
            "enabled": bool(git.get("enabled", False)),
            "allowed_repositories": repositories,
            "allowed_actions": list(git.get("allowed_actions", [])) if isinstance(git.get("allowed_actions", []), list) else [],
            "push_enabled": bool(git.get("push_enabled", False)),
        })
        workspace_result = workspace_profiles()
        refresh = _schedule_workspace_mount_refresh()
        return {"ok": True, "result": {"workspace": workspace_result, "action_policy": action_result, "mount_refresh": refresh}}
    if op == "update_action_policy":
        return {
            "ok": True,
            "result": update_action_policy(
                request.get("service_control"),
                request.get("docker_control"),
                request.get("git_write"),
            ),
        }
    if op == "start_admin_terminal":
        result = _start_admin_terminal(str(request.get("command", "")), str(request.get("cwd", "/")), bool(request.get("confirm", False)))
        return {"ok": True, "result": result}
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
    if op == "start_workspace_shell":
        if request.get("confirm") is not True:
            raise WorkspaceDenied("Sandboxed workspace shell execution requires confirm=true")
        result = _start_workspace_process(
            "shell", str(request.get("workspace", "")),
            command=str(request.get("command", "")),
        )
        return {"ok": True, "result": result}
    if op == "developer_access_status":
        return {"ok": True, "result": _developer_status()}
    if op == "developer_access_configure":
        return {"ok": True, "result": _developer_configure(request.get("policy"))}
    if op == "developer_access_authorize_sudo":
        # Detach the secret from the request mapping before any further handling.
        secret = request.pop("sudo_password", None)
        try:
            result = _developer_authorize_sudo(secret, request.get("ttl_minutes"), request.get("confirm"))
        finally:
            secret = None
        return {"ok": True, "result": result}
    if op == "developer_access_revoke_sudo":
        return {"ok": True, "result": _developer_revoke_request(str(request.get("reason") or "revoked")[:32])}
    if op == "start_developer_terminal":
        return {"ok": True, "result": _start_developer_terminal(
            request.get("command"), request.get("cwd", "/"), request.get("confirm"), request.get("privileged", False),
        )}
    if op == "start_managed_terminal":
        if request.get("confirm") is not True:
            raise ManagedTerminalDenied("Managed terminal execution requires confirm=true")
        result = _start_managed_terminal(
            str(request.get("profile", "inspect")),
            str(request.get("command", "")),
            str(request.get("cwd", "/opt")),
            request.get("write_roots", []),
            request.get("hidden_paths", []),
            request.get("read_only_paths", []),
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
    if op == "terminate_host_process":
        if NODE_ROLE != "managed":
            raise ProcessControlDenied("Host process termination is available only on enrolled managed nodes")
        if request.get("confirm") is not True:
            raise ProcessControlDenied("Host process termination requires confirm=true")
        result = terminate_host_process(
            Path("/"),
            int(request.get("pid", 0)),
            int(request.get("expected_start_ticks", 0)),
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
    if op == "install_staged_pdf":
        result = install_staged_pdf(
            str(request.get("path", "")),
            str(request.get("staging_id", "")),
            int(request.get("expected_size", 0)),
            str(request.get("expected_sha256", "")),
            managed_node=(NODE_ROLE == "managed"),
        )
        return {"ok": True, "result": result}
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
    if op == "git_compare_branches":
        return {"ok": True, "result": git_compare_branches(str(request.get("path", "")), str(request.get("left", "")), str(request.get("right", "")), int(request.get("max_commits", 20)))}
    if op == "git_merge_preview":
        return {"ok": True, "result": git_merge_preview(str(request.get("path", "")), str(request.get("destination", "")), str(request.get("source", "")), int(request.get("max_bytes", 200000)))}
    if op == "git_merge_branches":
        return {"ok": True, "result": git_merge_branches(str(request.get("path", "")), str(request.get("destination", "")), str(request.get("source", "")), str(request.get("expected_destination_head", "")), str(request.get("message", "")), bool(request.get("confirm", False)))}
    if op == "git_branches":
        return {"ok": True, "result": git_branches(str(request.get("path", "")), int(request.get("max_count", 200)))}
    if op == "git_branch_create":
        return {"ok": True, "result": git_branch_create(str(request.get("path", "")), str(request.get("name", "")), str(request.get("start_commit", "")))}
    if op == "git_branch_switch":
        return {"ok": True, "result": git_branch_switch(str(request.get("path", "")), str(request.get("name", "")))}
    if op == "git_reset_to_commit":
        return {"ok": True, "result": git_reset_to_commit(str(request.get("path", "")), str(request.get("target_commit", "")), str(request.get("expected_head", "")), bool(request.get("confirm", False)))}
    if op == "git_restore_paths":
        return {"ok": True, "result": git_restore_paths(str(request.get("path", "")), str(request.get("source_commit", "")), request.get("paths", []), bool(request.get("confirm", False)))}
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
    if op == "systemd_failed_units":
        return {"ok": True, "result": failed_units(int(request.get("max_results", 200)))}
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
    if op == "service_code_identity":
        return {"ok": True, "result": service_code_identity(str(request.get("unit", "")))}
    if op == "service_action":
        return {
            "ok": True,
            "result": service_action(
                str(request.get("unit", "")),
                str(request.get("action", "")),
            ),
        }
    if op == "unit_action":
        return {
            "ok": True,
            "result": unit_action(
                str(request.get("unit", "")),
                str(request.get("action", "")),
                request.get("confirm") is True,
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
    if op == "journal_diagnostics":
        return {"ok": True, "result": journal_diagnostics(
            int(request.get("lines", 200)), int(request.get("since_minutes", 60)),
            int(request.get("priority_max", 3)), str(request.get("text", "")), bool(request.get("current_boot", True)), False,
        )}
    if op == "kernel_diagnostics":
        return {"ok": True, "result": kernel_diagnostics(
            int(request.get("lines", 200)), int(request.get("since_minutes", 0)),
            int(request.get("priority_max", 4)), str(request.get("text", "")),
        )}
    if op == "firewall_status":
        return {"ok": True, "result": firewall_status()}
    if op == "tailscale_status":
        return {"ok": True, "result": tailscale_status()}
    if op == "sysctl_read":
        return {"ok": True, "result": sysctl_read(str(request.get("key", "")), Path("/"))}
    if op == "proc_snapshot":
        return {"ok": True, "result": proc_snapshot(str(request.get("topic", "")), Path("/"))}
    if op == "routing_diagnostics":
        return {"ok": True, "result": routing_diagnostics()}
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
    if op == "recover_joe_tunnel":
        return {
            "ok": True,
            "result": recover_joe_tunnel(request.get("confirm") is True),
        }
    if op == "docker_logs":
        return {
            "ok": True,
            "result": docker_logs(
                str(request.get("container", "")),
                int(request.get("lines", 200)),
                int(request.get("since_minutes", 0)),
                str(request.get("text", "")),
            ),
        }
    if op == "list_sessions":
        return {"ok": True, "result": _list_sessions()}
    if NODE_ROLE == "controller":
        # Privileged capabilities (packages, workspace binaries, Docker, privileged terminal) live in a
        # controller-only module that managed nodes do not ship.
        from src.privileged_bridge import PRIVILEGED_OPS, handle_privileged_op
        if op in PRIVILEGED_OPS:
            return {"ok": True, "result": handle_privileged_op(op, request)}
    raise ValueError(f"Unsupported bridge operation: {op}")


def _write_response(stream: Any, response: dict[str, Any]) -> bool:
    payload = (json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        stream.write(payload)
        return True
    except (BrokenPipeError, ConnectionResetError):
        return False


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
                LinuxDiagnosticError,
                ProcessControlDenied,
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
        _write_response(self.wfile, response)


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
