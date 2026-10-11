from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from src.command_policy import allowed_commands, validate_command
from src.security import redact_argv

TMUX_BIN = os.getenv("JOE_TMUX_BIN", "/usr/bin/tmux")
TMUX_SOCKET = Path(os.getenv("JOE_TMUX_SOCKET", "/run/joe-mcp-session/tmux.sock"))
RUNNER = os.getenv("JOE_PERSISTENT_RUNNER", "/usr/local/libexec/joe-mcp-session-runner")
META_DIR = Path(os.getenv("JOE_PERSISTENT_SESSION_DIR", "/var/lib/joe-mcp-work/persistent-sessions"))
SESSION_PREFIX = "ps_"
TMUX_PREFIX = "joe-ps-"
SESSION_RE = re.compile(r"^ps_([a-f0-9]{32})$")
PROMPT_RE = re.compile(r"(?:>>>|\.\.\.|[$#>]|password:|passphrase:)\s*$", re.IGNORECASE)
MAX_SESSIONS = int(os.getenv("JOE_PERSISTENT_MAX_SESSIONS", "20"))
MAX_SESSION_SECONDS = int(os.getenv("JOE_PERSISTENT_MAX_SECONDS", "86400"))
RETENTION_SECONDS = int(os.getenv("JOE_PERSISTENT_RETENTION_SECONDS", "3600"))
MAX_CAPTURE_BYTES = int(os.getenv("JOE_PERSISTENT_MAX_CAPTURE_BYTES", "1048576"))
MAX_INPUT_BYTES = int(os.getenv("JOE_BRIDGE_MAX_INPUT_BYTES", "65536"))

TMUX_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
    "HOME": "/",
}


class PersistentSessionError(RuntimeError):
    pass


def _session_parts(session_id: str) -> tuple[str, str]:
    match = SESSION_RE.fullmatch(str(session_id or ""))
    if not match:
        raise KeyError("Unknown persistent session_id")
    token = match.group(1)
    return token, f"{TMUX_PREFIX}{token}"


def _metadata_path(session_id: str) -> Path:
    _session_parts(session_id)
    return META_DIR / f"{session_id}.json"


def _tmux(args: list[str], timeout: float = 3.0, max_bytes: int = MAX_CAPTURE_BYTES) -> str:
    try:
        completed = subprocess.run(
            [TMUX_BIN, "-S", str(TMUX_SOCKET), *args],
            env=TMUX_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise PersistentSessionError("tmux is unavailable on the host") from exc
    except subprocess.TimeoutExpired as exc:
        raise PersistentSessionError("tmux operation timed out") from exc
    if completed.returncode != 0:
        message = completed.stderr[:4000].decode("utf-8", errors="replace").strip()
        raise PersistentSessionError(message or f"tmux exited with status {completed.returncode}")
    raw = completed.stdout
    truncated = len(raw) > max_bytes
    text = raw[-max_bytes:].decode("utf-8", errors="replace") if truncated else raw.decode("utf-8", errors="replace")
    return text


def backend_info() -> dict[str, Any]:
    socket_ready = False
    runner_ready = False
    try:
        info = TMUX_SOCKET.lstat()
        socket_ready = (
            stat.S_ISSOCK(info.st_mode)
            and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) & 0o022 == 0
        )
    except OSError:
        socket_ready = False
    try:
        runner_info = Path(RUNNER).lstat()
        runner_ready = (
            stat.S_ISREG(runner_info.st_mode)
            and runner_info.st_uid == 0
            and stat.S_IMODE(runner_info.st_mode) & 0o022 == 0
            and os.access(RUNNER, os.X_OK)
        )
    except OSError:
        runner_ready = False
    server_ready = False
    if socket_ready and runner_ready:
        try:
            _tmux(["list-sessions", "-F", "#{session_name}"], max_bytes=64_000)
            server_ready = True
        except PersistentSessionError:
            server_ready = False
    return {
        "backend": "tmux",
        "available": bool(socket_ready and runner_ready and server_ready),
        "max_sessions": MAX_SESSIONS,
        "max_runtime_seconds": MAX_SESSION_SECONDS,
        "retention_seconds": RETENTION_SECONDS,
        "history_lines": 5000,
    }


def _write_metadata(data: dict[str, Any]) -> Path:
    META_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if META_DIR.is_symlink():
        raise PersistentSessionError("Persistent session metadata directory cannot be a symlink")
    try:
        os.chmod(META_DIR, 0o700)
        dir_info = META_DIR.lstat()
    except OSError as exc:
        raise PersistentSessionError("Persistent session metadata directory is unavailable") from exc
    if not stat.S_ISDIR(dir_info.st_mode) or dir_info.st_uid != 0 or stat.S_IMODE(dir_info.st_mode) & 0o077:
        raise PersistentSessionError("Persistent session metadata directory is not securely owned")
    path = _metadata_path(str(data["session_id"]))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        payload = (json.dumps(data, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def _read_metadata(session_id: str) -> dict[str, Any]:
    path = _metadata_path(session_id)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise KeyError("Unknown persistent session_id") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise PersistentSessionError("Persistent session metadata is not securely owned")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PersistentSessionError("Persistent session metadata is invalid") from exc
    if not isinstance(data, dict) or data.get("session_id") != session_id:
        raise PersistentSessionError("Persistent session metadata does not match session id")
    return data


def _pane_status(meta: dict[str, Any]) -> dict[str, Any]:
    target = f"{meta['tmux_name']}:0.0"
    try:
        raw = _tmux(
            [
                "display-message",
                "-p",
                "-t",
                target,
                "#{pane_dead}\t#{pane_dead_status}\t#{pane_pid}\t#{pane_current_command}\t#{history_size}",
            ],
            max_bytes=16_000,
        ).strip()
    except PersistentSessionError as exc:
        return {
            "exists": False,
            "state": "lost",
            "returncode": None,
            "pid": None,
            "current_command": None,
            "history_lines": 0,
            "error": str(exc),
        }
    parts = raw.split("\t", 4)
    if len(parts) != 5:
        raise PersistentSessionError("Unexpected tmux pane status response")
    dead, dead_status, pid, current_command, history_size = parts
    return {
        "exists": True,
        "state": "completed" if dead == "1" else "running",
        "returncode": int(dead_status) if dead == "1" and dead_status.lstrip("-").isdigit() else None,
        "pid": int(pid) if pid.isdigit() else None,
        "current_command": current_command[:200],
        "history_lines": int(history_size) if history_size.isdigit() else 0,
    }


def _input_state(meta: dict[str, Any], status: dict[str, Any]) -> tuple[str, bool]:
    if status.get("state") != "running":
        return "closed", False
    target = f"{meta['tmux_name']}:0.0"
    try:
        recent = _tmux(["capture-pane", "-p", "-t", target, "-S", "-3"], max_bytes=8192)
    except PersistentSessionError:
        return "available", False
    nonempty = [line.rstrip() for line in recent.splitlines() if line.strip()]
    if nonempty and PROMPT_RE.search(nonempty[-1]):
        return "likely_waiting", True
    return "available", False


def _summary(meta: dict[str, Any]) -> dict[str, Any]:
    status = _pane_status(meta)
    started_at = float(meta.get("started_at", 0))
    runtime_seconds = max(0.0, time.time() - started_at) if started_at else 0.0
    input_state, waiting_for_input = _input_state(meta, status)
    return {
        "session_id": meta["session_id"],
        "backend": "tmux",
        "persistent": True,
        "pid": status.get("pid"),
        "command": redact_argv(list(meta.get("argv", []))),
        "current_command": status.get("current_command"),
        "cwd": meta.get("cwd", "/"),
        "state": status.get("state", "lost"),
        "returncode": status.get("returncode"),
        "started_at": started_at,
        "completed_at": None,
        "runtime_seconds": round(runtime_seconds, 3),
        "max_runtime_seconds": MAX_SESSION_SECONDS,
        "remaining_runtime_seconds": max(0, int(MAX_SESSION_SECONDS - runtime_seconds)) if status.get("state") == "running" else 0,
        "output_lines": int(status.get("history_lines", 0)),
        "output_truncated": False,
        "stdin_open": status.get("state") == "running",
        "input_state": input_state,
        "waiting_for_input": waiting_for_input,
    }


def start(command: str, cwd: str = "/") -> dict[str, Any]:
    argv = validate_command(command, cwd, Path("/"))
    info = backend_info()
    if not info["available"]:
        raise PersistentSessionError("Persistent tmux session backend is unavailable")
    active = [item for item in list_sessions()["sessions"] if item.get("state") in {"running", "completed"}]
    if len(active) >= MAX_SESSIONS:
        raise PersistentSessionError("Maximum persistent session count reached")

    token = uuid.uuid4().hex
    session_id = f"{SESSION_PREFIX}{token}"
    tmux_name = f"{TMUX_PREFIX}{token}"
    meta = {
        "version": 1,
        "session_id": session_id,
        "tmux_name": tmux_name,
        "command": command,
        "argv": argv,
        "cwd": cwd,
        "started_at": time.time(),
    }
    path = _write_metadata(meta)
    try:
        _tmux(["new-session", "-d", "-s", tmux_name, "-c", cwd, f"{RUNNER} {token}"], timeout=5.0, max_bytes=16_000)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return _summary(meta)


def _capture_lines(meta: dict[str, Any]) -> tuple[list[str], bool]:
    raw = _tmux(["capture-pane", "-p", "-t", f"{meta['tmux_name']}:0.0", "-S", "-"], max_bytes=MAX_CAPTURE_BYTES)
    lines = raw.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    encoded = raw.encode("utf-8", errors="replace")
    return lines, len(encoded) >= MAX_CAPTURE_BYTES


def read_output(session_id: str, offset: int = 0, max_lines: int = 200) -> dict[str, Any]:
    meta = _read_metadata(session_id)
    status = _pane_status(meta)
    if not status.get("exists"):
        raise PersistentSessionError("Persistent tmux session is no longer available")
    lines, truncated = _capture_lines(meta)
    limit = max(1, min(int(max_lines), 1000))
    requested = int(offset)
    start_index = max(0, len(lines) + requested) if requested < 0 else max(0, requested)
    start_index = min(start_index, len(lines))
    chunk = lines[start_index:start_index + limit]
    next_offset = start_index + len(chunk)
    started_at = float(meta.get("started_at", 0))
    runtime_seconds = max(0.0, time.time() - started_at) if started_at else 0.0
    input_state, waiting_for_input = _input_state(meta, status)
    return {
        "session_id": session_id,
        "backend": "tmux",
        "persistent": True,
        "pid": status.get("pid"),
        "state": status.get("state"),
        "returncode": status.get("returncode"),
        "current_command": status.get("current_command"),
        "runtime_seconds": round(runtime_seconds, 3),
        "input_state": input_state,
        "waiting_for_input": waiting_for_input,
        "lines": chunk,
        "offset": start_index,
        "next_offset": next_offset,
        "has_more": next_offset < len(lines),
        "output_lines": len(lines),
        "output_truncated": truncated,
    }


def interact(session_id: str, input_text: str, append_newline: bool = True) -> dict[str, Any]:
    meta = _read_metadata(session_id)
    if "\x00" in input_text:
        raise ValueError("NUL bytes are not allowed")
    encoded = input_text.encode("utf-8")
    if len(encoded) > MAX_INPUT_BYTES:
        raise ValueError(f"Input exceeds {MAX_INPUT_BYTES} byte limit")
    status = _pane_status(meta)
    if status.get("state") != "running":
        raise PersistentSessionError("Persistent session is not running")
    target = f"{meta['tmux_name']}:0.0"
    if input_text:
        _tmux(["send-keys", "-l", "-t", target, "--", input_text], max_bytes=16_000)
    if append_newline:
        _tmux(["send-keys", "-t", target, "Enter"], max_bytes=16_000)
    return {
        "session_id": session_id,
        "backend": "tmux",
        "persistent": True,
        "pid": status.get("pid"),
        "state": "running",
        "current_command": status.get("current_command"),
        "input_state": "available",
        "waiting_for_input": False,
        "bytes_written": len(encoded) + (1 if append_newline else 0),
        "append_newline": bool(append_newline),
    }


def kill(session_id: str, force: bool = False) -> dict[str, Any]:
    meta = _read_metadata(session_id)
    status = _pane_status(meta)
    if status.get("exists"):
        try:
            _tmux(["kill-session", "-t", str(meta["tmux_name"])], max_bytes=16_000)
        except PersistentSessionError:
            pass
    _metadata_path(session_id).unlink(missing_ok=True)
    return {
        "session_id": session_id,
        "backend": "tmux",
        "persistent": True,
        "pid": status.get("pid"),
        "signal": "session-close" if not force else "session-force-close",
        "requested": True,
        "joe_owned": True,
        "already_completed": status.get("state") == "completed",
    }


def list_sessions() -> dict[str, Any]:
    sessions: list[dict[str, Any]] = []
    if META_DIR.exists() and META_DIR.is_dir() and not META_DIR.is_symlink():
        for path in sorted(META_DIR.glob("ps_*.json")):
            try:
                meta = _read_metadata(path.stem)
                sessions.append(_summary(meta))
            except (KeyError, PersistentSessionError, OSError):
                continue
    sessions.sort(key=lambda item: float(item.get("started_at", 0)), reverse=True)
    return {
        "sessions": sessions,
        "backend": backend_info(),
        "allowed_commands": allowed_commands(),
        "max_runtime_seconds": MAX_SESSION_SECONDS,
    }


def reap_expired() -> None:
    now = time.time()
    for item in list_sessions()["sessions"]:
        age = now - float(item.get("started_at", now))
        session_id = str(item.get("session_id", ""))
        if item.get("state") == "running" and age > MAX_SESSION_SECONDS:
            try:
                kill(session_id, force=False)
            except (KeyError, PersistentSessionError, OSError):
                pass
        elif item.get("state") in {"completed", "lost"} and age > RETENTION_SECONDS:
            try:
                kill(session_id, force=False)
            except (KeyError, PersistentSessionError, OSError):
                _metadata_path(session_id).unlink(missing_ok=True)
