from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import time
from typing import Any

from src.action_policy import authorize_docker_action
from src.security import redact_text


DOCKER_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "HOME": "/",
    "DOCKER_HOST": "unix:///var/run/docker.sock",
    "DOCKER_CONFIG": "/nonexistent",
    "NO_COLOR": "1",
}
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
MAX_RESULTS = 500
MAX_OUTPUT_BYTES = 500_000
MAX_LOG_LINES = 500
MAX_LOG_SCAN_LINES = 2500
MAX_LOG_TEXT_FILTER = 500
MAX_LOG_SINCE_MINUTES = 10_080
MAX_LOG_STREAM_BYTES = 1_000_000
MAX_LOG_MESSAGE_CHARS = 4000
JOE_PROJECT_DIR = "/opt/joe-mcp-server"
JOE_COMPOSE_FILE = f"{JOE_PROJECT_DIR}/docker-compose.yml"
JOE_TUNNEL_CONTAINER = "joe-mcp-tunnel"


class DockerError(RuntimeError):
    pass


def _run(args: list[str], timeout: float = 8.0, max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    try:
        completed = subprocess.run(
            ["docker", *args],
            env=DOCKER_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DockerError("docker CLI is unavailable on the host") from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerError("docker operation timed out") from exc
    if completed.returncode != 0:
        error = completed.stderr[:4000].decode("utf-8", errors="replace").strip()
        raise DockerError(error or f"docker exited with status {completed.returncode}")
    raw = completed.stdout
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", errors="replace")


def _run_logs(args: list[str], timeout: float = 10.0) -> tuple[str, str]:
    try:
        completed = subprocess.run(
            ["docker", *args],
            env=DOCKER_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DockerError("docker CLI is unavailable on the host") from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerError("docker logs operation timed out") from exc
    if completed.returncode != 0:
        error = completed.stderr[:4000].decode("utf-8", errors="replace").strip()
        raise DockerError(error or f"docker logs exited with status {completed.returncode}")
    stdout = completed.stdout[:MAX_LOG_STREAM_BYTES].decode("utf-8", errors="replace")
    stderr = completed.stderr[:MAX_LOG_STREAM_BYTES].decode("utf-8", errors="replace")
    return stdout, stderr


def normalize_container(container: str) -> str:
    value = str(container or "").strip()
    if not value or not CONTAINER_RE.fullmatch(value):
        raise ValueError("container name/id contains unsupported characters")
    return value


def docker_containers(pattern: str = "*", max_results: int = 200) -> dict[str, Any]:
    if not pattern or len(pattern) > 256:
        raise ValueError("pattern must contain 1 to 256 characters")
    limit = max(1, min(int(max_results), MAX_RESULTS))
    template = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}"
    output = _run(["ps", "--all", "--no-trunc", "--format", template])
    needle = pattern.lower()
    containers: list[dict[str, str]] = []
    matched_total = 0
    for line in output.splitlines():
        parts = line.split("\t", 5)
        if len(parts) != 6:
            continue
        container_id, name, image, state, status, ports = parts
        if not fnmatch.fnmatchcase(name.lower(), needle):
            continue
        matched_total += 1
        if len(containers) < limit:
            containers.append({
                "id": container_id,
                "name": name,
                "image": image,
                "state": state,
                "status": status,
                "ports": ports,
            })
    return {
        "pattern": pattern,
        "containers": containers,
        "result_count": len(containers),
        "matched_total": matched_total,
        "truncated": matched_total > len(containers),
    }


def docker_container_status(container: str) -> dict[str, Any]:
    target = normalize_container(container)
    template = (
        "{{.Id}}\t{{.Name}}\t{{.Config.Image}}\t{{json .State}}\t"
        "{{.RestartCount}}\t{{.Created}}\t{{.HostConfig.RestartPolicy.Name}}"
    )
    output = _run(["inspect", "--type=container", "--format", template, target], max_bytes=64_000).strip()
    parts = output.split("\t")
    if len(parts) != 7:
        raise DockerError("docker returned an unexpected container status format")
    container_id, name, image, state_json, restarts, created, restart_policy = parts
    try:
        state_data = json.loads(state_json)
    except json.JSONDecodeError as exc:
        raise DockerError("docker returned invalid container state") from exc
    if not isinstance(state_data, dict):
        raise DockerError("docker returned invalid container state")
    health_data = state_data.get("Health")
    health = str(health_data.get("Status") or "") if isinstance(health_data, dict) else ""
    return {
        "id": container_id,
        "name": name.lstrip("/"),
        "image": image,
        "state": str(state_data.get("Status") or ""),
        "running": bool(state_data.get("Running", False)),
        "pid": _to_int(str(state_data.get("Pid") or "0")),
        "restart_count": _to_int(restarts),
        "health": health or None,
        "restart_policy": restart_policy or None,
        "created": created or None,
    }


def docker_action(container: str, action: str) -> dict[str, Any]:
    target = normalize_container(container)
    normalized_action = str(action or "").strip().lower()
    authorize_docker_action(target, normalized_action)

    before = docker_container_status(target)
    _run([normalized_action, target], timeout=30.0, max_bytes=4_000)
    after = docker_container_status(target)
    return {
        "container": target,
        "action": normalized_action,
        "before": {
            "state": before.get("state"),
            "running": before.get("running"),
            "pid": before.get("pid"),
            "restart_count": before.get("restart_count"),
        },
        "after": {
            "state": after.get("state"),
            "running": after.get("running"),
            "pid": after.get("pid"),
            "restart_count": after.get("restart_count"),
        },
    }


def recover_joe_tunnel(confirm: bool = False) -> dict[str, Any]:
    """Recreate only Joe's protected tunnel from the fixed controller Compose project."""
    if confirm is not True:
        raise DockerError("confirm=true is required to recreate the Joe secure tunnel")

    before = docker_container_status(JOE_TUNNEL_CONTAINER)
    _run(
        [
            "compose",
            "-f", JOE_COMPOSE_FILE,
            "--project-directory", JOE_PROJECT_DIR,
            "--profile", "tunnel",
            "up", "-d", "--no-deps", "--force-recreate", JOE_TUNNEL_CONTAINER,
        ],
        timeout=180.0,
        max_bytes=12_000,
    )

    deadline = time.monotonic() + 45.0
    after = docker_container_status(JOE_TUNNEL_CONTAINER)
    while time.monotonic() < deadline:
        if not after.get("running"):
            raise DockerError("Joe secure tunnel failed to remain running after recreation")
        if after.get("health") == "healthy":
            break
        time.sleep(1.0)
        after = docker_container_status(JOE_TUNNEL_CONTAINER)

    return {
        "container": JOE_TUNNEL_CONTAINER,
        "action": "recreate",
        "confirmed": True,
        "before": {
            "state": before.get("state"),
            "running": before.get("running"),
            "pid": before.get("pid"),
            "restart_count": before.get("restart_count"),
            "health": before.get("health"),
        },
        "after": {
            "state": after.get("state"),
            "running": after.get("running"),
            "pid": after.get("pid"),
            "restart_count": after.get("restart_count"),
            "health": after.get("health"),
        },
        "ready_for_verification": bool(after.get("running")),
    }


def docker_logs(container: str, lines: int = 200, since_minutes: int = 0, text: str = "") -> dict[str, Any]:
    target = normalize_container(container)
    line_limit = max(1, min(int(lines), MAX_LOG_LINES))
    since = max(0, min(int(since_minutes), MAX_LOG_SINCE_MINUTES))
    needle = str(text or "").strip()
    if len(needle) > MAX_LOG_TEXT_FILTER or any(ch in needle for ch in "\x00\r\n"):
        raise DockerError("Docker log text filter is invalid or too long")
    scan_limit = min(MAX_LOG_SCAN_LINES, max(line_limit, line_limit * 5 if needle else line_limit))
    args = ["logs", "--timestamps", f"--tail={scan_limit}"]
    if since:
        args.append(f"--since={since}m")
    args.append(target)
    stdout, stderr = _run_logs(args)

    raw_entries: list[tuple[str, int, str, str | None, str]] = []
    sequence = 0
    for stream, text in (("stdout", stdout), ("stderr", stderr)):
        for line in text.splitlines():
            sequence += 1
            timestamp: str | None = None
            message = line
            if " " in line:
                first, remainder = line.split(" ", 1)
                if "T" in first and (first.endswith("Z") or "+" in first):
                    timestamp = first
                    message = remainder
            sort_key = timestamp or f"~{sequence:09d}"
            raw_entries.append((sort_key, sequence, stream, timestamp, message))

    raw_entries.sort(key=lambda item: (item[0], item[1]))
    needle_lower = needle.lower()
    filtered = [item for item in raw_entries if not needle_lower or needle_lower in item[4].lower()]
    selected = filtered[-line_limit:]
    entries = [
        {
            "timestamp": timestamp,
            "stream": stream,
            "message": redact_text(message, MAX_LOG_MESSAGE_CHARS),
        }
        for _key, _sequence, stream, timestamp, message in selected
    ]
    return {
        "container": target,
        "requested_lines": line_limit,
        "scan_lines": scan_limit,
        "since_minutes": since,
        "text_filter": needle or None,
        "entries": entries,
        "entry_count": len(entries),
        "matched_total": len(filtered),
        "truncated": len(filtered) > len(entries),
        "redaction": "enabled",
    }


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
