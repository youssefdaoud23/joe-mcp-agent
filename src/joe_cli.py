from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

JOE_VERSION = os.getenv("JOE_VERSION", "0.28.0")
DEVICE_CONFIG = Path("/var/lib/joe-mcp-agent/config.json")
CONTROLLER_HEALTH = "http://127.0.0.1:8765/health"
TUNNEL_HEALTH = "http://127.0.0.1:8766/readyz"
MANAGED_SERVICES = (
    "joe-mcp-host-bridge.service",
    "joe-mcp-session-host.service",
    "joe-mcp-node-agent.service",
)
CONTROLLER_SERVICES = (
    "joe-mcp-host-bridge.service",
    "joe-mcp-session-host.service",
)


def _run(args: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": "/",
                "NO_COLOR": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)[:500]
    return completed.returncode, completed.stdout[:20_000].strip()


def _service_state(unit: str) -> str:
    code, output = _run(["/usr/bin/systemctl", "is-active", unit], timeout=5)
    value = output.splitlines()[0].strip() if output else "unknown"
    return value if code == 0 else value or "inactive"


def _http_status(url: str) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            body = response.read(512).decode("utf-8", errors="replace").strip()
            return response.status == 200, body or f"HTTP {response.status}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, str(exc)[:200]


def _role() -> str:
    return "managed" if DEVICE_CONFIG.is_file() else "controller"


def _device_summary(path: Path = DEVICE_CONFIG) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "device_id": str(data.get("device_id") or ""),
        "name": str(data.get("name") or ""),
        "server": str(data.get("server") or ""),
    }


def _print_status() -> int:
    role = _role()
    print(f"Joe MCP {JOE_VERSION}")
    print(f"Role: {role}")
    services = MANAGED_SERVICES if role == "managed" else CONTROLLER_SERVICES
    healthy = True
    for unit in services:
        state = _service_state(unit)
        healthy = healthy and state == "active"
        print(f"{unit}: {state}")
    if role == "managed":
        device = _device_summary()
        if device:
            print(f"Device: {device.get('name') or '-'} ({device.get('device_id') or '-'})")
            print(f"Controller: {device.get('server') or '-'}")
    else:
        ok, detail = _http_status(CONTROLLER_HEALTH)
        healthy = healthy and ok
        print(f"Controller API: {'ready' if ok else 'offline'} ({detail})")
        tunnel_ok, tunnel_detail = _http_status(TUNNEL_HEALTH)
        print(f"Secure tunnel: {'ready' if tunnel_ok else 'offline'} ({tunnel_detail})")
    return 0 if healthy else 1


def _doctor() -> int:
    role = _role()
    failures: list[str] = []
    print(f"Joe doctor - role={role} version={JOE_VERSION}")
    for binary in ("python3", "systemctl", "tmux"):
        path = shutil.which(binary)
        print(f"{binary}: {path or 'missing'}")
        if not path:
            failures.append(f"missing {binary}")
    services = MANAGED_SERVICES if role == "managed" else CONTROLLER_SERVICES
    for unit in services:
        state = _service_state(unit)
        print(f"{unit}: {state}")
        if state != "active":
            failures.append(f"{unit} is {state}")
    if role == "controller":
        ok, detail = _http_status(CONTROLLER_HEALTH)
        print(f"controller health: {'ok' if ok else 'failed'} - {detail}")
        if not ok:
            failures.append("controller health endpoint failed")
        tunnel_ok, tunnel_detail = _http_status(TUNNEL_HEALTH)
        print(f"secure tunnel: {'ok' if tunnel_ok else 'not ready'} - {tunnel_detail}")
    else:
        device = _device_summary()
        if not device.get("device_id") or not device.get("server"):
            failures.append("managed device identity is incomplete")
        print(f"device identity: {'ok' if device.get('device_id') else 'missing'}")
        print(f"controller: {device.get('server') or 'missing'}")
    if failures:
        print("Result: issues found")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print("Result: healthy")
    return 0


def _logs(lines: int) -> int:
    count = max(20, min(int(lines), 500))
    units = MANAGED_SERVICES if _role() == "managed" else CONTROLLER_SERVICES
    for unit in units:
        print(f"\n== {unit} ==")
        _code, output = _run([
            "/usr/bin/journalctl",
            "-u",
            unit,
            "-n",
            str(count),
            "--no-pager",
            "-o",
            "short-iso",
        ], timeout=12)
        print(output or "No log entries.")
    return 0


def _managed_action(action: str) -> int:
    if _role() != "managed":
        print(f"joe {action} is for managed devices. Controller lifecycle changes use Joe's guarded deployment workflow.")
        return 2
    if action == "update":
        args = ["/usr/bin/systemctl", "start", "--no-block", "joe-mcp-node-update.service"]
    elif action == "reconnect":
        args = ["/usr/bin/systemctl", "restart", "joe-mcp-node-agent.service"]
    elif action == "disconnect":
        args = ["/usr/bin/systemctl", "stop", "joe-mcp-node-agent.service"]
    else:
        return 2
    code, output = _run(args, timeout=12)
    if output:
        print(output)
    if code == 0:
        if action == "disconnect":
            print("Joe managed agent disconnected. Device credential was preserved.")
        elif action == "reconnect":
            print("Joe managed agent restarted and will reconnect automatically.")
        else:
            print("Joe managed update requested. Use 'joe status' to verify the agent after it completes.")
    return code


def _show_device() -> int:
    if _role() != "managed":
        print("This machine is the Joe controller, not a managed device.")
        return 0
    device = _device_summary()
    print(f"Name: {device.get('name') or '-'}")
    print(f"Device ID: {device.get('device_id') or '-'}")
    print(f"Controller: {device.get('server') or '-'}")
    print("Credential: stored securely (not displayed)")
    return 0


def _show_controller() -> int:
    if _role() == "managed":
        device = _device_summary()
        print(f"Controller: {device.get('server') or '-'}")
        print("Routing: outbound HTTPS")
        return 0
    ok, detail = _http_status(CONTROLLER_HEALTH)
    tunnel_ok, tunnel_detail = _http_status(TUNNEL_HEALTH)
    print(f"Controller API: {'ready' if ok else 'offline'} ({detail})")
    print(f"Secure tunnel: {'ready' if tunnel_ok else 'offline'} ({tunnel_detail})")
    return 0 if ok else 1


def _uninstall_guidance() -> int:
    if _role() == "managed":
        print("Safe removal guidance:")
        print("  1. Revoke this device in Joe Control Center -> Devices.")
        print("  2. Stop and disable joe-mcp-node-agent.service, joe-mcp-host-bridge.service, and joe-mcp-session-host.service.")
        print("  3. Remove /opt/joe-node only after confirming no Joe sessions are needed.")
        print("Joe does not auto-delete credentials or runtime data from this command.")
    else:
        print("Controller uninstall is intentionally not automated by the joe CLI.")
        print("Back up required state and use the documented controller removal procedure.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="joe", description="Joe MCP local administration helper")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="show Joe services and connectivity")
    sub.add_parser("doctor", help="run safe local diagnostics")
    logs = sub.add_parser("logs", help="show bounded Joe service logs")
    logs.add_argument("--lines", type=int, default=80)
    sub.add_parser("version", help="show Joe version")
    sub.add_parser("update", help="request a managed-agent update")
    sub.add_parser("reconnect", help="restart a managed agent")
    sub.add_parser("disconnect", help="stop a managed agent without deleting identity")
    sub.add_parser("device", help="show safe managed-device identity")
    sub.add_parser("controller", help="show controller connection status")
    sub.add_parser("uninstall", help="show safe removal guidance")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        return _print_status()
    if args.command == "doctor":
        return _doctor()
    if args.command == "logs":
        return _logs(args.lines)
    if args.command == "version":
        print(JOE_VERSION)
        return 0
    if args.command in {"update", "reconnect", "disconnect"}:
        return _managed_action(args.command)
    if args.command == "device":
        return _show_device()
    if args.command == "controller":
        return _show_controller()
    if args.command == "uninstall":
        return _uninstall_guidance()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
