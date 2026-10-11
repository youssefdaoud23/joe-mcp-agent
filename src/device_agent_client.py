#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

AGENT_VERSION = "0.2.0"
INSTALL_PATH = Path("/usr/local/libexec/joe-mcp-device-agent.py")
CONFIG_DIR = Path("/var/lib/joe-mcp-agent")
CONFIG_FILE = CONFIG_DIR / "config.json"
SERVICE_FILE = Path("/etc/systemd/system/joe-mcp-device-agent.service")


def _post(url: str, payload: dict, token: str = "") -> dict:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": f"JoeMCPDeviceAgent/{AGENT_VERSION}"}
    if token:
        headers["Authorization"] = f"Device {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error", "registration failed")
        except Exception:
            detail = "registration failed"
        raise RuntimeError(f"Server rejected request: {detail}") from exc


def _metadata(name: str = "", routing: bool = False) -> dict:
    hostname = platform.node() or "unknown"
    payload = {
        "name": name or hostname,
        "hostname": hostname,
        "os": platform.platform(),
        "architecture": platform.machine(),
        "agent_version": AGENT_VERSION,
    }
    if routing:
        payload["routing_version"] = "1"
    return payload


def _write_config(payload: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(CONFIG_FILE)


def _load_config() -> dict:
    data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Invalid Joe device-agent configuration")
    return data


def install(server: str, name: str, install_service: bool = True, pairing_code: str = "") -> None:
    if os.geteuid() != 0:
        raise SystemExit("Install must be run with sudo/root")
    server = server.rstrip("/")
    if not server.startswith("https://"):
        raise SystemExit("Joe device pairing requires an HTTPS server URL")
    code = str(pairing_code or "").strip() or getpass.getpass("Pairing code: ").strip()
    if not code:
        raise SystemExit("Pairing code is required")
    registered = _post(server + "/api/device/register", {"code": code, **_metadata(name, routing=not install_service)})
    token = str(registered.get("device_token") or "")
    device_id = str(registered.get("device_id") or "")
    if not token or not device_id:
        raise SystemExit("Joe server returned an incomplete pairing response")

    _write_config({"server": server, "device_id": device_id, "device_token": token, "name": name or platform.node()})

    if not install_service:
        print(f"Joe managed agent enrolled as {device_id}. The systemd routing agent will use the stored credential.")
        return

    INSTALL_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(Path(__file__), INSTALL_PATH)
    os.chmod(INSTALL_PATH, 0o755)
    service = """[Unit]\nDescription=Joe MCP Device Agent\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /usr/local/libexec/joe-mcp-device-agent.py --run\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nReadOnlyPaths=/\nReadWritePaths=/var/lib/joe-mcp-agent\n\n[Install]\nWantedBy=multi-user.target\n"""
    SERVICE_FILE.write_text(service, encoding="utf-8")
    os.chmod(SERVICE_FILE, 0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "joe-mcp-device-agent.service"], check=True)
    print(f"Joe device paired as {device_id}. The presence agent service is running.")


def heartbeat_once() -> None:
    cfg = _load_config()
    server = str(cfg.get("server") or "").rstrip("/")
    token = str(cfg.get("device_token") or "")
    if not server or not token:
        raise RuntimeError("Joe device-agent configuration is incomplete")
    _post(server + "/api/device/heartbeat", _metadata(str(cfg.get("name") or "")), token)


def run_loop() -> None:
    while True:
        try:
            heartbeat_once()
            delay = 30
        except Exception as exc:
            print(f"heartbeat error: {exc}", file=sys.stderr, flush=True)
            delay = 15
        time.sleep(delay)


def main() -> None:
    parser = argparse.ArgumentParser(description="Joe MCP lightweight device presence agent")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--enroll-only", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--server", default="")
    parser.add_argument("--name", default="")
    parser.add_argument("--pairing-code", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.install:
        install(args.server, args.name, install_service=True, pairing_code=args.pairing_code)
    elif args.enroll_only:
        install(args.server, args.name, install_service=False, pairing_code=args.pairing_code)
    elif args.run:
        run_loop()
    elif args.once:
        heartbeat_once()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
