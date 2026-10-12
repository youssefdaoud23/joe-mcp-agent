from __future__ import annotations

import json
import os
import platform
import random
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from src.node_executor import NodeExecutor
from src.remote_protocol import ACTION_REMOTE_TOOLS, ALL_REMOTE_TOOLS, LIFECYCLE_SHUTDOWN_AGENT, LIFECYCLE_UPDATE_AGENT, PROTOCOL_VERSION, READ_REMOTE_TOOLS

AGENT_VERSION = "0.7.0"
LIFECYCLE_ROTATE_TOKEN = "__rotate_device_token__"
UPDATE_SERVICE = "joe-mcp-node-update.service"
AGENT_SERVICE = "joe-mcp-node-agent.service"
CONFIG_FILE = Path(os.getenv("JOE_DEVICE_CONFIG", "/var/lib/joe-mcp-agent/config.json"))
POLL_SECONDS = 20
_STOP_REQUESTED = False


def _handle_stop_signal(signum: int, _frame: Any) -> None:
    global _STOP_REQUESTED
    _STOP_REQUESTED = True
    print(f"Joe node agent received signal {signum}; graceful shutdown requested", flush=True)


def _load_config() -> dict[str, str]:
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Joe node routing credential is unavailable") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Joe node routing credential is invalid")
    server = str(data.get("server") or "").rstrip("/")
    token = str(data.get("device_token") or "")
    device_id = str(data.get("device_id") or "")
    name = str(data.get("name") or platform.node() or "managed-node")[:120]
    if not server.startswith("https://") or not token or not device_id.startswith("dev_"):
        raise RuntimeError("Joe node routing credential is incomplete")
    return {"server": server, "token": token, "device_id": device_id, "name": name}


def _metadata(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "hostname": platform.node() or "unknown",
        "os": platform.platform(),
        "architecture": platform.machine(),
        "agent_version": AGENT_VERSION,
        "software_version": os.getenv("JOE_VERSION", "0.33.0"),
        "routing_version": str(PROTOCOL_VERSION),
        "filesystem_scope_version": "1",
        "remote_tools": len(ALL_REMOTE_TOOLS),
        "update_lifecycle": True,
        "shutdown_lifecycle": True,
    }


def _post(server: str, path: str, token: str, payload: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        server + path,
        data=raw,
        headers={
            "Authorization": f"Device {token}",
            "Content-Type": "application/json",
            "User-Agent": f"JoeMCPNode/{AGENT_VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8", errors="replace")).get("error", "request rejected")
        except Exception:
            detail = "request rejected"
        raise RuntimeError(f"Controller rejected request: {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Controller connection failed: {exc}") from exc
    if not body:
        return {}
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Controller returned an invalid response") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Controller returned an invalid response")
    return data


def _save_device_token(cfg: dict[str, str], token: str) -> None:
    payload = {
        "server": cfg["server"],
        "device_id": cfg["device_id"],
        "device_token": token,
        "name": cfg["name"],
    }
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(CONFIG_FILE)


def _trigger_managed_update(device_id: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["/usr/bin/systemctl", "start", "--no-block", UPDATE_SERVICE],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Managed Joe update service could not be started")
    return {
        "update_requested": True,
        "device_id": device_id,
        "service": UPDATE_SERVICE,
        "status_tool": "managed_update_status",
    }


def _stop_agent_service() -> None:
    try:
        subprocess.Popen(
            ["/usr/bin/systemctl", "stop", "--no-block", AGENT_SERVICE],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise RuntimeError("Managed Joe agent service could not be stopped") from exc


def _submit_result(server: str, token: str, job_id: str, result: dict[str, Any] | None, error: str | None) -> None:
    payload: dict[str, Any] = {"job_id": job_id}
    if error is not None:
        payload["error"] = str(error)[:4000]
    else:
        payload["result"] = result if isinstance(result, dict) else {"value": result}
    _post(server, "/api/device/result", token, payload, timeout=20)


def _report_offline(cfg: dict[str, str], reason: str = "agent_shutdown") -> None:
    try:
        _post(cfg["server"], "/api/device/offline", cfg["token"], {"reason": reason}, timeout=8)
        print("Joe node agent marked device offline", flush=True)
    except Exception as exc:
        print(f"offline presence update failed; controller TTL fallback remains active: {exc}", file=sys.stderr, flush=True)


def run() -> None:
    global _STOP_REQUESTED
    _STOP_REQUESTED = False
    cfg = _load_config()
    executor = NodeExecutor()
    failures = 0
    for wanted_signal in (signal.SIGTERM, signal.SIGINT):
        signal.signal(wanted_signal, _handle_stop_signal)
    print(
        f"Joe node agent {AGENT_VERSION} starting for {cfg['device_id']} with "
        f"{len(READ_REMOTE_TOOLS)} read and {len(ACTION_REMOTE_TOOLS)} action tools",
        flush=True,
    )
    try:
        while not _STOP_REQUESTED:
            try:
                cfg = _load_config()
                response = _post(
                    cfg["server"],
                    "/api/device/poll",
                    cfg["token"],
                    {"metadata": _metadata(cfg["name"]), "wait_seconds": POLL_SECONDS},
                    timeout=POLL_SECONDS + 10,
                )
                failures = 0
                executor.set_filesystem_policy(response.get("filesystem_policy"))
                job = response.get("job")
                if not isinstance(job, dict):
                    continue
                job_id = str(job.get("job_id") or "")
                tool = str(job.get("tool") or "")
                arguments = job.get("arguments", {})
                if not job_id.startswith("job_") or not isinstance(arguments, dict):
                    if job_id:
                        _submit_result(cfg["server"], cfg["token"], job_id, None, "Invalid routed job")
                    continue
                shutdown_after_result = False
                try:
                    if tool == LIFECYCLE_ROTATE_TOKEN:
                        rotated = _post(
                            cfg["server"],
                            "/api/device/rotate",
                            cfg["token"],
                            {"device_id": cfg["device_id"]},
                            timeout=20,
                        )
                        new_token = str(rotated.get("device_token") or "")
                        if not new_token:
                            raise RuntimeError("Controller returned an incomplete rotated credential")
                        _save_device_token(cfg, new_token)
                        result = {
                            "rotated": True,
                            "device_id": cfg["device_id"],
                            "grace_seconds": int(rotated.get("grace_seconds", 0) or 0),
                        }
                    elif tool == LIFECYCLE_SHUTDOWN_AGENT:
                        result = {"disconnect_requested": True, "device_id": cfg["device_id"], "service": AGENT_SERVICE, "credential_preserved": True}
                        shutdown_after_result = True
                    elif tool == LIFECYCLE_UPDATE_AGENT:
                        result = _trigger_managed_update(cfg["device_id"])
                    elif tool in ALL_REMOTE_TOOLS:
                        result = executor.execute(tool, arguments)
                    else:
                        raise RuntimeError("Unsupported routed lifecycle job")
                except Exception as exc:
                    _submit_result(cfg["server"], cfg["token"], job_id, None, str(exc))
                else:
                    _submit_result(cfg["server"], cfg["token"], job_id, result, None)
                    if shutdown_after_result:
                        print("Joe node agent stopping by controller request", flush=True)
                        _stop_agent_service()
                        return
            except Exception as exc:
                failures += 1
                if _STOP_REQUESTED:
                    break
                delay = min(30.0, 2.0 + failures * 2.0) + random.random()
                print(f"routing error: {exc}; retrying in {delay:.1f}s", file=sys.stderr, flush=True)
                time.sleep(delay)
    finally:
        print("Joe node agent shutting down; reporting offline presence", flush=True)
        try:
            cfg = _load_config()
            _report_offline(cfg)
        except Exception as exc:
            print(f"graceful shutdown could not reload device identity: {exc}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    run()
