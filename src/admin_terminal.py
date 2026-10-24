from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


STATE_FILE = Path(os.getenv("JOE_ADMIN_TERMINAL_FILE", "/var/lib/joe-mcp-work/admin-terminal.json"))
MAX_COMMAND_BYTES = 64 * 1024
MAX_RUNTIME_SECONDS = 1800


class AdminTerminalDenied(PermissionError):
    pass


def status(path: Path | None = None) -> dict[str, Any]:
    target = path or STATE_FILE
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {"version": 1, "enabled": False}
    except (OSError, json.JSONDecodeError) as exc:
        raise AdminTerminalDenied("Admin terminal configuration is invalid") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise AdminTerminalDenied("Unsupported admin terminal configuration version")
    return {
        "version": 1,
        "enabled": bool(data.get("enabled", False)),
        "default_enabled": False,
        "requires_confirmation": True,
        "runs_as_host_root": True,
        "joe_credentials_masked": True,
        "max_runtime_seconds": MAX_RUNTIME_SECONDS,
    }


def set_enabled(enabled: bool, confirm: bool = False, path: Path | None = None) -> dict[str, Any]:
    if confirm is not True:
        raise AdminTerminalDenied("Changing the admin terminal gate requires confirm=true")
    target = path or STATE_FILE
    if target.is_symlink():
        raise AdminTerminalDenied("Admin terminal configuration path cannot be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {"version": 1, "enabled": bool(enabled)}
    temp = target.with_name(f".{target.name}.tmp")
    try:
        temp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    except OSError as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise AdminTerminalDenied("Unable to save admin terminal configuration") from exc
    return status(target)


def validate_request(command: str, cwd: str, confirm: bool = False) -> tuple[str, str]:
    if status().get("enabled") is not True:
        raise AdminTerminalDenied("Admin terminal is disabled by policy")
    if confirm is not True:
        raise AdminTerminalDenied("Admin terminal execution requires confirm=true")
    payload = str(command or "")
    if not payload.strip() or "\x00" in payload or len(payload.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise AdminTerminalDenied("Admin terminal command must be non-empty, NUL-free, and at most 64 KiB")
    root = str(cwd or "/").strip()
    if not root.startswith("/") or "\x00" in root or "\n" in root or "\r" in root:
        raise AdminTerminalDenied("Admin terminal working directory must be an absolute host path")
    target = Path(root).resolve(strict=False)
    if not target.exists() or not target.is_dir():
        raise AdminTerminalDenied("Admin terminal working directory must be an existing directory")
    protected_cwds = (
        "/var/lib/joe-mcp-work/.secrets",
        "/var/lib/joe-mcp-work/sap",
        "/var/lib/joe-mcp-agent",
        "/opt/joe-mcp/python/current/.secrets",
        "/opt/joe-mcp/python/current/data/auth",
        "/opt/joe-mcp/python/current/data/devices",
        "/opt/joe-mcp/python/current/data/sessions",
    )
    value = str(target)
    if any(value == prefix or value.startswith(prefix + "/") for prefix in protected_cwds):
        raise AdminTerminalDenied("Admin terminal cannot start inside a Joe credential/control-data path")
    return payload, value


def masked_paths(project_root: str) -> list[str]:
    project = str(Path(project_root).resolve(strict=False))
    return [
        "-/var/lib/joe-mcp-work/.secrets",
        "-/var/lib/joe-mcp-work/actions.json",
        "-/var/lib/joe-mcp-work/workspaces.json",
        "-/var/lib/joe-mcp-work/admin-terminal.json",
        "-/var/lib/joe-mcp-work/sap",
        "-/var/lib/joe-mcp-agent/config.json",
        f"-{project}/.secrets",
        f"-{project}/data/auth",
        f"-{project}/data/audit",
        f"-{project}/data/devices",
        f"-{project}/data/sessions",
    ]
