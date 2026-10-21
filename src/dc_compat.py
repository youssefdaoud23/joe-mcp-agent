from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


STATE_FILE = Path(os.getenv("JOE_DC_COMPAT_FILE", "/var/lib/joe-mcp-work/desktop-commander.json"))
FALLBACK_FILE = Path(__file__).resolve().parents[1] / "config" / "desktop_commander.json"

# Mirrors Desktop Commander's current default command guardrail list.
DEFAULT_BLOCKED_COMMANDS = [
    "mkfs", "format", "mount", "umount", "fdisk", "dd", "parted", "diskpart",
    "sudo", "su", "passwd", "adduser", "useradd", "usermod", "groupadd", "chsh", "visudo",
    "shutdown", "reboot", "halt", "poweroff", "init",
    "iptables", "firewall", "netsh",
    "sfc", "bcdedit", "reg", "net", "sc", "runas", "cipher", "takeown",
]


class DesktopCommanderConfigError(PermissionError):
    pass


def _default_config() -> dict[str, Any]:
    return {
        "version": 1,
        "enabled": True,
        "blockedCommands": list(DEFAULT_BLOCKED_COMMANDS),
        "defaultShell": "/bin/bash",
        "allowedDirectories": [],
        "fileReadLineLimit": 1000,
        "fileWriteLineLimit": 50,
        "telemetryEnabled": False,
    }


def load_config(path: Path | None = None) -> dict[str, Any]:
    target = path or STATE_FILE
    try:
        source = target if target.exists() else FALLBACK_FILE
    except OSError:
        source = FALLBACK_FILE
    try:
        source_exists = source.exists()
    except OSError:
        source_exists = False
    if not source_exists:
        return _default_config()
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DesktopCommanderConfigError("Desktop Commander compatibility configuration is invalid") from exc
    if not isinstance(data, dict) or int(data.get("version", 0) or 0) != 1:
        raise DesktopCommanderConfigError("Unsupported Desktop Commander compatibility configuration version")
    result = _default_config()
    result.update(data)
    blocked = result.get("blockedCommands", [])
    directories = result.get("allowedDirectories", [])
    if not isinstance(blocked, list) or not all(isinstance(item, str) and item.strip() for item in blocked):
        raise DesktopCommanderConfigError("blockedCommands must be a list of command names")
    if not isinstance(directories, list) or not all(isinstance(item, str) and item.startswith("/") for item in directories):
        raise DesktopCommanderConfigError("allowedDirectories must be a list of absolute paths")
    result["blockedCommands"] = list(dict.fromkeys(item.strip() for item in blocked))
    result["allowedDirectories"] = list(dict.fromkeys(str(Path(item).resolve(strict=False)) for item in directories))
    shell = str(result.get("defaultShell", "/bin/bash") or "/bin/bash").strip()
    if shell not in {"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}:
        raise DesktopCommanderConfigError("defaultShell must be bash or sh")
    result["defaultShell"] = shell
    result["enabled"] = bool(result.get("enabled", False))
    result["telemetryEnabled"] = bool(result.get("telemetryEnabled", False))
    return result


def enabled() -> bool:
    try:
        return bool(load_config().get("enabled", False))
    except DesktopCommanderConfigError:
        return False


def blocked_commands() -> list[str]:
    return list(load_config().get("blockedCommands", DEFAULT_BLOCKED_COMMANDS))


def allowed_directories() -> list[str]:
    return list(load_config().get("allowedDirectories", []))


def default_shell() -> str:
    return str(load_config().get("defaultShell", "/bin/bash"))


def path_allowed(path: str) -> bool:
    if not enabled():
        return False
    directories = allowed_directories()
    if not directories:
        return True
    candidate = Path(path).resolve(strict=False)
    for raw in directories:
        root = Path(raw).resolve(strict=False)
        if candidate == root or candidate.is_relative_to(root):
            return True
    return False


def validate_shell_command(command: str) -> str:
    payload = str(command or "")
    if not payload.strip() or "\x00" in payload:
        raise DesktopCommanderConfigError("Command cannot be empty or contain NUL bytes")
    if len(payload.encode("utf-8")) > 64 * 1024:
        raise DesktopCommanderConfigError("Command exceeds the 64 KiB limit")
    # Guardrail, not a hardened sandbox: block configured command names when they
    # appear as executable tokens, including an absolute-path spelling.
    for name in blocked_commands():
        escaped = re.escape(name)
        if re.search(rf"(?i)(?<![A-Za-z0-9_.-])(?:/[A-Za-z0-9_./+-]+/)?{escaped}(?=$|[\s;&|()<>])", payload):
            raise DesktopCommanderConfigError(f"Command is blocked by Desktop Commander compatibility policy: {name}")
    return payload


def public_config() -> dict[str, Any]:
    data = load_config()
    return {
        "enabled": bool(data.get("enabled", False)),
        "blockedCommands": list(data.get("blockedCommands", [])),
        "defaultShell": str(data.get("defaultShell", "/bin/bash")),
        "allowedDirectories": list(data.get("allowedDirectories", [])),
        "fileReadLineLimit": int(data.get("fileReadLineLimit", 1000) or 1000),
        "fileWriteLineLimit": int(data.get("fileWriteLineLimit", 50) or 50),
        "telemetryEnabled": bool(data.get("telemetryEnabled", False)),
    }
