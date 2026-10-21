from __future__ import annotations

import json
import os
import pwd
import re
import time
from pathlib import Path
from typing import Any

# Shared policy/validation layer for the opt-in "Developer Access" feature.
#
# This module is imported by BOTH the private controller (to validate administrator input before it is
# stored/routed) and the managed node (host bridge + executor, to enforce the policy independently).
# It never stores, logs or returns sudo passwords.

POLICY_VERSION = 1
STATE_FILE = Path(os.getenv("JOE_DEVELOPER_ACCESS_FILE", "/var/lib/joe-mcp-work/developer-access.json"))
SUDO_TTL_CHOICES = (15, 30, 60)
DEFAULT_SUDO_TTL_MINUTES = 15
MAX_COMMAND_BYTES = 64 * 1024
MAX_PASSWORD_BYTES = 1024
MAX_RUNTIME_SECONDS = 1800
MAX_CONCURRENT_PRIVILEGED_RUNS = 4
ROOT_USER = "root"
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
POLICY_KEYS = frozenset({"enabled", "run_as_user", "sudo_allowed"})

# Joe credential and control-data locations that stay inaccessible from every Developer Access
# command, including root. Paths are masked with systemd InaccessiblePaths ("-" = ignore if absent).
JOE_PROTECTED_ABSOLUTE_PATHS = (
    "/var/lib/joe-mcp-agent",
    "/var/lib/joe-mcp-work",
    "/run/joe-mcp",
)
JOE_PROTECTED_PROJECT_SUBPATHS = (
    ".secrets",
    ".env",
    ".joe-node-install",
    "data/auth",
    "data/audit",
    "data/devices",
    "data/sessions",
)


class DeveloperAccessDenied(RuntimeError):
    """Policy or validation failure. Messages never contain commands or credentials."""


def default_policy() -> dict[str, Any]:
    return {"version": POLICY_VERSION, "enabled": False, "run_as_user": "", "sudo_allowed": False}


def validate_username(value: Any) -> str:
    if not isinstance(value, str):
        raise DeveloperAccessDenied("Linux user must be a string")
    name = value
    if not name:
        return ""
    if not USERNAME_RE.fullmatch(name):
        raise DeveloperAccessDenied("Linux user must be a lowercase POSIX account name (letters, digits, '_' or '-', at most 32 characters)")
    return name


def normalize_policy(value: Any) -> dict[str, Any]:
    """Strictly validate a Developer Access policy. Unknown keys and non-boolean flags are rejected."""
    if value is None:
        return default_policy()
    if not isinstance(value, dict):
        raise DeveloperAccessDenied("Developer Access policy must be an object")
    unknown = sorted(set(str(key) for key in value) - POLICY_KEYS - {"version"})
    if unknown:
        raise DeveloperAccessDenied("Unsupported Developer Access policy field(s): " + ", ".join(unknown))
    if "version" in value and value.get("version") != POLICY_VERSION:
        raise DeveloperAccessDenied("Unsupported Developer Access policy version")
    enabled = value.get("enabled", False)
    sudo_allowed = value.get("sudo_allowed", False)
    if not isinstance(enabled, bool) or not isinstance(sudo_allowed, bool):
        raise DeveloperAccessDenied("enabled and sudo_allowed must be true or false")
    user = validate_username(value.get("run_as_user", ""))
    if enabled and not user:
        raise DeveloperAccessDenied("Select the existing Linux user Developer Access runs as (root must be chosen explicitly)")
    if user == ROOT_USER and sudo_allowed:
        raise DeveloperAccessDenied("root runs directly and never uses sudo; sudo_allowed must be false for root")
    return {"version": POLICY_VERSION, "enabled": enabled, "run_as_user": user, "sudo_allowed": sudo_allowed}


def policies_equal(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    try:
        return normalize_policy(left) == normalize_policy(right)
    except DeveloperAccessDenied:
        return False


def normalize_sudo_ttl(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in SUDO_TTL_CHOICES:
        raise DeveloperAccessDenied("sudo authorization lifetime must be one of: " + ", ".join(str(item) for item in SUDO_TTL_CHOICES) + " minutes")
    return int(value)


def validate_password_shape(value: Any) -> str:
    """Shape-check a password without ever echoing it. Returns the value for immediate use only."""
    if not isinstance(value, str) or not value:
        raise DeveloperAccessDenied("A sudo password is required to authorize sudo")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise DeveloperAccessDenied("The sudo password contains characters that cannot be submitted")
    if len(value.encode("utf-8", errors="replace")) > MAX_PASSWORD_BYTES:
        raise DeveloperAccessDenied("The sudo password is too long")
    return value


def resolve_linux_user(name: str) -> dict[str, Any]:
    """Resolve an existing local account. Only the literal name 'root' may map to UID 0."""
    wanted = validate_username(name)
    if not wanted:
        raise DeveloperAccessDenied("A Linux user is required")
    try:
        entry = pwd.getpwnam(wanted)
    except KeyError as exc:
        raise DeveloperAccessDenied(f"Linux user does not exist on this device: {wanted}") from exc
    if entry.pw_uid == 0 and wanted != ROOT_USER:
        raise DeveloperAccessDenied("Accounts that alias UID 0 must be selected as root explicitly")
    if wanted == ROOT_USER and entry.pw_uid != 0:
        raise DeveloperAccessDenied("The root account on this device does not have UID 0")
    return {"name": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid, "home": entry.pw_dir, "is_root": entry.pw_uid == 0}


def protected_paths(project_root: str | Path | None = None) -> list[str]:
    paths = list(JOE_PROTECTED_ABSOLUTE_PATHS)
    root = str(project_root or os.getenv("JOE_PROJECT_ROOT", "") or "").strip()
    if root:
        project = str(Path(root).resolve(strict=False))
        paths.extend(f"{project.rstrip('/')}/{sub}" for sub in JOE_PROTECTED_PROJECT_SUBPATHS)
    for path in paths:
        if not path.startswith("/") or any(ch.isspace() for ch in path) or any(ch in path for ch in "\x00\r\n"):
            raise DeveloperAccessDenied("A Joe protected path cannot be masked safely; refusing to start Developer Access")
    return paths


def masked_paths(project_root: str | Path | None = None) -> list[str]:
    """systemd InaccessiblePaths= entries ('-' prefix: ignore when the path does not exist)."""
    return ["-" + path for path in protected_paths(project_root)]


def is_protected_path(path: str, project_root: str | Path | None = None) -> bool:
    candidate = str(Path(path).resolve(strict=False))
    for protected in protected_paths(project_root):
        resolved = str(Path(protected).resolve(strict=False))
        if candidate == resolved or candidate.startswith(resolved.rstrip("/") + "/"):
            return True
    return False


def validate_terminal_request(command: Any, cwd: Any, confirm: Any, privileged: Any, project_root: str | Path | None = None) -> tuple[str, str, bool]:
    if confirm is not True:
        raise DeveloperAccessDenied("Developer terminal execution requires confirm=true")
    if not isinstance(privileged, bool):
        raise DeveloperAccessDenied("privileged must be true or false")
    payload = command if isinstance(command, str) else ""
    if not payload.strip() or "\x00" in payload or len(payload.encode("utf-8", errors="replace")) > MAX_COMMAND_BYTES:
        raise DeveloperAccessDenied("Developer terminal command must be non-empty, NUL-free, and at most 64 KiB")
    raw_cwd = str(cwd or "/").strip() or "/"
    if not raw_cwd.startswith("/") or any(ch in raw_cwd for ch in "\x00\r\n"):
        raise DeveloperAccessDenied("Developer terminal working directory must be an absolute host path")
    target = Path(raw_cwd).resolve(strict=False)
    if is_protected_path(str(target), project_root):
        raise DeveloperAccessDenied("Developer terminal cannot start inside a Joe credential/control-data path")
    if not target.exists() or not target.is_dir():
        raise DeveloperAccessDenied("Developer terminal working directory must be an existing directory")
    return payload, str(target), privileged


def sandbox_properties(user: str, *, is_root: bool, runtime_seconds: int, project_root: str | Path | None = None, allow_privilege_gain: bool = False) -> list[str]:
    """systemd properties shared by every Developer Access unit.

    Deliberately absent: filesystem isolation, PrivateNetwork, capability/syscall filters. Developer
    Access is a real host environment; the only enforced boundary is the Joe credential masking and,
    for a normal user without an authorized sudo anchor, NoNewPrivileges.
    """
    properties = [
        f"User={user}",
        "UMask=0022",
        "InaccessiblePaths=" + " ".join(masked_paths(project_root)),
        f"RuntimeMaxSec={int(runtime_seconds)}s",
    ]
    if not is_root and not allow_privilege_gain:
        properties.append("NoNewPrivileges=yes")
    return properties


def build_terminal_argv(unit: str, cwd: str, properties: list[str]) -> list[str]:
    argv = [
        "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        f"--unit={unit}", f"--working-directory={cwd}",
        "--setenv=LANG=C.UTF-8", "--setenv=LC_ALL=C.UTF-8", "--setenv=TERM=dumb",
        "--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ]
    for item in properties:
        argv.extend(["--property", item])
    argv.extend(["--", "/bin/bash", "-s"])
    return argv


def load_policy(path: Path | None = None) -> dict[str, Any]:
    """Load the node-local policy. Any problem fails closed to the disabled default."""
    target = path or STATE_FILE
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        return normalize_policy(data)
    except (OSError, json.JSONDecodeError, DeveloperAccessDenied):
        return default_policy()


def save_policy(policy: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    target = path or STATE_FILE
    normalized = normalize_policy(policy)
    if target.is_symlink():
        raise DeveloperAccessDenied("Developer Access state path cannot be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = target.with_name(f".{target.name}.tmp")
    try:
        temp.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    except OSError as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise DeveloperAccessDenied("Unable to save Developer Access state") from exc
    return normalized


def public_status(policy: dict[str, Any], sudo: dict[str, Any] | None = None, *, available: bool = True, reason: str = "") -> dict[str, Any]:
    """The only shape that ever leaves the node/controller: no secrets, no command text."""
    normalized = normalize_policy(policy)
    state = sudo or {}
    authorized = bool(state.get("authorized"))
    remaining = max(0, int(state.get("remaining_seconds", 0) or 0)) if authorized else 0
    result: dict[str, Any] = {
        "version": POLICY_VERSION,
        "enabled": bool(normalized["enabled"]),
        "available": bool(available),
        "run_as_user": normalized["run_as_user"],
        "run_as_root": bool(normalized["enabled"] and normalized["run_as_user"] == ROOT_USER),
        "sudo_allowed": bool(normalized["sudo_allowed"]),
        "sudo_authorized": authorized,
        "sudo_remaining_seconds": remaining,
        "sudo_ttl_choices_minutes": list(SUDO_TTL_CHOICES),
        "requires_confirmation": True,
        "joe_credentials_masked": True,
        "default_enabled": False,
    }
    if authorized:
        result["sudo_user"] = str(state.get("user") or normalized["run_as_user"])
        expires = state.get("expires_at")
        if isinstance(expires, (int, float)):
            result["sudo_expires_at"] = int(expires)
    if reason:
        result["reason"] = str(reason)[:200]
    return result


def now() -> float:
    return time.time()
