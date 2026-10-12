from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from src.workspace_policy import WorkspaceDenied, matches_allowed_glob, resolve_workspace, workspace_relative_path


MAX_ARGS = 64
MAX_ARG_CHARS = 4096
MAX_INLINE_CODE_BYTES = 64 * 1024
MAX_SHELL_COMMAND_BYTES = 64 * 1024
NODE_CHECK_EXTENSIONS = {".js", ".mjs", ".cjs"}
PYTEST_SIMPLE_FLAGS = {"-q", "-v", "-vv", "-x", "-s", "--disable-warnings", "--collect-only", "--strict-markers"}
PYTEST_PREFIX_FLAGS = ("--maxfail=", "--tb=", "--durations=")
PYTEST_VALUE_FLAGS = {"-k", "-m"}
SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9_ .:/+*?!=<>&|()\[\]-]{1,500}$")


def _args(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > MAX_ARGS:
        raise WorkspaceDenied("Arguments must be a bounded list")
    result: list[str] = []
    for value in values:
        item = str(value)
        if not item or len(item) > MAX_ARG_CHARS or "\x00" in item or "\n" in item or "\r" in item:
            raise WorkspaceDenied("Invalid execution argument")
        result.append(item)
    return result


def _runtime(section: dict[str, Any], default: int) -> int:
    value = int(section.get("max_runtime_seconds", default) or default)
    return max(10, min(value, 3600))


def _network_mode(section: dict[str, Any]) -> str:
    value = str(section.get("network", "isolated") or "isolated").strip().lower()
    if value not in {"isolated", "host"}:
        raise WorkspaceDenied("Workspace execution network must be isolated or host")
    return value


def _node_executable() -> str:
    for raw in ("/usr/bin/node", "/usr/local/bin/node"):
        candidate = Path(raw)
        if candidate.exists() and candidate.is_file() and os.access(candidate, os.X_OK):
            resolved = candidate.resolve(strict=True)
            if str(resolved) in {"/usr/bin/node", "/usr/local/bin/node"}:
                return str(candidate)
    raise FileNotFoundError("node executable is unavailable")



def _python_executable(profile: dict[str, Any], section: dict[str, Any]) -> str:
    configured = str(section.get("executable", "/usr/bin/python3") or "/usr/bin/python3").strip()
    root = Path(profile["root"]).resolve(strict=False)
    if configured.startswith("/"):
        candidate = Path(configured)
    else:
        if "\x00" in configured or configured.startswith("../") or "/../" in configured:
            raise WorkspaceDenied("Invalid workspace Python executable")
        candidate = root / configured
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(str(candidate))
    resolved = candidate.resolve(strict=True)
    if not resolved.name.startswith("python"):
        raise WorkspaceDenied("Workspace executable must resolve to a Python interpreter")
    inside_workspace = resolved == root or resolved.is_relative_to(root)
    system_python = (
        resolved.parent in {Path("/usr/bin"), Path("/usr/local/bin")}
        and (resolved.name == "python" or resolved.name.startswith("python3"))
    )
    if not inside_workspace and not system_python:
        raise WorkspaceDenied("Workspace Python executable resolves outside the approved Python runtime")
    if not os.access(candidate, os.X_OK):
        raise WorkspaceDenied("Workspace Python executable is not executable")
    return str(candidate)

def _shell_executable(section: dict[str, Any]) -> str:
    configured = str(section.get("executable", "/bin/bash") or "/bin/bash").strip()
    if configured not in {"/bin/bash", "/bin/sh"}:
        raise WorkspaceDenied("Workspace shell executable must be /bin/bash or /bin/sh")
    candidate = Path(configured)
    if not candidate.exists() or not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise FileNotFoundError(configured)
    resolved = candidate.resolve(strict=True)
    if resolved not in {Path("/usr/bin/bash"), Path("/usr/bin/dash")} and resolved != candidate:
        raise WorkspaceDenied("Workspace shell resolves outside the approved system shell runtime")
    return configured


def build_shell_command(workspace: str, command: str) -> dict[str, Any]:
    profile = resolve_workspace(workspace, "modify")
    section = dict(profile.get("shell", {})) if isinstance(profile.get("shell"), dict) else {}
    if not bool(section.get("enabled", True)):
        raise WorkspaceDenied(f"Shell execution is disabled for workspace: {workspace}")
    section.setdefault("network", "isolated")
    section.setdefault("max_runtime_seconds", 600)
    payload = str(command or "")
    encoded = payload.encode("utf-8")
    if not payload.strip() or len(encoded) > MAX_SHELL_COMMAND_BYTES or "\x00" in payload:
        raise WorkspaceDenied("Workspace shell command must be non-empty, NUL-free, and at most 64 KiB")
    executable = _shell_executable(section)
    return {
        "workspace": profile["name"],
        "cwd": profile["root"],
        "argv": [executable, "-s"],
        "display": f"{Path(executable).name} -s [workspace command via stdin]",
        "max_runtime_seconds": _runtime(section, 600),
        "network": _network_mode(section),
        "workspace_access": "write",
        "stdin_payload": payload,
    }


def build_python_command(workspace: str, script: str, args: Any = None) -> dict[str, Any]:
    profile, candidate, relative = workspace_relative_path(workspace, script, "modify")
    section = profile.get("python", {}) if isinstance(profile.get("python"), dict) else {}
    if not bool(section.get("enabled", False)):
        raise WorkspaceDenied(f"Python execution is disabled for workspace: {workspace}")
    if not relative.endswith(".py") or not matches_allowed_glob(relative, section.get("allowed_globs", [])):
        raise WorkspaceDenied(f"Python script is not allow-listed: {relative}")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(str(candidate))
    extra = _args(args)
    executable = _python_executable(profile, section)
    return {
        "workspace": profile["name"],
        "cwd": profile["root"],
        "argv": [executable, relative, *extra],
        "display": f"python3 {relative}",
        "max_runtime_seconds": _runtime(section, 300),
        "network": _network_mode(section),
    }


def _validate_pytest_args(values: Any) -> list[str]:
    args = _args(values)
    output: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in PYTEST_SIMPLE_FLAGS or any(arg.startswith(prefix) for prefix in PYTEST_PREFIX_FLAGS):
            output.append(arg)
            index += 1
            continue
        if arg in PYTEST_VALUE_FLAGS:
            if index + 1 >= len(args) or not SAFE_VALUE_RE.fullmatch(args[index + 1]):
                raise WorkspaceDenied(f"Invalid value for pytest option: {arg}")
            output.extend([arg, args[index + 1]])
            index += 2
            continue
        raise WorkspaceDenied(f"Pytest option is not allow-listed: {arg}")
    return output


def build_pytest_command(workspace: str, targets: Any = None, args: Any = None) -> dict[str, Any]:
    profile = resolve_workspace(workspace, "modify")
    section = profile.get("pytest", {}) if isinstance(profile.get("pytest"), dict) else {}
    if not bool(section.get("enabled", False)):
        raise WorkspaceDenied(f"pytest execution is disabled for workspace: {workspace}")
    raw_targets = ["tests"] if targets is None else targets
    if not isinstance(raw_targets, list) or not raw_targets or len(raw_targets) > 32:
        raise WorkspaceDenied("pytest targets must be a non-empty bounded list")
    safe_targets: list[str] = []
    for target in raw_targets:
        _profile, candidate, relative = workspace_relative_path(workspace, str(target), "modify")
        patterns = section.get("allowed_globs", [])
        direct_allowed = matches_allowed_glob(relative, patterns)
        descendant_allowed = any(
            isinstance(pattern, str) and pattern.endswith("/**") and (relative == pattern[:-3] or relative.startswith(pattern[:-3] + "/"))
            for pattern in patterns if isinstance(pattern, str)
        )
        if not direct_allowed and not descendant_allowed:
            raise WorkspaceDenied(f"pytest target is not allow-listed: {relative}")
        if not candidate.exists():
            raise FileNotFoundError(str(candidate))
        safe_targets.append(relative)
    options = _validate_pytest_args(args)
    executable = _python_executable(profile, section)
    return {
        "workspace": profile["name"],
        "cwd": profile["root"],
        "argv": [executable, "-m", "pytest", *options, *safe_targets],
        "display": "python3 -m pytest " + " ".join([*options, *safe_targets]),
        "max_runtime_seconds": _runtime(section, 900),
        "network": _network_mode(section),
    }


def build_python_code_command(workspace: str, code: str, args: Any = None) -> dict[str, Any]:
    profile = resolve_workspace(workspace, "modify")
    section = profile.get("python", {}) if isinstance(profile.get("python"), dict) else {}
    if not bool(section.get("enabled", False)):
        raise WorkspaceDenied(f"Python execution is disabled for workspace: {workspace}")
    payload = str(code or "")
    encoded = payload.encode("utf-8")
    if not payload.strip() or len(encoded) > MAX_INLINE_CODE_BYTES or "\x00" in payload:
        raise WorkspaceDenied("Inline Python must be non-empty, NUL-free, and at most 64 KiB")
    executable = _python_executable(profile, section)
    extra = _args(args)
    return {
        "workspace": profile["name"],
        "cwd": profile["root"],
        "argv": [executable, "-c", payload, *extra],
        "display": "python3 -c [inline code]",
        "max_runtime_seconds": _runtime(section, 300),
        "network": _network_mode(section),
        "workspace_access": "write",
    }


def build_node_check_command(workspace: str, script: str) -> dict[str, Any]:
    profile, candidate, relative = workspace_relative_path(workspace, script, "read")
    if candidate.suffix.lower() not in NODE_CHECK_EXTENSIONS:
        raise WorkspaceDenied("JavaScript syntax check accepts only .js, .mjs, or .cjs files")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(str(candidate))
    if candidate.stat().st_size > 5 * 1024 * 1024:
        raise WorkspaceDenied("JavaScript file exceeds 5 MiB syntax-check limit")
    executable = _node_executable()
    return {
        "workspace": profile["name"],
        "cwd": profile["root"],
        "argv": [executable, "--check", relative],
        "display": f"node --check {relative}",
        "max_runtime_seconds": 60,
        "network": "isolated",
        "workspace_access": "read",
    }
