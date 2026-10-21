from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from src.security import AccessDenied, normalize_host_path, safe_host_path


WORKSPACES_FILE = Path(os.getenv("JOE_WORKSPACES_FILE", "/var/lib/joe-mcp-work/workspaces.json"))
WORKSPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
PERMISSIONS = ("read", "modify", "deploy")
MAX_WORKSPACES = 50


class WorkspaceDenied(PermissionError):
    pass


def load_workspace_policy(path: Path | None = None) -> dict[str, Any]:
    target = path or WORKSPACES_FILE
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorkspaceDenied("Workspace policy is unavailable") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceDenied("Workspace policy is invalid") from exc
    if not isinstance(data, dict) or data.get("version") not in {1, 2}:
        raise WorkspaceDenied("Unsupported workspace policy version")
    workspaces = data.get("workspaces")
    if not isinstance(workspaces, dict) or len(workspaces) > MAX_WORKSPACES:
        raise WorkspaceDenied("Workspace policy has an invalid workspace map")
    if data.get("version") == 1:
        for profile in workspaces.values():
            if not isinstance(profile, dict):
                continue
            shell = profile.get("shell")
            if not isinstance(shell, dict):
                shell = {}
                profile["shell"] = shell
            shell["enabled"] = True
            shell.setdefault("executable", "/bin/bash")
            shell.setdefault("max_runtime_seconds", 600)
            shell["network"] = "isolated"
        data["version"] = 2
    return data


def _profile(name: str, path: Path | None = None) -> dict[str, Any]:
    key = str(name or "").strip()
    if not WORKSPACE_RE.fullmatch(key):
        raise WorkspaceDenied("Invalid workspace name")
    raw = load_workspace_policy(path).get("workspaces", {}).get(key)
    if not isinstance(raw, dict):
        raise WorkspaceDenied(f"Unknown workspace: {key}")
    root = normalize_host_path(str(raw.get("root", "")))
    if root == "/":
        raise WorkspaceDenied("Workspace root cannot be the filesystem root")
    permissions = raw.get("permissions", {})
    if not isinstance(permissions, dict):
        raise WorkspaceDenied(f"Invalid permissions for workspace: {key}")
    result = dict(raw)
    result["name"] = key
    result["root"] = root.rstrip("/") or "/"
    result["permissions"] = {item: bool(permissions.get(item, False)) for item in PERMISSIONS}
    return result


def resolve_workspace(name: str, permission: str = "read", path: Path | None = None) -> dict[str, Any]:
    if permission not in PERMISSIONS:
        raise WorkspaceDenied(f"Unsupported workspace permission: {permission}")
    profile = _profile(name, path)
    if not profile["permissions"].get(permission, False):
        raise WorkspaceDenied(f"Workspace permission is disabled: {name}:{permission}")
    try:
        root = safe_host_path(profile["root"], Path("/"))
    except (AccessDenied, ValueError, OSError) as exc:
        raise WorkspaceDenied(str(exc)) from exc
    if not root.exists() or not root.is_dir():
        raise WorkspaceDenied(f"Workspace root is unavailable: {profile['root']}")
    profile["root_path"] = root
    return profile


def _effective_access(profile: dict[str, Any]) -> dict[str, Any]:
    try:
        from src.action_policy import action_policy_info
        actions = action_policy_info()
    except (PermissionError, OSError, ValueError):
        actions = {}
    permissions = profile.get("permissions", {}) if isinstance(profile.get("permissions"), dict) else {}
    python = _public_exec_section(profile.get("python"))
    pytest = _public_exec_section(profile.get("pytest"))
    shell = _public_shell_section(profile.get("shell"))
    sqlite = _public_sqlite_section(profile.get("sqlite"))
    http = _public_http_section(profile.get("http"))
    deployment = _public_deployment_section(profile.get("deployment"))
    service = actions.get("service_control", {}) if isinstance(actions.get("service_control"), dict) else {}
    git = actions.get("git_write", {}) if isinstance(actions.get("git_write"), dict) else {}
    service_actions = set(service.get("allowed_actions", [])) if isinstance(service.get("allowed_actions"), list) else set()
    configured_services = set(deployment.get("allowed_services", []))
    controlled_services = sorted(configured_services.intersection(service.get("allowed_units", []))) if isinstance(service.get("allowed_units"), list) else []
    service_enabled = bool(service.get("enabled", False)) and bool(controlled_services)
    git_actions = set(git.get("allowed_actions", [])) if isinstance(git.get("allowed_actions"), list) else set()
    git_repositories = set(git.get("allowed_repositories", [])) if isinstance(git.get("allowed_repositories"), list) else set()
    git_enabled = bool(git.get("enabled", False)) and profile.get("root") in git_repositories and bool(permissions.get("modify", False))
    local_git_actions = {"branch_create", "branch_switch", "stage", "commit", "reset"}
    return {
        "files": {
            "read": bool(permissions.get("read", False)),
            "modify": bool(permissions.get("modify", False)),
        },
        "execution": {
            "python": bool(python.get("enabled", False)),
            "pytest": bool(pytest.get("enabled", False)),
            "shell": bool(shell.get("enabled", False)),
            "sqlite_read": bool(sqlite.get("enabled", False)),
            "localhost_http": bool(http.get("enabled", False)),
            "deploy": bool(permissions.get("deploy", False)),
        },
        "systemd": {
            "read": bool(configured_services),
            "journal": bool(configured_services),
            "start": service_enabled and "start" in service_actions,
            "stop": service_enabled and "stop" in service_actions,
            "restart": service_enabled and "restart" in service_actions,
            "allowed_services": controlled_services,
        },
        "git": {
            "read": bool(permissions.get("read", False)),
            "branch_create": git_enabled and "branch_create" in git_actions,
            "branch_switch": git_enabled and "branch_switch" in git_actions,
            "stage": git_enabled and "stage" in git_actions,
            "commit": git_enabled and "commit" in git_actions,
            "restore_reset": git_enabled and "reset" in git_actions,
            "local_write": git_enabled and bool(local_git_actions.intersection(git_actions)),
            "push": git_enabled and bool(git.get("push_enabled", False)),
        },
    }


def workspace_profiles(path: Path | None = None) -> dict[str, Any]:
    data = load_workspace_policy(path)
    profiles: list[dict[str, Any]] = []
    for name in sorted(data.get("workspaces", {})):
        profile = _profile(name, path)
        public = {
            "name": profile["name"],
            "root": profile["root"],
            "permissions": profile["permissions"],
            "python": _public_exec_section(profile.get("python")),
            "pytest": _public_exec_section(profile.get("pytest")),
            "shell": _public_shell_section(profile.get("shell")),
            "sqlite": _public_sqlite_section(profile.get("sqlite")),
            "http": _public_http_section(profile.get("http")),
            "deployment": _public_deployment_section(profile.get("deployment")),
        }
        public["effective"] = _effective_access(profile)
        profiles.append(public)
    return {"version": 2, "workspaces": profiles}


def set_workspace_http_ports(
    name: str,
    ports: list[int],
    confirm: bool = False,
    path: Path | None = None,
) -> dict[str, Any]:
    """Replace one existing workspace's loopback HTTP port allow-list."""
    if confirm is not True:
        raise WorkspaceDenied("Changing workspace localhost HTTP ports requires confirm=true")
    if not isinstance(ports, list):
        raise WorkspaceDenied("ports must be a list")
    normalized: list[int] = []
    for raw in ports:
        if isinstance(raw, bool):
            raise WorkspaceDenied("localhost HTTP ports must be integers")
        try:
            port = int(raw)
        except (TypeError, ValueError) as exc:
            raise WorkspaceDenied("localhost HTTP ports must be integers") from exc
        if port < 1 or port > 65535:
            raise WorkspaceDenied(f"Invalid localhost HTTP port: {port}")
        if port not in normalized:
            normalized.append(port)
    if len(normalized) > 32:
        raise WorkspaceDenied("At most 32 localhost HTTP ports may be allow-listed")
    target = path or WORKSPACES_FILE
    if target.is_symlink():
        raise WorkspaceDenied("Workspace policy path cannot be a symlink")
    key = str(name or "").strip()
    if not WORKSPACE_RE.fullmatch(key):
        raise WorkspaceDenied("Invalid workspace name")
    data = load_workspace_policy(target)
    raw = data.get("workspaces", {}).get(key)
    if not isinstance(raw, dict):
        raise WorkspaceDenied(f"Unknown workspace: {key}")
    section = raw.get("http")
    if not isinstance(section, dict):
        section = {"enabled": False}
        raw["http"] = section
    section["allowed_ports"] = sorted(normalized)
    temp = target.with_name(f".{target.name}.tmp")
    try:
        temp.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    except OSError as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise WorkspaceDenied("Unable to save workspace policy") from exc
    return workspace_profiles(target)


def update_workspace_capabilities(
    name: str,
    permissions: dict[str, Any] | None = None,
    features: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    """Update only enable/disable gates for an existing workspace.

    Roots, executables, globs, ports, services, health URLs and test targets are
    intentionally immutable through this helper so the web UI cannot broaden a
    workspace while changing simple access switches.
    """
    target = path or WORKSPACES_FILE
    if target.is_symlink():
        raise WorkspaceDenied("Workspace policy path cannot be a symlink")
    key = str(name or "").strip()
    if not WORKSPACE_RE.fullmatch(key):
        raise WorkspaceDenied("Invalid workspace name")
    data = load_workspace_policy(target)
    raw = data.get("workspaces", {}).get(key)
    if not isinstance(raw, dict):
        raise WorkspaceDenied(f"Unknown workspace: {key}")

    if permissions is not None:
        if not isinstance(permissions, dict):
            raise WorkspaceDenied("permissions must be an object")
        unknown = set(permissions) - set(PERMISSIONS)
        if unknown:
            raise WorkspaceDenied(f"Unsupported workspace permission: {sorted(unknown)[0]}")
        current = raw.get("permissions")
        if not isinstance(current, dict):
            current = {}
            raw["permissions"] = current
        for permission, value in permissions.items():
            if not isinstance(value, bool):
                raise WorkspaceDenied(f"Workspace permission must be boolean: {permission}")
            current[permission] = value

    feature_names = {"python", "pytest", "shell", "sqlite", "http"}
    if features is not None:
        if not isinstance(features, dict):
            raise WorkspaceDenied("features must be an object")
        unknown = set(features) - feature_names
        if unknown:
            raise WorkspaceDenied(f"Unsupported workspace feature: {sorted(unknown)[0]}")
        for feature, value in features.items():
            if not isinstance(value, bool):
                raise WorkspaceDenied(f"Workspace feature must be boolean: {feature}")
            section = raw.get(feature)
            if not isinstance(section, dict):
                section = {}
                raw[feature] = section
            section["enabled"] = value

    temp = target.with_name(f".{target.name}.tmp")
    try:
        temp.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    except OSError as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise WorkspaceDenied("Unable to save workspace policy") from exc
    return workspace_profiles(target)



def register_linked_git_worktree_workspace(
    base_name: str,
    name: str,
    root: str,
    confirm: bool = False,
    path: Path | None = None,
) -> dict[str, Any]:
    """Register one linked Git worktree as a writable shell workspace.

    The new root must be a real linked worktree of the selected existing workspace.
    This never permits / and never accepts an unrelated repository.
    """
    if confirm is not True:
        raise WorkspaceDenied("Registering a linked Git worktree requires confirm=true")
    key = str(name or "").strip()
    if not WORKSPACE_RE.fullmatch(key):
        raise WorkspaceDenied("Invalid workspace name")
    target = path or WORKSPACES_FILE
    if target.is_symlink():
        raise WorkspaceDenied("Workspace policy path cannot be a symlink")
    data = load_workspace_policy(target)
    workspaces = data.get("workspaces", {})
    if not isinstance(workspaces, dict):
        raise WorkspaceDenied("Workspace policy has an invalid workspace map")
    if key in workspaces:
        raise WorkspaceDenied(f"Workspace already exists: {key}")
    if len(workspaces) >= MAX_WORKSPACES:
        raise WorkspaceDenied(f"Workspace policy supports at most {MAX_WORKSPACES} workspaces")

    base = _profile(base_name, target)
    if not base["permissions"].get("read", False) or not base["permissions"].get("modify", False):
        raise WorkspaceDenied("Base workspace must allow read and modify access")
    worktree_root = normalize_host_path(str(root or "").strip())
    if worktree_root == "/":
        raise WorkspaceDenied("Workspace root cannot be the filesystem root")
    root_path = Path(worktree_root)
    if root_path.is_symlink() or not root_path.exists() or not root_path.is_dir():
        raise WorkspaceDenied("Linked worktree root must be an existing non-symlink directory")

    base_root = Path(base["root"]).resolve(strict=True)
    base_git = base_root / ".git"
    if not base_git.is_dir() or base_git.is_symlink():
        raise WorkspaceDenied("Base workspace must be a primary Git worktree")
    marker_file = root_path / ".git"
    if marker_file.is_symlink() or not marker_file.is_file() or marker_file.stat().st_size > 4096:
        raise WorkspaceDenied("Target must be a linked Git worktree")
    try:
        line = marker_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise WorkspaceDenied("Unable to verify linked Git worktree") from exc
    if not line.startswith("gitdir: "):
        raise WorkspaceDenied("Target must be a linked Git worktree")
    gitdir_text = line[8:].strip()
    gitdir = Path(gitdir_text)
    if not gitdir.is_absolute():
        gitdir = (root_path / gitdir).resolve(strict=False)
    else:
        gitdir = gitdir.resolve(strict=False)
    worktrees_dir = (base_git / "worktrees").resolve(strict=False)
    if gitdir == worktrees_dir or not gitdir.is_relative_to(worktrees_dir) or not gitdir.is_dir():
        raise WorkspaceDenied("Target is not linked to the selected base workspace")
    backlink = gitdir / "gitdir"
    if backlink.is_file() and backlink.stat().st_size <= 4096:
        try:
            linked_marker = Path(backlink.read_text(encoding="utf-8").strip()).resolve(strict=False)
        except (OSError, ValueError) as exc:
            raise WorkspaceDenied("Unable to verify linked Git worktree backlink") from exc
        if linked_marker != marker_file.resolve(strict=False):
            raise WorkspaceDenied("Linked Git worktree backlink does not match target")

    base_raw = workspaces.get(str(base_name or "").strip())
    if not isinstance(base_raw, dict):
        raise WorkspaceDenied(f"Unknown workspace: {base_name}")
    clone = json.loads(json.dumps(base_raw))
    clone["root"] = worktree_root.rstrip("/") or "/"
    permissions = clone.get("permissions") if isinstance(clone.get("permissions"), dict) else {}
    permissions.update({"read": True, "modify": True, "deploy": False})
    clone["permissions"] = permissions
    shell = clone.get("shell") if isinstance(clone.get("shell"), dict) else {}
    shell.update({"enabled": True, "executable": str(shell.get("executable", "/bin/bash") or "/bin/bash"), "network": "isolated"})
    shell.setdefault("max_runtime_seconds", 600)
    clone["shell"] = shell
    clone["deployment"] = {"allowed_services": [], "default_services": [], "health_urls": [], "test_targets": []}
    workspaces[key] = clone
    data["version"] = 2

    temp = target.with_name(f".{target.name}.tmp")
    try:
        temp.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    except OSError as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise WorkspaceDenied("Unable to save workspace policy") from exc
    return workspace_profiles(target)


def discover_git_worktrees(base_name: str, path: Path | None = None) -> dict[str, Any]:
    base = resolve_workspace(base_name, "read", path)
    root = Path(base["root"]).resolve(strict=True)
    if not (root / ".git").is_dir():
        raise WorkspaceDenied("Base workspace must be a primary Git worktree")
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "worktree", "list", "--porcelain"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/"},
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise WorkspaceDenied("Unable to inspect Git worktrees") from exc
    if completed.returncode != 0:
        message = completed.stderr[:2000].decode("utf-8", errors="replace").strip()
        raise WorkspaceDenied(message or "Unable to inspect Git worktrees")
    text = completed.stdout[:250_000].decode("utf-8", errors="replace")
    registered = {
        str(Path(str(raw.get("root", ""))).resolve(strict=False)): name
        for name, raw in load_workspace_policy(path).get("workspaces", {}).items()
        if isinstance(raw, dict) and str(raw.get("root", "")).startswith("/")
    }
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in [*text.splitlines(), ""]:
        if not line:
            if current.get("path"):
                worktree_path = str(Path(str(current["path"])).resolve(strict=False))
                rows.append({
                    **current,
                    "path": worktree_path,
                    "linked": worktree_path != str(root),
                    "registered_workspace": registered.get(worktree_path),
                    "eligible_for_workspace_add": worktree_path != str(root) and Path(worktree_path).is_dir(),
                })
            current = {}
            continue
        if line.startswith("worktree "):
            current["path"] = line[9:]
        elif line.startswith("HEAD "):
            current["head"] = line[5:]
        elif line.startswith("branch refs/heads/"):
            current["branch"] = line[len("branch refs/heads/"):]
        elif line == "detached":
            current["detached"] = True
        elif line == "bare":
            current["bare"] = True
        elif line.startswith("prunable"):
            current["prunable"] = True
    return {"base_workspace": base_name, "base_root": str(root), "worktrees": rows, "count": len(rows)}


def remove_workspace(name: str, confirm: bool = False, path: Path | None = None) -> dict[str, Any]:
    if confirm is not True:
        raise WorkspaceDenied("Removing a workspace requires confirm=true")
    key = str(name or "").strip()
    if not WORKSPACE_RE.fullmatch(key):
        raise WorkspaceDenied("Invalid workspace name")
    if key == "joe-mcp":
        raise WorkspaceDenied("The Joe controller workspace cannot be removed")
    target = path or WORKSPACES_FILE
    if target.is_symlink():
        raise WorkspaceDenied("Workspace policy path cannot be a symlink")
    data = load_workspace_policy(target)
    raw = data.get("workspaces", {}).get(key)
    if not isinstance(raw, dict):
        raise WorkspaceDenied(f"Unknown workspace: {key}")
    root = Path(normalize_host_path(str(raw.get("root", ""))))
    marker = root / ".git"
    if not marker.is_file() or marker.is_symlink():
        raise WorkspaceDenied("Only linked Git worktree workspaces can be removed through this tool")
    del data["workspaces"][key]
    data["version"] = 2
    temp = target.with_name(f".{target.name}.tmp")
    try:
        temp.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    except OSError as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise WorkspaceDenied("Unable to save workspace policy") from exc
    return {"removed": True, "workspace": key, "root": str(root), **workspace_profiles(target)}


def _public_exec_section(value: Any) -> dict[str, Any]:
    section = value if isinstance(value, dict) else {}
    return {
        "enabled": bool(section.get("enabled", False)),
        "executable": str(section.get("executable", "/usr/bin/python3") or "/usr/bin/python3"),
        "allowed_globs": list(section.get("allowed_globs", [])) if isinstance(section.get("allowed_globs"), list) else [],
        "max_runtime_seconds": int(section.get("max_runtime_seconds", 0) or 0),
        "network": str(section.get("network", "isolated") or "isolated"),
    }


def _public_shell_section(value: Any) -> dict[str, Any]:
    section = value if isinstance(value, dict) else {}
    return {
        "enabled": bool(section.get("enabled", True)),
        "executable": str(section.get("executable", "/bin/bash") or "/bin/bash"),
        "max_runtime_seconds": int(section.get("max_runtime_seconds", 600) or 600),
        "network": str(section.get("network", "isolated") or "isolated"),
    }


def _public_sqlite_section(value: Any) -> dict[str, Any]:
    section = value if isinstance(value, dict) else {}
    return {
        "enabled": bool(section.get("enabled", False)),
        "allowed_globs": list(section.get("allowed_globs", [])) if isinstance(section.get("allowed_globs"), list) else [],
    }


def _public_http_section(value: Any) -> dict[str, Any]:
    section = value if isinstance(value, dict) else {}
    ports = section.get("allowed_ports", [])
    return {
        "enabled": bool(section.get("enabled", False)),
        "allowed_ports": [int(item) for item in ports if isinstance(item, int) or str(item).isdigit()],
    }


def _public_deployment_section(value: Any) -> dict[str, Any]:
    section = value if isinstance(value, dict) else {}
    return {
        "allowed_services": list(section.get("allowed_services", [])) if isinstance(section.get("allowed_services"), list) else [],
        "default_services": list(section.get("default_services", [])) if isinstance(section.get("default_services"), list) else [],
        "health_urls": list(section.get("health_urls", [])) if isinstance(section.get("health_urls"), list) else [],
        "test_targets": list(section.get("test_targets", [])) if isinstance(section.get("test_targets"), list) else [],
    }


def workspace_mutation_roots(path: Path | None = None) -> tuple[str, ...]:
    data = load_workspace_policy(path)
    roots: list[str] = []
    for name in data.get("workspaces", {}):
        try:
            profile = _profile(name, path)
        except WorkspaceDenied:
            continue
        if profile["permissions"].get("modify", False):
            roots.append(profile["root"])
    return tuple(dict.fromkeys(roots))


def workspace_for_host_path(host_path: str, permission: str = "read", path: Path | None = None) -> dict[str, Any] | None:
    normalized = Path(normalize_host_path(host_path)).resolve(strict=False)
    matches: list[dict[str, Any]] = []
    data = load_workspace_policy(path)
    for name in data.get("workspaces", {}):
        try:
            profile = _profile(name, path)
        except WorkspaceDenied:
            continue
        if not profile["permissions"].get(permission, False):
            continue
        root = Path(profile["root"]).resolve(strict=False)
        if normalized == root or normalized.is_relative_to(root):
            matches.append(profile)
    if not matches:
        return None
    matches.sort(key=lambda item: len(item["root"]), reverse=True)
    return matches[0]


def workspace_path_protected(host_path: str, path: Path | None = None) -> str | None:
    profile = workspace_for_host_path(host_path, "modify", path)
    if profile is None:
        return None
    normalized = Path(normalize_host_path(host_path))
    root = Path(profile["root"])
    try:
        rel = normalized.relative_to(root)
    except ValueError:
        return None
    parts = rel.parts
    if any(part in {".git", ".secrets"} for part in parts):
        return str(root / (parts[0] if parts else ""))
    if parts and (parts[-1] == ".env" or parts[-1].startswith(".env.")):
        return str(normalized)
    if len(parts) >= 2 and parts[0] == "data" and parts[1] in {"auth", "audit", "devices", "sessions"}:
        return str(root / parts[0] / parts[1])
    return None


def workspace_relative_path(name: str, relative: str, permission: str = "read", path: Path | None = None) -> tuple[dict[str, Any], Path, str]:
    profile = resolve_workspace(name, permission, path)
    raw = str(relative or "").strip().replace("\\", "/")
    if not raw or raw.startswith("/") or "\x00" in raw:
        raise WorkspaceDenied("Workspace path must be a non-empty relative path")
    normalized = os.path.normpath(raw).replace("\\", "/")
    if normalized in {".", ".."} or normalized.startswith("../"):
        raise WorkspaceDenied("Workspace path escapes the configured root")
    root = Path(profile["root"]).resolve(strict=False)
    candidate = (root / normalized).resolve(strict=False)
    if candidate != root and not candidate.is_relative_to(root):
        raise WorkspaceDenied("Workspace path escapes the configured root")
    return profile, candidate, normalized


def matches_allowed_glob(relative: str, patterns: Any) -> bool:
    if not isinstance(patterns, list):
        return False
    return any(isinstance(pattern, str) and pattern and fnmatch.fnmatchcase(relative, pattern) for pattern in patterns)
