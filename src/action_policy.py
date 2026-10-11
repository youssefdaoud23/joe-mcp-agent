from __future__ import annotations

import json
import os
import posixpath
import re
from pathlib import Path
from typing import Any

from src.write_policy import mutation_roots


ACTIONS_FILE = Path(
    os.getenv(
        "JOE_ACTIONS_FILE",
        str(Path(__file__).resolve().parents[1] / "config" / "actions.json"),
    )
)
SERVICE_ACTIONS = {"start", "stop", "restart"}
DOCKER_ACTIONS = {"start", "stop", "restart"}
GIT_LOCAL_ACTIONS = {"stage", "commit", "branch_create", "branch_switch", "reset"}
GIT_ACTIONS = GIT_LOCAL_ACTIONS | {"push"}
PROTECTED_SERVICE_UNITS = {"joe-mcp-host-bridge.service", "joe-mcp-session-host.service", "joe-mcp-node-agent.service", "joe-mcp-controller-deploy.service"}
PROTECTED_CONTAINERS = {"joe-mcp-server", "joe-mcp-tunnel", "joe-mcp-node", "joe-node-agent"}
SERVICE_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,256}\.service$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
MAX_POLICY_ITEMS = 200


class ActionDenied(PermissionError):
    """Raised when an administrative action is outside Joe MCP policy."""


def load_action_policy(path: Path | None = None) -> dict[str, Any]:
    target = path or ACTIONS_FILE
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ActionDenied("Administrative action policy is unavailable") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ActionDenied("Administrative action policy is invalid") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ActionDenied("Unsupported administrative action policy version")
    return data


def _section(name: str, path: Path | None = None) -> dict[str, Any]:
    value = load_action_policy(path).get(name, {})
    if not isinstance(value, dict):
        raise ActionDenied(f"Invalid {name} action policy")
    return value


def _clean_actions(values: Any, supported: set[str], label: str) -> list[str]:
    if not isinstance(values, list):
        raise ActionDenied(f"{label} allowed_actions must be a list")
    actions = sorted({str(item).strip().lower() for item in values if str(item).strip()})
    unsupported = [item for item in actions if item not in supported]
    if unsupported:
        raise ActionDenied(f"Unsupported {label} action: {unsupported[0]}")
    return actions


def _clean_targets(values: Any, pattern: re.Pattern[str], protected: set[str], label: str) -> list[str]:
    if not isinstance(values, list):
        raise ActionDenied(f"{label} allow-list must be a list")
    targets = sorted({str(item).strip() for item in values if str(item).strip()})
    if len(targets) > MAX_POLICY_ITEMS:
        raise ActionDenied(f"{label} allow-list exceeds {MAX_POLICY_ITEMS} items")
    for target in targets:
        if not pattern.fullmatch(target):
            raise ActionDenied(f"Invalid {label} target: {target}")
        if target in protected:
            raise ActionDenied(f"Protected {label} target cannot be controlled: {target}")
    return targets


def _clean_repositories(values: Any) -> list[str]:
    if not isinstance(values, list):
        raise ActionDenied("Git repository allow-list must be a list")
    repositories: list[str] = []
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        if not value.startswith("/") or "\x00" in value:
            raise ActionDenied(f"Invalid Git repository target: {value}")
        normalized = posixpath.normpath(value)
        if normalized == "/":
            raise ActionDenied(f"Invalid Git repository target: {value}")
        candidate = Path(normalized)
        roots = [Path(root) for root in mutation_roots()]
        if not any(candidate == root or candidate.is_relative_to(root) for root in roots):
            raise ActionDenied(f"Git repository is outside configured writable roots: {normalized}")
        repositories.append(normalized)
    repositories = sorted(set(repositories))
    if len(repositories) > MAX_POLICY_ITEMS:
        raise ActionDenied(f"Git repository allow-list exceeds {MAX_POLICY_ITEMS} items")
    return repositories


def authorize_git_action(repository: str, action: str, path: Path | None = None) -> None:
    policy = _section("git_write", path)
    normalized_action = str(action or "").strip().lower()
    if normalized_action not in GIT_ACTIONS:
        raise ActionDenied("Unsupported Git write action")
    if not bool(policy.get("enabled", False)):
        raise ActionDenied("Git write control is disabled by policy")
    normalized_repo = posixpath.normpath(str(repository or "").strip())
    if normalized_repo not in _clean_repositories(policy.get("allowed_repositories", [])):
        raise ActionDenied(f"Git repository is not allow-listed: {normalized_repo}")
    if normalized_action == "push":
        if not bool(policy.get("push_enabled", False)):
            raise ActionDenied("Git push is disabled by policy")
        return
    local_actions = _clean_actions(policy.get("allowed_actions", []), GIT_ACTIONS, "Git")
    if normalized_action not in GIT_LOCAL_ACTIONS or normalized_action not in local_actions:
        raise ActionDenied(f"Git action is not allowed by policy: {normalized_action}")


def authorize_service_action(unit: str, action: str, path: Path | None = None) -> None:
    policy = _section("service_control", path)
    normalized_action = str(action or "").strip().lower()
    if unit in PROTECTED_SERVICE_UNITS:
        raise ActionDenied(f"Protected systemd service cannot be controlled: {unit}")
    if normalized_action not in SERVICE_ACTIONS:
        raise ActionDenied("Only start, stop, and restart service actions are supported")
    if not bool(policy.get("enabled", False)):
        raise ActionDenied("Systemd service control is disabled by policy")
    if normalized_action not in _clean_actions(policy.get("allowed_actions", []), SERVICE_ACTIONS, "systemd"):
        raise ActionDenied(f"Systemd action is not allowed by policy: {normalized_action}")
    if unit not in _clean_targets(
        policy.get("allowed_units", []), SERVICE_UNIT_RE, PROTECTED_SERVICE_UNITS, "systemd service"
    ):
        raise ActionDenied(f"Systemd service is not allow-listed: {unit}")


def authorize_docker_action(container: str, action: str, path: Path | None = None) -> None:
    policy = _section("docker_control", path)
    normalized_action = str(action or "").strip().lower()
    if container in PROTECTED_CONTAINERS:
        raise ActionDenied(f"Protected Docker container cannot be controlled: {container}")
    if normalized_action not in DOCKER_ACTIONS:
        raise ActionDenied("Only start, stop, and restart Docker actions are supported")
    if not bool(policy.get("enabled", False)):
        raise ActionDenied("Docker control is disabled by policy")
    if normalized_action not in _clean_actions(policy.get("allowed_actions", []), DOCKER_ACTIONS, "Docker"):
        raise ActionDenied(f"Docker action is not allowed by policy: {normalized_action}")
    if container not in _clean_targets(
        policy.get("allowed_containers", []), CONTAINER_RE, PROTECTED_CONTAINERS, "Docker container"
    ):
        raise ActionDenied(f"Docker container is not allow-listed: {container}")


def update_action_capabilities(
    service_enabled: bool | None = None,
    docker_enabled: bool | None = None,
    git_enabled: bool | None = None,
    git_push_enabled: bool | None = None,
    confirm_push: bool = False,
    path: Path | None = None,
) -> dict[str, Any]:
    """Change only top-level capability gates while preserving every allow-list.

    This is the MCP-safe administrative path. It intentionally cannot add or
    remove services, containers, repositories, or local Git actions. Enabling
    push requires its own explicit confirmation and an enabled Git write gate.
    """
    target = path or ACTIONS_FILE
    current = action_policy_info(target)
    service = current["service_control"]
    docker = current["docker_control"]
    git = current["git_write"]

    next_service_enabled = service["enabled"] if service_enabled is None else bool(service_enabled)
    next_docker_enabled = docker["enabled"] if docker_enabled is None else bool(docker_enabled)
    next_git_enabled = git["enabled"] if git_enabled is None else bool(git_enabled)
    next_push_enabled = git["push_enabled"] if git_push_enabled is None else bool(git_push_enabled)

    if next_push_enabled and not confirm_push:
        raise ActionDenied("Enabling Git push requires confirm_push=true")
    if next_push_enabled and not next_git_enabled:
        raise ActionDenied("Git push cannot be enabled while Git write control is disabled")

    return update_action_policy(
        service_control={
            "enabled": next_service_enabled,
            "allowed_units": service["allowed_units"],
            "allowed_actions": service["allowed_actions"],
        },
        docker_control={
            "enabled": next_docker_enabled,
            "allowed_containers": docker["allowed_containers"],
            "allowed_actions": docker["allowed_actions"],
        },
        git_write={
            "enabled": next_git_enabled,
            "allowed_repositories": git["allowed_repositories"],
            "allowed_actions": git["allowed_actions"],
            "push_enabled": next_push_enabled,
        },
        path=target,
    )


def update_action_policy(
    service_control: dict[str, Any] | None = None,
    docker_control: dict[str, Any] | None = None,
    git_write: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    target = path or ACTIONS_FILE
    if target.is_symlink():
        raise ActionDenied("Administrative action policy path cannot be a symlink")
    data = load_action_policy(target)

    if service_control is not None:
        if not isinstance(service_control, dict):
            raise ActionDenied("service_control must be an object")
        data["service_control"] = {
            "enabled": bool(service_control.get("enabled", False)),
            "allowed_units": _clean_targets(
                service_control.get("allowed_units", []), SERVICE_UNIT_RE, PROTECTED_SERVICE_UNITS, "systemd service"
            ),
            "allowed_actions": _clean_actions(
                service_control.get("allowed_actions", []), SERVICE_ACTIONS, "systemd"
            ),
        }

    if docker_control is not None:
        if not isinstance(docker_control, dict):
            raise ActionDenied("docker_control must be an object")
        data["docker_control"] = {
            "enabled": bool(docker_control.get("enabled", False)),
            "allowed_containers": _clean_targets(
                docker_control.get("allowed_containers", []), CONTAINER_RE, PROTECTED_CONTAINERS, "Docker container"
            ),
            "allowed_actions": _clean_actions(
                docker_control.get("allowed_actions", []), DOCKER_ACTIONS, "Docker"
            ),
        }

    if git_write is not None:
        if not isinstance(git_write, dict):
            raise ActionDenied("git_write must be an object")
        requested_actions = _clean_actions(git_write.get("allowed_actions", []), GIT_ACTIONS, "Git")
        data["git_write"] = {
            "enabled": bool(git_write.get("enabled", False)),
            "allowed_repositories": _clean_repositories(git_write.get("allowed_repositories", [])),
            "allowed_actions": [item for item in requested_actions if item in GIT_LOCAL_ACTIONS],
            "push_enabled": bool(git_write.get("push_enabled", False)),
        }

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
        raise ActionDenied("Unable to save administrative action policy") from exc
    return action_policy_info(target)


def action_policy_info(path: Path | None = None) -> dict[str, Any]:
    data = load_action_policy(path)
    service = data.get("service_control", {}) if isinstance(data.get("service_control", {}), dict) else {}
    docker = data.get("docker_control", {}) if isinstance(data.get("docker_control", {}), dict) else {}
    git = data.get("git_write", {}) if isinstance(data.get("git_write", {}), dict) else {}
    return {
        "version": 1,
        "service_control": {
            "enabled": bool(service.get("enabled", False)),
            "allowed_units": list(service.get("allowed_units", [])) if isinstance(service.get("allowed_units", []), list) else [],
            "allowed_actions": list(service.get("allowed_actions", [])) if isinstance(service.get("allowed_actions", []), list) else [],
            "protected_units": sorted(PROTECTED_SERVICE_UNITS),
        },
        "docker_control": {
            "enabled": bool(docker.get("enabled", False)),
            "allowed_containers": list(docker.get("allowed_containers", [])) if isinstance(docker.get("allowed_containers", []), list) else [],
            "allowed_actions": list(docker.get("allowed_actions", [])) if isinstance(docker.get("allowed_actions", []), list) else [],
            "protected_containers": sorted(PROTECTED_CONTAINERS),
        },
        "git_write": {
            "enabled": bool(git.get("enabled", False)),
            "allowed_repositories": list(git.get("allowed_repositories", [])) if isinstance(git.get("allowed_repositories", []), list) else [],
            "allowed_actions": [
                item for item in (git.get("allowed_actions", []) if isinstance(git.get("allowed_actions", []), list) else [])
                if item in GIT_LOCAL_ACTIONS
            ],
            "push_enabled": bool(git.get("push_enabled", False)),
        },
    }
