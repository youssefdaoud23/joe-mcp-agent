from __future__ import annotations

from typing import Any

from src.bridge_client import (
    BridgeError,
    BridgeUnavailable,
    git_diff as bridge_git_diff,
    git_log as bridge_git_log,
    git_status as bridge_git_status,
    localhost_http as bridge_localhost_http,
    service_status as bridge_service_status,
    workspace_profiles as bridge_workspace_profiles,
)
from src.lifecycle_bridge import git_restore_previous as bridge_git_restore_previous


def deployment_profile(workspace: str) -> dict[str, Any]:
    data = bridge_workspace_profiles()
    for item in data.get("workspaces", []):
        if item.get("name") == workspace:
            if not item.get("permissions", {}).get("deploy", False):
                raise RuntimeError(f"Deployment permission is disabled for workspace: {workspace}")
            return item
    raise RuntimeError(f"Unknown deployment workspace: {workspace}")


def deployment_services(profile: dict[str, Any], requested: list[str] | None) -> list[str]:
    deployment = profile.get("deployment", {}) if isinstance(profile.get("deployment"), dict) else {}
    allowed = [str(item) for item in deployment.get("allowed_services", [])]
    selected = [str(item) for item in (requested if requested is not None else deployment.get("default_services", []))]
    if len(selected) > 50:
        raise RuntimeError("Too many deployment services requested")
    invalid = [item for item in selected if item not in allowed]
    if invalid:
        raise RuntimeError(f"Deployment service is not allow-listed: {invalid[0]}")
    return list(dict.fromkeys(selected))


def deployment_preflight_data(workspace: str, services: list[str] | None = None) -> dict[str, Any]:
    profile = deployment_profile(workspace)
    selected = deployment_services(profile, services)
    root = str(profile["root"])
    status = bridge_git_status(root)
    diff = bridge_git_diff(root, False, 200_000)
    commits = bridge_git_log(root, 1).get("commits", [])
    service_states = [bridge_service_status(unit) for unit in selected]
    deployment = profile.get("deployment", {})
    checks = []
    for url in deployment.get("health_urls", []):
        try:
            checks.append(bridge_localhost_http(workspace, str(url), "GET", "", 5.0))
        except (BridgeError, BridgeUnavailable) as exc:
            checks.append({"url": url, "error": str(exc)})
    return {
        "workspace": workspace,
        "root": root,
        "current_commit": commits[0].get("commit") if commits else None,
        "branch": status.get("branch"),
        "git": status,
        "diff": diff,
        "services": selected,
        "service_states": service_states,
        "health_checks": checks,
        "test_targets": list(deployment.get("test_targets", [])),
        "workflow": [
            "review edit and diff",
            "run allow-listed pytest and wait for success",
            "stage explicit changed files",
            "commit staged files",
            "restart only selected allow-listed services",
            "run deployment_verify",
        ],
        "rollback": "Use deployment_restore_previous only with the exact failed deployment commit and confirm=true, then restart selected services and verify again.",
    }


def deployment_verify_data(workspace: str, services: list[str] | None = None) -> dict[str, Any]:
    profile = deployment_profile(workspace)
    selected = deployment_services(profile, services)
    deployment = profile.get("deployment", {})
    service_states = [bridge_service_status(unit) for unit in selected]
    checks = [bridge_localhost_http(workspace, str(url), "GET", "", 5.0) for url in deployment.get("health_urls", [])]
    services_healthy = all(item.get("active_state") == "active" for item in service_states)
    http_healthy = all(200 <= int(item.get("status", 0)) < 400 for item in checks)
    return {
        "workspace": workspace,
        "healthy": services_healthy and http_healthy,
        "services_healthy": services_healthy,
        "http_healthy": http_healthy,
        "service_states": service_states,
        "health_checks": checks,
    }


def deployment_restore_previous_data(workspace: str, expected_head: str, confirm: bool = False) -> dict[str, Any]:
    profile = deployment_profile(workspace)
    result = bridge_git_restore_previous(str(profile["root"]), expected_head, confirm)
    deployment = profile.get("deployment", {})
    result["workspace"] = workspace
    result["next_steps"] = {
        "restart_only": list(deployment.get("default_services", [])),
        "health_urls": list(deployment.get("health_urls", [])),
        "verify_with": "deployment_verify",
    }
    return result
