from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path
from typing import Any

SOCKET_PATH = Path(os.getenv("JOE_BRIDGE_SOCKET", "/run/joe-mcp/bridge.sock"))
DEFAULT_TIMEOUT = float(os.getenv("JOE_BRIDGE_TIMEOUT", "2.0"))
SQLITE_DIAGNOSTIC_TIMEOUT = max(30.0, min(float(os.getenv("JOE_SQLITE_DIAGNOSTIC_TIMEOUT", "330")), 900.0))
DOCKER_READ_TIMEOUT = 15.0
DOCKER_ACTION_TIMEOUT = 60.0


class BridgeUnavailable(ConnectionError):
    pass


class BridgeError(RuntimeError):
    pass


def request(op: str, *, timeout: float | None = None, **payload: Any) -> dict[str, Any]:
    message = {"op": op, **payload}
    data = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(DEFAULT_TIMEOUT if timeout is None else max(0.1, float(timeout)))
            client.connect(str(SOCKET_PATH))
            client.sendall(data)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 2_000_000:
                    raise BridgeError("Bridge response exceeded size limit")
                if b"\n" in chunk:
                    break
    except (FileNotFoundError, ConnectionRefusedError, socket.timeout, OSError) as exc:
        raise BridgeUnavailable(f"Host bridge unavailable: {exc}") from exc

    raw = b"".join(chunks).split(b"\n", 1)[0]
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeError("Invalid response from host bridge") from exc
    if not isinstance(response, dict):
        raise BridgeError("Invalid response from host bridge")
    if not response.get("ok"):
        raise BridgeError(str(response.get("error") or "Host bridge request failed"))
    result = response.get("result", {})
    return result if isinstance(result, dict) else {"value": result}


def ping() -> dict[str, Any]:
    return request("ping")


def controller_deploy_request(expected_head: str, confirm: bool = False) -> dict[str, Any]:
    return request("controller_deploy_request", expected_head=expected_head, confirm=confirm)


def controller_deploy_status() -> dict[str, Any]:
    return request("controller_deploy_status")


def controller_rollback_request(deployment_request_id: str, confirm: bool = False) -> dict[str, Any]:
    return request("controller_rollback_request", deployment_request_id=deployment_request_id, confirm=confirm)


def host_runtime_update_request(expected_head: str, confirm: bool = False) -> dict[str, Any]:
    return request("host_runtime_update_request", expected_head=expected_head, confirm=confirm)


def host_runtime_update_status() -> dict[str, Any]:
    return request("host_runtime_update_status")


def host_runtime_rollback_request(update_request_id: str, confirm: bool = False) -> dict[str, Any]:
    return request("host_runtime_rollback_request", update_request_id=update_request_id, confirm=confirm)


def public_agent_export_request(expected_head: str, confirm: bool = False) -> dict[str, Any]:
    return request("public_agent_export_request", expected_head=expected_head, confirm=confirm, timeout=30.0)


def public_agent_publish_request(expected_head: str, confirm: bool = False) -> dict[str, Any]:
    return request("public_agent_publish_request", expected_head=expected_head, confirm=confirm, timeout=120.0)


def action_policy_status() -> dict[str, Any]:
    return request("action_policy_status")


def admin_terminal_status() -> dict[str, Any]:
    return request("admin_terminal_status")


def set_admin_terminal_enabled(enabled: bool, confirm: bool = False) -> dict[str, Any]:
    return request("set_admin_terminal_enabled", enabled=enabled, confirm=confirm)


def start_admin_terminal(command: str, cwd: str = "/", confirm: bool = False) -> dict[str, Any]:
    return request("start_admin_terminal", command=command, cwd=cwd, confirm=confirm, timeout=15.0)


def update_action_capabilities(
    service_enabled: bool | None = None,
    docker_enabled: bool | None = None,
    git_enabled: bool | None = None,
    git_push_enabled: bool | None = None,
    confirm_push: bool = False,
) -> dict[str, Any]:
    return request(
        "update_action_capabilities",
        service_enabled=service_enabled,
        docker_enabled=docker_enabled,
        git_enabled=git_enabled,
        git_push_enabled=git_push_enabled,
        confirm_push=confirm_push,
    )


def update_action_policy(
    service_control: dict[str, Any],
    docker_control: dict[str, Any],
    git_write: dict[str, Any],
) -> dict[str, Any]:
    return request(
        "update_action_policy",
        service_control=service_control,
        docker_control=docker_control,
        git_write=git_write,
    )


def update_workspace_capabilities(
    workspace: str,
    permissions: dict[str, Any],
    features: dict[str, Any],
) -> dict[str, Any]:
    return request(
        "update_workspace_capabilities",
        workspace=workspace,
        permissions=permissions,
        features=features,
    )


def start_process(command: str, cwd: str = "/", persistent: bool = False) -> dict[str, Any]:
    return request("start_process", command=command, cwd=cwd, persistent=persistent)


def read_process_output(session_id: str, offset: int = 0, max_lines: int = 200) -> dict[str, Any]:
    return request("read_process_output", session_id=session_id, offset=offset, max_lines=max_lines)


def interact_with_process(session_id: str, input_text: str, append_newline: bool = True) -> dict[str, Any]:
    return request(
        "interact_with_process",
        session_id=session_id,
        input_text=input_text,
        append_newline=append_newline,
    )


def kill_process(session_id: str, force: bool = False) -> dict[str, Any]:
    return request("kill_process", session_id=session_id, force=force)


def terminate_host_process(
    pid: int,
    expected_start_ticks: int,
    force: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    return request(
        "terminate_host_process",
        pid=pid,
        expected_start_ticks=expected_start_ticks,
        force=force,
        confirm=confirm,
    )


def write_file(path: str, content: str, mode: str = "rewrite") -> dict[str, Any]:
    return request("write_file", path=path, content=content, mode=mode)


def edit_file(path: str, old_text: str, new_text: str, expected_replacements: int = 1) -> dict[str, Any]:
    return request(
        "edit_file",
        path=path,
        old_text=old_text,
        new_text=new_text,
        expected_replacements=expected_replacements,
    )


def edit_spreadsheet_range(path: str, cell_range: str, values: list[list[Any]]) -> dict[str, Any]:
    return request("edit_spreadsheet_range", path=path, cell_range=cell_range, values=values)


def write_pdf(path: str, content: str) -> dict[str, Any]:
    return request("write_pdf", path=path, content=content)


def install_staged_pdf(path: str, staging_id: str, expected_size: int, expected_sha256: str) -> dict[str, Any]:
    return request("install_staged_pdf", path=path, staging_id=staging_id, expected_size=expected_size, expected_sha256=expected_sha256, timeout=30.0)


def create_directory(path: str, parents: bool = True) -> dict[str, Any]:
    return request("create_directory", path=path, parents=parents)


def move_file(source: str, destination: str) -> dict[str, Any]:
    return request("move_file", source=source, destination=destination)


def copy_file(source: str, destination: str) -> dict[str, Any]:
    return request("copy_file", source=source, destination=destination)


def trash_path(path: str) -> dict[str, Any]:
    return request("trash_path", path=path)


def list_trash(max_results: int = 200) -> dict[str, Any]:
    return request("list_trash", max_results=max_results)


def restore_trash(trash_id: str, destination: str = "") -> dict[str, Any]:
    return request("restore_trash", trash_id=trash_id, destination=destination)


def purge_trash(trash_id: str, confirm: bool = False) -> dict[str, Any]:
    return request("purge_trash", trash_id=trash_id, confirm=confirm)


def git_status(path: str) -> dict[str, Any]:
    return request("git_status", path=path)


def git_diff(path: str, staged: bool = False, max_bytes: int = 200_000) -> dict[str, Any]:
    return request("git_diff", path=path, staged=staged, max_bytes=max_bytes)


def git_log(path: str, max_count: int = 20) -> dict[str, Any]:
    return request("git_log", path=path, max_count=max_count)


def git_compare_branches(path: str, left: str, right: str, max_commits: int = 20) -> dict[str, Any]:
    return request("git_compare_branches", path=path, left=left, right=right, max_commits=max_commits)


def git_merge_preview(path: str, destination: str, source: str, max_bytes: int = 200_000) -> dict[str, Any]:
    return request("git_merge_preview", path=path, destination=destination, source=source, max_bytes=max_bytes)


def git_merge_branches(path: str, destination: str, source: str, expected_destination_head: str, message: str = "", confirm: bool = False) -> dict[str, Any]:
    return request("git_merge_branches", path=path, destination=destination, source=source, expected_destination_head=expected_destination_head, message=message, confirm=confirm)


def git_stage(path: str, paths: list[str]) -> dict[str, Any]:
    return request("git_stage", path=path, paths=paths)


def git_commit(path: str, message: str) -> dict[str, Any]:
    return request("git_commit", path=path, message=message)


def git_push(path: str, expected_branch: str, remote: str = "origin") -> dict[str, Any]:
    return request("git_push", path=path, expected_branch=expected_branch, remote=remote)


def list_services(pattern: str = "*", max_results: int = 200) -> dict[str, Any]:
    return request("list_services", pattern=pattern, max_results=max_results)


def service_status(unit: str) -> dict[str, Any]:
    return request("service_status", unit=unit)


def service_code_identity(unit: str) -> dict[str, Any]:
    return request("service_code_identity", unit=unit)


def systemd_failed_units(max_results: int = 200) -> dict[str, Any]:
    return request("systemd_failed_units", max_results=max_results)


def service_action(unit: str, action: str) -> dict[str, Any]:
    return request("service_action", unit=unit, action=action)


def unit_action(unit: str, action: str, confirm: bool = False) -> dict[str, Any]:
    return request("unit_action", unit=unit, action=action, confirm=confirm)


def update_systemd_unit_policy(allowed_units: list[str], allowed_actions: list[str], enabled: bool | None = None, confirm: bool = False) -> dict[str, Any]:
    return request("update_systemd_unit_policy", allowed_units=allowed_units, allowed_actions=allowed_actions, enabled=enabled, confirm=confirm)


def journal_logs(unit: str, lines: int = 200, since_minutes: int = 0, text: str = "", since: str = "", until: str = "") -> dict[str, Any]:
    return request("journal_logs", unit=unit, lines=lines, since_minutes=since_minutes, text=text, since=since, until=until)


def journal_diagnostics(lines: int = 200, since_minutes: int = 60, priority_max: int = 3, text: str = "", current_boot: bool = True) -> dict[str, Any]:
    return request("journal_diagnostics", lines=lines, since_minutes=since_minutes, priority_max=priority_max, text=text, current_boot=current_boot)


def kernel_diagnostics(lines: int = 200, since_minutes: int = 0, priority_max: int = 4, text: str = "") -> dict[str, Any]:
    return request("kernel_diagnostics", lines=lines, since_minutes=since_minutes, priority_max=priority_max, text=text)


def firewall_status() -> dict[str, Any]:
    return request("firewall_status")


def tailscale_status() -> dict[str, Any]:
    return request("tailscale_status")


def sysctl_read(key: str) -> dict[str, Any]:
    return request("sysctl_read", key=key)


def proc_snapshot(topic: str) -> dict[str, Any]:
    return request("proc_snapshot", topic=topic)


def routing_diagnostics() -> dict[str, Any]:
    return request("routing_diagnostics")


def docker_containers(pattern: str = "*", max_results: int = 200) -> dict[str, Any]:
    return request("docker_containers", timeout=DOCKER_READ_TIMEOUT, pattern=pattern, max_results=max_results)


def docker_container_status(container: str) -> dict[str, Any]:
    return request("docker_container_status", timeout=DOCKER_READ_TIMEOUT, container=container)


def docker_action(container: str, action: str) -> dict[str, Any]:
    return request("docker_action", timeout=DOCKER_ACTION_TIMEOUT, container=container, action=action)


def recover_joe_tunnel(confirm: bool = False) -> dict[str, Any]:
    return request("recover_joe_tunnel", timeout=60.0, confirm=confirm)


def docker_logs(container: str, lines: int = 200, since_minutes: int = 0, text: str = "") -> dict[str, Any]:
    return request(
        "docker_logs",
        timeout=DOCKER_READ_TIMEOUT,
        container=container,
        lines=lines,
        since_minutes=since_minutes,
        text=text,
    )


def list_sessions() -> dict[str, Any]:
    return request("list_sessions")


def workspace_profiles() -> dict[str, Any]:
    return request("workspace_profiles")


def dc_equivalence_self_test() -> dict[str, Any]:
    return request("dc_equivalence_self_test", timeout=90.0)


def workspace_discover_git_worktrees(base_workspace: str) -> dict[str, Any]:
    return request("workspace_discover_git_worktrees", base_workspace=base_workspace)


def workspace_remove(workspace: str, confirm: bool = False) -> dict[str, Any]:
    return request("workspace_remove", workspace=workspace, confirm=confirm)


def workspace_update(workspace: str, permissions: dict[str, Any] | None = None, features: dict[str, Any] | None = None, confirm: bool = False) -> dict[str, Any]:
    return request("workspace_update", workspace=workspace, permissions=permissions, features=features, confirm=confirm)


def set_workspace_http_ports(workspace: str, ports: list[int], confirm: bool = False) -> dict[str, Any]:
    return request("set_workspace_http_ports", workspace=workspace, ports=ports, confirm=confirm)


def register_git_worktree_workspace(base_workspace: str, workspace: str, root: str, confirm: bool = False) -> dict[str, Any]:
    return request(
        "register_git_worktree_workspace",
        base_workspace=base_workspace,
        workspace=workspace,
        root=root,
        confirm=confirm,
    )


def start_workspace_python(workspace: str, script: str, args: list[str] | None = None) -> dict[str, Any]:
    return request("start_workspace_python", workspace=workspace, script=script, args=args or [])


def start_workspace_python_code(workspace: str, code: str, args: list[str] | None = None) -> dict[str, Any]:
    return request("start_workspace_python_code", workspace=workspace, code=code, args=args or [])


def start_workspace_node_check(workspace: str, script: str) -> dict[str, Any]:
    return request("start_workspace_node_check", workspace=workspace, script=script)


def start_workspace_shell(workspace: str, command: str, confirm: bool = False) -> dict[str, Any]:
    return request("start_workspace_shell", workspace=workspace, command=command, confirm=confirm)


def start_managed_terminal(
    profile: str,
    command: str,
    cwd: str,
    write_roots: list[str] | None = None,
    hidden_paths: list[str] | None = None,
    read_only_paths: list[str] | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    return request(
        "start_managed_terminal",
        profile=profile,
        command=command,
        cwd=cwd,
        write_roots=write_roots or [],
        hidden_paths=hidden_paths or [],
        read_only_paths=read_only_paths or [],
        confirm=confirm,
    )


def developer_access_status() -> dict[str, Any]:
    return request("developer_access_status", timeout=10.0)


def developer_access_configure(policy: dict[str, Any]) -> dict[str, Any]:
    return request("developer_access_configure", timeout=10.0, policy=policy)


def developer_access_authorize_sudo(sudo_password: str, ttl_minutes: int, confirm: bool = False) -> dict[str, Any]:
    # The password travels only inside this request body on the node-local Unix socket.
    return request("developer_access_authorize_sudo", timeout=40.0, sudo_password=sudo_password, ttl_minutes=ttl_minutes, confirm=confirm)


def developer_access_revoke_sudo(reason: str = "revoked") -> dict[str, Any]:
    return request("developer_access_revoke_sudo", timeout=30.0, reason=reason)


def start_developer_terminal(command: str, cwd: str = "/", confirm: bool = False, privileged: bool = False) -> dict[str, Any]:
    return request("start_developer_terminal", timeout=25.0, command=command, cwd=cwd, confirm=confirm, privileged=privileged)


def start_workspace_pytest(workspace: str, targets: list[str] | None = None, args: list[str] | None = None) -> dict[str, Any]:
    return request("start_workspace_pytest", workspace=workspace, targets=targets, args=args or [])


def sqlite_tables(workspace: str, database: str) -> dict[str, Any]:
    return request("sqlite_tables", workspace=workspace, database=database)


def sqlite_schema(workspace: str, database: str, table: str = "") -> dict[str, Any]:
    return request("sqlite_schema", workspace=workspace, database=database, table=table)


def start_sqlite_diagnostic(workspace: str, database: str, query: str, max_rows: int = 100) -> dict[str, Any]:
    return request("start_sqlite_diagnostic", workspace=workspace, database=database, query=query, max_rows=max_rows)


def sqlite_query(workspace: str, database: str, query: str, max_rows: int = 100) -> dict[str, Any]:
    diagnostic = bool(re.fullmatch(r"\s*PRAGMA\s+(quick_check|integrity_check)\s*;?\s*", str(query or ""), flags=re.IGNORECASE))
    return request(
        "sqlite_query",
        timeout=SQLITE_DIAGNOSTIC_TIMEOUT if diagnostic else None,
        workspace=workspace,
        database=database,
        query=query,
        max_rows=max_rows,
    )


def sqlite_table_stats(workspace: str, database: str, table: str, timestamp_column: str = "") -> dict[str, Any]:
    return request("sqlite_table_stats", workspace=workspace, database=database, table=table, timestamp_column=timestamp_column)


def localhost_http(workspace: str, url: str, method: str = "GET", body: str = "", timeout_seconds: float = 5.0) -> dict[str, Any]:
    return request("localhost_http", workspace=workspace, url=url, method=method, body=body, timeout_seconds=timeout_seconds)


def git_branches(path: str, max_count: int = 200) -> dict[str, Any]:
    return request("git_branches", path=path, max_count=max_count)


def git_branch_create(path: str, name: str, start_commit: str = "") -> dict[str, Any]:
    return request("git_branch_create", path=path, name=name, start_commit=start_commit)


def git_branch_switch(path: str, name: str) -> dict[str, Any]:
    return request("git_branch_switch", path=path, name=name)


def git_restore_paths(path: str, source_commit: str, paths: list[str], confirm: bool = False) -> dict[str, Any]:
    return request("git_restore_paths", path=path, source_commit=source_commit, paths=paths, confirm=confirm)


def git_reset_to_commit(path: str, target_commit: str, expected_head: str, confirm: bool = False) -> dict[str, Any]:
    return request("git_reset_to_commit", path=path, target_commit=target_commit, expected_head=expected_head, confirm=confirm)


def git_rollback_last(path: str, expected_head: str, confirm: bool = False) -> dict[str, Any]:
    return request("git_rollback_last", path=path, expected_head=expected_head, confirm=confirm)


def list_timers(pattern: str = "*", max_results: int = 200) -> dict[str, Any]:
    return request("list_timers", pattern=pattern, max_results=max_results)


def timer_status(unit: str) -> dict[str, Any]:
    return request("timer_status", unit=unit)


def unit_file(unit: str) -> dict[str, Any]:
    return request("unit_file", unit=unit)


def sap_profiles() -> dict[str, Any]:
    return request("sap_profiles")


def sap_profile_configure(name: str, base_url: str, client: str = "", username: str = "", password: str = "", bearer_token: str = "", verify_tls: bool = True, allow_insecure_http: bool = False, confirm: bool = False) -> dict[str, Any]:
    return request("sap_profile_configure", name=name, base_url=base_url, client=client, username=username, password=password, bearer_token=bearer_token, verify_tls=verify_tls, allow_insecure_http=allow_insecure_http, confirm=confirm, timeout=30.0)


def sap_profile_remove(name: str, confirm: bool = False) -> dict[str, Any]:
    return request("sap_profile_remove", name=name, confirm=confirm)


def sap_host_discover() -> dict[str, Any]:
    return request("sap_host_discover", timeout=10.0)


def sap_process_list(instance_number: str, host: str = "") -> dict[str, Any]:
    return request("sap_process_list", instance_number=instance_number, host=host, timeout=30.0)


def sap_system_info(instance_number: str, host: str = "") -> dict[str, Any]:
    return request("sap_system_info", instance_number=instance_number, host=host, timeout=45.0)


def sap_instance_action(instance_number: str, action: str, host: str = "", confirm: bool = False) -> dict[str, Any]:
    return request("sap_instance_action", instance_number=instance_number, action=action, host=host, confirm=confirm, timeout=75.0)


def sap_rfc_status() -> dict[str, Any]:
    return request("sap_rfc_status")


def abap_adt_get(profile: str, path: str, accept: str = "") -> dict[str, Any]:
    return request("abap_adt_get", profile=profile, path=path, accept=accept, timeout=45.0)


def abap_object_search(profile: str, query: str, object_type: str = "", max_results: int = 50) -> dict[str, Any]:
    return request("abap_object_search", profile=profile, query=query, object_type=object_type, max_results=max_results, timeout=45.0)


def abap_source_read(profile: str, source_uri: str) -> dict[str, Any]:
    return request("abap_source_read", profile=profile, source_uri=source_uri, timeout=45.0)


def abap_adt_change(profile: str, method: str, path: str, body: str = "", content_type: str = "application/xml; charset=utf-8", confirm: bool = False) -> dict[str, Any]:
    return request("abap_adt_change", profile=profile, method=method, path=path, body=body, content_type=content_type, confirm=confirm, timeout=75.0)


def abap_source_update(profile: str, source_uri: str, source: str, lock_handle: str = "", transport_request: str = "", confirm: bool = False) -> dict[str, Any]:
    return request("abap_source_update", profile=profile, source_uri=source_uri, source=source, lock_handle=lock_handle, transport_request=transport_request, confirm=confirm, timeout=75.0)


def abap_activate(profile: str, object_uri: str, object_name: str = "", confirm: bool = False) -> dict[str, Any]:
    return request("abap_activate", profile=profile, object_uri=object_uri, object_name=object_name, confirm=confirm, timeout=75.0)


def abap_atc_run(profile: str, path: str, body: str, confirm: bool = False) -> dict[str, Any]:
    return request("abap_atc_run", profile=profile, path=path, body=body, confirm=confirm, timeout=120.0)
