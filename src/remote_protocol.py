from __future__ import annotations

PROTOCOL_VERSION = 1
LIFECYCLE_UPDATE_AGENT = "__update_managed_agent__"
LIFECYCLE_SHUTDOWN_AGENT = "__shutdown_managed_agent__"
# Developer Access control-plane jobs. These names are deliberately NOT members of READ_REMOTE_TOOLS or
# ACTION_REMOTE_TOOLS, so no MCP/ChatGPT tool call can route them; only the account-admin controller
# functions in src/developer_access_controller.py submit them.
LIFECYCLE_DEVELOPER_ACCESS_CONFIGURE = "__developer_access_configure__"
LIFECYCLE_DEVELOPER_ACCESS_AUTHORIZE_SUDO = "__developer_access_authorize_sudo__"
LIFECYCLE_DEVELOPER_ACCESS_REVOKE_SUDO = "__developer_access_revoke_sudo__"
DEVELOPER_ACCESS_LIFECYCLE_JOBS = frozenset({
    LIFECYCLE_DEVELOPER_ACCESS_CONFIGURE,
    LIFECYCLE_DEVELOPER_ACCESS_AUTHORIZE_SUDO,
    LIFECYCLE_DEVELOPER_ACCESS_REVOKE_SUDO,
})
DEVELOPER_ACCESS_PROTOCOL_VERSION = "1"
# Argument keys that carry a secret. They are stripped from routed job state the moment a job is
# dispatched to the managed node and are never accepted on the ordinary tool-routing path.
SENSITIVE_ARGUMENT_KEYS = frozenset({"sudo_password"})
DEVELOPER_TERMINAL_ARGUMENTS = frozenset({"command", "cwd", "confirm", "privileged"})
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_SAP_ARGUMENT_BYTES = 1_250_000
MAX_RESULT_BYTES = 1_500_000
LARGE_ARGUMENT_REMOTE_TOOLS = frozenset({"abap_source_update", "abap_adt_change", "abap_atc_run"})


def max_argument_bytes_for_tool(tool: str) -> int:
    return MAX_SAP_ARGUMENT_BYTES if str(tool or "").strip() in LARGE_ARGUMENT_REMOTE_TOOLS else MAX_ARGUMENT_BYTES


def scrub_sensitive_arguments(arguments: dict | None) -> dict:
    """Return a copy of routed-job arguments with every secret-bearing key removed."""
    if not isinstance(arguments, dict):
        return {}
    return {key: value for key, value in arguments.items() if key not in SENSITIVE_ARGUMENT_KEYS}


def has_sensitive_arguments(arguments: dict | None) -> bool:
    return isinstance(arguments, dict) and any(key in SENSITIVE_ARGUMENT_KEYS for key in arguments)
MAX_JOB_SECONDS = 30
MAX_QUEUE_PER_DEVICE = 20

READ_REMOTE_TOOLS = frozenset({
    "server_info",
    "node_policy",
    "get_config",
    "managed_update_status",
    "host_info",
    "list_directory",
    "directory_tree",
    "read_text_file",
    "read_file",
    "read_multiple_files",
    "path_info",
    "get_file_info",
    "file_inspect",
    "read_url",
    "http_probe",
    "list_processes",
    "process_info",
    "process_memory_info",
    "list_open_ports",
    "search_files",
    "search_content",
    "start_search",
    "get_search_results",
    "list_searches",
    "git_status",
    "git_diff",
    "git_log",
    "git_branches",
    "git_compare_branches",
    "git_merge_preview",
    "workspace_discover_git_worktrees",
    "list_services",
    "service_status",
    "service_code_identity",
    "systemd_failed_units",
    "list_timers",
    "timer_status",
    "unit_file",
    "journal_logs",
    "journal_diagnostics",
    "kernel_diagnostics",
    "firewall_status",
    "tailscale_status",
    "sysctl_read",
    "proc_snapshot",
    "routing_diagnostics",
    "docker_containers",
    "docker_container_status",
    "docker_logs",
    "read_process_output",
    "list_sessions",
    "workspace_profiles",
    "sqlite_tables",
    "sqlite_schema",
    "sqlite_query",
    "sqlite_table_stats",
    "localhost_http",
    "list_trash",
    "deployment_preflight",
    "deployment_verify",
    "developer_access_status",
    "sap_profiles",
    "sap_host_discover",
    "sap_process_list",
    "sap_system_info",
    "sap_rfc_status",
    "abap_adt_get",
    "abap_object_search",
    "abap_source_read",
})

ACTION_REMOTE_TOOLS = frozenset({
    "stop_search",
    "git_stage",
    "git_commit",
    "git_push",
    "git_branch_create",
    "git_branch_switch",
    "git_merge_branches",
    "git_restore_to_commit",
    "git_restore_previous",
    "git_restore_paths",
    "service_action",
    "unit_action",
    "docker_action",
    "start_process",
    "start_workspace_python",
    "start_workspace_python_code",
    "start_workspace_node_check",
    "start_workspace_shell",
    "start_managed_terminal",
    "start_developer_terminal",
    "start_workspace_pytest",
    "interact_with_process",
    "kill_process",
    "terminate_host_process",
    "write_file",
    "write_pdf",
    "edit_file",
    "edit_block",
    "edit_spreadsheet_range",
    "force_terminate",
    "create_directory",
    "move_file",
    "copy_file",
    "trash_path",
    "restore_trash",
    "purge_trash",
    "deployment_restore_previous",
    "sap_profile_configure",
    "sap_profile_remove",
    "sap_instance_action",
    "abap_adt_change",
    "abap_source_update",
    "abap_activate",
    "abap_atc_run",
})

ALL_REMOTE_TOOLS = READ_REMOTE_TOOLS | ACTION_REMOTE_TOOLS
