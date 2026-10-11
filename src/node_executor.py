from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
from typing import Any, Callable

from src.bridge_client import (
    create_directory as bridge_create_directory,
    copy_file as bridge_copy_file,
    ping as bridge_ping,
    docker_action as bridge_docker_action,
    docker_container_status as bridge_docker_container_status,
    docker_containers as bridge_docker_containers,
    docker_logs as bridge_docker_logs,
    edit_file as bridge_edit_file,
    edit_spreadsheet_range as bridge_edit_spreadsheet_range,
    git_commit as bridge_git_commit,
    git_diff as bridge_git_diff,
    git_log as bridge_git_log,
    git_branches as bridge_git_branches,
    git_branch_create as bridge_git_branch_create,
    git_branch_switch as bridge_git_branch_switch,
    git_push as bridge_git_push,
    git_stage as bridge_git_stage,
    git_status as bridge_git_status,
    interact_with_process as bridge_interact_with_process,
    journal_logs as bridge_journal_logs,
    list_timers as bridge_list_timers,
    timer_status as bridge_timer_status,
    unit_file as bridge_unit_file,
    kill_process as bridge_kill_process,
    list_services as bridge_list_services,
    list_sessions as bridge_list_sessions,
    workspace_profiles as bridge_workspace_profiles,
    sqlite_tables as bridge_sqlite_tables,
    sqlite_schema as bridge_sqlite_schema,
    sqlite_query as bridge_sqlite_query,
    sqlite_table_stats as bridge_sqlite_table_stats,
    localhost_http as bridge_localhost_http,
    move_file as bridge_move_file,
    trash_path as bridge_trash_path,
    list_trash as bridge_list_trash,
    restore_trash as bridge_restore_trash,
    purge_trash as bridge_purge_trash,
    read_process_output as bridge_read_process_output,
    service_action as bridge_service_action,
    service_status as bridge_service_status,
    start_process as bridge_start_process,
    start_workspace_node_check as bridge_start_workspace_node_check,
    start_workspace_python as bridge_start_workspace_python,
    start_workspace_python_code as bridge_start_workspace_python_code,
    start_workspace_pytest as bridge_start_workspace_pytest,
    write_file as bridge_write_file,
    write_pdf as bridge_write_pdf,
)
from src.lifecycle_bridge import git_restore_previous as bridge_git_restore_previous, git_restore_to_commit as bridge_git_restore_to_commit
from src.deployment_ops import deployment_preflight_data, deployment_restore_previous_data, deployment_verify_data
from src.file_inspect import directory_tree as inspect_directory_tree, inspect_file
from src.filesystem_scope import (
    FULL_HOST_MODE,
    can_read as filesystem_can_read,
    can_write as filesystem_can_write,
    default_filesystem_policy,
    normalize_filesystem_policy,
)
from src.rich_file import read_multiple_rich_files, read_rich_file, rich_file_info
from src.url_read import read_url
from src.process_ops import list_open_ports as inspect_open_ports, list_processes as inspect_processes, process_info as inspect_process_info
from src.read_tools import read_multiple_text_files, read_text_page
from src.remote_protocol import ALL_REMOTE_TOOLS, MAX_ARGUMENT_BYTES, MAX_RESULT_BYTES
from src.search_sessions import SearchManager
from src.search_tools import search_content as bounded_search_content, search_files as bounded_search_files
from src.security import is_host_path_allowed, redact_argv, safe_host_path


class NodeExecutionError(RuntimeError):
    pass


class NodeExecutor:
    def __init__(self, host_root: Path | None = None) -> None:
        self.host_root = host_root or Path(os.getenv("JOE_HOST_ROOT", "/host"))
        self.node_name = os.getenv("JOE_NODE_NAME", "managed-node")
        self.version = os.getenv("JOE_VERSION", "0.28.2")
        self.mode = os.getenv("JOE_MODE", "guarded")
        self.filesystem_policy = default_filesystem_policy()
        self.searches = SearchManager(self.host_root)
        self._tools: dict[str, Callable[..., dict[str, Any]]] = {
            "server_info": self.server_info,
            "node_policy": self.node_policy,
            "get_config": self.node_policy,
            "managed_update_status": self.managed_update_status,
            "host_info": self.host_info,
            "list_directory": self.list_directory,
            "directory_tree": self.directory_tree,
            "read_text_file": self.read_text_file,
            "read_file": self.read_file,
            "read_multiple_files": self.read_multiple_files,
            "path_info": self.path_info,
            "get_file_info": self.get_file_info,
            "file_inspect": self.file_inspect,
            "read_url": self.read_url,
            "list_processes": self.list_processes,
            "process_info": self.process_info,
            "list_open_ports": self.list_open_ports,
            "search_files": self.search_files,
            "search_content": self.search_content,
            "start_search": self.start_search,
            "get_search_results": self.get_search_results,
            "list_searches": self.list_searches,
            "stop_search": self.stop_search,
            "git_status": bridge_git_status,
            "git_diff": bridge_git_diff,
            "git_log": bridge_git_log,
            "git_branches": bridge_git_branches,
            "git_branch_create": bridge_git_branch_create,
            "git_branch_switch": bridge_git_branch_switch,
            "git_restore_to_commit": bridge_git_restore_to_commit,
            "git_restore_previous": bridge_git_restore_previous,
            "git_stage": bridge_git_stage,
            "git_commit": bridge_git_commit,
            "git_push": bridge_git_push,
            "list_services": bridge_list_services,
            "list_timers": bridge_list_timers,
            "timer_status": bridge_timer_status,
            "unit_file": bridge_unit_file,
            "service_status": bridge_service_status,
            "service_action": bridge_service_action,
            "journal_logs": bridge_journal_logs,
            "docker_containers": bridge_docker_containers,
            "docker_container_status": bridge_docker_container_status,
            "docker_action": bridge_docker_action,
            "docker_logs": bridge_docker_logs,
            "start_process": bridge_start_process,
            "start_workspace_python": bridge_start_workspace_python,
            "start_workspace_python_code": bridge_start_workspace_python_code,
            "start_workspace_node_check": bridge_start_workspace_node_check,
            "start_workspace_pytest": bridge_start_workspace_pytest,
            "read_process_output": bridge_read_process_output,
            "interact_with_process": bridge_interact_with_process,
            "kill_process": bridge_kill_process,
            "write_file": bridge_write_file,
            "write_pdf": self.write_pdf,
            "edit_file": bridge_edit_file,
            "edit_block": self.edit_block,
            "edit_spreadsheet_range": bridge_edit_spreadsheet_range,
            "force_terminate": self.force_terminate,
            "create_directory": bridge_create_directory,
            "move_file": bridge_move_file,
            "copy_file": bridge_copy_file,
            "trash_path": bridge_trash_path,
            "list_trash": bridge_list_trash,
            "restore_trash": bridge_restore_trash,
            "purge_trash": bridge_purge_trash,
            "list_sessions": bridge_list_sessions,
            "workspace_profiles": self.workspace_profiles,
            "sqlite_tables": bridge_sqlite_tables,
            "sqlite_schema": bridge_sqlite_schema,
            "sqlite_query": bridge_sqlite_query,
            "sqlite_table_stats": bridge_sqlite_table_stats,
            "localhost_http": bridge_localhost_http,
            "deployment_preflight": deployment_preflight_data,
            "deployment_verify": deployment_verify_data,
            "deployment_restore_previous": deployment_restore_previous_data,
        }

    @staticmethod
    def _json_size(value: Any) -> int:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def set_filesystem_policy(self, policy: dict[str, Any] | None) -> dict[str, Any]:
        normalized = normalize_filesystem_policy(policy)
        if normalized != self.filesystem_policy:
            self.searches = SearchManager(self.host_root)
        self.filesystem_policy = normalized
        return normalized

    def _restricted(self) -> bool:
        return str(self.filesystem_policy.get("mode") or FULL_HOST_MODE) != FULL_HOST_MODE

    def _resolved_scope_path(self, path: str) -> str:
        candidate = safe_host_path(path, self.host_root)
        resolved = candidate.resolve(strict=False)
        root = self.host_root.resolve(strict=False)
        if root == Path("/"):
            return str(resolved)
        if resolved == root:
            return "/"
        try:
            return "/" + resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise NodeExecutionError("Path resolves outside the managed host root") from exc

    def _require_path(self, path: str, *, write: bool = False) -> str:
        resolved = self._resolved_scope_path(path)
        allowed = filesystem_can_write(self.filesystem_policy, resolved) if write else filesystem_can_read(self.filesystem_policy, resolved)
        if not allowed:
            access = "write" if write else "read"
            raise NodeExecutionError(f"Filesystem {access} denied outside configured device scope")
        return resolved

    def _workspace_root(self, workspace: str) -> str:
        data = bridge_workspace_profiles()
        for item in data.get("workspaces", []) if isinstance(data, dict) else []:
            if isinstance(item, dict) and str(item.get("name") or "") == str(workspace or ""):
                root = str(item.get("root") or "")
                if root:
                    return root
        raise NodeExecutionError("Workspace is unavailable")

    def _require_workspace(self, workspace: str, *, write: bool = False) -> str:
        root = self._workspace_root(workspace)
        self._require_path(root, write=write)
        return root

    def _enforce_filesystem_scope(self, tool: str, arguments: dict[str, Any]) -> None:
        if not self._restricted():
            return
        read_path_tools = {
            "list_directory", "directory_tree", "read_text_file", "read_file", "path_info",
            "get_file_info", "file_inspect", "search_files", "search_content",
        }
        write_path_tools = {
            "write_file", "write_pdf", "edit_file", "edit_spreadsheet_range", "create_directory", "trash_path",
        }
        git_read_tools = {"git_status", "git_diff", "git_log", "git_branches"}
        git_write_tools = {
            "git_stage", "git_commit", "git_push", "git_branch_create", "git_branch_switch",
            "git_restore_to_commit", "git_restore_previous",
        }
        workspace_read_tools = {
            "sqlite_tables", "sqlite_schema", "sqlite_query", "sqlite_table_stats", "localhost_http",
            "deployment_preflight", "deployment_verify",
        }
        workspace_write_tools = {
            "start_workspace_python", "start_workspace_python_code", "start_workspace_pytest",
            "deployment_restore_previous",
        }
        restricted_session_tools = {
            "start_process", "read_process_output", "interact_with_process", "kill_process", "force_terminate",
            "list_sessions", "list_processes", "process_info", "list_open_ports",
        }
        restricted_global_tools = {
            "list_services", "service_status", "service_action", "list_timers", "timer_status", "unit_file", "journal_logs",
            "docker_containers", "docker_container_status", "docker_action", "docker_logs",
        }
        safe_nonfilesystem_tools = {
            "server_info", "node_policy", "get_config", "managed_update_status", "host_info", "read_url",
            "get_search_results", "list_searches", "stop_search", "workspace_profiles",
        }
        if tool in restricted_session_tools:
            raise NodeExecutionError("Process and session tools are disabled while device filesystem scope is restricted")
        if tool in restricted_global_tools:
            raise NodeExecutionError("System-wide service, journal, and container tools are disabled while device filesystem scope is restricted")
        if tool in {"list_trash", "restore_trash", "purge_trash"}:
            raise NodeExecutionError("Global trash tools are disabled while device filesystem scope is restricted")
        if tool == "read_file" and bool(arguments.get("isUrl") if arguments.get("is_url") is None else arguments.get("is_url")):
            return
        if tool in read_path_tools:
            key = "root" if tool in {"search_files", "search_content"} else "path"
            self._require_path(str(arguments.get(key) or "/"), write=False)
            return
        if tool == "start_search":
            root = str(arguments.get("root") or arguments.get("path") or "")
            if root:
                self._require_path(root, write=False)
            else:
                raise NodeExecutionError("Restricted device searches require an explicit approved root")
            return
        if tool == "read_multiple_files":
            paths = arguments.get("paths")
            if not isinstance(paths, list) or not paths:
                raise NodeExecutionError("Restricted multi-file reads require explicit paths")
            for path in paths:
                self._require_path(str(path), write=False)
            return
        if tool in write_path_tools:
            target_path = str(arguments.get("outputPath") or arguments.get("path") or "") if tool == "write_pdf" else str(arguments.get("path") or "")
            self._require_path(target_path, write=True)
            return
        if tool == "edit_block":
            self._require_path(str(arguments.get("file_path") or ""), write=True)
            return
        if tool == "copy_file":
            self._require_path(str(arguments.get("source") or ""), write=False)
            self._require_path(str(arguments.get("destination") or ""), write=True)
            return
        if tool == "move_file":
            self._require_path(str(arguments.get("source") or ""), write=True)
            self._require_path(str(arguments.get("destination") or ""), write=True)
            return
        if tool in git_read_tools:
            self._require_path(str(arguments.get("path") or ""), write=False)
            return
        if tool in git_write_tools:
            self._require_path(str(arguments.get("path") or ""), write=True)
            return
        if tool in workspace_read_tools:
            self._require_workspace(str(arguments.get("workspace") or ""), write=False)
            return
        if tool == "start_workspace_node_check":
            self._require_workspace(str(arguments.get("workspace") or ""), write=False)
            return
        if tool in workspace_write_tools:
            self._require_workspace(str(arguments.get("workspace") or ""), write=True)
            return
        if tool in safe_nonfilesystem_tools:
            return
        raise NodeExecutionError("Remote tool is not classified for restricted filesystem scope")

    def execute(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        name = str(tool or "").strip()
        if name not in ALL_REMOTE_TOOLS or name not in self._tools:
            raise NodeExecutionError("Remote tool is not supported")
        if not isinstance(arguments, dict):
            raise NodeExecutionError("Remote tool arguments must be an object")
        if self._json_size(arguments) > MAX_ARGUMENT_BYTES:
            raise NodeExecutionError("Remote tool arguments exceed size limit")
        self._enforce_filesystem_scope(name, arguments)
        target = self._tools[name]
        try:
            inspect.signature(target).bind(**arguments)
        except TypeError as exc:
            raise NodeExecutionError(f"Invalid arguments for {name}: {exc}") from exc
        try:
            result = target(**arguments)
        except Exception as exc:
            raise NodeExecutionError(str(exc)) from exc
        if not isinstance(result, dict):
            result = {"value": result}
        if self._json_size(result) > MAX_RESULT_BYTES:
            raise NodeExecutionError("Remote tool result exceeds size limit")
        return result

    def _read_small(self, path: Path, limit: int = 64_000) -> str:
        with path.open("rb") as handle:
            return handle.read(limit).decode("utf-8", errors="replace")

    def server_info(self) -> dict[str, Any]:
        return {
            "name": "Joe MCP Server",
            "version": self.version,
            "node": self.node_name,
            "mode": self.mode,
            "host_root": str(self.host_root),
            "remote_agent": True,
        }

    def node_policy(self) -> dict[str, Any]:
        data = bridge_ping()
        write_policy = dict(data.get("write_policy", {}) or {})
        if self._restricted():
            for key in ("roots", "workspace_mutation_roots"):
                values = write_policy.get(key, [])
                write_policy[key] = [
                    str(path) for path in values
                    if isinstance(path, str) and filesystem_can_write(self.filesystem_policy, path)
                ]
        return {
            "write_policy": write_policy,
            "action_policy": data.get("action_policy", {}),
            "allowed_commands": data.get("allowed_commands", []),
            "persistent_sessions": data.get("persistent_sessions", {}),
            "workspace_policy": self.workspace_profiles(),
            "filesystem_scope": self.filesystem_policy,
        }

    def workspace_profiles(self) -> dict[str, Any]:
        data = bridge_workspace_profiles()
        if not self._restricted() or not isinstance(data, dict):
            return data
        visible: list[dict[str, Any]] = []
        for item in data.get("workspaces", []):
            if not isinstance(item, dict):
                continue
            root = str(item.get("root") or "")
            try:
                resolved = self._resolved_scope_path(root)
            except Exception:
                continue
            if filesystem_can_read(self.filesystem_policy, resolved):
                row = dict(item)
                permissions = dict(row.get("permissions", {}) or {})
                if not filesystem_can_write(self.filesystem_policy, resolved):
                    permissions["modify"] = False
                    permissions["deploy"] = False
                row["permissions"] = permissions
                visible.append(row)
        result = dict(data)
        result["workspaces"] = visible
        return result

    def managed_update_status(self) -> dict[str, Any]:
        relative = Path("var/lib/joe-mcp-agent/update-status.json")
        target = self.host_root / relative
        if not target.is_file():
            return {"state": "never", "installed_version": self.version}
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise NodeExecutionError("Managed update status is unavailable") from exc
        if not isinstance(data, dict):
            raise NodeExecutionError("Managed update status is invalid")
        allowed = (
            "version",
            "request_id",
            "state",
            "started_at",
            "finished_at",
            "previous_version",
            "installed_version",
            "rollback_attempted",
            "rollback_succeeded",
            "error",
        )
        result = {key: data.get(key) for key in allowed if key in data}
        if result.get("error") is not None:
            result["error"] = str(result["error"])[:500]
        return result

    def host_info(self) -> dict[str, Any]:
        result: dict[str, Any] = {"node": self.node_name}
        for key, path in {
            "hostname": "/etc/hostname",
            "os_release": "/etc/os-release",
            "uptime": "/proc/uptime",
            "loadavg": "/proc/loadavg",
        }.items():
            target = safe_host_path(path, self.host_root)
            result[key] = self._read_small(target, 16_000).strip() if target.exists() else None
        try:
            result["process_count"] = sum(1 for item in (self.host_root / "proc").iterdir() if item.name.isdigit())
        except OSError:
            result["process_count"] = None
        try:
            values: dict[str, int] = {}
            for line in (self.host_root / "proc/meminfo").read_text(encoding="utf-8", errors="replace").splitlines():
                key, value = line.split(":", 1)
                values[key] = int(value.strip().split()[0])
            total = values.get("MemTotal", 0)
            available = values.get("MemAvailable", 0)
            result["memory_used"] = f"{round((total - available) * 100 / total, 1)}%" if total else "n/a"
        except (OSError, ValueError):
            result["memory_used"] = "n/a"
        try:
            stats = os.statvfs(self.host_root)
            total_bytes = stats.f_blocks * stats.f_frsize
            free_bytes = stats.f_bavail * stats.f_frsize
            result["disk_used"] = f"{round((total_bytes - free_bytes) * 100 / total_bytes, 1)}%" if total_bytes else "n/a"
        except OSError:
            result["disk_used"] = "n/a"
        return result

    def list_directory(self, path: str, max_entries: int = 200, depth: int = 1) -> dict[str, Any]:
        if int(depth) > 1:
            return inspect_directory_tree(path, self.host_root, max(1, min(int(depth) - 1, 4)), max_entries, False)
        target = safe_host_path(path, self.host_root)
        if not target.exists():
            return {"path": path, "exists": False, "entries": []}
        if not target.is_dir():
            raise ValueError("Path is not a directory")
        limit = max(1, min(int(max_entries), 1000))
        base = path.rstrip("/") or "/"
        entries: list[dict[str, Any]] = []
        restricted = 0
        for child in sorted(target.iterdir(), key=lambda item: item.name):
            child_path = f"/{child.name}" if base == "/" else f"{base}/{child.name}"
            if not is_host_path_allowed(child_path, self.host_root):
                restricted += 1
                continue
            if len(entries) >= limit:
                break
            info = child.lstat()
            kind = "symlink" if child.is_symlink() else ("directory" if child.is_dir() else "file")
            entries.append({"name": child.name, "type": kind, "size": info.st_size, "mode": oct(info.st_mode & 0o7777)})
        return {"path": path, "exists": True, "entries": entries, "restricted_entries_hidden": restricted}

    def directory_tree(self, path: str, max_depth: int = 2, max_entries: int = 200, include_hidden: bool = False) -> dict[str, Any]:
        return inspect_directory_tree(path, self.host_root, max_depth, max_entries, include_hidden)

    def read_text_file(self, path: str, offset: int = 0, length: int = 200, max_bytes: int = 100_000) -> dict[str, Any]:
        return read_text_page(path, self.host_root, offset, length, max_bytes)

    def read_file(
        self,
        path: str,
        isUrl: bool = False,
        offset: int = 0,
        length: int = 1000,
        sheet: str = "",
        range: str = "",
        options: dict[str, Any] | None = None,
        is_url: bool | None = None,
        cell_range: str = "",
        raw_xml: bool = False,
    ) -> dict[str, Any]:
        use_url = bool(isUrl if is_url is None else is_url)
        if use_url:
            return read_url(path)
        opts = options or {}
        return read_rich_file(path, self.host_root, offset, length, sheet, str(range or cell_range or ""), bool(raw_xml or opts.get("raw_xml", False)))

    def read_multiple_files(
        self,
        paths: list[str],
        offset: int = 0,
        length: int = 200,
        max_bytes_per_file: int = 100_000,
        rich: bool = False,
    ) -> dict[str, Any]:
        if rich:
            return read_multiple_rich_files(paths, self.host_root, offset, length)
        return read_multiple_text_files(paths, self.host_root, offset, length, max_bytes_per_file)

    def path_info(self, path: str) -> dict[str, Any]:
        target = safe_host_path(path, self.host_root)
        if not target.exists():
            return {"path": path, "exists": False}
        info = target.lstat()
        return {
            "path": path,
            "exists": True,
            "type": "directory" if target.is_dir() else "file",
            "size": info.st_size,
            "mode": oct(info.st_mode & 0o7777),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mtime": info.st_mtime,
        }

    def get_file_info(self, path: str) -> dict[str, Any]:
        return rich_file_info(path, self.host_root)

    def file_inspect(self, path: str, max_archive_entries: int = 100) -> dict[str, Any]:
        return inspect_file(path, self.host_root, max_archive_entries)

    def read_url(self, url: str, timeout_seconds: float = 10.0, max_bytes: int = 1_000_000) -> dict[str, Any]:
        return read_url(url, timeout_seconds, max_bytes)

    def write_pdf(self, path: str, content: Any, outputPath: str = "", options: dict[str, Any] | None = None) -> dict[str, Any]:
        if not isinstance(content, str):
            raise ValueError("Existing-PDF insert/delete/sourcePdf operations are not supported yet")
        result = bridge_write_pdf(str(outputPath or path), content)
        result["options_applied"] = False if options else None
        return result

    def edit_block(
        self,
        file_path: str,
        old_string: str = "",
        new_string: str = "",
        expected_replacements: int = 1,
        range: str = "",
        content: list[list[Any]] | None = None,
        cell_range: str = "",
        values: list[list[Any]] | None = None,
    ) -> dict[str, Any]:
        wanted_range = str(range or cell_range or "")
        if wanted_range:
            return bridge_edit_spreadsheet_range(file_path, wanted_range, content if content is not None else (values or []))
        return bridge_edit_file(file_path, old_string, new_string, expected_replacements)

    def force_terminate(self, session_id: str) -> dict[str, Any]:
        return bridge_kill_process(session_id, True)

    def list_processes(self, max_processes: int = 200) -> dict[str, Any]:
        return inspect_processes(self.host_root, max_processes)

    def process_info(self, pid: int) -> dict[str, Any]:
        return inspect_process_info(self.host_root, pid)

    def list_open_ports(self, max_results: int = 500) -> dict[str, Any]:
        return inspect_open_ports(self.host_root, max_results)

    def search_files(
        self,
        root: str,
        pattern: str,
        max_results: int = 200,
        max_depth: int = 8,
        max_scanned: int = 10_000,
        include_hidden: bool = False,
    ) -> dict[str, Any]:
        return bounded_search_files(root, pattern, self.host_root, max_results, max_depth, max_scanned, include_hidden)

    def search_content(
        self,
        root: str,
        query: str,
        file_glob: str = "*",
        max_results: int = 100,
        max_depth: int = 8,
        max_scanned: int = 10_000,
        case_sensitive: bool = False,
        include_hidden: bool = False,
    ) -> dict[str, Any]:
        return bounded_search_content(
            root,
            query,
            self.host_root,
            file_glob,
            max_results,
            max_depth,
            max_scanned,
            case_sensitive,
            include_hidden,
        )

    def start_search(
        self,
        root: str,
        pattern: str,
        search_type: str = "files",
        file_glob: str = "*",
        max_results: int = 500,
        max_depth: int = 8,
        max_scanned: int = 10_000,
        case_sensitive: bool = False,
        include_hidden: bool = False,
        context_lines: int = 0,
        early_termination: bool = False,
        literal_search: bool | None = None,
    ) -> dict[str, Any]:
        return self.searches.start(
            root,
            pattern,
            search_type,
            file_glob,
            max_results,
            max_depth,
            max_scanned,
            case_sensitive,
            include_hidden,
            context_lines,
            early_termination,
            literal_search,
        )

    def get_search_results(self, session_id: str, offset: int = 0, length: int = 100) -> dict[str, Any]:
        return self.searches.results(session_id, offset, length)

    def list_searches(self) -> dict[str, Any]:
        return self.searches.list()

    def stop_search(self, session_id: str) -> dict[str, Any]:
        return self.searches.stop(session_id)
