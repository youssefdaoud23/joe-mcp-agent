from __future__ import annotations

import os
import shlex
from pathlib import Path

from src.security import AccessDenied, safe_host_path


class CommandDenied(PermissionError):
    """Raised when a command is outside the Step 3A read-only command policy."""


NO_ARG_COMMANDS = {"whoami", "pwd", "cat"}
SIMPLE_COMMANDS = {
    "hostname": {"", "-f", "--fqdn", "-s", "--short"},
    "uptime": {"", "-p", "--pretty", "-s", "--since"},
    "date": {"", "-I", "--iso-8601", "-R", "--rfc-email", "-u", "--utc"},
}
UNAME_FLAGS = {"-a", "--all", "-s", "--kernel-name", "-n", "--nodename", "-r", "--kernel-release", "-v", "--kernel-version", "-m", "--machine", "-p", "--processor", "-i", "--hardware-platform", "-o", "--operating-system"}
ID_FLAGS = {"-u", "--user", "-g", "--group", "-G", "--groups", "-n", "--name", "-r", "--real", "-Z", "--context"}
FREE_FLAGS = {"-b", "--bytes", "-k", "--kibi", "-m", "--mebi", "-g", "--gibi", "-h", "--human", "-w", "--wide", "-t", "--total"}
DF_FLAGS = {"-h", "--human-readable", "-H", "--si", "-T", "--print-type", "-i", "--inodes", "-P", "--portability"}
SS_FLAGS = {"-l", "--listening", "-t", "--tcp", "-u", "--udp", "-n", "--numeric", "-p", "--processes", "-a", "--all", "-s", "--summary"}
IP_OBJECTS = {"address", "addr", "link", "route"}
IP_GLOBAL_FLAGS = {"-br", "-brief", "-o", "-oneline", "-s", "-stats", "-d", "-details", "-j", "-json", "-p", "-pretty"}
SHELL_META = set(";&|`$><\n\r\x00")
MAX_ARGS = 64
MAX_ARG_LEN = 4096


def parse_command(command: str) -> list[str]:
    if not isinstance(command, str) or not command.strip():
        raise CommandDenied("Command cannot be empty")
    if any(ch in command for ch in SHELL_META):
        raise CommandDenied("Shell metacharacters, expansion and redirection are disabled")
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        raise CommandDenied(f"Invalid command syntax: {exc}") from exc
    if not argv or len(argv) > MAX_ARGS:
        raise CommandDenied("Command has an invalid number of arguments")
    if any(len(arg) > MAX_ARG_LEN for arg in argv):
        raise CommandDenied("Command argument is too long")
    if "/" in argv[0]:
        raise CommandDenied("Executable must be selected by approved command name")
    return argv


def _validate_path(value: str, host_root: Path, base_dir: str = "/") -> None:
    if value.startswith("-"):
        raise CommandDenied(f"Unexpected option: {value}")
    if value.startswith("/"):
        path = value
    else:
        path = os.path.normpath(os.path.join(base_dir, value))
    try:
        safe_host_path(path, host_root)
    except (AccessDenied, ValueError, OSError) as exc:
        raise CommandDenied(str(exc)) from exc


def _flag_allowed(arg: str, allowed_flags: set[str]) -> bool:
    if arg in allowed_flags:
        return True
    if arg.startswith("--") or not arg.startswith("-") or len(arg) < 3:
        return False
    return all(f"-{char}" in allowed_flags for char in arg[1:])


def _flags_and_paths(
    args: list[str],
    allowed_flags: set[str],
    host_root: Path,
    *,
    allow_paths: bool = False,
    base_dir: str = "/",
) -> None:
    for arg in args:
        if arg.startswith("-"):
            if not _flag_allowed(arg, allowed_flags):
                raise CommandDenied(f"Option not allowed: {arg}")
        elif allow_paths:
            _validate_path(arg, host_root, base_dir)
        else:
            raise CommandDenied(f"Positional argument not allowed: {arg}")


def validate_command(command: str, cwd: str, host_root: Path = Path("/")) -> list[str]:
    argv = parse_command(command)
    exe, args = argv[0], argv[1:]

    _validate_path(cwd, host_root)
    cwd_path = Path(cwd)
    if not cwd_path.is_absolute():
        raise CommandDenied("Working directory must be absolute")
    if not cwd_path.exists() or not cwd_path.is_dir():
        raise CommandDenied("Working directory does not exist or is not a directory")

    if exe in NO_ARG_COMMANDS:
        if args:
            raise CommandDenied(f"{exe} does not accept arguments in read-only mode")
    elif exe in SIMPLE_COMMANDS:
        joined = " ".join(args)
        if joined not in SIMPLE_COMMANDS[exe]:
            raise CommandDenied(f"Arguments not allowed for {exe}")
    elif exe == "uname":
        _flags_and_paths(args, UNAME_FLAGS, host_root)
    elif exe == "id":
        _flags_and_paths(args, ID_FLAGS, host_root)
    elif exe == "free":
        _flags_and_paths(args, FREE_FLAGS, host_root)
    elif exe == "df":
        _flags_and_paths(args, DF_FLAGS, host_root, allow_paths=True, base_dir=cwd)
    elif exe == "ss":
        _flags_and_paths(args, SS_FLAGS, host_root)
    elif exe == "ip":
        remaining = list(args)
        while remaining and remaining[0].startswith("-"):
            if remaining[0] not in IP_GLOBAL_FLAGS:
                raise CommandDenied(f"ip option not allowed: {remaining[0]}")
            remaining.pop(0)
        if not remaining or remaining[0] not in IP_OBJECTS:
            raise CommandDenied("Only ip address, link and route inspection is allowed")
        if len(remaining) > 2:
            raise CommandDenied("Mutating or advanced ip subcommands are disabled")
        if len(remaining) == 2 and remaining[1] not in {"show", "list"}:
            raise CommandDenied("Only ip ... show/list is allowed")
    else:
        raise CommandDenied(f"Executable is not in the read-only allow-list: {exe}")

    return argv


def allowed_commands() -> list[str]:
    return ["cat", "date", "df", "free", "hostname", "id", "ip", "pwd", "ss", "uname", "uptime", "whoami"]
