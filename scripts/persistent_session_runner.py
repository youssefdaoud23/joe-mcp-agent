from __future__ import annotations

import json
import os
import re
import resource
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.command_policy import validate_command

META_DIR = Path(os.getenv("JOE_PERSISTENT_SESSION_DIR", "/var/lib/joe-mcp-work/persistent-sessions"))
TOKEN_RE = re.compile(r"^[a-f0-9]{32}$")
SAFE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
    "PAGER": "cat",
    "SYSTEMD_PAGER": "cat",
    "GIT_PAGER": "cat",
    "NO_COLOR": "1",
    "HOME": "/",
}


def fail(message: str, code: int = 126) -> None:
    print(f"Joe persistent session runner: {message}", file=sys.stderr, flush=True)
    raise SystemExit(code)


def apply_limits() -> None:
    limits = (
        (resource.RLIMIT_CPU, (15, 15)),
        (resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024)),
        (resource.RLIMIT_NOFILE, (64, 64)),
        (resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024)),
    )
    for which, value in limits:
        try:
            resource.setrlimit(which, value)
        except (ValueError, OSError):
            pass


def main() -> None:
    if len(sys.argv) != 2 or not TOKEN_RE.fullmatch(sys.argv[1]):
        fail("invalid session token")
    token = sys.argv[1]
    session_id = f"ps_{token}"
    path = META_DIR / f"{session_id}.json"
    try:
        info = path.lstat()
    except OSError:
        fail("session metadata unavailable")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        fail("session metadata is not securely owned")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("session metadata is invalid")
    if not isinstance(data, dict) or data.get("session_id") != session_id:
        fail("session metadata does not match token")
    command = str(data.get("command", ""))
    cwd = str(data.get("cwd", "/"))
    recorded_argv = data.get("argv", [])
    if not isinstance(recorded_argv, list) or not all(isinstance(item, str) for item in recorded_argv):
        fail("session argv is invalid")
    try:
        argv = validate_command(command, cwd, Path("/"))
    except Exception as exc:
        fail(str(exc))
    if argv != recorded_argv:
        fail("session command validation mismatch")
    try:
        os.chdir(cwd)
    except OSError:
        fail("working directory is unavailable")
    apply_limits()
    try:
        os.execvpe(argv[0], argv, SAFE_ENV)
    except OSError as exc:
        fail(f"unable to execute command: {exc}", 127)


if __name__ == "__main__":
    main()
