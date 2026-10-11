from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

TMUX = "/usr/bin/tmux"
SOCKET = Path(os.getenv("JOE_TMUX_SOCKET", "/run/joe-mcp-session/tmux.sock"))
KEEPER = "joe-keeper"
SAFE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "HOME": "/",
    "TERM": "dumb",
}
STOP = False


def tmux(args: list[str], check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [TMUX, "-S", str(SOCKET), *args],
        env=SAFE_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
    )
    if check and result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or f"tmux exited with status {result.returncode}")
    return result


def stop_handler(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def main() -> int:
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    SOCKET.parent.mkdir(parents=True, exist_ok=True)

    existing = tmux(["list-sessions"], check=False)
    if existing.returncode != 0 and SOCKET.exists():
        try:
            SOCKET.unlink()
        except OSError:
            pass

    if tmux(["has-session", "-t", KEEPER], check=False).returncode != 0:
        tmux(["-f", "/dev/null", "new-session", "-d", "-s", KEEPER, "/usr/bin/sleep", "infinity"])
    tmux(["set-option", "-g", "remain-on-exit", "on"])
    tmux(["set-option", "-g", "history-limit", "5000"])

    while not STOP:
        if tmux(["has-session", "-t", KEEPER], check=False).returncode != 0:
            print("Joe persistent session host: tmux keeper disappeared", file=sys.stderr, flush=True)
            return 1
        time.sleep(2)

    tmux(["kill-server"], check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
