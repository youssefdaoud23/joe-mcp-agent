"""Joe Developer Access sudo anchor.

This file is loaded as TEXT by the host bridge and executed as the *selected Linux user* inside a
transient systemd unit:  python3 -I -c <this source> /usr/bin/sudo   (it is never imported).

Why an anchor exists
--------------------
sudo's timestamp ticket is keyed to the parent process (no controlling terminal => parent PID) or to a
terminal. The host bridge runs under NoNewPrivileges and a read-only /run, so it cannot hold a sudo
ticket itself, and independent one-shot units would each need the password again. The anchor is the
single long-lived parent that (1) validates the password once with ``sudo -S -v``, (2) immediately
discards it, and (3) launches every later privileged command as ``sudo -n`` so the operating system's
own ticket is what authorizes it. No password is ever kept, and no ticket outlives the anchor.

Control channel
---------------
JSON lines on stdin/stdout, which are the private pipes of the bridge's ``systemd-run --pipe``
client. There is no filesystem socket, token or file, so no other process can reach the anchor.

stdin  (bridge -> anchor): authorize | run | kill | revoke
stdout (anchor -> bridge): authorized | denied | started | output | exit | error | expired

The anchor lives for at most the authorized lifetime, is non-dumpable, and exits (after ``sudo -k``)
on revoke, expiry, or loss of the control pipe.
"""
import ctypes
import json
import os
import select
import signal
import subprocess
import sys
import threading
import time

SAFE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "TERM": "dumb",
}
MAX_CONTROL_LINE = 4 * 1024 * 1024
MAX_RUNS = 4
MAX_RUN_SECONDS = 1800
CHUNK = 8192
_OUT_LOCK = threading.Lock()


def emit(event):
    data = (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8")
    with _OUT_LOCK:
        try:
            os.write(1, data)
        except OSError:
            pass


def make_undumpable():
    # PR_SET_DUMPABLE=0: other processes of the same user cannot ptrace us or read /proc/<pid>/{mem,fd}.
    try:
        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)
    except Exception:
        pass


class LineReader:
    def __init__(self, fd):
        self.fd = fd
        self.buffer = b""
        self.eof = False

    def readline(self, timeout):
        """Return a decoded line, '' on EOF, or None when the timeout elapses."""
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            index = self.buffer.find(b"\n")
            if index >= 0:
                line, self.buffer = self.buffer[:index], self.buffer[index + 1:]
                return line.decode("utf-8", errors="replace")
            if self.eof:
                if self.buffer:
                    line, self.buffer = self.buffer, b""
                    return line.decode("utf-8", errors="replace")
                return ""
            if len(self.buffer) > MAX_CONTROL_LINE:
                raise ValueError("control line too large")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([self.fd], [], [], remaining)
            if not ready:
                return None
            chunk = os.read(self.fd, 65536)
            if not chunk:
                self.eof = True
            else:
                self.buffer += chunk


def spawn_sudo(sudo, args, **kwargs):
    """The ONLY way the anchor starts sudo.

    sudo keys its ticket to the invoking parent process AND session. Every sudo child must therefore be
    a plain child of this anchor in the anchor's own session: never pass start_new_session / preexec
    setsid / process_group here, or sudo will stop recognizing the ticket ("a password is required").
    The retention probe and the real privileged runs share this helper so they cannot diverge.
    """
    kwargs.pop("start_new_session", None)
    kwargs.pop("preexec_fn", None)
    kwargs.pop("process_group", None)
    return subprocess.Popen([sudo] + list(args), env=SAFE_ENV, close_fds=True, **kwargs)


def run_sudo(sudo, args, stdin_bytes=None, timeout=20):
    process = spawn_sudo(
        sudo, args,
        stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if stdin_bytes is not None and process.stdin is not None:
            try:
                process.stdin.write(stdin_bytes)
                process.stdin.close()
            except OSError:
                pass
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return 124


def validate_password(sudo, password):
    """Validate with the OS sudo, then prove the ticket is retained for later non-interactive use."""
    payload = password.encode("utf-8", errors="replace") + b"\n"
    code = run_sudo(sudo, ["-S", "-p", "", "-v"], payload)
    payload = b""
    if code != 0:
        return False, "authorization_failed"
    if run_sudo(sudo, ["-n", "-v"]) != 0:
        run_sudo(sudo, ["-k"], timeout=10)
        return False, "ticket_not_retained"
    return True, ""


class Run:
    def __init__(self, run_id, process):
        self.run_id = run_id
        self.process = process
        self.done = threading.Event()
        self.killed = False


def pump(run, runs, lock):
    process = run.process
    head = b""
    pending = b""
    try:
        while True:
            chunk = os.read(process.stdout.fileno(), CHUNK)
            if not chunk:
                break
            if len(head) < 512:
                head += chunk[:512]
            pending += chunk
            while True:
                index = pending.find(b"\n")
                if index < 0 and len(pending) < CHUNK:
                    break
                if index < 0:
                    line, pending = pending[:CHUNK], pending[CHUNK:]
                else:
                    line, pending = pending[:index], pending[index + 1:]
                emit({"event": "output", "id": run.run_id, "line": line.decode("utf-8", errors="replace")})
        if pending:
            emit({"event": "output", "id": run.run_id, "line": pending.decode("utf-8", errors="replace")})
    finally:
        code = process.wait()
        reauth = code != 0 and b"a password is required" in head
        emit({"event": "exit", "id": run.run_id, "returncode": code, "reauth_required": reauth, "killed": run.killed})
        run.done.set()
        with lock:
            runs.pop(run.run_id, None)


def write_payload(process, payload):
    try:
        process.stdin.write(payload)
    except OSError:
        pass
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass


def stop_run(run, force):
    run.killed = True
    try:
        os.kill(run.process.pid, signal.SIGKILL if force else signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    if not force:
        def escalate():
            if not run.done.wait(5):
                try:
                    os.kill(run.process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        threading.Thread(target=escalate, daemon=True).start()


def start_run(sudo, request, runs, lock):
    run_id = str(request.get("id") or "")
    cwd = str(request.get("cwd") or "")
    payload = str(request.get("payload") or "")
    if not run_id or not cwd.startswith("/") or not payload.strip():
        emit({"event": "error", "id": run_id, "message": "invalid run request"})
        return
    with lock:
        if len(runs) >= MAX_RUNS:
            emit({"event": "error", "id": run_id, "message": "too many concurrent privileged commands"})
            return
    limit = max(1, min(int(request.get("max_seconds") or MAX_RUN_SECONDS), MAX_RUN_SECONDS))
    args = ["-n", "--", "/bin/bash", "-c", 'cd -- "$1" && exec /bin/bash -s', "joe-developer", cwd]
    try:
        process = spawn_sudo(sudo, args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    except OSError:
        emit({"event": "error", "id": run_id, "message": "unable to start privileged command"})
        return
    data = payload.encode("utf-8", errors="replace")
    if not data.endswith(b"\n"):
        data += b"\n"
    run = Run(run_id, process)
    with lock:
        runs[run_id] = run
    emit({"event": "started", "id": run_id, "pid": process.pid})
    threading.Thread(target=write_payload, args=(process, data), daemon=True).start()
    threading.Thread(target=pump, args=(run, runs, lock), daemon=True).start()
    def expire():
        if not run.done.is_set():
            stop_run(run, False)

    timer = threading.Timer(limit, expire)
    timer.daemon = True
    timer.start()


def shutdown(sudo, runs, lock, reason):
    with lock:
        active = list(runs.values())
    for run in active:
        stop_run(run, False)
    for run in active:
        run.done.wait(6)
    # Invalidate the ticket for this anchor (the OS-level equivalent of "revoke").
    run_sudo(sudo, ["-k"], timeout=10)
    emit({"event": reason})


def main(argv):
    sudo = argv[1] if len(argv) > 1 and argv[1].startswith("/") else "/usr/bin/sudo"
    make_undumpable()
    reader = LineReader(0)
    try:
        first = reader.readline(30)
        request = json.loads(first) if first else {}
    except (ValueError, OSError):
        request = {}
    if not isinstance(request, dict) or request.get("op") != "authorize":
        emit({"event": "denied", "reason": "protocol_error"})
        return 2
    password = request.pop("password", None)
    try:
        ttl = max(60, min(int(request.get("ttl_seconds")), 3600))
    except (TypeError, ValueError):
        emit({"event": "denied", "reason": "protocol_error"})
        return 2
    request = None
    if not isinstance(password, str) or not password:
        emit({"event": "denied", "reason": "authorization_failed"})
        return 3
    ok, reason = validate_password(sudo, password)
    password = None
    if not ok:
        emit({"event": "denied", "reason": reason})
        return 3
    deadline = time.monotonic() + ttl
    emit({"event": "authorized", "ttl_seconds": ttl})
    runs = {}
    lock = threading.Lock()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            shutdown(sudo, runs, lock, "expired")
            return 0
        try:
            line = reader.readline(min(remaining, 1.0))
        except ValueError:
            shutdown(sudo, runs, lock, "revoked")
            return 0
        if line is None:
            continue
        if line == "":
            shutdown(sudo, runs, lock, "revoked")
            return 0
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict):
            continue
        op = message.get("op")
        if op == "run":
            start_run(sudo, message, runs, lock)
        elif op == "kill":
            with lock:
                target = runs.get(str(message.get("id") or ""))
            if target is not None:
                stop_run(target, bool(message.get("force")))
        elif op == "revoke":
            shutdown(sudo, runs, lock, "revoked")
            return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
