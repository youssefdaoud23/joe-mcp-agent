from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.security import redact_text

SAFE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/", "PAGER": "cat", "NO_COLOR": "1",
    "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0",
}
MAX_BYTES = 750_000
SYSCTL_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,15}$")
PROC_TOPICS = {
    "meminfo": "/proc/meminfo",
    "vmstat": "/proc/vmstat",
    "loadavg": "/proc/loadavg",
    "uptime": "/proc/uptime",
    "cpuinfo": "/proc/cpuinfo",
    "pressure_cpu": "/proc/pressure/cpu",
    "pressure_memory": "/proc/pressure/memory",
    "pressure_io": "/proc/pressure/io",
    "net_dev": "/proc/net/dev",
    "net_snmp": "/proc/net/snmp",
    "net_netstat": "/proc/net/netstat",
}


class LinuxDiagnosticError(RuntimeError):
    pass


def _run(binary: str, args: list[str], timeout: float = 8.0, max_bytes: int = MAX_BYTES, allow_nonzero: bool = False) -> dict[str, Any]:
    executable = shutil.which(binary)
    if not executable:
        return {"available": False, "command": binary, "output": "", "returncode": None}
    try:
        completed = subprocess.run(
            [executable, *args], env=SAFE_ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise LinuxDiagnosticError(f"{binary} diagnostic timed out") from exc
    raw_out = completed.stdout[:max_bytes]
    raw_err = completed.stderr[:64_000]
    if completed.returncode != 0 and not allow_nonzero:
        err = raw_err.decode("utf-8", errors="replace").strip()
        raise LinuxDiagnosticError(err or f"{binary} exited with status {completed.returncode}")
    text = raw_out.decode("utf-8", errors="replace")
    return {
        "available": True,
        "command": binary,
        "returncode": int(completed.returncode),
        "output": redact_text(text, max_chars=max_bytes),
        "stderr": redact_text(raw_err.decode("utf-8", errors="replace"), max_chars=8000) if raw_err else "",
        "truncated": len(completed.stdout) > max_bytes,
    }


def firewall_status() -> dict[str, Any]:
    ufw = _run("ufw", ["status", "verbose"], timeout=8.0, max_bytes=250_000, allow_nonzero=True)
    nft = _run("nft", ["-j", "list", "ruleset"], timeout=10.0, max_bytes=500_000, allow_nonzero=True)
    nft_summary: dict[str, Any] | None = None
    if nft.get("available") and nft.get("returncode") == 0:
        try:
            parsed = json.loads(str(nft.get("output") or "{}"))
            rows = parsed.get("nftables", []) if isinstance(parsed, dict) else []
            counts = {"tables": 0, "chains": 0, "rules": 0, "sets": 0}
            for row in rows if isinstance(rows, list) else []:
                if not isinstance(row, dict):
                    continue
                for key, out_key in (("table", "tables"), ("chain", "chains"), ("rule", "rules"), ("set", "sets")):
                    if key in row:
                        counts[out_key] += 1
            nft_summary = counts
        except json.JSONDecodeError:
            nft_summary = None
    return {
        "ufw": ufw,
        "nftables": {**nft, "summary": nft_summary},
        "read_only": True,
    }


def tailscale_status() -> dict[str, Any]:
    result = _run("tailscale", ["status", "--json"], timeout=8.0, max_bytes=750_000, allow_nonzero=True)
    if not result.get("available") or result.get("returncode") != 0:
        return {"available": bool(result.get("available")), "returncode": result.get("returncode"), "error": result.get("stderr") or None, "read_only": True}
    try:
        data = json.loads(str(result.get("output") or "{}"))
    except json.JSONDecodeError as exc:
        raise LinuxDiagnosticError("tailscale returned invalid JSON") from exc
    def peer(row: Any) -> dict[str, Any]:
        item = row if isinstance(row, dict) else {}
        return {
            "host_name": item.get("HostName"), "dns_name": item.get("DNSName"),
            "tailscale_ips": item.get("TailscaleIPs", [])[:8] if isinstance(item.get("TailscaleIPs"), list) else [],
            "online": bool(item.get("Online", False)), "active": bool(item.get("Active", False)),
            "exit_node": bool(item.get("ExitNode", False)), "exit_node_option": bool(item.get("ExitNodeOption", False)),
            "relay": item.get("Relay"), "rx_bytes": item.get("RxBytes"), "tx_bytes": item.get("TxBytes"),
        }
    self_row = peer(data.get("Self", {})) if isinstance(data, dict) else {}
    raw_peers = data.get("Peer", {}) if isinstance(data, dict) else {}
    peer_rows = []
    if isinstance(raw_peers, dict):
        peer_rows = [peer(value) for value in raw_peers.values()][:200]
    return {
        "available": True,
        "backend_state": data.get("BackendState") if isinstance(data, dict) else None,
        "tailscale_ips": data.get("TailscaleIPs", [])[:8] if isinstance(data, dict) and isinstance(data.get("TailscaleIPs"), list) else [],
        "self": self_row,
        "peers": peer_rows,
        "peer_count": len(raw_peers) if isinstance(raw_peers, dict) else len(peer_rows),
        "read_only": True,
    }


def sysctl_read(key: str, host_root: Path = Path("/")) -> dict[str, Any]:
    normalized = str(key or "").strip()
    if not SYSCTL_KEY_RE.fullmatch(normalized):
        raise LinuxDiagnosticError("sysctl key must be a dotted kernel key using letters, digits, underscore, or dash")
    relative = Path("proc/sys") / Path(*normalized.split("."))
    root = host_root.resolve(strict=False)
    target = (root / relative).resolve(strict=False)
    proc_sys = (root / "proc/sys").resolve(strict=False)
    try:
        target.relative_to(proc_sys)
    except ValueError as exc:
        raise LinuxDiagnosticError("sysctl path escaped /proc/sys") from exc
    if not target.is_file() or target.is_symlink():
        raise LinuxDiagnosticError("sysctl key not found or is not a regular readable value")
    try:
        raw = target.read_bytes()[:8193]
    except OSError as exc:
        raise LinuxDiagnosticError("sysctl value could not be read") from exc
    if len(raw) > 8192:
        raise LinuxDiagnosticError("sysctl value exceeds bounded read limit")
    return {"key": normalized, "value": raw.decode("utf-8", errors="replace").strip(), "read_only": True}


def proc_snapshot(topic: str, host_root: Path = Path("/")) -> dict[str, Any]:
    name = str(topic or "").strip().lower()
    relative = PROC_TOPICS.get(name)
    if not relative:
        raise LinuxDiagnosticError("unsupported /proc topic; use one of: " + ", ".join(sorted(PROC_TOPICS)))
    target = host_root / relative.lstrip("/")
    try:
        raw = target.read_bytes()[:250_001]
    except OSError as exc:
        raise LinuxDiagnosticError(f"/proc topic unavailable: {name}") from exc
    truncated = len(raw) > 250_000
    text = raw[:250_000].decode("utf-8", errors="replace")
    return {"topic": name, "path": relative, "content": redact_text(text, max_chars=250_000), "truncated": truncated, "read_only": True}


def routing_diagnostics() -> dict[str, Any]:
    commands = {
        "links": ["-json", "link", "show"],
        "addresses": ["-json", "address", "show"],
        "routes": ["-json", "route", "show", "table", "all"],
        "rules": ["-json", "rule", "show"],
    }
    result: dict[str, Any] = {"available": True, "read_only": True}
    for name, args in commands.items():
        row = _run("ip", args, timeout=8.0, max_bytes=500_000, allow_nonzero=True)
        if not row.get("available"):
            result["available"] = False
            result[name] = []
            continue
        if row.get("returncode") != 0:
            result[name] = {"error": row.get("stderr") or f"ip returned {row.get('returncode')}"}
            continue
        try:
            parsed = json.loads(str(row.get("output") or "[]"))
        except json.JSONDecodeError:
            parsed = []
        result[name] = parsed[:500] if isinstance(parsed, list) else []
    return result
