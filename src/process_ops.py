from __future__ import annotations

import os
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.security import redact_argv

MAX_PROCESSES = 1000
MAX_PORTS = 2000


def _read_text(path: Path, limit: int = 65536) -> str:
    return path.read_bytes()[:limit].decode("utf-8", errors="replace")


def _proc_stat(item: Path) -> dict[str, Any]:
    text = _read_text(item / "stat", 32768).strip()
    close = text.rfind(")")
    if close < 0:
        raise ValueError("invalid proc stat")
    pid = int(text[: text.find(" ")])
    comm = text[text.find("(") + 1 : close]
    fields = text[close + 2 :].split()
    return {
        "pid": pid,
        "comm": comm,
        "state": fields[0],
        "ppid": int(fields[1]),
        "utime_ticks": int(fields[11]),
        "stime_ticks": int(fields[12]),
        "start_ticks": int(fields[19]),
    }


def _boot_time(proc_root: Path) -> float | None:
    try:
        for line in _read_text(proc_root / "stat", 200000).splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def _memory_rss(item: Path) -> int | None:
    try:
        for line in _read_text(item / "status", 65536).splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _cmdline(item: Path) -> str:
    raw = (item / "cmdline").read_bytes()[:16000]
    argv = [part.decode("utf-8", errors="replace") for part in raw.split(b"\x00") if part]
    return redact_argv(argv)


def _link(item: Path, name: str) -> str | None:
    try:
        return os.readlink(item / name)
    except OSError:
        return None


def _started_at(stat: dict[str, Any], boot: float | None) -> str | None:
    if boot is None:
        return None
    ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    try:
        return datetime.fromtimestamp(boot + stat["start_ticks"] / ticks, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _cpu_seconds(stat: dict[str, Any]) -> float:
    ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    return round((stat["utime_ticks"] + stat["stime_ticks"]) / ticks, 3)


def _port_tables(proc_root: Path) -> list[dict[str, Any]]:
    tables = [("tcp", "tcp"), ("tcp6", "tcp6"), ("udp", "udp"), ("udp6", "udp6")]
    rows: list[dict[str, Any]] = []
    for proto, filename in tables:
        path = proc_root / "net" / filename
        try:
            lines = _read_text(path, 2_000_000).splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            local = parts[1]
            state = parts[3]
            inode = parts[9]
            try:
                address_hex, port_hex = local.split(":", 1)
                port = int(port_hex, 16)
                if proto.endswith("6"):
                    raw = bytes.fromhex(address_hex)
                    chunks = [raw[i:i+4][::-1] for i in range(0, 16, 4)]
                    address = socket.inet_ntop(socket.AF_INET6, b"".join(chunks))
                else:
                    address = socket.inet_ntoa(struct.pack("<I", int(address_hex, 16)))
            except (ValueError, OSError):
                continue
            if proto.startswith("tcp") and state != "0A":
                continue
            rows.append({"protocol": proto, "address": address, "port": port, "state": "listen" if proto.startswith("tcp") else "open", "inode": inode})
    return rows


def _inode_owners(proc_root: Path, wanted: set[str]) -> dict[str, set[int]]:
    owners: dict[str, set[int]] = {inode: set() for inode in wanted}
    if not wanted:
        return owners
    for item in proc_root.iterdir():
        if not item.name.isdigit():
            continue
        fd_root = item / "fd"
        try:
            for fd in fd_root.iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    inode = target[8:-1]
                    if inode in owners:
                        owners[inode].add(int(item.name))
        except OSError:
            continue
    return owners


def list_open_ports(host_root: Path, max_results: int = 500) -> dict[str, Any]:
    proc_root = host_root / "proc"
    limit = max(1, min(int(max_results), MAX_PORTS))
    rows = _port_tables(proc_root)
    owners = _inode_owners(proc_root, {row["inode"] for row in rows})
    output: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda x: (x["port"], x["protocol"], x["address"])):
        pids = sorted(owners.get(row["inode"], set()))
        comm = None
        if pids:
            try:
                comm = _read_text(proc_root / str(pids[0]) / "comm", 4096).strip()
            except OSError:
                pass
        output.append({k: v for k, v in row.items() if k != "inode"} | {"pids": pids, "comm": comm})
        if len(output) >= limit:
            break
    return {"available": proc_root.exists(), "ports": output, "count": len(output), "truncated": len(rows) > len(output)}


def process_info(host_root: Path, pid: int) -> dict[str, Any]:
    value = int(pid)
    if value <= 0:
        raise ValueError("pid must be positive")
    proc_root = host_root / "proc"
    item = proc_root / str(value)
    if not item.is_dir():
        raise FileNotFoundError(f"Process not found: {value}")
    stat = _proc_stat(item)
    boot = _boot_time(proc_root)
    all_ports = list_open_ports(host_root, MAX_PORTS).get("ports", [])
    ports = [row for row in all_ports if value in row.get("pids", [])]
    return {
        "pid": value,
        "ppid": stat["ppid"],
        "comm": stat["comm"],
        "state": stat["state"],
        "cmdline": _cmdline(item),
        "cwd": _link(item, "cwd"),
        "executable": _link(item, "exe"),
        "cpu_time_seconds": _cpu_seconds(stat),
        "memory_rss_bytes": _memory_rss(item),
        "start_time": _started_at(stat, boot),
        "open_ports": ports,
    }


def list_processes(host_root: Path, max_processes: int = 200) -> dict[str, Any]:
    proc_root = host_root / "proc"
    limit = max(1, min(int(max_processes), MAX_PROCESSES))
    rows: list[dict[str, Any]] = []
    if not proc_root.exists():
        return {"available": False, "processes": []}
    boot = _boot_time(proc_root)
    for item in sorted((p for p in proc_root.iterdir() if p.name.isdigit()), key=lambda p: int(p.name)):
        if len(rows) >= limit:
            break
        try:
            stat = _proc_stat(item)
            rows.append({
                "pid": stat["pid"],
                "ppid": stat["ppid"],
                "comm": stat["comm"],
                "state": stat["state"],
                "cmdline": _cmdline(item),
                "cwd": _link(item, "cwd"),
                "executable": _link(item, "exe"),
                "cpu_time_seconds": _cpu_seconds(stat),
                "memory_rss_bytes": _memory_rss(item),
                "start_time": _started_at(stat, boot),
            })
        except (OSError, ValueError, FileNotFoundError):
            continue
    return {"available": True, "processes": rows, "count": len(rows), "truncated": len(rows) >= limit}
