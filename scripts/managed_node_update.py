from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

STATE_ROOT = Path("/var/lib/joe-mcp-agent")
STATUS_FILE = STATE_ROOT / "update-status.json"
BACKUP_ROOT = STATE_ROOT / "update-backups"
CONFIG_FILE = STATE_ROOT / "config.json"
UNIT_PATHS = (
    Path("/etc/systemd/system/joe-mcp-host-bridge.service"),
    Path("/etc/systemd/system/joe-mcp-session-host.service"),
    Path("/etc/systemd/system/joe-mcp-node-agent.service"),
    Path("/etc/systemd/system/joe-mcp-node-update.service"),
    Path("/etc/systemd/system/joe-mcp-host-bridge.service.d"),
    Path("/usr/local/libexec/joe-mcp-session-runner"),
    Path("/usr/local/libexec/joe-mcp-git-askpass"),
    Path("/usr/local/bin/joe"),
)
SERVICES = (
    "joe-mcp-host-bridge.service",
    "joe-mcp-session-host.service",
    "joe-mcp-node-agent.service",
)


class ManagedUpdateError(RuntimeError):
    pass


def _atomic_status(payload: dict) -> None:
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    STATE_ROOT.chmod(0o700)
    tmp = STATUS_FILE.with_name(f".{STATUS_FILE.name}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    os.replace(tmp, STATUS_FILE)


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedUpdateError(f"Unable to read {path.name}") from exc
    if not isinstance(data, dict):
        raise ManagedUpdateError(f"Invalid {path.name}")
    return data


def _version(project_root: Path) -> str:
    try:
        return (project_root / ".joe-node-install").read_text(encoding="utf-8").strip()[:64]
    except OSError:
        return "unknown"


def _validate_project_root(raw: str) -> Path:
    root = Path(str(raw or "")).resolve(strict=False)
    if not root.is_absolute() or root == Path("/") or not (root / ".joe-node-install").is_file():
        raise ManagedUpdateError("Managed Joe project root is invalid")
    return root


def _server_origin() -> str:
    cfg = _read_json(CONFIG_FILE)
    server = str(cfg.get("server") or "").rstrip("/")
    parsed = urlsplit(server)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ManagedUpdateError("Managed Joe controller URL is invalid")
    return server


def _copy_entry(source: Path, destination: Path) -> None:
    if source.is_dir() and not source.is_symlink():
        shutil.copytree(source, destination, symlinks=False)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)


def _snapshot(project_root: Path, backup_dir: Path) -> dict:
    backup_dir.mkdir(parents=True, exist_ok=False)
    backup_dir.chmod(0o700)
    project_backup = backup_dir / "project"
    shutil.copytree(project_root, project_backup, symlinks=False)
    manifest: dict[str, dict[str, object]] = {}
    system_backup = backup_dir / "system"
    for index, path in enumerate(UNIT_PATHS):
        key = str(index)
        exists = path.exists() or path.is_symlink()
        manifest[key] = {"path": str(path), "exists": exists}
        if exists:
            _copy_entry(path, system_backup / key)
    (backup_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _remove_entry(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def _restore(project_root: Path, backup_dir: Path, manifest: dict) -> None:
    project_backup = backup_dir / "project"
    if not project_backup.is_dir():
        raise ManagedUpdateError("Managed Joe rollback project snapshot is missing")
    _remove_entry(project_root)
    shutil.copytree(project_backup, project_root, symlinks=False)
    system_backup = backup_dir / "system"
    for key, item in manifest.items():
        if not isinstance(item, dict):
            continue
        path = Path(str(item.get("path") or ""))
        if not path.is_absolute() or str(path) not in {str(candidate) for candidate in UNIT_PATHS}:
            raise ManagedUpdateError("Managed Joe rollback manifest contains an unsafe path")
        _remove_entry(path)
        if bool(item.get("exists")):
            source = system_backup / key
            if not source.exists() and not source.is_symlink():
                raise ManagedUpdateError("Managed Joe rollback system snapshot is incomplete")
            _copy_entry(source, path)


def _systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["/usr/bin/systemctl", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )
    if check and completed.returncode != 0:
        raise ManagedUpdateError(f"systemctl {' '.join(args)} failed")
    return completed


def _services_healthy() -> bool:
    return all(_systemctl("is-active", "--quiet", unit, check=False).returncode == 0 for unit in SERVICES)


def _restore_runtime(project_root: Path, backup_dir: Path, manifest: dict) -> bool:
    try:
        _restore(project_root, backup_dir, manifest)
        _systemctl("daemon-reload")
        for unit in SERVICES:
            _systemctl("restart", unit)
        return _services_healthy()
    except Exception:
        return False


def _prune_backups(keep: Path) -> None:
    try:
        rows = sorted((item for item in BACKUP_ROOT.iterdir() if item.is_dir()), key=lambda item: item.stat().st_mtime, reverse=True)
    except OSError:
        return
    kept = 0
    for item in rows:
        if item == keep or kept < 1:
            kept += 1
            continue
        shutil.rmtree(item, ignore_errors=True)


def main() -> int:
    if len(sys.argv) != 2:
        raise ManagedUpdateError("Expected fixed managed-node project root")
    project_root = _validate_project_root(sys.argv[1])
    server = _server_origin()
    request_id = "upd_" + uuid.uuid4().hex
    previous_version = _version(project_root)
    started_at = time.time()
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    BACKUP_ROOT.chmod(0o700)
    backup_dir = BACKUP_ROOT / request_id
    status = {
        "version": 1,
        "request_id": request_id,
        "state": "running",
        "started_at": started_at,
        "finished_at": None,
        "previous_version": previous_version,
        "installed_version": previous_version,
        "rollback_attempted": False,
        "rollback_succeeded": False,
        "error": None,
    }
    _atomic_status(status)
    manifest: dict = {}
    try:
        manifest = _snapshot(project_root, backup_dir)
        with tempfile.TemporaryDirectory(prefix="joe-node-update-") as tmpdir:
            installer = Path(tmpdir) / "install-node.sh"
            request = urllib.request.Request(server + "/install", headers={"User-Agent": "JoeMCPManagedUpdater/1"})
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read(512_000)
            if not payload.startswith(b"#!/usr/bin/env bash"):
                raise ManagedUpdateError("Controller returned an invalid managed-node installer")
            installer.write_bytes(payload)
            installer.chmod(0o700)
            completed = subprocess.run(
                ["/bin/bash", str(installer), "--server", server, "--install-dir", str(project_root)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=900,
                check=False,
            )
            if completed.returncode != 0:
                raise ManagedUpdateError(f"Managed-node installer failed with exit code {completed.returncode}")
        if not _services_healthy():
            raise ManagedUpdateError("Managed-node services are not healthy after update")
        status.update(
            {
                "state": "passed",
                "finished_at": time.time(),
                "installed_version": _version(project_root),
            }
        )
        _atomic_status(status)
        _prune_backups(backup_dir)
        return 0
    except Exception as exc:
        status["rollback_attempted"] = bool(manifest)
        rollback_ok = _restore_runtime(project_root, backup_dir, manifest) if manifest else False
        status.update(
            {
                "state": "failed_rolled_back" if rollback_ok else "failed",
                "finished_at": time.time(),
                "installed_version": _version(project_root),
                "rollback_succeeded": rollback_ok,
                "error": str(exc)[:500],
            }
        )
        _atomic_status(status)
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ManagedUpdateError as exc:
        _atomic_status(
            {
                "version": 1,
                "request_id": None,
                "state": "failed",
                "started_at": time.time(),
                "finished_at": time.time(),
                "previous_version": None,
                "installed_version": None,
                "rollback_attempted": False,
                "rollback_succeeded": False,
                "error": str(exc)[:500],
            }
        )
        raise SystemExit(1)
