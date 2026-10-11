from __future__ import annotations

import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from src.rich_write import create_docx, create_xlsx, edit_docx_xml
from src.write_policy import safe_write_path

MAX_WRITE_BYTES = int(os.getenv("JOE_MAX_WRITE_BYTES", "1048576"))
MAX_TEXT_FILE_BYTES = int(os.getenv("JOE_MAX_TEXT_FILE_BYTES", "2097152"))
MAX_COPY_BYTES = int(os.getenv("JOE_MAX_COPY_BYTES", str(100 * 1024 * 1024)))
TRASH_ROOT = Path(os.getenv("JOE_TRASH_ROOT", "/var/lib/joe-mcp-work/trash"))
TRASH_ID_RE = re.compile(r"^[a-f0-9]{32}$")


def _encoded(text: str) -> bytes:
    data = text.encode("utf-8")
    if len(data) > MAX_WRITE_BYTES:
        raise ValueError(f"Write payload exceeds {MAX_WRITE_BYTES} byte limit")
    return data


def _open_no_follow(path: Path, flags: int, mode: int = 0o644) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags | nofollow, mode)


def write_file(path: str, content: str, mode: str = "rewrite") -> dict[str, Any]:
    suffix = Path(str(path or "")).suffix.lower()
    if suffix == ".docx":
        if mode != "rewrite":
            raise ValueError("DOCX creation currently supports rewrite mode only")
        return create_docx(path, content)
    if suffix == ".xlsx":
        if mode != "rewrite":
            raise ValueError("Excel creation currently supports rewrite mode only")
        return create_xlsx(path, content)
    if suffix == ".xlsm":
        raise ValueError("Creating or rewriting .xlsm could discard VBA content; create .xlsx or use edit_spreadsheet_range on an existing .xlsm")
    target = safe_write_path(path)
    if target.exists() and not target.is_file():
        raise ValueError("Target exists but is not a regular file")
    if not target.parent.exists() or not target.parent.is_dir():
        raise FileNotFoundError(f"Parent directory does not exist: {target.parent}")

    data = _encoded(content)
    current_size = target.stat().st_size if target.exists() else 0
    if mode == "rewrite":
        resulting_size = len(data)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    elif mode == "append":
        resulting_size = current_size + len(data)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    else:
        raise ValueError("mode must be 'rewrite' or 'append'")
    if resulting_size > MAX_TEXT_FILE_BYTES:
        raise ValueError(f"Resulting file exceeds {MAX_TEXT_FILE_BYTES} byte limit")

    existed = target.exists()
    fd = _open_no_follow(target, flags)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise

    return {
        "path": path,
        "mode": mode,
        "created": not existed,
        "bytes_written": len(data),
        "size": target.stat().st_size,
    }


def edit_file(path: str, old_text: str, new_text: str, expected_replacements: int = 1) -> dict[str, Any]:
    if Path(str(path or "")).suffix.lower() == ".docx":
        return edit_docx_xml(path, old_text, new_text, expected_replacements)
    target = safe_write_path(path, must_exist=True)
    if not target.is_file():
        raise ValueError("Target is not a regular file")
    if not old_text:
        raise ValueError("old_text cannot be empty")
    expected = int(expected_replacements)
    if expected < 1 or expected > 1000:
        raise ValueError("expected_replacements must be between 1 and 1000")
    if target.stat().st_size > MAX_TEXT_FILE_BYTES:
        raise ValueError("Target file exceeds editable size limit")

    fd = _open_no_follow(target, os.O_RDONLY)
    with os.fdopen(fd, "rb", closefd=True) as handle:
        raw = handle.read(MAX_TEXT_FILE_BYTES + 1)
    if len(raw) > MAX_TEXT_FILE_BYTES:
        raise ValueError("Target file exceeds editable size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Target is not valid UTF-8 text") from exc

    actual = text.count(old_text)
    if actual != expected:
        raise ValueError(f"Expected {expected} replacement(s), found {actual}")
    updated = text.replace(old_text, new_text)
    encoded = updated.encode("utf-8")
    if len(encoded) > MAX_TEXT_FILE_BYTES:
        raise ValueError("Edited file would exceed size limit")

    fd = _open_no_follow(target, os.O_WRONLY | os.O_TRUNC)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise

    return {
        "path": path,
        "replacements": actual,
        "old_size": len(raw),
        "new_size": len(encoded),
    }


def create_directory(path: str, parents: bool = True) -> dict[str, Any]:
    target = safe_write_path(path)
    if target.exists():
        if not target.is_dir():
            raise FileExistsError(f"Path exists and is not a directory: {path}")
        return {"path": path, "created": False, "exists": True}
    target.mkdir(parents=bool(parents), exist_ok=False, mode=0o755)
    return {"path": path, "created": True, "exists": True}


def move_file(source: str, destination: str) -> dict[str, Any]:
    src = safe_write_path(source, must_exist=True)
    dst = safe_write_path(destination)
    if dst.exists():
        raise FileExistsError(f"Destination already exists: {destination}")
    if not dst.parent.exists() or not dst.parent.is_dir():
        raise FileNotFoundError(f"Destination parent does not exist: {dst.parent}")
    os.rename(src, dst)
    return {
        "source": source,
        "destination": destination,
        "moved": True,
        "type": "directory" if dst.is_dir() else "file",
    }



def copy_file(source: str, destination: str) -> dict[str, Any]:
    src = safe_write_path(source, must_exist=True)
    dst = safe_write_path(destination)
    if src.is_symlink() or not src.is_file():
        raise ValueError("Only regular files can be copied")
    if src.stat().st_size > MAX_COPY_BYTES:
        raise ValueError(f"Source file exceeds {MAX_COPY_BYTES} byte copy limit")
    if dst.exists():
        raise FileExistsError(f"Destination already exists: {destination}")
    if not dst.parent.exists() or not dst.parent.is_dir():
        raise FileNotFoundError(f"Destination parent does not exist: {dst.parent}")
    shutil.copy2(src, dst, follow_symlinks=False)
    return {"source": source, "destination": destination, "copied": True, "bytes": dst.stat().st_size}


def _trash_item(trash_id: str) -> tuple[Path, Path, Path]:
    value = str(trash_id or "").strip().lower()
    if not TRASH_ID_RE.fullmatch(value):
        raise ValueError("Invalid trash id")
    base = TRASH_ROOT / value
    return base, base / "item", base / "metadata.json"


def _trash_root() -> Path:
    TRASH_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(TRASH_ROOT, 0o700)
    return TRASH_ROOT


def trash_path(path: str) -> dict[str, Any]:
    src = safe_write_path(path, must_exist=True)
    if src.is_symlink():
        raise ValueError("Symlink trash targets are not supported")
    trash_id = uuid.uuid4().hex
    base, item, metadata_path = _trash_item(trash_id)
    _trash_root()
    base.mkdir(mode=0o700)
    metadata = {
        "id": trash_id,
        "original_path": path,
        "name": src.name,
        "type": "directory" if src.is_dir() else "file",
        "trashed_at": time.time(),
    }
    try:
        shutil.move(str(src), str(item))
        metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(metadata_path, 0o600)
    except Exception:
        if item.exists() and not src.exists():
            shutil.move(str(item), str(src))
        shutil.rmtree(base, ignore_errors=True)
        raise
    return metadata | {"trashed": True}


def list_trash(max_results: int = 200) -> dict[str, Any]:
    root = _trash_root()
    limit = max(1, min(int(max_results), 1000))
    entries: list[dict[str, Any]] = []
    for base in sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True):
        if len(entries) >= limit:
            break
        _b, item, metadata_path = _trash_item(base.name)
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if not isinstance(metadata, dict) or not item.exists():
                continue
            metadata["size"] = item.stat().st_size if item.is_file() else None
            entries.append(metadata)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
    return {"entries": entries, "count": len(entries), "trash_root": str(root)}


def restore_trash(trash_id: str, destination: str = "") -> dict[str, Any]:
    base, item, metadata_path = _trash_item(trash_id)
    if not item.exists() or not metadata_path.is_file():
        raise FileNotFoundError("Trash entry not found")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    original = str(metadata.get("original_path") or "")
    target_path = str(destination or original)
    dst = safe_write_path(target_path)
    if dst.exists():
        raise FileExistsError(f"Restore destination already exists: {target_path}")
    if not dst.parent.exists() or not dst.parent.is_dir():
        raise FileNotFoundError(f"Restore parent does not exist: {dst.parent}")
    shutil.move(str(item), str(dst))
    shutil.rmtree(base, ignore_errors=True)
    return {"id": trash_id, "restored": True, "destination": target_path, "original_path": original}


def purge_trash(trash_id: str, confirm: bool = False) -> dict[str, Any]:
    if confirm is not True:
        raise ValueError("Permanent trash purge requires confirm=true")
    base, item, metadata_path = _trash_item(trash_id)
    if not base.exists() or not item.exists() or not metadata_path.exists():
        raise FileNotFoundError("Trash entry not found")
    shutil.rmtree(base)
    return {"id": trash_id, "purged": True}
