import mimetypes
import os
import re
import struct
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from src.security import is_host_path_allowed, normalize_host_path, safe_host_path

MAX_INSPECT_FILE_BYTES = int(os.getenv("JOE_MAX_INSPECT_FILE_BYTES", str(50 * 1024 * 1024)))
MAX_PACKAGE_ENTRIES = 200
MAX_PREVIEW_CHARS = 20_000
MAX_TREE_ENTRIES = 500
MAX_TREE_SCANNED = 5_000


def _kind(path: Path) -> str:
    if path.is_symlink():
        return "symlink"
    if path.is_dir():
        return "directory"
    if path.is_file():
        return "file"
    return "other"


def _jpeg_dimensions(path: Path) -> tuple[int, int] | None:
    try:
        with path.open("rb") as handle:
            if handle.read(2) != b"\xff\xd8":
                return None
            while True:
                marker_start = handle.read(1)
                if not marker_start:
                    return None
                if marker_start != b"\xff":
                    continue
                marker = handle.read(1)
                while marker == b"\xff":
                    marker = handle.read(1)
                if not marker or marker in {b"\xd8", b"\xd9"}:
                    continue
                raw_len = handle.read(2)
                if len(raw_len) != 2:
                    return None
                segment_len = struct.unpack(">H", raw_len)[0]
                if segment_len < 2:
                    return None
                if marker[0] in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                    data = handle.read(segment_len - 2)
                    if len(data) >= 5:
                        height, width = struct.unpack(">HH", data[1:5])
                        return width, height
                    return None
                handle.seek(segment_len - 2, 1)
    except OSError:
        return None


def _image_metadata(path: Path, suffix: str) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            head = handle.read(32)
    except OSError:
        return {}
    if suffix == ".png" and len(head) >= 24 and head.startswith(b"\x89PNG\r\n\x1a\n"):
        width, height = struct.unpack(">II", head[16:24])
        return {"format": "png", "width": width, "height": height}
    if suffix == ".gif" and len(head) >= 10 and head[:6] in {b"GIF87a", b"GIF89a"}:
        width, height = struct.unpack("<HH", head[6:10])
        return {"format": "gif", "width": width, "height": height}
    if suffix in {".jpg", ".jpeg"}:
        dims = _jpeg_dimensions(path)
        return {"format": "jpeg", "width": dims[0], "height": dims[1]} if dims else {"format": "jpeg"}
    return {}


def _zip_metadata(path: Path, suffix: str, max_entries: int) -> dict[str, Any]:
    result: dict[str, Any] = {"package": suffix.lstrip(".") or "zip", "entries": [], "entry_count": 0, "entries_truncated": False}
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            result["entry_count"] = len(infos)
            for info in infos[:max_entries]:
                result["entries"].append({
                    "name": info.filename[:500],
                    "size": int(info.file_size),
                    "compressed_size": int(info.compress_size),
                    "directory": bool(info.is_dir()),
                })
            result["entries_truncated"] = len(infos) > max_entries

            if suffix == ".docx" and "word/document.xml" in archive.namelist():
                doc_info = archive.getinfo("word/document.xml")
                if doc_info.file_size <= 2_000_000:
                    raw = archive.read("word/document.xml")
                    root = ET.fromstring(raw)
                    texts = [node.text or "" for node in root.iter() if node.tag.endswith("}t")]
                    preview = " ".join(texts).strip()
                    result["text_preview"] = preview[:MAX_PREVIEW_CHARS]
                    result["text_preview_truncated"] = len(preview) > MAX_PREVIEW_CHARS
                else:
                    result["text_preview_skipped"] = "document XML exceeds preview limit"

            if suffix == ".xlsx":
                names = set(archive.namelist())
                if "xl/workbook.xml" in names:
                    workbook_info = archive.getinfo("xl/workbook.xml")
                    if workbook_info.file_size <= 2_000_000:
                        root = ET.fromstring(archive.read("xl/workbook.xml"))
                        sheets = []
                        for node in root.iter():
                            if node.tag.endswith("}sheet"):
                                name = str(node.attrib.get("name") or "")
                                if name:
                                    sheets.append(name[:120])
                        result["sheets"] = sheets[:100]
                        result["sheet_count"] = len(sheets)
                if "xl/sharedStrings.xml" in names:
                    shared_info = archive.getinfo("xl/sharedStrings.xml")
                    if shared_info.file_size <= 4_000_000:
                        root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
                        strings = []
                        total_chars = 0
                        for node in root.iter():
                            if node.tag.endswith("}t") and node.text:
                                strings.append(node.text)
                                total_chars += len(node.text)
                                if total_chars >= MAX_PREVIEW_CHARS:
                                    break
                        preview = " | ".join(strings)
                        result["shared_strings_preview"] = preview[:MAX_PREVIEW_CHARS]
                        result["shared_strings_preview_truncated"] = len(preview) > MAX_PREVIEW_CHARS
                    else:
                        result["shared_strings_preview_skipped"] = "shared strings XML exceeds preview limit"
    except (OSError, zipfile.BadZipFile, ET.ParseError, RuntimeError, KeyError) as exc:
        result["package_error"] = str(exc)[:300]
    return result


def inspect_file(path: str, host_root: Path, max_archive_entries: int = 100) -> dict[str, Any]:
    normalized = normalize_host_path(path)
    target = safe_host_path(normalized, host_root)
    if not target.exists():
        return {"path": normalized, "exists": False}
    info = target.lstat()
    kind = _kind(target)
    result: dict[str, Any] = {
        "path": normalized,
        "exists": True,
        "type": kind,
        "size": int(info.st_size),
        "mode": oct(info.st_mode & 0o7777),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mtime": float(info.st_mtime),
        "extension": target.suffix.lower(),
    }
    if kind != "file":
        return result
    mime, _encoding = mimetypes.guess_type(target.name)
    result["mime"] = mime or "application/octet-stream"
    if info.st_size > MAX_INSPECT_FILE_BYTES:
        result["format_inspection"] = "skipped_size_limit"
        result["inspect_size_limit"] = MAX_INSPECT_FILE_BYTES
        return result

    suffix = target.suffix.lower()
    image = _image_metadata(target, suffix)
    if image:
        result["image"] = image
    if suffix in {".zip", ".docx", ".xlsx", ".pptx"}:
        result["archive"] = _zip_metadata(target, suffix, max(1, min(int(max_archive_entries), MAX_PACKAGE_ENTRIES)))
    elif suffix == ".pdf":
        try:
            with target.open("rb") as handle:
                raw = handle.read(min(info.st_size, 8 * 1024 * 1024))
            if raw.startswith(b"%PDF-"):
                version = raw[5:8].decode("ascii", errors="replace")
                pages = len(re.findall(rb"/Type\s*/Page\b", raw))
                result["pdf"] = {"version": version, "approx_page_count": pages, "page_count_is_approximate": True}
        except OSError:
            pass
    return result


def directory_tree(
    path: str,
    host_root: Path,
    max_depth: int = 2,
    max_entries: int = 200,
    include_hidden: bool = False,
) -> dict[str, Any]:
    normalized = normalize_host_path(path)
    target = safe_host_path(normalized, host_root)
    if not target.exists():
        return {"path": normalized, "exists": False, "entries": []}
    if not target.is_dir():
        raise ValueError("Path is not a directory")
    depth_limit = max(0, min(int(max_depth), 4))
    entry_limit = max(1, min(int(max_entries), MAX_TREE_ENTRIES))
    entries: list[dict[str, Any]] = []
    restricted = 0
    scanned = 0
    truncated = False

    def walk(current: Path, current_host_path: str, depth: int) -> None:
        nonlocal restricted, scanned, truncated
        if depth > depth_limit or truncated:
            return
        try:
            children = sorted(current.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
        except OSError:
            return
        for child in children:
            if truncated:
                return
            scanned += 1
            if scanned > MAX_TREE_SCANNED:
                truncated = True
                return
            if not include_hidden and child.name.startswith("."):
                continue
            child_path = f"/{child.name}" if current_host_path == "/" else f"{current_host_path.rstrip('/')}/{child.name}"
            if not is_host_path_allowed(child_path, host_root):
                restricted += 1
                continue
            if len(entries) >= entry_limit:
                truncated = True
                return
            try:
                info = child.lstat()
                kind = _kind(child)
            except OSError:
                continue
            entries.append({
                "path": child_path,
                "name": child.name,
                "depth": depth,
                "type": kind,
                "size": int(info.st_size),
                "mtime": float(info.st_mtime),
            })
            if kind == "directory" and depth < depth_limit:
                walk(child, child_path, depth + 1)

    walk(target, normalized, 0)
    return {
        "path": normalized,
        "exists": True,
        "entries": entries,
        "count": len(entries),
        "max_depth": depth_limit,
        "restricted_entries_hidden": restricted,
        "scanned": min(scanned, MAX_TREE_SCANNED),
        "truncated": truncated,
    }
