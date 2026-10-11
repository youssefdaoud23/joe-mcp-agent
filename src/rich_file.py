from __future__ import annotations

import base64
import json
import mimetypes
import re
import struct
import zlib
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from src.file_inspect import inspect_file
from src.read_tools import read_text_page
from src.security import normalize_host_path, safe_host_path

MAX_BINARY_PREVIEW_BYTES = 1_000_000
MAX_RICH_FILE_BYTES = 50 * 1024 * 1024
MAX_DOC_XML_BYTES = 4 * 1024 * 1024
MAX_SHEET_CELLS = 20_000
MAX_PDF_TEXT_CHARS = 200_000
CELL_RE = re.compile(r"^([A-Za-z]+)([1-9][0-9]*)$")
RANGE_RE = re.compile(r"^([A-Za-z]+[1-9][0-9]*)(?::([A-Za-z]+[1-9][0-9]*))?$")


def _column_number(value: str) -> int:
    result = 0
    for char in value.upper():
        if not ("A" <= char <= "Z"):
            raise ValueError("Invalid spreadsheet column")
        result = result * 26 + ord(char) - 64
    return result


def _cell_coords(value: str) -> tuple[int, int]:
    match = CELL_RE.fullmatch(str(value or "").strip())
    if not match:
        raise ValueError("Invalid cell reference")
    return int(match.group(2)), _column_number(match.group(1))


def _range_bounds(value: str) -> tuple[int, int, int, int] | None:
    text = str(value or "").strip()
    if not text:
        return None
    match = RANGE_RE.fullmatch(text)
    if not match:
        raise ValueError("Spreadsheet range must look like A1:D100")
    r1, c1 = _cell_coords(match.group(1))
    r2, c2 = _cell_coords(match.group(2) or match.group(1))
    if r2 < r1 or c2 < c1:
        raise ValueError("Spreadsheet range end must not precede the start")
    if (r2 - r1 + 1) * (c2 - c1 + 1) > MAX_SHEET_CELLS:
        raise ValueError(f"Spreadsheet range exceeds {MAX_SHEET_CELLS} cell limit")
    return r1, c1, r2, c2


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _docx_outline(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as archive:
        info = archive.getinfo("word/document.xml")
        if info.file_size > MAX_DOC_XML_BYTES:
            raise ValueError("DOCX document XML exceeds bounded read limit")
        root = ET.fromstring(archive.read("word/document.xml"))
        body = next((node for node in root.iter() if _xml_local(node.tag) == "body"), None)
        elements: list[dict[str, Any]] = []
        if body is None:
            return {"format": "docx", "elements": [], "count": 0}
        for index, child in enumerate(list(body)):
            kind = _xml_local(child.tag)
            if kind == "p":
                text = "".join(node.text or "" for node in child.iter() if _xml_local(node.tag) == "t")
                style = ""
                for node in child.iter():
                    if _xml_local(node.tag) == "pStyle":
                        style = next((str(v) for k, v in node.attrib.items() if _xml_local(k) == "val"), "")
                        break
                if text or style:
                    elements.append({"index": index, "type": "paragraph", "text": text[:20_000], "style": style[:120]})
            elif kind == "tbl":
                rows: list[list[str]] = []
                for tr in child.iter():
                    if _xml_local(tr.tag) != "tr":
                        continue
                    cells: list[str] = []
                    for tc in list(tr):
                        if _xml_local(tc.tag) != "tc":
                            continue
                        text = " ".join((node.text or "") for node in tc.iter() if _xml_local(node.tag) == "t").strip()
                        cells.append(text[:5000])
                    if cells:
                        rows.append(cells[:50])
                    if len(rows) >= 200:
                        break
                elements.append({"index": index, "type": "table", "rows": rows, "rows_truncated": len(rows) >= 200})
            if len(elements) >= 1000:
                break
        return {"format": "docx", "elements": elements, "count": len(elements), "truncated": len(elements) >= 1000}


def _docx_xml(path: Path, offset: int, length: int) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as archive:
        info = archive.getinfo("word/document.xml")
        if info.file_size > MAX_DOC_XML_BYTES:
            raise ValueError("DOCX document XML exceeds bounded read limit")
        raw = archive.read("word/document.xml")
    try:
        root = ET.fromstring(raw)
        ET.indent(root, space="  ")
        text = ET.tostring(root, encoding="unicode")
    except ET.ParseError:
        text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    start = max(0, int(offset))
    count = max(1, min(int(length), 1000))
    selected = lines[start:start + count]
    return {
        "format": "docx-xml",
        "offset": start,
        "lines_returned": len(selected),
        "total_lines": len(lines),
        "has_more": start + len(selected) < len(lines),
        "content": "\n".join(selected),
    }


def _xlsx_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    info = archive.getinfo("xl/sharedStrings.xml")
    if info.file_size > MAX_DOC_XML_BYTES:
        raise ValueError("XLSX shared strings exceed bounded read limit")
    root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    values: list[str] = []
    for si in root.iter():
        if _xml_local(si.tag) != "si":
            continue
        text = "".join(node.text or "" for node in si.iter() if _xml_local(node.tag) == "t")
        values.append(text)
        if len(values) >= 200_000:
            break
    return values


def _xlsx_sheet_map(archive: zipfile.ZipFile) -> list[tuple[str, str]]:
    workbook = ET.fromstring(archive.read("xl/workbook.xml"))
    rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    rel_map: dict[str, str] = {}
    for rel in rels.iter():
        if _xml_local(rel.tag) != "Relationship":
            continue
        rid = str(rel.attrib.get("Id") or "")
        target = str(rel.attrib.get("Target") or "")
        if rid and target:
            if not target.startswith("/"):
                target = "xl/" + target.lstrip("/")
            else:
                target = target.lstrip("/")
            rel_map[rid] = target
    sheets: list[tuple[str, str]] = []
    for node in workbook.iter():
        if _xml_local(node.tag) != "sheet":
            continue
        name = str(node.attrib.get("name") or "")
        rid = next((str(v) for k, v in node.attrib.items() if _xml_local(k) == "id"), "")
        target = rel_map.get(rid, "")
        if name and target:
            sheets.append((name, target))
    return sheets


def _xlsx_value(cell: ET.Element, shared: list[str]) -> Any:
    cell_type = str(cell.attrib.get("t") or "")
    inline = next((node for node in cell.iter() if _xml_local(node.tag) == "is"), None)
    if inline is not None:
        return "".join(node.text or "" for node in inline.iter() if _xml_local(node.tag) == "t")
    value_node = next((node for node in cell if _xml_local(node.tag) == "v"), None)
    if value_node is None or value_node.text is None:
        return None
    raw = value_node.text
    if cell_type == "s":
        try:
            idx = int(raw)
            return shared[idx] if 0 <= idx < len(shared) else raw
        except ValueError:
            return raw
    if cell_type in {"str", "e"}:
        return raw
    if cell_type == "b":
        return raw == "1"
    try:
        number = float(raw)
        return int(number) if number.is_integer() else number
    except ValueError:
        return raw


def _xlsx_rows(path: Path, sheet: str, cell_range: str, offset: int, length: int) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as archive:
        sheets = _xlsx_sheet_map(archive)
        if not sheets:
            return {"format": "xlsx", "sheets": [], "rows": []}
        selected: tuple[str, str] | None = None
        wanted = str(sheet or "").strip()
        if wanted:
            if wanted.isdigit():
                index = int(wanted)
                if 0 <= index < len(sheets):
                    selected = sheets[index]
            else:
                selected = next((item for item in sheets if item[0] == wanted), None)
            if selected is None:
                raise ValueError("Requested spreadsheet sheet was not found")
        else:
            selected = sheets[0]
        name, target = selected
        info = archive.getinfo(target)
        if info.file_size > 20 * 1024 * 1024:
            raise ValueError("Spreadsheet sheet exceeds bounded read limit")
        shared = _xlsx_shared_strings(archive)
        root = ET.fromstring(archive.read(target))
        bounds = _range_bounds(cell_range)
        cells: dict[tuple[int, int], Any] = {}
        max_row = max_col = 0
        for cell in root.iter():
            if _xml_local(cell.tag) != "c":
                continue
            ref = str(cell.attrib.get("r") or "")
            match = CELL_RE.fullmatch(ref)
            if not match:
                continue
            row = int(match.group(2)); col = _column_number(match.group(1))
            if bounds and not (bounds[0] <= row <= bounds[2] and bounds[1] <= col <= bounds[3]):
                continue
            cells[(row, col)] = _xlsx_value(cell, shared)
            max_row = max(max_row, row); max_col = max(max_col, col)
        if bounds:
            row_start, col_start, row_end, col_end = bounds
        else:
            row_start = max(1, int(offset) + 1)
            row_end = min(max_row or row_start, row_start + max(1, min(int(length), 1000)) - 1)
            col_start = 1
            col_end = min(max_col or 1, 200)
            if (row_end - row_start + 1) * (col_end - col_start + 1) > MAX_SHEET_CELLS:
                row_end = row_start + max(0, MAX_SHEET_CELLS // max(1, col_end - col_start + 1) - 1)
        rows = [[cells.get((row, col)) for col in range(col_start, col_end + 1)] for row in range(row_start, row_end + 1)]
        return {
            "format": "xlsx",
            "sheet": name,
            "sheet_index": sheets.index(selected),
            "sheets": [item[0] for item in sheets],
            "range": cell_range or f"rows {row_start}:{row_end}",
            "rows": rows,
            "row_count": len(rows),
            "column_count": max((len(row) for row in rows), default=0),
        }


def _pdf_unescape(value: bytes) -> str:
    output = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char != 92:
            output.append(char); index += 1; continue
        index += 1
        if index >= len(value):
            break
        char = value[index]
        mapping = {110: 10, 114: 13, 116: 9, 98: 8, 102: 12, 40: 40, 41: 41, 92: 92}
        if char in mapping:
            output.append(mapping[char]); index += 1; continue
        if 48 <= char <= 55:
            digits = bytes([char]); index += 1
            while index < len(value) and len(digits) < 3 and 48 <= value[index] <= 55:
                digits += bytes([value[index]]); index += 1
            output.append(int(digits, 8) & 0xFF); continue
        if char in {10, 13}:
            if char == 13 and index + 1 < len(value) and value[index + 1] == 10:
                index += 1
            index += 1; continue
        output.append(char); index += 1
    return output.decode("latin-1", errors="replace")


def _pdf_stream_text(data: bytes) -> str:
    chunks: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, flags=re.S):
        stream = match.group(1)
        header = data[max(0, match.start() - 500):match.start()]
        if b"/FlateDecode" in header:
            try:
                stream = zlib.decompress(stream)
            except zlib.error:
                continue
        for token in re.finditer(rb"\((?:\\.|[^\\)])*\)\s*Tj|\[(.*?)\]\s*TJ", stream, flags=re.S):
            whole = token.group(0)
            if whole.startswith(b"("):
                inner = whole[1:whole.rfind(b")")]
                chunks.append(_pdf_unescape(inner))
            else:
                array = token.group(1) or b""
                pieces = [_pdf_unescape(part) for part in re.findall(rb"\((?:\\.|[^\\)])*\)", array)]
                if pieces:
                    chunks.append("".join(piece[1:-1] if piece.startswith("(") and piece.endswith(")") else piece for piece in pieces))
            if sum(len(value) for value in chunks) >= MAX_PDF_TEXT_CHARS:
                break
        if sum(len(value) for value in chunks) >= MAX_PDF_TEXT_CHARS:
            break
    return "\n".join(value.strip() for value in chunks if value.strip())[:MAX_PDF_TEXT_CHARS]


def read_rich_file(
    path: str,
    host_root: Path,
    offset: int = 0,
    length: int = 1000,
    sheet: str = "",
    cell_range: str = "",
    raw_xml: bool = False,
) -> dict[str, Any]:
    normalized = normalize_host_path(path)
    target = safe_host_path(normalized, host_root)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(normalized)
    size = target.stat().st_size
    if size > MAX_RICH_FILE_BYTES:
        raise ValueError(f"Rich file read is limited to {MAX_RICH_FILE_BYTES} bytes")
    suffix = target.suffix.lower()
    mime, _ = mimetypes.guess_type(target.name)
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        if size > MAX_BINARY_PREVIEW_BYTES:
            return inspect_file(normalized, host_root) | {"content_omitted": "image exceeds bounded inline preview limit"}
        raw = target.read_bytes()
        return inspect_file(normalized, host_root) | {
            "encoding": "base64",
            "data": base64.b64encode(raw).decode("ascii"),
            "data_uri_prefix": f"data:{mime or 'application/octet-stream'};base64,",
        }
    if suffix == ".docx":
        return _docx_xml(target, offset, length) if raw_xml or int(offset) > 0 else _docx_outline(target)
    if suffix in {".xlsx", ".xlsm"}:
        return _xlsx_rows(target, sheet, cell_range, offset, length)
    if suffix == ".xls":
        raise ValueError("Legacy .xls binary workbooks are not supported safely; convert to .xlsx first")
    if suffix == ".pdf":
        raw = target.read_bytes()
        text = _pdf_stream_text(raw)
        lines = text.splitlines()
        start = max(0, int(offset)); count = max(1, min(int(length), 1000))
        return inspect_file(normalized, host_root) | {
            "format": "pdf",
            "text_extraction": "best_effort",
            "offset": start,
            "lines_returned": len(lines[start:start + count]),
            "total_lines": len(lines),
            "has_more": start + count < len(lines),
            "content": "\n".join(lines[start:start + count]),
        }
    return read_text_page(normalized, host_root, offset, length, 1_000_000)


def rich_file_info(path: str, host_root: Path) -> dict[str, Any]:
    info = inspect_file(path, host_root)
    normalized = normalize_host_path(path)
    target = safe_host_path(normalized, host_root)
    if not target.exists() or not target.is_file():
        return info
    suffix = target.suffix.lower()
    if suffix in {".xlsx", ".xlsm"}:
        try:
            with zipfile.ZipFile(target, "r") as archive:
                sheet_rows: list[dict[str, Any]] = []
                for name, sheet_path in _xlsx_sheet_map(archive)[:100]:
                    row_count = col_count = 0
                    try:
                        sheet_info = archive.getinfo(sheet_path)
                        if sheet_info.file_size <= 20 * 1024 * 1024:
                            root = ET.fromstring(archive.read(sheet_path))
                            for cell in root.iter():
                                if _xml_local(cell.tag) != "c":
                                    continue
                                ref = str(cell.attrib.get("r") or "")
                                match = CELL_RE.fullmatch(ref)
                                if not match:
                                    continue
                                row_count = max(row_count, int(match.group(2)))
                                col_count = max(col_count, _column_number(match.group(1)))
                    except (KeyError, ET.ParseError, OSError, ValueError):
                        pass
                    sheet_rows.append({"name": name, "rowCount": row_count, "colCount": col_count})
                info["sheets"] = sheet_rows
        except (zipfile.BadZipFile, KeyError, ET.ParseError, OSError):
            pass
    if (info.get("mime") or "").startswith("text/") or suffix in {".md", ".py", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".log", ".sh", ".js", ".ts", ".css", ".html", ".xml", ".csv", ".sql"}:
        try:
            with target.open("rb") as handle:
                raw = handle.read(min(target.stat().st_size, 4 * 1024 * 1024))
            text = raw.decode("utf-8")
            lines = text.splitlines()
            info["line_count"] = len(lines)
            info["last_line"] = len(lines) - 1 if lines else -1
            info["append_position"] = len(lines)
            info["line_count_truncated"] = target.stat().st_size > len(raw)
        except (OSError, UnicodeDecodeError):
            pass
    return info


def read_multiple_rich_files(
    paths: list[str],
    host_root: Path,
    offset: int = 0,
    length: int = 200,
    max_files: int = 20,
) -> dict[str, Any]:
    if not isinstance(paths, list):
        raise ValueError("paths must be a list")
    selected = [str(path) for path in paths[:max(1, min(int(max_files), 20))]]
    files: list[dict[str, Any]] = []
    for path in selected:
        try:
            result = read_rich_file(path, host_root, offset, length)
            files.append({"path": path, "ok": True, "result": result})
        except Exception as exc:
            files.append({"path": path, "ok": False, "error": str(exc)[:500]})
    return {"files": files, "count": len(files), "requested": len(paths), "truncated": len(paths) > len(selected)}
