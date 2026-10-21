from __future__ import annotations

import html
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from src.rich_file import _cell_coords, _range_bounds, _xlsx_sheet_map, _xml_local
from src.write_policy import safe_write_path

MAX_DOCUMENT_BYTES = 50 * 1024 * 1024
MAX_DOC_REPLACEMENTS = 1000
MAX_PDF_SOURCE_CHARS = 500_000
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

ET.register_namespace("w", W_NS)
ET.register_namespace("", MAIN_NS)
ET.register_namespace("r", REL_NS)


def _atomic_bytes(path: Path, data: bytes) -> None:
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("Generated document exceeds size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.joe.tmp")
    tmp.write_bytes(data)
    tmp.chmod(0o600)
    tmp.replace(path)


def _zip_bytes(items: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in items.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _word_paragraph(text: str, style: str = "") -> str:
    style_xml = f'<w:pPr><w:pStyle w:val="{html.escape(style)}"/></w:pPr>' if style else ""
    safe = html.escape(text)
    return f'<w:p>{style_xml}<w:r><w:t xml:space="preserve">{safe}</w:t></w:r></w:p>'


def _markdown_paragraphs(markdown: str) -> list[str]:
    paragraphs: list[str] = []
    for raw in str(markdown or "").splitlines():
        line = raw.rstrip()
        if not line:
            paragraphs.append(_word_paragraph("")); continue
        if line.startswith("### "):
            paragraphs.append(_word_paragraph(line[4:], "Heading3")); continue
        if line.startswith("## "):
            paragraphs.append(_word_paragraph(line[3:], "Heading2")); continue
        if line.startswith("# "):
            paragraphs.append(_word_paragraph(line[2:], "Heading1")); continue
        if line.startswith(("- ", "* ")):
            paragraphs.append(_word_paragraph("• " + line[2:])); continue
        paragraphs.append(_word_paragraph(line))
    return paragraphs


def create_docx(path: str, markdown: str) -> dict[str, Any]:
    target = safe_write_path(path)
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{W_NS}"><w:body>'
        + "".join(_markdown_paragraphs(markdown))
        + '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>'
        + '</w:body></w:document>'
    ).encode("utf-8")
    styles = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:styles xmlns:w="{W_NS}">'
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="32"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="28"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="24"/></w:rPr></w:style>'
        '</w:styles>'
    ).encode("utf-8")
    items = {
        "[Content_Types].xml": b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>',
        "_rels/.rels": b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": document,
        "word/styles.xml": styles,
        "word/_rels/document.xml.rels": b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>',
    }
    existed = target.exists()
    data = _zip_bytes(items)
    _atomic_bytes(target, data)
    return {"path": path, "format": "docx", "created": not existed, "bytes_written": len(data), "size": target.stat().st_size}


def edit_docx_xml(path: str, old_text: str, new_text: str, expected_replacements: int = 1) -> dict[str, Any]:
    target = safe_write_path(path, must_exist=True)
    if target.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("DOCX exceeds editable size limit")
    expected = int(expected_replacements)
    if expected < 1 or expected > MAX_DOC_REPLACEMENTS:
        raise ValueError("expected_replacements is outside allowed range")
    with zipfile.ZipFile(target, "r") as archive:
        items = {info.filename: archive.read(info.filename) for info in archive.infolist() if not info.is_dir()}
    candidates = [name for name in items if name == "word/document.xml" or re.fullmatch(r"word/(header|footer)[0-9]+\.xml", name)]
    rendered: dict[str, str] = {}
    actual = 0
    for name in candidates:
        try:
            root = ET.fromstring(items[name]); ET.indent(root, space="  "); text = ET.tostring(root, encoding="unicode")
        except ET.ParseError:
            text = items[name].decode("utf-8", errors="replace")
        rendered[name] = text
        actual += text.count(old_text)
    if actual != expected:
        raise ValueError(f"Expected {expected} replacement(s), found {actual}")
    changed = 0
    for name, text in rendered.items():
        count = text.count(old_text)
        if not count:
            continue
        updated = text.replace(old_text, new_text)
        try:
            root = ET.fromstring(updated)
        except ET.ParseError as exc:
            raise ValueError(f"Edited DOCX XML is invalid in {name}: {exc}") from exc
        items[name] = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        changed += count
    data = _zip_bytes(items)
    _atomic_bytes(target, data)
    return {"path": path, "format": "docx", "replacements": changed, "size": target.stat().st_size}


def _cell_ref(row: int, col: int) -> str:
    letters = ""
    value = col
    while value:
        value, remainder = divmod(value - 1, 26)
        letters = chr(65 + remainder) + letters
    return f"{letters}{row}"


def _sheet_xml(rows: list[list[Any]]) -> bytes:
    root = ET.Element(f"{{{MAIN_NS}}}worksheet")
    data = ET.SubElement(root, f"{{{MAIN_NS}}}sheetData")
    for row_index, values in enumerate(rows, 1):
        row = ET.SubElement(data, f"{{{MAIN_NS}}}row", {"r": str(row_index)})
        for col_index, value in enumerate(values, 1):
            if value is None:
                continue
            ref = _cell_ref(row_index, col_index)
            if isinstance(value, bool):
                cell = ET.SubElement(row, f"{{{MAIN_NS}}}c", {"r": ref, "t": "b"}); ET.SubElement(cell, f"{{{MAIN_NS}}}v").text = "1" if value else "0"
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                cell = ET.SubElement(row, f"{{{MAIN_NS}}}c", {"r": ref}); ET.SubElement(cell, f"{{{MAIN_NS}}}v").text = str(value)
            else:
                cell = ET.SubElement(row, f"{{{MAIN_NS}}}c", {"r": ref, "t": "inlineStr"}); inline = ET.SubElement(cell, f"{{{MAIN_NS}}}is"); ET.SubElement(inline, f"{{{MAIN_NS}}}t").text = str(value)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def create_xlsx(path: str, content: str) -> dict[str, Any]:
    target = safe_write_path(path)
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("Excel content must be JSON 2D array or object of sheet names to 2D arrays") from exc
    if isinstance(payload, list):
        sheets = {"Sheet1": payload}
    elif isinstance(payload, dict):
        sheets = payload
    else:
        raise ValueError("Excel content must be JSON 2D array or object")
    normalized: list[tuple[str, list[list[Any]]]] = []
    total_cells = 0
    for name, rows in sheets.items():
        title = str(name or "Sheet").strip()[:31]
        if not title or any(char in title for char in "[]:*?/\\"):
            raise ValueError("Invalid Excel sheet name")
        if not isinstance(rows, list) or any(not isinstance(row, list) for row in rows):
            raise ValueError("Each Excel sheet must be a 2D array")
        total_cells += sum(len(row) for row in rows)
        if total_cells > 100_000:
            raise ValueError("Excel creation exceeds 100000 cell limit")
        normalized.append((title, rows))
    if not normalized:
        normalized = [("Sheet1", [])]
    workbook = ET.Element(f"{{{MAIN_NS}}}workbook")
    sheet_container = ET.SubElement(workbook, f"{{{MAIN_NS}}}sheets")
    rel_root = ET.Element("Relationships", xmlns="http://schemas.openxmlformats.org/package/2006/relationships")
    content_types = ['<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>']
    items: dict[str, bytes] = {
        "_rels/.rels": b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    }
    for index, (name, rows) in enumerate(normalized, 1):
        ET.SubElement(sheet_container, f"{{{MAIN_NS}}}sheet", {"name": name, "sheetId": str(index), f"{{{REL_NS}}}id": f"rId{index}"})
        ET.SubElement(rel_root, "Relationship", {"Id": f"rId{index}", "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet", "Target": f"worksheets/sheet{index}.xml"})
        items[f"xl/worksheets/sheet{index}.xml"] = _sheet_xml(rows)
        content_types.append(f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    content_types.append("</Types>")
    items["[Content_Types].xml"] = "".join(content_types).encode("utf-8")
    items["xl/workbook.xml"] = ET.tostring(workbook, encoding="utf-8", xml_declaration=True)
    items["xl/_rels/workbook.xml.rels"] = ET.tostring(rel_root, encoding="utf-8", xml_declaration=True)
    data = _zip_bytes(items)
    existed = target.exists()
    _atomic_bytes(target, data)
    return {"path": path, "format": "xlsx", "created": not existed, "sheets": [name for name, _ in normalized], "bytes_written": len(data), "size": target.stat().st_size}


def edit_xlsx_range(path: str, cell_range: str, values: list[list[Any]]) -> dict[str, Any]:
    target = safe_write_path(path, must_exist=True)
    if target.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("XLSX exceeds editable size limit")
    range_text = str(cell_range or "").strip()
    if "!" in range_text:
        sheet_name, range_only = range_text.split("!", 1)
        sheet_name = sheet_name.strip("'")
    else:
        sheet_name, range_only = "", range_text
    bounds = _range_bounds(range_only)
    if bounds is None:
        raise ValueError("Spreadsheet range is required")
    r1, c1, r2, c2 = bounds
    expected_rows = r2 - r1 + 1; expected_cols = c2 - c1 + 1
    if not isinstance(values, list) or len(values) != expected_rows or any(not isinstance(row, list) or len(row) != expected_cols for row in values):
        raise ValueError(f"Spreadsheet values must be exactly {expected_rows}x{expected_cols}")
    with zipfile.ZipFile(target, "r") as archive:
        items = {info.filename: archive.read(info.filename) for info in archive.infolist() if not info.is_dir()}
        sheets = _xlsx_sheet_map(archive)
    is_macro = target.suffix.lower() == ".xlsm"
    macro_before = items.get("xl/vbaProject.bin") if is_macro else None
    selected = next((item for item in sheets if item[0] == sheet_name), None) if sheet_name else (sheets[0] if sheets else None)
    if selected is None:
        raise ValueError("Requested spreadsheet sheet was not found")
    name, sheet_path = selected
    root = ET.fromstring(items[sheet_path])
    data = next((node for node in root.iter() if _xml_local(node.tag) == "sheetData"), None)
    if data is None:
        data = ET.SubElement(root, f"{{{MAIN_NS}}}sheetData")
    row_map: dict[int, ET.Element] = {}
    cell_map: dict[str, ET.Element] = {}
    for row in list(data):
        if _xml_local(row.tag) != "row":
            continue
        try:
            row_num = int(row.attrib.get("r", "0")); row_map[row_num] = row
        except ValueError:
            continue
        for cell in list(row):
            if _xml_local(cell.tag) == "c" and cell.attrib.get("r"):
                cell_map[str(cell.attrib["r"])] = cell
    updated = 0
    for row_offset, row_values in enumerate(values):
        row_num = r1 + row_offset
        row_node = row_map.get(row_num)
        if row_node is None:
            row_node = ET.SubElement(data, f"{{{MAIN_NS}}}row", {"r": str(row_num)}); row_map[row_num] = row_node
        for col_offset, value in enumerate(row_values):
            col_num = c1 + col_offset; ref = _cell_ref(row_num, col_num)
            cell = cell_map.get(ref)
            style = cell.attrib.get("s") if cell is not None else None
            if cell is not None:
                row_node.remove(cell)
            attrs = {"r": ref}
            if style is not None:
                attrs["s"] = style
            if isinstance(value, bool):
                attrs["t"] = "b"; cell = ET.SubElement(row_node, f"{{{MAIN_NS}}}c", attrs); ET.SubElement(cell, f"{{{MAIN_NS}}}v").text = "1" if value else "0"
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                cell = ET.SubElement(row_node, f"{{{MAIN_NS}}}c", attrs); ET.SubElement(cell, f"{{{MAIN_NS}}}v").text = str(value)
            elif value is None:
                cell = ET.SubElement(row_node, f"{{{MAIN_NS}}}c", attrs)
            else:
                attrs["t"] = "inlineStr"; cell = ET.SubElement(row_node, f"{{{MAIN_NS}}}c", attrs); inline = ET.SubElement(cell, f"{{{MAIN_NS}}}is"); ET.SubElement(inline, f"{{{MAIN_NS}}}t").text = str(value)
            cell_map[ref] = cell; updated += 1
        row_node[:] = sorted(list(row_node), key=lambda cell: _cell_coords(str(cell.attrib.get("r") or "A1"))[1])
    data[:] = sorted(list(data), key=lambda row: int(row.attrib.get("r", "0") or 0))
    items[sheet_path] = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    if is_macro and macro_before is not None and items.get("xl/vbaProject.bin") != macro_before:
        raise ValueError("XLSM macro project changed unexpectedly; edit was blocked")
    packed = _zip_bytes(items); _atomic_bytes(target, packed)
    return {"path": path, "format": "xlsm" if is_macro else "xlsx", "sheet": name, "range": range_only, "cells_updated": updated, "size": target.stat().st_size, "macros_present": bool(macro_before) if is_macro else False, "macros_preserved": bool(macro_before) if is_macro else False}


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_text(text: str, width: int) -> list[str]:
    words = str(text or "").split()
    if not words:
        return [""]
    lines: list[str] = []; current = words[0]
    for word in words[1:]:
        candidate = current + " " + word
        if len(candidate) <= width:
            current = candidate
        else:
            lines.append(current); current = word
    lines.append(current)
    return lines


def create_pdf_bytes(markdown: str) -> tuple[bytes, int]:
    source = str(markdown or "")
    if len(source) > MAX_PDF_SOURCE_CHARS:
        raise ValueError("PDF source exceeds bounded input limit")
    page_marker = '<div style="page-break-before: always;"></div>'
    source_pages = source.split(page_marker)
    pages: list[list[tuple[int, str]]] = []
    for chunk in source_pages:
        current: list[tuple[int, str]] = []
        for raw in chunk.splitlines():
            line = raw.rstrip()
            size = 11; text = line
            if line.startswith("### "): size = 14; text = line[4:]
            elif line.startswith("## "): size = 16; text = line[3:]
            elif line.startswith("# "): size = 20; text = line[2:]
            elif line.startswith(("- ", "* ")): text = "• " + line[2:]
            for wrapped in _wrap_text(text, max(24, int(95 * 11 / size))):
                current.append((size, wrapped))
                if len(current) >= 48:
                    pages.append(current); current = []
        pages.append(current)
    pages = [page for page in pages if page] or [[(11, "")]]
    objects: list[bytes] = []
    def add(body: bytes) -> int:
        objects.append(body); return len(objects)
    font_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    pending_pages: list[tuple[int, int]] = []
    for page in pages:
        commands = [b"BT", b"1 0 0 1 54 760 Tm"]
        first = True
        for size, text in page:
            if not first:
                commands.append(b"0 -16 Td")
            commands.append(f"/F1 {size} Tf".encode("ascii"))
            commands.append(f"({_pdf_escape(text)}) Tj".encode("latin-1", errors="replace"))
            first = False
        commands.append(b"ET")
        stream = b"\n".join(commands)
        content_id = add(f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream")
        page_id = add(b"")
        page_ids.append(page_id); pending_pages.append((page_id, content_id))
    pages_id = add(b"")
    for page_id, content_id in pending_pages:
        objects[page_id - 1] = f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode("ascii")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")
    catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii"))
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, body in enumerate(objects, 1):
        offsets.append(len(output)); output.extend(f"{index} 0 obj\n".encode("ascii")); output.extend(body); output.extend(b"\nendobj\n")
    xref = len(output); output.extend(f"xref\n0 {len(objects)+1}\n".encode("ascii")); output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]: output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer\n<< /Size {len(objects)+1} /Root {catalog_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    data = bytes(output)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("Generated PDF exceeds size limit")
    return data, len(page_ids)


def create_pdf(path: str, markdown: str) -> dict[str, Any]:
    target = safe_write_path(path)
    data, page_count = create_pdf_bytes(markdown)
    existed = target.exists()
    _atomic_bytes(target, data)
    return {"path": path, "format": "pdf", "created": not existed, "pages": page_count, "bytes_written": len(data), "size": target.stat().st_size, "renderer": "joe-basic-markdown"}
