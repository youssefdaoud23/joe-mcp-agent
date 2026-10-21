from __future__ import annotations

import hashlib
import io
import os
import re
import uuid
from pathlib import Path
from typing import Any

from src.rich_write import MAX_DOCUMENT_BYTES, MAX_PDF_SOURCE_CHARS, create_pdf_bytes
from src.security import normalize_host_path, safe_host_path

MAX_PDF_INPUT_BYTES = MAX_DOCUMENT_BYTES
MAX_PDF_OUTPUT_BYTES = MAX_DOCUMENT_BYTES
MAX_PDF_PAGES = 1000
MAX_PDF_OPERATIONS = 100
MAX_DELETE_INDEXES = 1000
STAGING_ID_RE = re.compile(r"^[a-f0-9]{32}$")


def _library():
    try:
        from pypdf import PdfReader, PdfWriter  # type: ignore
    except ImportError as exc:
        raise ValueError("PDF page operations require the pypdf runtime dependency") from exc
    return PdfReader, PdfWriter


def _load_reader(path: str, host_root: Path):
    PdfReader, _PdfWriter = _library()
    normalized = normalize_host_path(path)
    if Path(normalized).suffix.lower() != ".pdf":
        raise ValueError("PDF source path must end in .pdf")
    target = safe_host_path(normalized, host_root)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(normalized)
    size = target.stat().st_size
    if size <= 0 or size > MAX_PDF_INPUT_BYTES:
        raise ValueError(f"PDF source must be between 1 and {MAX_PDF_INPUT_BYTES} bytes")
    raw = target.read_bytes()
    try:
        reader = PdfReader(io.BytesIO(raw), strict=False)
    except Exception as exc:
        raise ValueError(f"Unable to parse PDF source: {exc}") from exc
    if bool(getattr(reader, "is_encrypted", False)):
        raise ValueError("Encrypted PDF page operations are not supported")
    try:
        count = len(reader.pages)
    except Exception as exc:
        raise ValueError(f"Unable to enumerate PDF pages: {exc}") from exc
    if count > MAX_PDF_PAGES:
        raise ValueError(f"PDF exceeds {MAX_PDF_PAGES} page limit")
    return reader


def _reader_from_bytes(data: bytes, label: str):
    PdfReader, _PdfWriter = _library()
    if len(data) > MAX_PDF_INPUT_BYTES:
        raise ValueError(f"{label} exceeds PDF size limit")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
    except Exception as exc:
        raise ValueError(f"Unable to parse {label}: {exc}") from exc
    if bool(getattr(reader, "is_encrypted", False)):
        raise ValueError(f"Encrypted {label} is not supported")
    if len(reader.pages) > MAX_PDF_PAGES:
        raise ValueError(f"{label} exceeds {MAX_PDF_PAGES} page limit")
    return reader


def _page_index(value: Any, count: int, *, insertion: bool) -> int:
    if isinstance(value, bool):
        raise ValueError("PDF page index must be an integer")
    try:
        index = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("PDF page index must be an integer") from exc
    if index < 0:
        index = count + index
    upper = count if insertion else count - 1
    if index < 0 or index > upper:
        kind = "insertion" if insertion else "page"
        raise ValueError(f"PDF {kind} index {value} is out of range for {count} page(s)")
    return index


def _metadata(reader: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        metadata = reader.metadata or {}
        for key, value in metadata.items():
            name = str(key or "")
            if name.startswith("/") and value is not None:
                result[name] = str(value)[:4000]
    except Exception:
        return {}
    return result


def build_modified_pdf(path: str, operations: list[dict[str, Any]], host_root: Path) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(operations, list) or not operations:
        raise ValueError("Existing-PDF modification requires a non-empty operations array")
    if len(operations) > MAX_PDF_OPERATIONS:
        raise ValueError(f"PDF operation count exceeds {MAX_PDF_OPERATIONS}")

    base_reader = _load_reader(path, host_root)
    readers: list[Any] = [base_reader]
    pages = list(base_reader.pages)
    original_pages = len(pages)
    applied: list[dict[str, Any]] = []

    for position, raw_operation in enumerate(operations):
        if not isinstance(raw_operation, dict):
            raise ValueError(f"PDF operation {position} must be an object")
        op_type = str(raw_operation.get("type") or "").strip().lower()
        if op_type == "delete":
            raw_indexes = raw_operation.get("pageIndexes")
            if not isinstance(raw_indexes, list) or not raw_indexes:
                raise ValueError("PDF delete operation requires non-empty pageIndexes")
            if len(raw_indexes) > MAX_DELETE_INDEXES:
                raise ValueError("PDF delete pageIndexes exceeds bounded limit")
            normalized = sorted({_page_index(value, len(pages), insertion=False) for value in raw_indexes}, reverse=True)
            for index in normalized:
                del pages[index]
            applied.append({"type": "delete", "deleted": len(normalized)})
        elif op_type == "insert":
            insert_at = _page_index(raw_operation.get("pageIndex"), len(pages), insertion=True)
            has_markdown = "markdown" in raw_operation and raw_operation.get("markdown") is not None
            has_source = bool(str(raw_operation.get("sourcePdfPath") or "").strip())
            if has_markdown == has_source:
                raise ValueError("PDF insert requires exactly one of markdown or sourcePdfPath")
            if has_markdown:
                markdown = raw_operation.get("markdown")
                if not isinstance(markdown, str):
                    raise ValueError("PDF insert markdown must be text")
                if len(markdown) > MAX_PDF_SOURCE_CHARS:
                    raise ValueError("Inserted PDF markdown exceeds bounded input limit")
                inserted_reader = _reader_from_bytes(create_pdf_bytes(markdown)[0], "inserted markdown PDF")
                source_kind = "markdown"
            else:
                source_path = str(raw_operation.get("sourcePdfPath") or "")
                inserted_reader = _load_reader(source_path, host_root)
                source_kind = "pdf"
            readers.append(inserted_reader)
            inserted_pages = list(inserted_reader.pages)
            if len(pages) + len(inserted_pages) > MAX_PDF_PAGES:
                raise ValueError(f"PDF result would exceed {MAX_PDF_PAGES} page limit")
            pages[insert_at:insert_at] = inserted_pages
            applied.append({"type": "insert", "source": source_kind, "inserted": len(inserted_pages), "pageIndex": insert_at})
        else:
            raise ValueError(f"Unsupported PDF operation type: {op_type or '[empty]'}")
        if len(pages) > MAX_PDF_PAGES:
            raise ValueError(f"PDF result would exceed {MAX_PDF_PAGES} page limit")

    _PdfReader, PdfWriter = _library()
    writer = PdfWriter()
    metadata = _metadata(base_reader)
    if metadata:
        try:
            writer.add_metadata(metadata)
        except Exception:
            pass
    for page in pages:
        writer.add_page(page)
    buffer = io.BytesIO()
    try:
        writer.write(buffer)
    except Exception as exc:
        raise ValueError(f"Unable to serialize modified PDF: {exc}") from exc
    output = buffer.getvalue()
    if len(output) <= 0 or len(output) > MAX_PDF_OUTPUT_BYTES:
        raise ValueError(f"Modified PDF exceeds {MAX_PDF_OUTPUT_BYTES} byte limit")

    verification = _reader_from_bytes(output, "generated PDF")
    if len(verification.pages) != len(pages):
        raise ValueError("Generated PDF page-count verification failed")
    return output, {
        "format": "pdf",
        "original_pages": original_pages,
        "pages": len(pages),
        "operations_applied": applied,
        "operation_count": len(applied),
        "bytes_written": len(output),
        "engine": "pypdf",
    }


def stage_pdf_bytes(data: bytes, staging_root: Path) -> dict[str, Any]:
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ValueError("PDF staging payload is empty")
    payload = bytes(data)
    if len(payload) > MAX_PDF_OUTPUT_BYTES:
        raise ValueError("PDF staging payload exceeds size limit")
    staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(staging_root, 0o700)
    token = uuid.uuid4().hex
    if not STAGING_ID_RE.fullmatch(token):
        raise ValueError("Unable to create PDF staging id")
    target = staging_root / f"{token}.pdf"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        target.unlink(missing_ok=True)
        raise
    return {"token": token, "path": target, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
