from __future__ import annotations

import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from src.security import SECRET_NAME_RE, redact_text
from src.workspace_policy import WorkspaceDenied, matches_allowed_glob, workspace_path_protected, workspace_relative_path


IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
MAX_ROWS = 500
MAX_COLUMNS = 100
MAX_CELL_CHARS = 20_000
MAX_QUERY_CHARS = 20_000
DEFAULT_QUERY_MAX_SECONDS = 10.0
DIAGNOSTIC_QUERY_MAX_SECONDS = max(30.0, min(float(os.getenv("JOE_SQLITE_DIAGNOSTIC_MAX_SECONDS", "300")), 900.0))


class SQLiteReadError(RuntimeError):
    pass


def _database(workspace: str, database: str) -> tuple[dict[str, Any], Path, str]:
    profile, candidate, relative = workspace_relative_path(workspace, database, "read")
    section = profile.get("sqlite", {}) if isinstance(profile.get("sqlite"), dict) else {}
    if not bool(section.get("enabled", False)):
        raise WorkspaceDenied(f"SQLite access is disabled for workspace: {workspace}")
    if not matches_allowed_glob(relative, section.get("allowed_globs", [])):
        raise WorkspaceDenied(f"SQLite database is not allow-listed: {relative}")
    if workspace_path_protected(str(candidate)):
        raise WorkspaceDenied("SQLite database is inside a protected workspace path")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(str(candidate))
    return profile, candidate, relative


def _connect(path: Path, max_seconds: float = DEFAULT_QUERY_MAX_SECONDS) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3.0)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    deadline = time.monotonic() + max(0.1, float(max_seconds))
    connection.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
    return connection


def _ident(value: str, label: str) -> str:
    item = str(value or "").strip()
    if not IDENT_RE.fullmatch(item):
        raise SQLiteReadError(f"Invalid SQLite {label}")
    return item


def sqlite_tables(workspace: str, database: str) -> dict[str, Any]:
    profile, path, relative = _database(workspace, database)
    with _connect(path) as con:
        rows = con.execute(
            "SELECT name, type FROM sqlite_schema WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
    return {
        "workspace": profile["name"], "database": relative,
        "objects": [{"name": str(name), "type": str(kind)} for name, kind in rows],
        "count": len(rows),
    }


def sqlite_schema(workspace: str, database: str, table: str = "") -> dict[str, Any]:
    profile, path, relative = _database(workspace, database)
    target = str(table or "").strip()
    with _connect(path) as con:
        if target:
            name = _ident(target, "table name")
            rows = con.execute(
                "SELECT name, type, sql FROM sqlite_schema WHERE name=? AND type IN ('table','view','index','trigger') ORDER BY type, name",
                (name,),
            ).fetchall()
            columns = con.execute(f'PRAGMA table_info("{name}")').fetchall()
        else:
            rows = con.execute(
                "SELECT name, type, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall()
            columns = []
    return {
        "workspace": profile["name"], "database": relative, "table": target or None,
        "schema": [{"name": str(name), "type": str(kind), "sql": redact_text(str(sql or ""), 50_000)} for name, kind, sql in rows[:500]],
        "columns": [
            {"cid": row[0], "name": row[1], "type": row[2], "notnull": bool(row[3]), "default": redact_text(str(row[4]), 4000) if row[4] is not None else None, "pk": bool(row[5])}
            for row in columns[:MAX_COLUMNS]
        ],
    }


def _read_only_query(query: str) -> str:
    text = str(query or "").strip()
    if not text or len(text) > MAX_QUERY_CHARS or "\x00" in text:
        raise SQLiteReadError("SQLite query is empty or too large")
    trimmed = text.rstrip().rstrip(";").strip()
    if ";" in trimmed:
        raise SQLiteReadError("Only one SQLite statement is allowed")
    if re.fullmatch(r"PRAGMA\s+(quick_check|integrity_check)", trimmed, flags=re.IGNORECASE):
        return trimmed
    first = trimmed.split(None, 1)[0].upper() if trimmed else ""
    if first not in {"SELECT", "WITH", "EXPLAIN"}:
        raise SQLiteReadError("Only read-only SELECT, WITH, EXPLAIN, PRAGMA quick_check, or PRAGMA integrity_check queries are allowed")
    return trimmed


def sqlite_query(workspace: str, database: str, query: str, max_rows: int = 100) -> dict[str, Any]:
    profile, path, relative = _database(workspace, database)
    statement = _read_only_query(query)
    diagnostic = bool(re.fullmatch(r"PRAGMA\s+(quick_check|integrity_check)", statement, flags=re.IGNORECASE))
    limit = max(1, min(int(max_rows), MAX_ROWS))
    try:
        with _connect(path, DIAGNOSTIC_QUERY_MAX_SECONDS if diagnostic else DEFAULT_QUERY_MAX_SECONDS) as con:
            cursor = con.execute(statement)
            columns = [str(item[0]) for item in (cursor.description or [])][:MAX_COLUMNS]
            rows = cursor.fetchmany(limit + 1)
    except sqlite3.Error as exc:
        raise SQLiteReadError(f"SQLite query failed: {exc}") from exc
    truncated = len(rows) > limit
    sensitive_indexes = {index for index, name in enumerate(columns) if SECRET_NAME_RE.search(name)}
    output_rows: list[list[Any]] = []
    for row in rows[:limit]:
        converted: list[Any] = []
        for index, value in enumerate(row[:MAX_COLUMNS]):
            if index in sensitive_indexes:
                converted.append("[REDACTED]")
            elif isinstance(value, bytes):
                converted.append(f"[BLOB {len(value)} bytes]")
            elif isinstance(value, str):
                converted.append(redact_text(value, MAX_CELL_CHARS))
            else:
                converted.append(value)
        output_rows.append(converted)
    return {
        "workspace": profile["name"], "database": relative, "columns": columns,
        "rows": output_rows, "row_count": len(output_rows), "truncated": truncated,
    }


def sqlite_table_stats(workspace: str, database: str, table: str, timestamp_column: str = "") -> dict[str, Any]:
    profile, path, relative = _database(workspace, database)
    table_name = _ident(table, "table name")
    timestamp = _ident(timestamp_column, "timestamp column") if timestamp_column else ""
    with _connect(path) as con:
        exists = con.execute(
            "SELECT 1 FROM sqlite_schema WHERE name=? AND type IN ('table','view')", (table_name,)
        ).fetchone()
        if not exists:
            raise SQLiteReadError(f"SQLite table or view not found: {table_name}")
        count = int(con.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()[0])
        minimum = maximum = None
        if timestamp:
            names = {str(row[1]) for row in con.execute(f'PRAGMA table_info("{table_name}")').fetchall()}
            if timestamp not in names:
                raise SQLiteReadError(f"SQLite column not found: {timestamp}")
            minimum, maximum = con.execute(
                f'SELECT MIN("{timestamp}"), MAX("{timestamp}") FROM "{table_name}"'
            ).fetchone()
    return {
        "workspace": profile["name"], "database": relative, "table": table_name,
        "row_count": count, "timestamp_column": timestamp or None,
        "min_timestamp": minimum, "max_timestamp": maximum,
    }
