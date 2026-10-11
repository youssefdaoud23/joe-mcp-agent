from __future__ import annotations

import fnmatch
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.search_tools import MAX_CONTENT_FILE_BYTES, _limits, _search_prefix_denied, _walk
from src.security import normalize_host_path, redact_text, safe_host_path

SEARCH_RETENTION_SECONDS = 300
MAX_SESSIONS = 50


@dataclass
class SearchSession:
    id: str
    search_type: str
    root: str
    pattern: str
    created_at: float
    state: str = "running"
    results: list[dict[str, Any]] = field(default_factory=list)
    scanned_entries: int = 0
    files_examined: int = 0
    error: str | None = None
    completed_at: float | None = None
    stop_event: threading.Event = field(default_factory=threading.Event, repr=False)


class SearchManager:
    def __init__(self, host_root: Path) -> None:
        self.host_root = host_root
        self._lock = threading.Lock()
        self._sessions: dict[str, SearchSession] = {}

    def _cleanup(self) -> None:
        cutoff = time.time() - SEARCH_RETENTION_SECONDS
        with self._lock:
            stale = [sid for sid, session in self._sessions.items() if session.completed_at and session.completed_at < cutoff]
            for sid in stale:
                self._sessions.pop(sid, None)

    def start(
        self,
        root: str,
        pattern: str,
        search_type: str = "files",
        file_glob: str = "*",
        max_results: int = 500,
        max_depth: int = 8,
        max_scanned: int = 10_000,
        case_sensitive: bool = False,
        include_hidden: bool = False,
        context_lines: int = 0,
        early_termination: bool = False,
        literal_search: bool | None = None,
    ) -> dict[str, Any]:
        self._cleanup()
        kind = str(search_type or "files").strip().lower()
        if kind not in {"files", "content"}:
            raise ValueError("search_type must be 'files' or 'content'")
        if not pattern or len(pattern) > 512:
            raise ValueError("pattern must contain 1 to 512 characters")
        if not file_glob or len(file_glob) > 512:
            raise ValueError("file_glob must contain 1 to 512 characters")
        effective_literal = bool(literal_search) if literal_search is not None else kind == "content"
        if kind == "content" and not effective_literal:
            try:
                re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"Invalid content-search regular expression: {exc}") from exc
        result_limit, depth_limit, scan_limit = _limits(max_results, max_depth, max_scanned)
        normalized_root = normalize_host_path(root)
        if _search_prefix_denied(normalized_root):
            raise PermissionError(f"Search root is restricted: {normalized_root}")
        target = safe_host_path(normalized_root, self.host_root)
        if not target.exists() or not target.is_dir():
            raise FileNotFoundError(normalized_root)

        with self._lock:
            if len(self._sessions) >= MAX_SESSIONS:
                raise RuntimeError("too many retained search sessions")
            session = SearchSession(
                id=uuid.uuid4().hex,
                search_type=kind,
                root=normalized_root,
                pattern=pattern,
                created_at=time.time(),
            )
            self._sessions[session.id] = session

        context = max(0, min(int(context_lines), 20))
        thread = threading.Thread(
            target=self._worker,
            args=(
                session,
                file_glob,
                result_limit,
                depth_limit,
                scan_limit,
                case_sensitive,
                include_hidden,
                context,
                bool(early_termination),
                effective_literal,
            ),
            daemon=True,
            name=f"joe-search-{session.id[:8]}",
        )
        thread.start()
        return self._summary(session)

    def _append(self, session: SearchSession, item: dict[str, Any]) -> None:
        with self._lock:
            session.results.append(item)

    def _worker(
        self,
        session: SearchSession,
        file_glob: str,
        result_limit: int,
        depth_limit: int,
        scan_limit: int,
        case_sensitive: bool,
        include_hidden: bool,
        context_lines: int,
        early_termination: bool,
        literal_search: bool,
    ) -> None:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = None if literal_search or session.search_type == "files" else re.compile(session.pattern, flags)
            needle = session.pattern if case_sensitive else session.pattern.lower()
            glob = file_glob if case_sensitive else file_glob.lower()
            for child, display, _depth, scanned_now, is_dir, is_file in _walk(
                session.root, self.host_root, depth_limit, scan_limit, bool(include_hidden)
            ):
                session.scanned_entries = scanned_now
                if session.stop_event.is_set():
                    session.state = "stopped"
                    break

                if session.search_type == "files":
                    name = child.name if case_sensitive else child.name.lower()
                    match_pattern = session.pattern if case_sensitive else session.pattern.lower()
                    matched = name == match_pattern if literal_search else fnmatch.fnmatchcase(name, match_pattern)
                    if matched:
                        try:
                            size = child.stat().st_size if is_file else None
                        except OSError:
                            size = None
                        self._append(session, {"path": display, "type": "directory" if is_dir else "file", "size": size})
                        if early_termination and not any(char in match_pattern for char in "*?["):
                            session.state = "completed"
                            break
                else:
                    if not is_file:
                        continue
                    name = child.name if case_sensitive else child.name.lower()
                    if not fnmatch.fnmatchcase(name, glob):
                        continue
                    try:
                        size = child.stat().st_size
                    except OSError:
                        continue
                    if size > MAX_CONTENT_FILE_BYTES:
                        continue
                    try:
                        raw = child.read_bytes()
                    except OSError:
                        continue
                    if b"\x00" in raw:
                        continue
                    session.files_examined += 1
                    lines = raw.decode("utf-8", errors="replace").splitlines()
                    for index, line in enumerate(lines):
                        haystack = line if case_sensitive else line.lower()
                        matched = (needle in haystack) if literal_search else bool(regex and regex.search(line))
                        if matched:
                            item: dict[str, Any] = {
                                "path": display,
                                "line": index + 1,
                                "text": redact_text(line, 500),
                            }
                            if context_lines:
                                before = lines[max(0, index - context_lines):index]
                                after = lines[index + 1:index + 1 + context_lines]
                                item["context_before"] = [redact_text(value, 500) for value in before]
                                item["context_after"] = [redact_text(value, 500) for value in after]
                            self._append(session, item)
                            if len(session.results) >= result_limit:
                                break

                if len(session.results) >= result_limit:
                    session.state = "completed"
                    break
            else:
                if session.state == "running":
                    session.state = "completed"
        except Exception as exc:
            session.error = str(exc)
            session.state = "error"
        finally:
            if session.state == "running":
                session.state = "completed"
            session.completed_at = time.time()

    def results(self, session_id: str, offset: int = 0, length: int = 100) -> dict[str, Any]:
        self._cleanup()
        session = self._get(session_id)
        clean_length = max(1, min(int(length), 500))
        clean_offset = int(offset)
        with self._lock:
            total = len(session.results)
            if clean_offset < 0:
                start = max(0, total + clean_offset)
            else:
                start = min(clean_offset, total)
            end = min(total, start + clean_length)
            page = list(session.results[start:end])
        result = self._summary(session)
        result.update({
            "offset": clean_offset,
            "length": clean_length,
            "results": page,
            "returned": len(page),
            "total_results": total,
            "has_more": end < total or session.state == "running",
        })
        return result

    def list(self) -> dict[str, Any]:
        self._cleanup()
        with self._lock:
            sessions = [self._summary(session) for session in self._sessions.values()]
        sessions.sort(key=lambda item: item["created_at"], reverse=True)
        return {"sessions": sessions, "count": len(sessions), "retention_seconds": SEARCH_RETENTION_SECONDS}

    def stop(self, session_id: str) -> dict[str, Any]:
        session = self._get(session_id)
        session.stop_event.set()
        if session.state == "running":
            session.state = "stopping"
        return self._summary(session)

    def _get(self, session_id: str) -> SearchSession:
        with self._lock:
            session = self._sessions.get(str(session_id or ""))
        if session is None:
            raise KeyError(f"unknown search session: {session_id}")
        return session

    @staticmethod
    def _summary(session: SearchSession) -> dict[str, Any]:
        now = session.completed_at or time.time()
        runtime_seconds = max(0.0, now - session.created_at)
        execution_state = {
            "running": "running",
            "stopping": "stopping",
            "completed": "completed",
            "stopped": "canceled",
            "error": "failed",
        }.get(session.state, session.state)
        exit_reason = {
            "completed": "search_completed",
            "stopped": "search_stopped",
            "error": "search_error",
        }.get(session.state)
        return {
            "session_id": session.id,
            "search_type": session.search_type,
            "root": session.root,
            "pattern": session.pattern,
            "state": session.state,
            "execution_state": execution_state,
            "created_at": session.created_at,
            "completed_at": session.completed_at,
            "runtime_seconds": round(runtime_seconds, 3),
            "duration_ms": round(runtime_seconds * 1000.0, 1),
            "exit_reason": exit_reason,
            "result_count": len(session.results),
            "scanned_entries": session.scanned_entries,
            "files_examined": session.files_examined,
            "error": session.error,
            "progress": {
                "result_count": len(session.results),
                "scanned_entries": session.scanned_entries,
                "files_examined": session.files_examined,
            },
        }
