from __future__ import annotations

import json
import sys

from src.sqlite_ops import SQLiteReadError, sqlite_query
from src.workspace_policy import WorkspaceDenied


def main() -> int:
    if len(sys.argv) != 5:
        print(json.dumps({"ok": False, "error": "invalid diagnostic worker arguments"}))
        return 2
    workspace, database, query, max_rows_raw = sys.argv[1:]
    try:
        result = sqlite_query(workspace, database, query, int(max_rows_raw))
    except (SQLiteReadError, WorkspaceDenied, FileNotFoundError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc), "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
