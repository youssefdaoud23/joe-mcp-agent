from __future__ import annotations

import http.client
import ipaddress
from typing import Any
from urllib.parse import urlsplit

from src.security import redact_text
from src.workspace_policy import WorkspaceDenied, resolve_workspace


MAX_BODY_BYTES = 100_000
MAX_REQUEST_BODY_BYTES = 64_000
ALLOWED_METHODS = {"GET", "HEAD"}
SAFE_RESPONSE_HEADERS = {"content-type", "content-length", "date", "server", "location", "cache-control", "etag", "last-modified"}


class LocalHTTPError(RuntimeError):
    pass


def _target(workspace: str, url: str) -> tuple[dict[str, Any], str, str, int, str]:
    profile = resolve_workspace(workspace, "read")
    section = profile.get("http", {}) if isinstance(profile.get("http"), dict) else {}
    if not bool(section.get("enabled", False)):
        raise WorkspaceDenied(f"Local HTTP checks are disabled for workspace: {workspace}")
    parsed = urlsplit(str(url or "").strip())
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.fragment:
        raise LocalHTTPError("Only plain localhost HTTP URLs without credentials/fragments are allowed")
    hostname = (parsed.hostname or "").lower()
    if hostname == "localhost":
        host = "127.0.0.1"
    else:
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise LocalHTTPError("HTTP target must be localhost or a loopback IP") from exc
        if not address.is_loopback:
            raise LocalHTTPError("HTTP target must be loopback-only")
        host = str(address)
    port = parsed.port or 80
    allowed_ports = {int(item) for item in section.get("allowed_ports", []) if str(item).isdigit()}
    if port not in allowed_ports:
        raise LocalHTTPError(f"Local HTTP port is not allow-listed for workspace {workspace}: {port}")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return profile, host, hostname, port, path


def localhost_http(
    workspace: str,
    url: str,
    method: str = "GET",
    body: str = "",
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    profile, host, requested_host, port, path = _target(workspace, url)
    verb = str(method or "GET").strip().upper()
    if verb not in ALLOWED_METHODS:
        raise LocalHTTPError("Only GET and HEAD localhost HTTP checks are allowed")
    payload = str(body or "").encode("utf-8")
    if payload:
        raise LocalHTTPError("GET/HEAD inspection requests cannot include a request body")
    timeout = max(0.2, min(float(timeout_seconds), 10.0))
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    host_header = f"[{requested_host}]" if ":" in requested_host else requested_host
    if port != 80:
        host_header = f"{host_header}:{port}"
    headers = {"Host": host_header, "User-Agent": "Joe-MCP/0.18"}
    try:
        connection.request(verb, path, body=payload if payload else None, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_BODY_BYTES + 1) if verb != "HEAD" else b""
        response_headers = {
            key.lower(): value[:2000]
            for key, value in response.getheaders()
            if key.lower() in SAFE_RESPONSE_HEADERS
        }
    except (OSError, http.client.HTTPException) as exc:
        raise LocalHTTPError(f"Local HTTP request failed: {exc}") from exc
    finally:
        connection.close()
    truncated = len(raw) > MAX_BODY_BYTES
    text = raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
    return {
        "workspace": profile["name"], "url": url, "method": verb,
        "status": int(response.status), "reason": str(response.reason),
        "headers": response_headers, "body": redact_text(text, MAX_BODY_BYTES),
        "body_truncated": truncated,
    }
