from __future__ import annotations

import base64
import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
import time
from typing import Any

from src.security import redact_text

MAX_URL_BYTES = 1_000_000
MAX_REDIRECTS = 4
ALLOWED_SCHEMES = {"http", "https"}


class URLReadError(RuntimeError):
    pass


def _validate_url(url: str) -> urllib.parse.SplitResult:
    try:
        parsed = urllib.parse.urlsplit(str(url or "").strip())
    except ValueError as exc:
        raise URLReadError("Invalid URL") from exc
    if parsed.scheme.lower() not in ALLOWED_SCHEMES or not parsed.hostname:
        raise URLReadError("Only http/https URLs with a hostname are supported")
    if parsed.username or parsed.password:
        raise URLReadError("URLs with embedded credentials are not allowed")
    if len(parsed.geturl()) > 4096:
        raise URLReadError("URL exceeds length limit")
    host = parsed.hostname.rstrip(".")
    try:
        addresses = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme.lower() == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise URLReadError("URL hostname could not be resolved") from exc
    if not addresses:
        raise URLReadError("URL hostname did not resolve")
    for item in addresses:
        raw = item[4][0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise URLReadError("URL resolved to an invalid address") from exc
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified:
            raise URLReadError("URL resolves to a private, local, reserved, or non-routable address")
    return parsed


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(newurl)
        count = int(req.headers.get("X-Joe-Redirect-Count", "0") or 0)
        if count >= MAX_REDIRECTS:
            raise URLReadError("URL redirect limit exceeded")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.add_header("X-Joe-Redirect-Count", str(count + 1))
        return redirected


def read_url(url: str, timeout_seconds: float = 10.0, max_bytes: int = MAX_URL_BYTES) -> dict[str, Any]:
    parsed = _validate_url(url)
    limit = max(1, min(int(max_bytes), MAX_URL_BYTES))
    timeout = max(1.0, min(float(timeout_seconds), 20.0))
    request = urllib.request.Request(
        parsed.geturl(),
        headers={"User-Agent": "JoeMCP/0.26", "Accept": "text/*,application/json,application/xml,image/*;q=0.5,*/*;q=0.1"},
        method="GET",
    )
    opener = urllib.request.build_opener(_SafeRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            _validate_url(final_url)
            content_type = str(response.headers.get_content_type() or "application/octet-stream")
            charset = response.headers.get_content_charset() or "utf-8"
            raw = response.read(limit + 1)
            truncated = len(raw) > limit
            raw = raw[:limit]
            status = int(getattr(response, "status", 200) or 200)
    except URLReadError:
        raise
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        raise URLReadError(f"URL request failed: {exc}") from exc
    result: dict[str, Any] = {
        "url": parsed.geturl(),
        "final_url": final_url,
        "status": status,
        "content_type": content_type,
        "bytes": len(raw),
        "truncated": truncated,
    }
    if content_type.startswith("text/") or content_type in {"application/json", "application/xml", "application/xhtml+xml", "application/javascript"}:
        text = raw.decode(charset, errors="replace")
        result["encoding"] = charset
        result["content"] = redact_text(text, max_chars=min(16000, max(1, limit)))
    elif content_type.startswith("image/"):
        result["encoding"] = "base64"
        result["data"] = base64.b64encode(raw).decode("ascii")
        result["data_uri_prefix"] = f"data:{content_type};base64,"
    else:
        result["content_omitted"] = "binary response is not returned unless it is an image"
    return result

SAFE_PROBE_HEADERS = {"content-type", "content-length", "date", "server", "location", "cache-control", "etag", "last-modified"}


def http_probe(url: str, method: str = "HEAD", timeout_seconds: float = 10.0, max_bytes: int = 32768) -> dict[str, Any]:
    parsed = _validate_url(url)
    verb = str(method or "HEAD").strip().upper()
    if verb not in {"HEAD", "GET"}:
        raise URLReadError("HTTP probe supports only HEAD and GET")
    limit = max(0, min(int(max_bytes), 100_000))
    timeout = max(1.0, min(float(timeout_seconds), 20.0))
    request = urllib.request.Request(
        parsed.geturl(),
        headers={"User-Agent": "JoeMCP-Probe/1", "Accept": "*/*"},
        method=verb,
    )
    opener = urllib.request.build_opener(_SafeRedirect())
    started = time.monotonic()
    response = None
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise URLReadError(f"HTTP probe failed: {exc}") from exc
    try:
        final_url = response.geturl()
        _validate_url(final_url)
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        headers = {
            str(key).lower(): str(value)[:2000]
            for key, value in response.headers.items()
            if str(key).lower() in SAFE_PROBE_HEADERS
        }
        raw = response.read(limit + 1) if verb == "GET" and limit > 0 else b""
    finally:
        response.close()
    truncated = len(raw) > limit
    raw = raw[:limit]
    result: dict[str, Any] = {
        "url": parsed.geturl(), "final_url": final_url, "method": verb, "status": status,
        "ok": 200 <= status < 400, "latency_ms": round((time.monotonic() - started) * 1000, 1),
        "headers": headers, "bytes": len(raw), "truncated": truncated,
    }
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if raw and (content_type.startswith("text/") or content_type in {"application/json", "application/xml", "application/xhtml+xml", "application/javascript"}):
        result["content"] = redact_text(raw.decode("utf-8", errors="replace"), max_chars=limit)
    elif raw:
        result["content_omitted"] = "non-text probe response body omitted"
    return result

