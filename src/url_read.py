from __future__ import annotations

import base64
import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
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
