from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit


class AccessDenied(PermissionError):
    """Raised when a host path is outside Joe MCP's read policy."""


PROJECT_ROOT = os.getenv("JOE_PROJECT_ROOT", "/opt/joe-mcp/python/current").rstrip("/") or "/opt/joe-mcp/python/current"


SENSITIVE_COMPONENTS = {
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".azure",
    ".secrets",
    ".password-store",
}

SENSITIVE_BASENAMES = {
    "shadow",
    "gshadow",
    ".htpasswd",
    ".netrc",
    ".pypirc",
    ".git-credentials",
    ".npmrc",
    ".pgpass",
    ".my.cnf",
    ".mylogin.cnf",
    "auth.json",
    "credentials",
    "credentials.json",
    "mcp.token",
    "session.secret",
    "setup.token",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

SENSITIVE_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
}

DENIED_PREFIXES = (
    "/etc/ssl/private",
    f"{PROJECT_ROOT}/data/auth",
    f"{PROJECT_ROOT}/data/audit",
    f"{PROJECT_ROOT}/data/devices",
    f"{PROJECT_ROOT}/data/sessions",
    "/var/lib/joe-mcp-work/persistent-sessions",
    "/var/lib/joe-mcp-work/sap",
)

SAFE_PROC_FILES = {
    "/proc/uptime",
    "/proc/loadavg",
    "/proc/meminfo",
}

SECRET_NAME_RE = re.compile(
    r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|client[_-]?secret|"
    r"access[_-]?key|private[_-]?key|authorization|auth[_-]?token)",
    re.IGNORECASE,
)

JWT_RE = re.compile(r"^[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}$")
JWT_INLINE_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}(?![A-Za-z0-9_-])")
BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}")
AUTH_HEADER_RE = re.compile(r"(?i)(\bauthorization\s*[:=]\s*)(?:Bearer|Basic)\s+[^\s,;]+")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<prefix>[\"']?(?:pass(?:word|wd)?|secret|token|api[_-]?key|client[_-]?secret|"
    r"access[_-]?key|private[_-]?key|authorization|auth[_-]?token)[\"']?\s*[:=]\s*)"
    r"(?P<quote>[\"']?)(?P<value>[^\s,;\"']+)(?P=quote)"
)
URL_CREDENTIAL_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s/@]+(@)")
OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")
PRIVATE_KEY_MARKER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)


def normalize_host_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("Host path must be absolute")
    normalized = posixpath.normpath(path)
    return normalized if normalized.startswith("/") else f"/{normalized}"


def _path_policy_reason(host_path: str) -> str | None:
    normalized = normalize_host_path(host_path)
    lowered = normalized.lower()

    if lowered == "/proc" or lowered.startswith("/proc/"):
        if lowered not in SAFE_PROC_FILES:
            return "generic /proc filesystem access is restricted; use dedicated process tools"

    for prefix in DENIED_PREFIXES:
        if lowered == prefix or lowered.startswith(prefix + "/"):
            return f"path is inside restricted area {prefix}"

    parts = PurePosixPath(normalized).parts[1:]
    lowered_parts = [part.lower() for part in parts]

    for index, component in enumerate(lowered_parts[:-1]):
        if component in SENSITIVE_COMPONENTS:
            return f"path contains restricted directory {component}"
        if component == ".config" and index + 1 < len(lowered_parts):
            if lowered_parts[index + 1] in {"gh", "gcloud"}:
                return f"path contains restricted credential directory .config/{lowered_parts[index + 1]}"
        if component == ".local" and lowered_parts[index:index + 3] == [".local", "share", "keyrings"]:
            return "path contains restricted keyring directory"

    if lowered_parts:
        basename = lowered_parts[-1]
        if basename in SENSITIVE_COMPONENTS:
            return f"path targets restricted directory {basename}"
        if basename in SENSITIVE_BASENAMES:
            return f"file {basename} is restricted"
        if basename == ".env" or basename.startswith(".env."):
            return "environment credential files are restricted"
        if any(basename.endswith(suffix) for suffix in SENSITIVE_SUFFIXES):
            return f"credential/key file type is restricted ({Path(basename).suffix})"

    return None


def safe_host_path(path: str, host_root: Path) -> Path:
    """Map an absolute host path into /host while enforcing the read policy.

    The resolved path must remain under host_root. This prevents symlink-based escape
    from the host mount into the container filesystem.
    """
    normalized = normalize_host_path(path)
    reason = _path_policy_reason(normalized)
    if reason:
        raise AccessDenied(f"Access denied for {normalized}: {reason}")

    root = host_root.resolve(strict=False)
    candidate = host_root / normalized.lstrip("/")
    resolved = candidate.resolve(strict=False)
    if resolved != root and not resolved.is_relative_to(root):
        raise AccessDenied(f"Access denied for {normalized}: resolved path escapes host root")

    if resolved != root:
        resolved_host_path = "/" + resolved.relative_to(root).as_posix()
        resolved_reason = _path_policy_reason(resolved_host_path)
        if resolved_reason:
            raise AccessDenied(
                f"Access denied for {normalized}: resolved target is restricted ({resolved_reason})"
            )
    return candidate


def is_host_path_allowed(path: str, host_root: Path) -> bool:
    try:
        safe_host_path(path, host_root)
        return True
    except (AccessDenied, ValueError, OSError):
        return False


def _redact_url_credentials(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.scheme or parsed.hostname is None or parsed.password is None:
        return value
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    userinfo = parsed.username or ""
    netloc = f"{userinfo}:[REDACTED]@{host}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def redact_text(value: str, max_chars: int = 4000) -> str:
    """Redact common credential forms from untrusted log/message text."""
    text = str(value or "")
    if PRIVATE_KEY_MARKER_RE.search(text):
        return "[REDACTED PRIVATE KEY MATERIAL]"
    text = AUTH_HEADER_RE.sub(r"\1[REDACTED]", text)
    text = BEARER_RE.sub(r"\1[REDACTED]", text)
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group('prefix')}[REDACTED]", text)
    text = URL_CREDENTIAL_RE.sub(r"\1[REDACTED]\2", text)
    text = JWT_INLINE_RE.sub("[REDACTED JWT]", text)
    text = OPENAI_KEY_RE.sub("[REDACTED API KEY]", text)
    limit = max(1, min(int(max_chars), 16000))
    return text[:limit] + ("…" if len(text) > limit else "")


def redact_argv(argv: list[str]) -> str:
    """Return a display-safe command line with common credential values redacted."""
    result: list[str] = []
    redact_next = False

    for raw in argv:
        arg = raw or ""
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
            continue

        if arg.lower() == "bearer":
            result.append(arg)
            redact_next = True
            continue

        if arg.startswith("-") and "=" not in arg and SECRET_NAME_RE.search(arg.lstrip("-")):
            result.append(arg)
            redact_next = True
            continue

        if "=" in arg:
            key, value = arg.split("=", 1)
            if SECRET_NAME_RE.search(key.lstrip("-")):
                result.append(f"{key}=[REDACTED]")
                continue
            arg = f"{key}={_redact_url_credentials(value)}"
        else:
            arg = _redact_url_credentials(arg)

        if JWT_RE.match(arg):
            arg = "[REDACTED]"

        result.append(arg)

    if redact_next:
        result.append("[REDACTED]")

    return " ".join(result)
