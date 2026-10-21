from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


PROFILE_FILE = Path(os.getenv("JOE_SAP_PROFILE_FILE", "/var/lib/joe-mcp-work/sap/profiles.json"))
MAX_RESPONSE_BYTES = 1_000_000
MAX_SOURCE_BYTES = 2_000_000
MAX_CHANGE_BYTES = 2_000_000
MAX_SAPCONTROL_BYTES = 512_000
PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
INSTANCE_RE = re.compile(r"^[0-9]{2}$")
HOST_RE = re.compile(r"^[A-Za-z0-9_.-]{1,253}$")
SAP_SID_RE = re.compile(r"^[A-Z0-9]{3}$")
SAP_INSTANCE_DIR_RE = re.compile(r"^[A-Z][A-Z0-9_]*[0-9]{2}$")
ALLOWED_ADT_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE"}
MUTATING_ADT_METHODS = {"POST", "PUT", "DELETE"}


class SAPError(RuntimeError):
    pass


def _safe_profile_name(name: str) -> str:
    value = str(name or "").strip()
    if not PROFILE_RE.fullmatch(value):
        raise SAPError("SAP profile name must contain only letters, numbers, dot, dash, or underscore")
    return value


def _load_profiles(path: Path | None = None) -> dict[str, Any]:
    target = path or PROFILE_FILE
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": 1, "profiles": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise SAPError("SAP connection profile store is invalid") from exc
    if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(raw.get("profiles"), dict):
        raise SAPError("Unsupported SAP connection profile store")
    return raw


def _save_profiles(data: dict[str, Any], path: Path | None = None) -> None:
    target = path or PROFILE_FILE
    if target.is_symlink():
        raise SAPError("SAP connection profile store cannot be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target.parent, 0o700)
    temp = target.with_name(f".{target.name}.tmp")
    try:
        temp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, target)
        os.chmod(target, 0o600)
    except OSError as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise SAPError("Unable to save SAP connection profile store") from exc


def _public_profile(name: str, profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "base_url": str(profile.get("base_url", "")),
        "client": str(profile.get("client", "")),
        "username": str(profile.get("username", "")),
        "auth": "bearer" if profile.get("bearer_token") else ("basic" if profile.get("password") else "none"),
        "verify_tls": bool(profile.get("verify_tls", True)),
        "allow_insecure_http": bool(profile.get("allow_insecure_http", False)),
        "configured": True,
    }


def sap_profiles(path: Path | None = None) -> dict[str, Any]:
    data = _load_profiles(path)
    profiles = data.get("profiles", {})
    rows = [_public_profile(name, value) for name, value in sorted(profiles.items()) if isinstance(value, dict)]
    return {"profiles": rows, "count": len(rows), "credentials_redacted": True}


def configure_sap_profile(
    name: str,
    base_url: str,
    client: str = "",
    username: str = "",
    password: str = "",
    bearer_token: str = "",
    verify_tls: bool = True,
    allow_insecure_http: bool = False,
    confirm: bool = False,
    path: Path | None = None,
) -> dict[str, Any]:
    if confirm is not True:
        raise SAPError("Configuring an SAP connection profile requires confirm=true")
    key = _safe_profile_name(name)
    parsed = urllib.parse.urlsplit(str(base_url or "").strip())
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SAPError("SAP base_url must not contain credentials, query parameters, or fragments")
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise SAPError("SAP base_url must be an absolute HTTP(S) URL")
    if parsed.scheme == "http" and not bool(allow_insecure_http):
        raise SAPError("Plain HTTP requires allow_insecure_http=true")
    normalized_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")).rstrip("/")
    sap_client = str(client or "").strip()
    if sap_client and not re.fullmatch(r"[0-9]{3}", sap_client):
        raise SAPError("SAP client must be exactly three digits")
    user = str(username or "").strip()
    pwd = str(password or "")
    token = str(bearer_token or "")
    if pwd and token:
        raise SAPError("Configure either password or bearer_token, not both")
    if pwd and not user:
        raise SAPError("Basic authentication requires username")
    if len(user) > 128 or len(pwd.encode("utf-8")) > 4096 or len(token.encode("utf-8")) > 16384:
        raise SAPError("SAP credential field exceeds allowed size")
    data = _load_profiles(path)
    profiles = data["profiles"]
    profiles[key] = {
        "base_url": normalized_url,
        "client": sap_client,
        "username": user,
        "password": pwd,
        "bearer_token": token,
        "verify_tls": bool(verify_tls),
        "allow_insecure_http": bool(allow_insecure_http),
    }
    _save_profiles(data, path)
    return _public_profile(key, profiles[key])


def remove_sap_profile(name: str, confirm: bool = False, path: Path | None = None) -> dict[str, Any]:
    if confirm is not True:
        raise SAPError("Removing an SAP connection profile requires confirm=true")
    key = _safe_profile_name(name)
    data = _load_profiles(path)
    profiles = data["profiles"]
    existed = key in profiles
    profiles.pop(key, None)
    _save_profiles(data, path)
    return {"name": key, "removed": existed}


def _profile(name: str, path: Path | None = None) -> dict[str, Any]:
    key = _safe_profile_name(name)
    data = _load_profiles(path)
    value = data["profiles"].get(key)
    if not isinstance(value, dict):
        raise SAPError(f"Unknown SAP profile: {key}")
    return value


def _sapcontrol_binary() -> str:
    candidates = [
        "/usr/sap/hostctrl/exe/sapcontrol",
        "/usr/sap/hostctrl/exe/sapcontrol.bin",
        "/usr/bin/sapcontrol",
        "/usr/local/bin/sapcontrol",
    ]
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise SAPError("sapcontrol was not found in approved SAP host locations")


def sap_host_discover() -> dict[str, Any]:
    sap_root = Path("/usr/sap")
    systems: list[dict[str, Any]] = []
    if sap_root.is_dir() and not sap_root.is_symlink():
        for sid_dir in sorted(sap_root.iterdir(), key=lambda p: p.name):
            if not sid_dir.is_dir() or sid_dir.is_symlink() or not SAP_SID_RE.fullmatch(sid_dir.name):
                continue
            instances: list[dict[str, str]] = []
            try:
                children = list(sid_dir.iterdir())
            except OSError:
                children = []
            for child in sorted(children, key=lambda p: p.name):
                if child.is_dir() and not child.is_symlink() and SAP_INSTANCE_DIR_RE.fullmatch(child.name):
                    instances.append({"name": child.name, "number": child.name[-2:], "path": str(child)})
            systems.append({"sid": sid_dir.name, "root": str(sid_dir), "instances": instances})
    try:
        binary = _sapcontrol_binary()
    except SAPError:
        binary = None
    return {"sap_root": str(sap_root), "systems": systems, "system_count": len(systems), "sapcontrol": binary, "sapcontrol_available": bool(binary)}


def _sapcontrol(instance_number: str, function: str, host: str = "", timeout: float = 20.0) -> dict[str, Any]:
    nr = str(instance_number or "").strip()
    if not INSTANCE_RE.fullmatch(nr):
        raise SAPError("SAP instance number must be exactly two digits")
    function_name = str(function or "").strip()
    allowed = {"GetProcessList", "GetSystemInstanceList", "GetVersionInfo", "GetAlertTree", "Start", "Stop", "RestartInstance"}
    if function_name not in allowed:
        raise SAPError("Unsupported sapcontrol function")
    argv = [_sapcontrol_binary()]
    target_host = str(host or "").strip()
    if target_host:
        if not HOST_RE.fullmatch(target_host):
            raise SAPError("Invalid SAP host name")
        argv += ["-host", target_host]
    argv += ["-nr", nr, "-format", "script", "-function", function_name]
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1.0, min(float(timeout), 60.0)),
            check=False,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/"},
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise SAPError("sapcontrol execution failed") from exc
    stdout = completed.stdout[:MAX_SAPCONTROL_BYTES].decode("utf-8", errors="replace")
    stderr = completed.stderr[:65536].decode("utf-8", errors="replace")
    if completed.returncode != 0:
        raise SAPError((stderr or stdout or "sapcontrol returned an error")[:4000].strip())
    rows: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            if current:
                rows.append(current)
                current = {}
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            current[key.strip()] = value.strip()
    if current:
        rows.append(current)
    return {"instance_number": nr, "host": target_host or "local", "function": function_name, "rows": rows[:500], "row_count": len(rows), "output": stdout[:MAX_SAPCONTROL_BYTES], "truncated": len(completed.stdout) > MAX_SAPCONTROL_BYTES}


def sap_process_list(instance_number: str, host: str = "") -> dict[str, Any]:
    return _sapcontrol(instance_number, "GetProcessList", host)


def sap_system_info(instance_number: str, host: str = "") -> dict[str, Any]:
    return {
        "instances": _sapcontrol(instance_number, "GetSystemInstanceList", host),
        "versions": _sapcontrol(instance_number, "GetVersionInfo", host),
    }


def sap_instance_action(instance_number: str, action: str, host: str = "", confirm: bool = False) -> dict[str, Any]:
    if confirm is not True:
        raise SAPError("SAP instance lifecycle actions require confirm=true")
    target_host = str(host or "").strip().lower()
    if target_host:
        local_names = {"localhost", "127.0.0.1", "::1", socket.gethostname().lower(), socket.getfqdn().lower()}
        if target_host not in local_names:
            raise SAPError("SAP instance lifecycle actions are restricted to the enrolled local SAP host")
    mapping = {"start": "Start", "stop": "Stop", "restart": "RestartInstance"}
    key = str(action or "").strip().lower()
    function = mapping.get(key)
    if not function:
        raise SAPError("SAP instance action must be start, stop, or restart")
    result = _sapcontrol(instance_number, function, host, timeout=60.0)
    return {"action": key, "executed": True, **result}


def _auth_headers(profile: dict[str, Any]) -> dict[str, str]:
    headers = {"User-Agent": "Joe-MCP-SAP/1", "Accept-Encoding": "identity"}
    token = str(profile.get("bearer_token", "") or "")
    password = str(profile.get("password", "") or "")
    username = str(profile.get("username", "") or "")
    if token:
        headers["Authorization"] = "Bearer " + token
    elif username or password:
        raw = f"{username}:{password}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    return headers


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        parsed = urllib.parse.urlsplit(base_url)
        self._origin = (parsed.scheme.lower(), parsed.netloc.lower())

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme.lower(), parsed.netloc.lower()) != self._origin:
            raise urllib.error.HTTPError(newurl, code, "SAP ADT cross-origin redirect refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener(profile: dict[str, Any]) -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    if not bool(profile.get("verify_tls", True)):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPCookieProcessor(jar),
        _SameOriginRedirect(str(profile.get("base_url", ""))),
    )


def _validate_adt_path(path: str) -> str:
    value = str(path or "").strip()
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise SAPError("ADT path must be a relative SAP ADT path, not a full URL")
    normalized_path = parsed.path
    if not normalized_path.startswith("/sap/bc/adt/"):
        raise SAPError("ADT path must stay under /sap/bc/adt/")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise SAPError("Invalid ADT path")
    return urllib.parse.urlunsplit(("", "", normalized_path, parsed.query, ""))


def _adt_url(profile: dict[str, Any], path: str) -> str:
    parsed = urllib.parse.urlsplit(_validate_adt_path(path))
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    client = str(profile.get("client", "") or "").strip()
    if client and not any(key.lower() == "sap-client" for key, _value in query):
        query.append(("sap-client", client))
    relative = urllib.parse.urlunsplit(("", "", parsed.path, urllib.parse.urlencode(query), ""))
    return str(profile["base_url"]).rstrip("/") + relative


def _do_request(
    profile: dict[str, Any],
    method: str,
    path: str,
    body: bytes | None = None,
    content_type: str = "",
    accept: str = "application/xml, text/plain;q=0.9, */*;q=0.1",
    csrf_token: str = "",
    opener: urllib.request.OpenerDirector | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    verb = str(method or "GET").upper()
    if verb not in ALLOWED_ADT_METHODS:
        raise SAPError("Unsupported ADT HTTP method")
    client = opener or _opener(profile)
    headers = _auth_headers(profile)
    headers["Accept"] = accept
    if content_type:
        headers["Content-Type"] = content_type
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    request = urllib.request.Request(_adt_url(profile, path), data=body, headers=headers, method=verb)
    try:
        with client.open(request, timeout=max(1.0, min(float(timeout), 60.0))) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
            status = int(getattr(response, "status", 200) or 200)
            response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        data = exc.read(65536)
        message = data.decode("utf-8", errors="replace").strip()
        raise SAPError(f"SAP ADT HTTP {exc.code}: {message[:4000] or exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SAPError(f"SAP ADT request failed: {exc}") from exc
    if len(data) > MAX_RESPONSE_BYTES:
        raise SAPError("SAP ADT response exceeded the 1 MB limit")
    text = data.decode("utf-8", errors="replace")
    safe_headers = {}
    for key in ("content-type", "etag", "location", "x-csrf-token", "sap-processing-info"):
        if key in response_headers:
            safe_headers[key] = response_headers[key]
    return {"status": status, "path": _validate_adt_path(path), "content_type": response_headers.get("content-type", ""), "headers": safe_headers, "body": text, "bytes": len(data)}


def _csrf(profile: dict[str, Any], opener: urllib.request.OpenerDirector) -> str:
    headers = _auth_headers(profile)
    headers.update({"Accept": "application/atomsvc+xml, application/xml;q=0.9", "X-CSRF-Token": "Fetch"})
    request = urllib.request.Request(_adt_url(profile, "/sap/bc/adt/discovery"), headers=headers, method="GET")
    try:
        with opener.open(request, timeout=20.0) as response:
            response.read(65536)
            token = str(response.headers.get("X-CSRF-Token", "") or "").strip()
    except urllib.error.HTTPError as exc:
        raise SAPError(f"Unable to fetch SAP ADT CSRF token: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SAPError(f"Unable to fetch SAP ADT CSRF token: {exc}") from exc
    if not token:
        raise SAPError("SAP ADT did not return a CSRF token")
    return token


def abap_adt_get(profile_name: str, path: str, accept: str = "") -> dict[str, Any]:
    profile = _profile(profile_name)
    result = _do_request(profile, "GET", path, accept=accept or "application/xml, text/plain;q=0.9, */*;q=0.1")
    return {"profile": _safe_profile_name(profile_name), **result}


def abap_object_search(profile_name: str, query: str, object_type: str = "", max_results: int = 50) -> dict[str, Any]:
    text = str(query or "").strip()
    if not text or len(text) > 256:
        raise SAPError("ABAP search query must be between 1 and 256 characters")
    limit = max(1, min(int(max_results), 200))
    params = {"operation": "quickSearch", "query": text, "maxResults": str(limit)}
    object_kind = str(object_type or "").strip()
    if object_kind:
        if not re.fullmatch(r"[A-Za-z0-9_/.-]{1,64}", object_kind):
            raise SAPError("Invalid ABAP object type")
        params["objectType"] = object_kind
    path = "/sap/bc/adt/repository/informationsystem/search?" + urllib.parse.urlencode(params)
    response = abap_adt_get(profile_name, path, "application/xml")
    refs: list[dict[str, str]] = []
    try:
        root = ET.fromstring(response.get("body", ""))
        for elem in root.iter():
            attrs = {key.split("}")[-1]: value for key, value in elem.attrib.items()}
            uri = attrs.get("uri", "")
            if uri.startswith("/sap/bc/adt/"):
                refs.append({key: attrs[key] for key in ("name", "type", "uri", "description") if attrs.get(key)})
                if len(refs) >= limit:
                    break
    except ET.ParseError:
        pass
    return {"profile": _safe_profile_name(profile_name), "query": text, "object_type": object_kind, "results": refs, "count": len(refs), "raw": response}


def abap_source_read(profile_name: str, source_uri: str) -> dict[str, Any]:
    path = _validate_adt_path(source_uri)
    if "/source/" not in path and not path.endswith("/source/main"):
        raise SAPError("ABAP source URI must identify an ADT source resource")
    result = abap_adt_get(profile_name, path, "text/plain, application/xml;q=0.8, */*;q=0.1")
    if int(result.get("bytes", 0)) > MAX_SOURCE_BYTES:
        raise SAPError("ABAP source exceeded size limit")
    return result


def abap_adt_change(
    profile_name: str,
    method: str,
    path: str,
    body: str = "",
    content_type: str = "application/xml; charset=utf-8",
    confirm: bool = False,
) -> dict[str, Any]:
    if confirm is not True:
        raise SAPError("SAP ADT mutations require confirm=true")
    verb = str(method or "").upper()
    if verb not in MUTATING_ADT_METHODS:
        raise SAPError("ADT mutation method must be POST, PUT, or DELETE")
    payload = str(body or "").encode("utf-8")
    if len(payload) > MAX_CHANGE_BYTES:
        raise SAPError("SAP ADT mutation body exceeds the 2 MB limit")
    ctype = str(content_type or "").strip()
    if len(ctype) > 200 or "\r" in ctype or "\n" in ctype:
        raise SAPError("Invalid ADT content type")
    profile = _profile(profile_name)
    opener = _opener(profile)
    token = _csrf(profile, opener)
    result = _do_request(profile, verb, path, payload if verb != "DELETE" else None, ctype, csrf_token=token, opener=opener, timeout=60.0)
    return {"profile": _safe_profile_name(profile_name), "mutated": True, **result}


def _append_query(path: str, **params: str) -> str:
    parsed = urllib.parse.urlsplit(_validate_adt_path(path))
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    existing = {key for key, _value in query}
    for key, value in params.items():
        if value and key not in existing:
            query.append((key, value))
    return urllib.parse.urlunsplit(("", "", parsed.path, urllib.parse.urlencode(query), ""))


def abap_source_update(
    profile_name: str,
    source_uri: str,
    source: str,
    lock_handle: str = "",
    transport_request: str = "",
    confirm: bool = False,
) -> dict[str, Any]:
    path = _validate_adt_path(source_uri)
    if "/source/" not in path and not path.endswith("/source/main"):
        raise SAPError("ABAP source URI must identify an ADT source resource")
    lock = str(lock_handle or "").strip()
    corr = str(transport_request or "").strip().upper()
    if lock and not re.fullmatch(r"[A-Za-z0-9_.:+/-]{1,256}", lock):
        raise SAPError("Invalid ADT lock handle")
    if corr and not re.fullmatch(r"[A-Z0-9]{8,20}", corr):
        raise SAPError("Invalid SAP transport request")
    path = _append_query(path, lockHandle=lock, corrNr=corr)
    result = abap_adt_change(profile_name, "PUT", path, source, "text/plain; charset=utf-8", confirm)
    result.update({"source_uri": source_uri, "transport_request": corr or None, "lock_handle_supplied": bool(lock)})
    return result


def abap_activate(profile_name: str, object_uri: str, object_name: str = "", confirm: bool = False) -> dict[str, Any]:
    uri = _validate_adt_path(object_uri)
    name = str(object_name or "").strip()
    if name and len(name) > 128:
        raise SAPError("ABAP object name is too long")
    escaped_uri = uri.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    escaped_name = name.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    name_attr = f' adtcore:name="{escaped_name}"' if escaped_name else ""
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">'
        f'<adtcore:objectReference adtcore:uri="{escaped_uri}"{name_attr}/>'
        '</adtcore:objectReferences>'
    )
    result = abap_adt_change(
        profile_name,
        "POST",
        "/sap/bc/adt/activation?method=activate&preauditRequested=true",
        body,
        "application/xml; charset=utf-8",
        confirm,
    )
    result.update({"object_uri": uri, "object_name": name or None, "activation_requested": True})
    return result


def abap_atc_run(profile_name: str, path: str, body: str, confirm: bool = False) -> dict[str, Any]:
    adt_path = _validate_adt_path(path)
    if not adt_path.startswith("/sap/bc/adt/atc/"):
        raise SAPError("ATC requests must stay under /sap/bc/adt/atc/")
    result = abap_adt_change(profile_name, "POST", adt_path, body, "application/xml; charset=utf-8", confirm)
    result["atc_requested"] = True
    return result


def sap_rfc_status() -> dict[str, Any]:
    sdk_candidates = [
        "/usr/sap/nwrfcsdk/lib/libsapnwrfc.so",
        "/usr/local/sap/nwrfcsdk/lib/libsapnwrfc.so",
        "/opt/sap/nwrfcsdk/lib/libsapnwrfc.so",
    ]
    sdk = next((path for path in sdk_candidates if Path(path).is_file()), None)
    try:
        import pyrfc  # type: ignore  # noqa: F401
        pyrfc_available = True
    except Exception:
        pyrfc_available = False
    return {
        "sdk_library": sdk,
        "sdk_available": bool(sdk),
        "pyrfc_available": pyrfc_available,
        "call_enabled": bool(sdk and pyrfc_available),
        "note": "Joe does not bundle the proprietary SAP NetWeaver RFC SDK; install and license it separately before RFC calls are enabled.",
    }
