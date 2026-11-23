"""HTTP request extractor (scheme, host, port, normalised path, SSRF-relevant facts)."""
from __future__ import annotations

import ipaddress
import posixpath
from urllib.parse import parse_qsl, unquote, urlsplit


def extract(arguments: dict, field: str = "url", method_field: str = "method") -> dict:
    url = arguments.get(field)
    if not isinstance(url, str) or not url.strip() or len(url) > 8192 or any(c in url for c in "\r\n\t "):
        return {"http": {"parsed": False}}
    try:
        parts = urlsplit(url)
        port = parts.port
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        return {"http": {"parsed": False}}
    if parts.scheme.lower() not in ("http", "https", "ftp", "ws", "wss", "file") or (not host and parts.scheme != "file"):
        return {"http": {"parsed": False}}

    is_ip = private = False
    try:
        address = ipaddress.ip_address(host)
        is_ip = True
        private = address.is_private or address.is_loopback or address.is_link_local or address.is_reserved
    except ValueError:
        pass
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".internal") or host.endswith(".local"):
        private = True

    # decode percent-escapes once, then normalise "..", so /a/%2e%2e/b cannot hide a traversal
    decoded = unquote(parts.path or "/")
    absolute = decoded.startswith("/")
    path = posixpath.normpath(decoded) if decoded else "/"
    if absolute and not path.startswith("/"):
        path = "/" + path
    if path.startswith("//"):
        path = "/" + path.lstrip("/")
    method = arguments.get(method_field)
    return {"http": {
        "parsed": True,
        "method": method.upper() if isinstance(method, str) else "GET",
        "scheme": parts.scheme.lower(),
        "host": host,
        "port": port if port is not None else {"http": 80, "https": 443}.get(parts.scheme.lower(), 0),
        "path": path,
        "host_is_ip": is_ip,
        "host_is_private": private,
        "has_credentials": parts.username is not None or parts.password is not None,
        "query_key": sorted({k.lower() for k, _ in parse_qsl(parts.query, keep_blank_values=True)}),
    }}
