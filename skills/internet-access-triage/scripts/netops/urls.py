"""URL validation and redaction for target-scoped probes."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


def parse_target(value: str, allow_http: bool = False) -> dict[str, object]:
    if not isinstance(value, str) or not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("URL must be non-empty and contain no control characters")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as error:
        raise ValueError("URL has an invalid authority or port") from error
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise ValueError("URL scheme must be https or http")
    if scheme == "http" and not allow_http:
        raise ValueError("Plain HTTP requires --allow-http for an explicitly approved diagnostic or test target")
    if not parts.hostname:
        raise ValueError("URL must contain a hostname")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("URL credentials are not accepted")
    if parts.fragment:
        # Fragments are client-side only and should never enter a probe.
        value = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        parts = urlsplit(value)
    hostname = parts.hostname.rstrip(".")
    try:
        ipaddress.ip_address(hostname)
        normalized_host = hostname.lower()
    except ValueError:
        try:
            normalized_host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("URL hostname is invalid") from error
        if not re.fullmatch(r"[a-z0-9.-]+", normalized_host) or ".." in normalized_host:
            raise ValueError("URL hostname is invalid")
    default_port = 443 if scheme == "https" else 80
    target = {
        "url": value,
        "scheme": scheme,
        "hostname": normalized_host,
        "port": port or default_port,
        "address_family": "IPv6" if ":" in normalized_host else ("IPv4" if normalized_host.replace(".", "").isdigit() else None),
        "protocol": "HTTPS" if scheme == "https" else "HTTP",
    }
    return target


def redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parts.port}" if parts.port is not None else ""
        authority = host + port
        path = parts.path or "/"
        query = "[redacted]" if parts.query else ""
        return urlunsplit((parts.scheme, authority, path, query, ""))
    except ValueError:
        return "[invalid URL]"


def redact_text(text: str, urls: list[str] | None = None) -> str:
    result = text
    for value in urls or []:
        if value:
            result = result.replace(value, redact_url(value))
    result = re.sub(r"(?i)(https?://[^\s\"']+)", lambda match: redact_url(match.group(1)), result)
    result = re.sub(r"(?i)(authorization|proxy-authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]+",
                    r"\1: [redacted]", result)
    return result


def validate_dns_endpoint(server: str, transport: str) -> str:
    if not isinstance(server, str) or not server or any(ord(char) < 33 or ord(char) == 127 for char in server):
        raise ValueError("DNS server must be non-empty and contain no whitespace or control characters")
    if transport not in {"udp", "tcp", "tls", "https", "quic"}:
        raise ValueError("DNS transport must be udp, tcp, tls, https, or quic")
    expected_scheme = {"udp": "", "tcp": "tcp", "tls": "tls", "https": "https", "quic": "quic"}[transport]
    if transport in ("udp", "tcp"):
        if "://" in server or any(char in server for char in "/?#@"):
            raise ValueError("Plain DNS server must be a hostname or IP address with an optional port")
        if server.count(":") > 1:
            try:
                ipaddress.IPv6Address(server)
            except ValueError as error:
                raise ValueError("DNS server IPv6 address is invalid") from error
        else:
            host = server.rsplit(":", 1)[0] if ":" in server else server
            if not host:
                raise ValueError("DNS server hostname is missing")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or ".." in host:
                    raise ValueError("DNS server hostname is invalid")
        return server
    value = server if "://" in server else f"{expected_scheme}://{server}"
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError as error:
        raise ValueError("DNS server URL has an invalid authority or port") from error
    if parts.scheme.lower() != expected_scheme or not parts.hostname:
        raise ValueError(f"DNS server URL must use {expected_scheme} and contain a hostname")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("DNS server credentials are not accepted")
    if parts.query or parts.fragment:
        raise ValueError("DNS server query strings and fragments are not accepted")
    if expected_scheme != "https" and parts.path not in ("", "/"):
        raise ValueError("DNS server paths are supported only for HTTPS resolver URLs")
    return value
