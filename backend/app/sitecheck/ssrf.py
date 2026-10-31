"""SSRF protection for the live website checker.

Rules enforced:
  * http/https only; no userinfo in the URL; no custom ports outside {80,443}.
  * Resolve DNS and reject if ANY resolved IP is loopback, private, link-local
    (incl. cloud metadata 169.254.169.254), multicast, reserved or unspecified.
  * Pin the resolver to the validated IPs for the duration of the request, so the
    socket actually connects to a checked address (defeats DNS rebinding / TOCTOU).
  * Redirects are validated again by the caller before being followed.

Only one target is pinned at a time (guarded by a lock); this is a single-user demo backend.
"""
import ipaddress
import socket
import threading
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {None, 80, 443}

_lock = threading.Lock()
_pinned: dict[str, list] = {}
_orig_getaddrinfo = socket.getaddrinfo


class SSRFError(Exception):
    pass


def _patched_getaddrinfo(host, *args, **kwargs):
    key = (host or "").lower()
    if key in _pinned:
        port = args[0] if args else 0
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0)) for ip in _pinned[key]]
    return _orig_getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _patched_getaddrinfo  # installed once; inert unless a host is pinned


def _ip_is_blocked(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, "unparseable address"
    for flag, label in (("is_loopback", "loopback"), ("is_private", "private"), ("is_link_local", "link-local / cloud metadata"),
                        ("is_multicast", "multicast"), ("is_reserved", "reserved"), ("is_unspecified", "unspecified")):
        if getattr(ip, flag):
            return True, label
    return False, None


def normalize(url):
    url = (url or "").strip()
    if "://" not in url:
        url = "https://" + url
    return url


def validate_url(url):
    """Return (scheme, host, port). Raise SSRFError on anything unsafe."""
    url = normalize(url)
    p = urlparse(url)
    if p.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"Only http and https URLs are allowed (got '{p.scheme or 'none'}').")
    if p.username or p.password:
        raise SSRFError("URLs with embedded credentials are not allowed.")
    if not p.hostname:
        raise SSRFError("The URL has no host.")
    try:
        port = p.port
    except ValueError as exc:
        raise SSRFError("The URL has a malformed port.") from exc
    if port not in ALLOWED_PORTS:
        raise SSRFError(f"Only ports 80 and 443 are allowed (got {port}).")
    host = p.hostname.lower()
    # A literal IP in the URL must itself be public; a hostname is validated after DNS resolution.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_literal_ip = False
    else:
        is_literal_ip = True
    if is_literal_ip:
        blocked, why = _ip_is_blocked(host)
        if blocked:
            raise SSRFError(f"The target address is {why} and cannot be assessed.")
    return p.scheme, host, port


def resolve_public_ips(host):
    """Resolve host and return its public IPs. Raise SSRFError if any resolved IP is disallowed."""
    try:
        infos = _orig_getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for '{host}'.") from exc
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise SSRFError(f"'{host}' did not resolve to any address.")
    for ip in ips:
        blocked, why = _ip_is_blocked(ip)
        if blocked:
            raise SSRFError(f"'{host}' resolves to a {why} address ({ip}); internal/private targets are rejected.")
    return ips


class pinned:
    """Context manager: pin `host` to `ips` so the actual socket connects only to a validated IP."""

    def __init__(self, host, ips):
        self.host = (host or "").lower()
        self.ips = ips

    def __enter__(self):
        _lock.acquire()
        _pinned[self.host] = self.ips
        return self

    def __exit__(self, *exc):
        _pinned.pop(self.host, None)
        _lock.release()
        return False
