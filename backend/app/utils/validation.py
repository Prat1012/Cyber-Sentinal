"""Input validation helpers.

Targets are strictly validated so that only IP addresses, hostnames and
explicitly authorized lab targets are accepted. Values containing shell
metacharacters, whitespace or path separators are rejected outright.
"""

import ipaddress
import re
import socket
from typing import Optional

from app.utils.errors import ValidationFailedError

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$"
)

# Characters that must never appear in a target string (defense in depth).
_FORBIDDEN_CHARS = set(";|&$`\"'\\<>(){}[]*?~! \t\r\n\u0000")


def validate_target_address(address: str) -> tuple[str, str]:
    """Validate a target address.

    Returns ``(normalized_address, address_type)`` where address_type is
    ``"ip"`` or ``"hostname"``. Raises ``ValidationFailedError`` for anything
    that is not a clean IP address or hostname.
    """
    if not address or len(address) > 253:
        raise ValidationFailedError("Target address is empty or too long.")

    if any(ch in _FORBIDDEN_CHARS for ch in address):
        raise ValidationFailedError(
            "Target address contains forbidden characters; only IP addresses "
            "and hostnames are accepted."
        )

    # Try IP first.
    try:
        ip = ipaddress.ip_address(address)
        return str(ip), "ip"
    except ValueError:
        pass

    # CIDR ranges are allowed as *scan* targets too (handled by nmap), but for
    # single targets we keep hostname semantics; a slash is not a hostname.
    if "/" in address:
        raise ValidationFailedError("Target address must be a single IP or hostname.")

    # Hostname.
    if not _HOSTNAME_RE.match(address):
        raise ValidationFailedError("Target is not a valid IP address or hostname.")

    # localhost and single-label names are fine for a lab, but a hostname
    # consisting only of digits is actually an IP that failed to parse.
    if address.replace(".", "").isdigit():
        raise ValidationFailedError("Target is not a valid IP address or hostname.")

    return address.lower(), "hostname"


def is_loopback_or_private(ip: str) -> bool:
    """True for loopback, link-local and RFC1918 private addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_reserved  # e.g. 0.0.0.0, broadcast handling below
        or ip == "0.0.0.0"
    )


def target_is_locally_authorized(address: str, address_type: str) -> bool:
    """Check a target is within the default authorized lab scope."""
    if address_type == "hostname":
        return address.lower() == "localhost" or address.lower() == "ip6-localhost"
    return is_loopback_or_private(address)


def resolve_hostname_to_ips(hostname: str) -> list[str]:
    """Best-effort DNS resolution; returns [] on failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, OSError):
        return []
    ips = sorted({info[4][0] for info in infos})
    return ips


def sanitize_filename(name: str) -> str:
    """Strip path separators and control characters from a filename."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    cleaned = cleaned.strip("._")
    return cleaned or "file"


def validate_port_range(value: str, max_ports: int = 1024) -> str:
    """Validate an nmap-style port range.

    Accepts ``top-100`` / ``top-1000`` or a single port / ``a-b`` range.
    Limits the number of ports to ``max_ports`` to keep scans controlled.
    """
    v = value.strip().lower()
    if v in {"top-100", "top-1000"}:
        return v

    m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", v)
    if not m:
        raise ValidationFailedError(
            "port_range must be 'top-100', 'top-1000' or a numeric range like '1-1024'."
        )
    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else start
    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        raise ValidationFailedError("Invalid port range bounds.")
    if (end - start + 1) > max_ports:
        raise ValidationFailedError(
            f"Port range is too large (max {max_ports} ports per scan)."
        )
    return f"{start}-{end}"


def validate_username(username: str) -> None:
    if not (3 <= len(username) <= 64):
        raise ValidationFailedError("Username must be between 3 and 64 characters.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        raise ValidationFailedError(
            "Username may only contain letters, digits, '.', '_' and '-'."
        )


def validate_password(password: str) -> None:
    if len(password) < 8:
        raise ValidationFailedError("Password must be at least 8 characters.")
    if len(password.encode("utf-8")) > 72:
        raise ValidationFailedError("Password is too long (max 72 bytes).")
