"""Safe TLS analysis.

Checks certificate validity, expiration, hostname match and basic metadata
using the standard library ``ssl`` plus ``cryptography`` for certificate
parsing. No attempts are made to bypass TLS protections.
"""

import datetime as dt
import logging
import socket
import ssl
import warnings
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.config import Settings
from app.scanners.base import TLSResult

logger = logging.getLogger(__name__)


class TLSScanner:
    """Inspect the TLS configuration of an authorized HTTPS target."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._timeout = settings.WEB_CONNECT_TIMEOUT

    def scan(self, hostname: str, port: int = 443) -> TLSResult:
        result = TLSResult(hostname=hostname, port=port)
        peer_der: Optional[bytes] = None
        errors: list[str] = []

        # 1) Strict handshake (certificate + hostname verification).
        try:
            peer_der = self._handshake(hostname, port, verify=True)
            result.connected = True
            result.cert_valid = True
        except ssl.SSLCertVerificationError as exc:
            errors.append(str(exc))
            result.connected = True
            result.cert_valid = False
            msg = exc.verify_message or ""
            result.hostname_mismatch = any(
                token in msg
                for token in ("IP address mismatch", "Hostname mismatch", "not valid for")
            )
            # Still fetch the certificate (without verification) for metadata.
            try:
                peer_der = self._handshake(hostname, port, verify=False)
            except Exception as inner:  # noqa: BLE001
                errors.append(f"Could not retrieve certificate: {inner}")
        except (socket.timeout, OSError) as exc:
            errors.append(f"TLS connection failed: {exc}")
            result.errors = errors
            return result
        except Exception as exc:  # noqa: BLE001
            errors.append(f"TLS handshake error: {exc}")
            result.errors = errors
            return result

        # 2) Negotiated version from the strict handshake.
        try:
            with self._open_connection(hostname, port, verify=True) as conn:
                result.tls_version = conn.version()
        except Exception:  # noqa: BLE001
            pass

        # 3) Certificate metadata.
        if peer_der:
            self._analyze_certificate(peer_der, hostname, result)

        # 4) Legacy protocol probe (TLS 1.0 / 1.1) — best effort.
        result.legacy_tls_supported = self._legacy_tls_probe(hostname, port)

        result.errors = errors
        return result

    # -- internals ----------------------------------------------------------

    def _handshake(self, hostname: str, port: int, verify: bool) -> bytes:
        with self._open_connection(hostname, port, verify=verify) as conn:
            der = conn.getpeercert(binary_form=True)
            if not der:
                raise ssl.SSLError("No peer certificate presented")
            return der

    def _open_connection(self, hostname: str, port: int, verify: bool):
        if verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((hostname, port), timeout=self._timeout)
        conn = ctx.wrap_socket(raw, server_hostname=hostname)
        return _CloseOnExit(conn)

    def _analyze_certificate(self, der: bytes, hostname: str, result: TLSResult) -> None:
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Could not parse certificate: {exc}")
            return

        result.not_before = cert.not_valid_before_utc.isoformat()
        result.not_after = cert.not_valid_after_utc.isoformat()
        result.days_to_expiry = (cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).total_seconds() / 86400

        result.issuer = _dn_to_str(cert.issuer)
        result.subject = _dn_to_str(cert.subject)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            result.san = ", ".join(san.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            result.san = None

        result.self_signed = result.subject == result.issuer

        now = dt.datetime.now(dt.timezone.utc)
        if result.days_to_expiry < 0:
            result.cert_valid = False
        elif result.not_before and result.not_after and not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            result.cert_valid = False

        # Hostname match against SAN (simple containment check).
        if result.san and hostname:
            result.hostname_mismatch = result.hostname_mismatch or (
                hostname not in [s for s in result.san.split(", ")]
                and not any(_wildcard_matches(h, hostname) for h in result.san.split(", "))
            )

    def _legacy_tls_probe(self, hostname: str, port: int) -> bool:
        # TLS 1.0/1.1 enum members are deprecated in newer CPython; probe them
        # best-effort and never fail the scan if the runtime refuses.
        legacy_members = ("TLSv1", "TLSv1_1")
        for member_name in legacy_members:
            try:
                member = getattr(ssl.TLSVersion, member_name)
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = member
                    ctx.maximum_version = member
                raw = socket.create_connection((hostname, port), timeout=3)
                with ctx.wrap_socket(raw, server_hostname=hostname) as conn:
                    if conn.version():
                        return True
            except Exception:  # noqa: BLE001
                continue
        return False


class _CloseOnExit:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self._conn

    def __exit__(self, *exc):
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass
        return False


def _dn_to_str(dn: x509.Name) -> str:
    parts = []
    for attr in dn:
        short = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME: "C",
            NameOID.LOCALITY_NAME: "L",
        }.get(attr.oid, attr.oid._name)
        parts.append(f"{short}={attr.value}")
    return ", ".join(parts)


def _wildcard_matches(pattern: str, hostname: str) -> bool:
    if not pattern.startswith("*."):
        return False
    return hostname.endswith(pattern[1:])
