"""SSL/TLS audit module (US-06).

Audits SSL/TLS configuration: protocol version, cipher suite,
certificate details, and potential vulnerabilities.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from src.utils.logger import get_logger

logger = get_logger(__name__)

# TLS version mapping
TLS_VERSION_MAP: dict[int, str] = {
    ssl.TLSVersion.TLSv1: "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
    ssl.TLSVersion.TLSv1_2: "TLS 1.2",
    ssl.TLSVersion.TLSv1_3: "TLS 1.3",
}

# Weak cipher keywords
WEAK_CIPHERS = [
    "NULL", "EXPORT", "RC4", "DES", "MD5", "3DES",
    "PSK", "SRP", "aNULL", "eNULL",
]

# Strong ciphers (for TLS 1.2 and below)
STRONG_CIPHERS_PREFIXES = [
    "TLS_AES_256_GCM", "TLS_AES_128_GCM", "TLS_CHACHA20",
    "ECDHE-ECDSA-AES256-GCM", "ECDHE-ECDSA-AES128-GCM",
    "ECDHE-RSA-AES256-GCM", "ECDHE-RSA-AES128-GCM",
    "ECDHE-ECDSA-CHACHA20", "ECDHE-RSA-CHACHA20",
    "DHE-RSA-AES256-GCM", "DHE-RSA-AES128-GCM",
]


def audit_ssl(hostname: str, port: int = 443) -> dict[str, Any]:
    """Audit SSL/TLS configuration for a given hostname and port.

    Args:
        hostname: The target hostname (e.g., ``example.com``).
        port: The target port (default 443).

    Returns:
        A dict with keys:
        - ``status``: ``"success"`` or ``"error"``
        - ``data``: dict containing TLS version, cipher, certificate info,
          and vulnerability assessment
        - ``error``: ``None`` or error message
    """
    logger.info(f"Auditing SSL/TLS for {hostname}:{port}")

    if not hostname or not isinstance(hostname, str):
        return {
            "status": "error",
            "data": {},
            "error": "Invalid hostname",
        }

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                # Get protocol version
                tls_version_num = tls_sock.version()
                tls_version_name = TLS_VERSION_MAP.get(
                    tls_sock._sslobj._get_tls_version_number(),  # type: ignore[attr-defined]
                    tls_version_num or "Unknown",
                )

                # Get cipher suite
                cipher_name, cipher_proto, cipher_bits = tls_sock.cipher()

                # Get certificate
                cert_bin = tls_sock.getpeercert()
                if cert_bin is None:
                    return {
                        "status": "error",
                        "data": {},
                        "error": "No certificate returned by server",
                    }

                # Parse certificate details
                cert_info = _parse_certificate(cert_bin)

                # Assess vulnerabilities
                vulnerabilities = _assess_vulnerabilities(
                    tls_version_name, cipher_name, cert_info,
                )

                return {
                    "status": "success",
                    "data": {
                        "hostname": hostname,
                        "port": port,
                        "tls_version": tls_version_name,
                        "cipher": {
                            "name": cipher_name,
                            "protocol": cipher_proto,
                            "bits": cipher_bits,
                            "is_weak": _is_weak_cipher(cipher_name),
                            "is_strong": _is_strong_cipher(cipher_name),
                        },
                        "certificate": cert_info,
                        "vulnerabilities": vulnerabilities,
                        "secure": len(vulnerabilities) == 0,
                    },
                    "error": None,
                }

    except socket.timeout:
        logger.warning(f"Connection timeout for {hostname}:{port}")
        return {
            "status": "error",
            "data": {},
            "error": f"Connection timeout to {hostname}:{port}",
        }
    except ssl.SSLError as e:
        logger.warning(f"SSL error for {hostname}:{port}: {e}")
        return {
            "status": "error",
            "data": {},
            "error": f"SSL error: {e}",
        }
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {hostname}: {e}")
        return {
            "status": "error",
            "data": {},
            "error": f"DNS resolution failed: {e}",
        }
    except ConnectionRefusedError:
        logger.warning(f"Connection refused for {hostname}:{port}")
        return {
            "status": "error",
            "data": {},
            "error": f"Connection refused to {hostname}:{port}",
        }
    except OSError as e:
        logger.warning(f"Network error for {hostname}:{port}: {e}")
        return {
            "status": "error",
            "data": {},
            "error": f"Network error: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected SSL audit error for {hostname}:{port}: {e}")
        return {
            "status": "error",
            "data": {},
            "error": f"Unexpected error: {e}",
        }


def _parse_certificate(cert: dict[str, Any]) -> dict[str, Any]:
    """Parse an SSL certificate dict into a structured result."""
    # Subject (format: ((('field', 'value'),), ...))
    subject_items = cert.get("subject", [])
    subject_str = ", ".join(
        f"{k}={v}"
        for rdn in subject_items
        for ava in rdn
        for k, v in [ava]  # ava is a (key, value) tuple
    )

    # Issuer
    issuer_items = cert.get("issuer", [])
    issuer_str = ", ".join(
        f"{k}={v}"
        for rdn in issuer_items
        for ava in rdn
        for k, v in [ava]
    )

    # Validity dates
    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")

    not_before = _parse_asn1_time(not_before_str)
    not_after = _parse_asn1_time(not_after_str)
    now = datetime.now(timezone.utc)

    # SAN (Subject Alternative Names)
    san_list: list[str] = []
    san_data = cert.get("subjectAltName", ())
    for san_type, san_value in san_data:
        if san_type == "DNS":
            san_list.append(san_value)

    # OCSP Must-Staple check (via TLS feature extension)
    # This is a best-effort check from the cert dict
    ocsp_must_staple = False
    extensions = cert.get("extensions", [])
    for ext in extensions:
        if "must-staple" in str(ext).lower() or "1.3.6.1.5.5.7.1.24" in str(ext):
            ocsp_must_staple = True
            break

    # Self-signed check
    is_self_signed = subject_str == issuer_str

    # Serial number
    serial_number = str(cert.get("serialNumber", ""))

    # Fingerprint (SHA256)
    fingerprint = cert.get("fingerprint", "") or ""

    return {
        "subject": subject_str,
        "issuer": issuer_str,
        "serial_number": serial_number,
        "not_before": not_before.isoformat() if not_before else "",
        "not_after": not_after.isoformat() if not_after else "",
        "expired": bool(not_after and now > not_after),
        "expires_in_days": (not_after - now).days if not_after and now < not_after else 0,
        "self_signed": is_self_signed,
        "subject_alternative_names": san_list,
        "ocsp_must_staple": ocsp_must_staple,
        "fingerprint_sha256": fingerprint,
    }


def _parse_asn1_time(time_str: str) -> datetime | None:
    """Parse an ASN.1 time string (YYYYMMDDHHMMSSZ) to datetime."""
    if not time_str:
        return None
    try:
        # Handle various formats
        # Format: "May 24 12:34:56 2025 GMT" or "20250524123456Z"
        if "GMT" in time_str or time_str.endswith("Z"):
            clean = time_str.replace(" GMT", "").replace("Z", "")
            for fmt in (
                "%b %d %H:%M:%S %Y",
                "%Y%m%d%H%M%S",
                "%Y-%m-%dT%H:%M:%S",
            ):
                try:
                    return datetime.strptime(clean, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return datetime.strptime(time_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        logger.debug(f"Could not parse time: {time_str}")
        return None


def _is_weak_cipher(cipher_name: str) -> bool:
    """Check if a cipher suite name indicates weak crypto."""
    upper = cipher_name.upper()
    return any(weak in upper for weak in WEAK_CIPHERS)


def _is_strong_cipher(cipher_name: str) -> bool:
    """Check if a cipher suite is considered strong."""
    return any(cipher_name.startswith(prefix) for prefix in STRONG_CIPHERS_PREFIXES)


def _assess_vulnerabilities(
    tls_version: str,
    cipher_name: str,
    cert_info: dict[str, Any],
) -> list[dict[str, Any]]:
    """Assess potential vulnerabilities from TLS config."""
    vulns: list[dict[str, Any]] = []

    # TLS version checks
    if tls_version in ("TLS 1.0", "TLS 1.1"):
        vulns.append({
            "name": "OUTDATED_TLS_VERSION",
            "severity": "HIGH",
            "description": f"{tls_version} is deprecated and insecure",
            "recommendation": "Upgrade to TLS 1.2 or TLS 1.3",
        })
    elif tls_version == "TLS 1.2":
        vulns.append({
            "name": "MODERATE_TLS_VERSION",
            "severity": "LOW",
            "description": "TLS 1.2 is acceptable but TLS 1.3 is preferred",
            "recommendation": "Enable TLS 1.3 if possible",
        })

    # Weak cipher
    if _is_weak_cipher(cipher_name):
        vulns.append({
            "name": "WEAK_CIPHER_SUITE",
            "severity": "HIGH",
            "description": f"Cipher suite '{cipher_name}' is weak",
            "recommendation": "Disable weak ciphers (NULL, EXPORT, RC4, DES, MD5, 3DES)",
        })

    # Expired certificate
    if cert_info.get("expired"):
        vulns.append({
            "name": "EXPIRED_CERTIFICATE",
            "severity": "CRITICAL",
            "description": f"Certificate expired on {cert_info['not_after']}",
            "recommendation": "Renew the certificate immediately",
        })

    # Certificate expiring soon
    expires_in = cert_info.get("expires_in_days", 0)
    if 0 < expires_in <= 30:
        vulns.append({
            "name": "CERTIFICATE_EXPIRING_SOON",
            "severity": "MEDIUM",
            "description": f"Certificate expires in {expires_in} days",
            "recommendation": "Renew the certificate before expiration",
        })

    # Self-signed certificate
    if cert_info.get("self_signed"):
        vulns.append({
            "name": "SELF_SIGNED_CERTIFICATE",
            "severity": "MEDIUM",
            "description": "Certificate is self-signed",
            "recommendation": "Use a certificate from a trusted CA",
        })

    return vulns


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    result = audit_ssl(host, port)
    print(f"Status: {result['status']}")
    if result["data"]:
        print(f"TLS: {result['data']['tls_version']}")
        print(f"Cipher: {result['data']['cipher']['name']} "
              f"({result['data']['cipher']['bits']} bits)")
        print(f"Certificate: {result['data']['certificate']['subject']}")
        print(f"Expires: {result['data']['certificate']['not_after']}")
        print(f"Vulnerabilities: {len(result['data']['vulnerabilities'])}")
        for v in result['data']['vulnerabilities']:
            print(f"  [{v['severity']}] {v['name']}: {v['description']}")
