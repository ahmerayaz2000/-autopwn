"""SSL/TLS inspection module: certificate expiry, weak protocols, self-signed detection."""
import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _make_finding(title: str, description: str, evidence: str,
                  severity: str, cvss: float, remediation: str,
                  ftype: str = "vulnerability") -> Dict[str, Any]:
    return {
        "type": ftype,
        "title": title,
        "description": description,
        "evidence": evidence,
        "severity": severity,
        "cvss": cvss,
        "module": "ssl",
        "remediation": remediation,
    }


async def run(hostname: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    print("[*] [SSL/TLS] Starting SSL/TLS security check...")
    loop = asyncio.get_event_loop()

    # ── Fetch DER-encoded certificate ────────────────────────────────────────
    cert_der: Optional[bytes] = await loop.run_in_executor(None, _get_cert_der, hostname)

    if cert_der is None:
        findings.append(_make_finding(
            "SSL/TLS Unavailable",
            f"Could not establish an SSL/TLS connection to {hostname}:443.",
            "No certificate retrieved.",
            "INFO", 0.0,
            "Ensure the server is accessible on port 443 and has a valid certificate.",
            "info",
        ))
        print(f"[+] [SSL/TLS] Complete — {len(findings)} finding(s)")
        return findings

    # ── Parse certificate ─────────────────────────────────────────────────────
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        now = datetime.now(timezone.utc)

        # Handle both cryptography >= 42 (utc-aware) and older (naive) versions
        try:
            exp = cert.not_valid_after_utc
            start = cert.not_valid_before_utc
        except AttributeError:
            exp = cert.not_valid_after.replace(tzinfo=timezone.utc)      # type: ignore[attr-defined]
            start = cert.not_valid_before.replace(tzinfo=timezone.utc)   # type: ignore[attr-defined]

        days_left = (exp - now).days

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []

        wildcards = [s for s in sans if s.startswith("*.")]

        findings.append(_make_finding(
            "SSL Certificate Information",
            f"Certificate details for {hostname}.",
            (
                f"Subject      : {cert.subject.rfc4514_string()}\n"
                f"Issuer       : {cert.issuer.rfc4514_string()}\n"
                f"Valid From   : {start.strftime('%Y-%m-%d')}\n"
                f"Valid Until  : {exp.strftime('%Y-%m-%d')}\n"
                f"Days Left    : {days_left}\n"
                f"SANs         : {', '.join(sans[:10]) or 'None'}\n"
                f"Wildcards    : {', '.join(wildcards) or 'None'}"
            ),
            "INFO", 0.0,
            "Ensure the certificate covers all required hostnames and is renewed before expiry.",
            "info",
        ))

        # Expiry checks
        if days_left < 0:
            findings.append(_make_finding(
                "SSL Certificate Expired",
                f"Certificate expired {abs(days_left)} days ago on {exp.strftime('%Y-%m-%d')}.",
                f"Expiry : {exp.strftime('%Y-%m-%d %H:%M UTC')}\nExpired: {abs(days_left)} days ago",
                "CRITICAL", 9.8,
                "Renew the SSL certificate immediately.",
            ))
        elif days_left < 14:
            findings.append(_make_finding(
                f"SSL Certificate Expires in {days_left} Days (Critical)",
                f"Certificate will expire on {exp.strftime('%Y-%m-%d')}.",
                f"Expiry   : {exp.strftime('%Y-%m-%d %H:%M UTC')}\nDays left: {days_left}",
                "CRITICAL", 9.8,
                "Renew the SSL certificate immediately.",
            ))
        elif days_left < 30:
            findings.append(_make_finding(
                f"SSL Certificate Expiring Soon ({days_left} Days)",
                f"Certificate will expire on {exp.strftime('%Y-%m-%d')}.",
                f"Expiry   : {exp.strftime('%Y-%m-%d %H:%M UTC')}\nDays left: {days_left}",
                "HIGH", 7.5,
                "Schedule certificate renewal as soon as possible.",
            ))

    except ImportError:
        findings.append(_make_finding(
            "cryptography Library Not Installed",
            "Certificate parsing skipped — install cryptography: pip install cryptography",
            "",
            "INFO", 0.0, "", "error",
        ))
    except Exception as exc:
        findings.append(_make_finding(
            "Certificate Parsing Error",
            f"Could not parse certificate: {exc}",
            str(exc),
            "INFO", 0.0, "", "error",
        ))

    # ── Self-signed check ─────────────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                pass
    except ssl.SSLCertVerificationError as exc:
        msg = str(exc).lower()
        if "self" in msg and "sign" in msg:
            findings.append(_make_finding(
                "Self-Signed SSL Certificate",
                "The certificate is not issued by a trusted Certificate Authority.",
                str(exc),
                "HIGH", 7.4,
                "Replace with a certificate from a trusted CA (e.g., Let's Encrypt).",
            ))
        elif "expired" not in msg:
            findings.append(_make_finding(
                "SSL Certificate Verification Failed",
                f"Certificate validation error: {exc}",
                str(exc),
                "MEDIUM", 5.9,
                "Investigate and resolve the certificate chain/validation issue.",
            ))
    except Exception:
        pass

    # ── Weak protocol checks ──────────────────────────────────────────────────
    proto_findings = await loop.run_in_executor(None, _check_old_protocols, hostname)
    findings.extend(proto_findings)

    print(f"[+] [SSL/TLS] Complete — {len(findings)} finding(s)")
    return findings


def _get_cert_der(hostname: str) -> Optional[bytes]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert(binary_form=True)
    except Exception:
        return None


def _check_old_protocols(hostname: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    candidates = {
        "TLSv1":   ("HIGH",     7.4, "TLS 1.0 is deprecated (RFC 8996). Disable and enforce TLS 1.2+."),
        "TLSv1_1": ("HIGH",     7.4, "TLS 1.1 is deprecated (RFC 8996). Disable and enforce TLS 1.2+."),
    }

    for attr_name, (severity, cvss, remediation) in candidates.items():
        proto_version = getattr(ssl.TLSVersion, attr_name, None)
        if proto_version is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto_version
            ctx.maximum_version = proto_version
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    label = attr_name.replace("_", ".")
                    findings.append(_make_finding(
                        f"Deprecated Protocol Supported: {label}",
                        f"Server accepted a {label} handshake.",
                        f"Successfully negotiated {label} with {hostname}:443",
                        severity, cvss, remediation,
                    ))
        except Exception:
            pass

    return findings
