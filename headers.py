"""HTTP security-headers audit module."""
from typing import Any, Dict, List

import aiohttp

REQUIRED_HEADERS: Dict[str, Dict[str, Any]] = {
    "Strict-Transport-Security": {
        "severity": "HIGH", "cvss": 7.4,
        "description": "HSTS missing — enables protocol-downgrade and cookie-hijacking attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM", "cvss": 6.1,
        "description": "CSP missing — increases the impact of XSS vulnerabilities.",
        "remediation": "Implement a strict Content-Security-Policy header tailored to your application.",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM", "cvss": 5.3,
        "description": "X-Content-Type-Options missing — enables MIME-sniffing attacks.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM", "cvss": 6.1,
        "description": "X-Frame-Options missing — site may be embedded in iframes (clickjacking).",
        "remediation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing is required internally)",
    },
    "Referrer-Policy": {
        "severity": "LOW", "cvss": 3.1,
        "description": "Referrer-Policy missing — sensitive URL fragments may leak via Referer header.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW", "cvss": 3.1,
        "description": "Permissions-Policy missing — browser features (camera, mic, geo) may be over-permissive.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

DISCLOSURE_HEADERS = (
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
)

_HEADERS = {"User-Agent": "AutoPwn/1.0 (Authorized Security Scanner)"}


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
        "module": "headers",
        "remediation": remediation,
    }


async def run(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    print("[*] [Headers] Auditing HTTP security headers...")

    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=15)

    try:
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=_HEADERS
        ) as session:
            async with session.get(target_url) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                present = set(resp_headers.keys())

                # Enumerate all headers
                raw_dump = "\n".join(
                    f"{k}: {v}" for k, v in list(resp.headers.items())[:40]
                )
                findings.append(_make_finding(
                    "HTTP Response Headers Enumerated",
                    f"Collected {len(resp.headers)} response headers from {target_url}.",
                    raw_dump,
                    "INFO", 0.0,
                    "Review all response headers for security misconfigurations.",
                    "info",
                ))

                # Missing security headers
                for header, meta in REQUIRED_HEADERS.items():
                    if header.lower() not in present:
                        findings.append(_make_finding(
                            f"Missing Security Header: {header}",
                            meta["description"],
                            f"Header '{header}' is absent from the response.",
                            meta["severity"], meta["cvss"], meta["remediation"],
                        ))

                # HSTS value checks
                hsts_val = resp_headers.get("strict-transport-security", "")
                if hsts_val:
                    if "max-age=0" in hsts_val:
                        findings.append(_make_finding(
                            "HSTS Explicitly Disabled (max-age=0)",
                            "HSTS is disabled — downgrade attacks are possible.",
                            f"Strict-Transport-Security: {hsts_val}",
                            "HIGH", 7.4,
                            "Set max-age to at least 31536000 (one year).",
                        ))
                    elif "includesubdomains" not in hsts_val.lower():
                        findings.append(_make_finding(
                            "HSTS Missing includeSubDomains",
                            "Subdomains are not covered by HSTS, leaving them vulnerable.",
                            f"Strict-Transport-Security: {hsts_val}",
                            "LOW", 3.1,
                            "Append '; includeSubDomains' to the HSTS header.",
                        ))

                # Information-disclosure headers
                for dh in DISCLOSURE_HEADERS:
                    val = resp_headers.get(dh.lower(), "")
                    if val:
                        findings.append(_make_finding(
                            f"Server Technology Disclosed: {dh}",
                            f"The '{dh}' header reveals implementation details to potential attackers.",
                            f"{dh}: {val}",
                            "LOW", 3.1,
                            f"Remove or redact the '{dh}' response header at the web-server/proxy level.",
                        ))

                # HTTP (not HTTPS) check
                if target_url.startswith("http://"):
                    findings.append(_make_finding(
                        "Plain HTTP Used (No TLS)",
                        "The target is served over unencrypted HTTP.",
                        f"URL: {target_url}",
                        "HIGH", 7.4,
                        "Redirect all HTTP traffic to HTTPS and enable HSTS.",
                    ))

    except Exception as exc:
        findings.append(_make_finding(
            "Header Audit Failed",
            f"Could not fetch headers from {target_url}: {exc}",
            str(exc),
            "INFO", 0.0, "", "error",
        ))

    print(f"[+] [Headers] Complete — {len(findings)} finding(s)")
    return findings
