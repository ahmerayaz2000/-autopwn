"""Reconnaissance module: DNS enumeration, WHOIS, and zone-transfer checks."""
import asyncio
import json
import socket
from typing import Any, Dict, List


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
        "module": "recon",
        "remediation": remediation,
    }


async def run(hostname: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    print("[*] [Recon] Starting DNS & WHOIS reconnaissance...")
    loop = asyncio.get_event_loop()

    # ── DNS records ──────────────────────────────────────────────────────────
    dns_records: Dict[str, List[str]] = {}
    try:
        import dns.resolver
        import dns.zone
        import dns.query

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                answers = resolver.resolve(hostname, rtype)
                dns_records[rtype] = [str(r) for r in answers]
            except Exception:
                pass

        findings.append(_make_finding(
            "DNS Records Enumerated",
            f"Collected DNS records for {hostname}.",
            json.dumps(dns_records, indent=2),
            "INFO", 0.0,
            "Review exposed DNS records for sensitive information.",
            "info",
        ))

        # Zone-transfer attempt
        for ns in dns_records.get("NS", []):
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns.rstrip("."), hostname, timeout=5)
                )
                if zone:
                    findings.append(_make_finding(
                        "DNS Zone Transfer Allowed",
                        f"DNS zone transfer succeeded from nameserver {ns}.",
                        f"Zone transfer from {ns} returned {len(list(zone.nodes.keys()))} records.",
                        "HIGH", 7.5,
                        "Restrict AXFR to authorised secondary nameservers only.",
                    ))
            except Exception:
                pass

    except ImportError:
        findings.append(_make_finding(
            "dnspython Not Installed",
            "DNS reconnaissance skipped — dnspython unavailable.",
            "pip install dnspython",
            "INFO", 0.0, "", "info",
        ))

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    try:
        import whois  # python-whois

        w = await loop.run_in_executor(None, whois.whois, hostname)
        whois_data: Dict[str, str] = {}
        for field in ("registrar", "creation_date", "expiration_date",
                      "name_servers", "org", "emails"):
            val = getattr(w, field, None)
            if val:
                whois_data[field] = str(val)

        findings.append(_make_finding(
            "WHOIS Information Retrieved",
            f"Domain registration metadata for {hostname}.",
            json.dumps(whois_data, indent=2),
            "INFO", 0.0,
            "Enable WHOIS privacy protection to hide registrant contact details.",
            "info",
        ))
    except ImportError:
        pass
    except Exception:
        pass

    # ── IP resolution + reverse DNS ──────────────────────────────────────────
    try:
        ip = socket.gethostbyname(hostname)
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except Exception:
            rdns = "N/A"
        findings.append(_make_finding(
            "IP Address & Reverse DNS",
            f"{hostname} resolves to {ip} (reverse: {rdns}).",
            f"A record : {ip}\nReverse  : {rdns}",
            "INFO", 0.0,
            "Ensure reverse-DNS names don't leak internal naming conventions.",
            "info",
        ))
    except Exception:
        pass

    print(f"[+] [Recon] Complete — {len(findings)} finding(s)")
    return findings
