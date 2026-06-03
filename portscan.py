"""Port-scan module: Nmap wrapper with risk-rated findings."""
from typing import Any, Dict, List

# (port) -> (label, severity, cvss, remediation)
HIGH_RISK_PORTS: Dict[int, tuple] = {
    21:    ("FTP",        "HIGH",     7.5, "Replace FTP with SFTP or FTPS; FTP transmits credentials in plaintext."),
    22:    ("SSH",        "MEDIUM",   4.0, "Restrict SSH to key-based authentication; disable password login."),
    23:    ("Telnet",     "CRITICAL", 9.1, "Disable Telnet immediately — all traffic including credentials is plaintext."),
    25:    ("SMTP",       "MEDIUM",   5.3, "Restrict SMTP relay; ensure authenticated submission only."),
    53:    ("DNS",        "LOW",      3.7, "Restrict recursive DNS; limit zone transfers to authorised secondaries."),
    110:   ("POP3",       "MEDIUM",   5.3, "Use POP3S (port 995); plain POP3 leaks credentials."),
    111:   ("RPC",        "HIGH",     7.5, "Block RPC portmapper from external access."),
    135:   ("MSRPC",      "HIGH",     7.5, "Restrict Windows RPC to internal networks and apply MS patches."),
    139:   ("NetBIOS",    "HIGH",     8.8, "Block NetBIOS at the perimeter firewall."),
    143:   ("IMAP",       "MEDIUM",   5.3, "Use IMAPS (port 993); plain IMAP leaks credentials."),
    445:   ("SMB",        "CRITICAL", 9.8, "Block SMB at the perimeter — vulnerable to EternalBlue/WannaCry."),
    1433:  ("MSSQL",      "CRITICAL", 9.8, "Restrict MS SQL to internal networks; never expose to internet."),
    1521:  ("Oracle DB",  "CRITICAL", 9.8, "Restrict Oracle DB to application servers; never expose externally."),
    2049:  ("NFS",        "HIGH",     8.1, "Restrict NFS exports; never expose to the internet."),
    3306:  ("MySQL",      "CRITICAL", 9.8, "Restrict MySQL to localhost or application server only."),
    3389:  ("RDP",        "CRITICAL", 9.8, "Block RDP externally or place behind VPN; patch BlueKeep (CVE-2019-0708)."),
    5432:  ("PostgreSQL", "CRITICAL", 9.8, "Restrict PostgreSQL to localhost or application server only."),
    5900:  ("VNC",        "CRITICAL", 9.8, "Disable VNC or restrict to VPN; enforce strong authentication."),
    6379:  ("Redis",      "CRITICAL", 9.8, "Bind Redis to 127.0.0.1 and require AUTH password."),
    27017: ("MongoDB",    "CRITICAL", 9.8, "Enable MongoDB authentication; bind to localhost only."),
}


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
        "module": "portscan",
        "remediation": remediation,
    }


def run_sync(hostname: str) -> List[Dict[str, Any]]:
    """Blocking Nmap scan — run via ThreadPoolExecutor from autopwn.py."""
    findings: List[Dict[str, Any]] = []
    print("[*] [PortScan] Starting Nmap port scan (top 1000 ports)...")

    try:
        import nmap  # python-nmap

        nm = nmap.PortScanner()
        nm.scan(hostname, arguments="-sV -T4 --top-ports 1000 --open")

        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    svc = nm[host][proto][port]
                    if svc["state"] != "open":
                        continue

                    label = svc.get("name", "unknown")
                    product = svc.get("product", "")
                    version = svc.get("version", "")
                    open_ports.append(
                        f"{port}/{proto}  {label}  {product} {version}".strip()
                    )

                    if port in HIGH_RISK_PORTS and HIGH_RISK_PORTS[port][1] != "INFO":
                        svc_label, severity, cvss, rem = HIGH_RISK_PORTS[port]
                        findings.append(_make_finding(
                            f"High-Risk Port Open: {port}/{proto} ({svc_label})",
                            f"Port {port} ({svc_label}) is open on {hostname}. "
                            f"Service: {product} {version}".strip(),
                            f"Port    : {port}/{proto}\nService : {label}\n"
                            f"Product : {product} {version}".strip(),
                            severity, cvss, rem,
                        ))

        findings.insert(0, _make_finding(
            "Open Ports Summary",
            f"Found {len(open_ports)} open port(s) on {hostname}.",
            "\n".join(open_ports) if open_ports else "No open ports detected.",
            "INFO", 0.0,
            "Close unnecessary ports; apply firewall rules to restrict access.",
            "info",
        ))

    except ImportError:
        findings.append(_make_finding(
            "python-nmap Not Installed",
            "Port scan skipped — python-nmap is not installed.",
            "pip install python-nmap",
            "INFO", 0.0, "", "error",
        ))
    except Exception as exc:
        msg = str(exc)
        nmap_missing = "nmap program was not found" in msg.lower() or "nmap executable" in msg.lower()
        findings.append(_make_finding(
            "Port Scan Failed — Nmap Not in PATH" if nmap_missing else "Port Scan Error",
            "Nmap binary not found. Install Nmap from https://nmap.org and add it to PATH."
            if nmap_missing else f"Unexpected error during port scan: {msg}",
            msg,
            "INFO", 0.0,
            "Download and install Nmap from https://nmap.org, then add its install directory to PATH.",
            "error",
        ))

    print(f"[+] [PortScan] Complete — {len(findings)} finding(s)")
    return findings
