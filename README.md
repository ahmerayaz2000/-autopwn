# AutoPwn — Automated Web Penetration Testing Tool

> Give it a URL. Get a full security report in under 90 seconds.

AutoPwn runs **5 security modules in parallel**, scores every finding by **CVSSv3 severity**, and generates a **professional PDF report**  with zero human intervention after the URL is entered.

---

## Demo

```
python autopwn.py https://target.com
```

```
[*] Target URL  : https://target.com
[*] Modules     : Recon | Port Scan | Web Scan | Headers | SSL/TLS
[*] Mode        : Parallel (5 concurrent modules)
------------------------------------------------------------
[+] [Recon]    Complete — 3 finding(s)
[+] [PortScan] Complete — 4 finding(s)
[+] [WebScan]  Complete — 5 finding(s)
[+] [Headers]  Complete — 11 finding(s)
[+] [SSL/TLS]  Complete — 3 finding(s)
------------------------------------------------------------

============================================================
  SCAN RESULTS SUMMARY
============================================================
  Total Findings : 17        Vulnerabilities : 10
  Critical       : 2         High            : 3
  Medium         : 3         Low             : 2
  Overall Risk   : CRITICAL
============================================================

[+] PDF Report  : reports/autopwn_target.com_20260603_120000.pdf
```

---

## Features

| Module | What it checks |
|--------|---------------|
| **Recon** | DNS records (A/MX/NS/TXT/SOA), WHOIS, zone-transfer vulnerability, reverse DNS |
| **Port Scan** | Nmap top-1000 ports, flags 20 high-risk services (SMB, RDP, Redis, MongoDB…) |
| **Web Scan** | SQL injection, open redirect, 25+ sensitive paths (.env, .git, phpinfo, admin…) |
| **Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, server tech disclosure |
| **SSL/TLS** | Certificate expiry, self-signed certs, deprecated TLS 1.0/1.1 support |

**PDF Report includes:**
- Cover page with risk rating
- Executive summary with severity breakdown
- Findings index with CVSS scores
- Detailed evidence + remediation for every finding
- Prioritised remediation table

---

## Requirements

- Python 3.11+
- [Nmap](https://nmap.org/download.html) installed and in PATH

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/autopwn.git
cd autopwn

python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

pip install -r requirements.txt
```

---

## Usage

```bash
python autopwn.py <target_url>

# Examples
python autopwn.py https://example.com
python autopwn.py http://testaspnet.vulnweb.com
```

Reports are saved to `reports/autopwn_<host>_<timestamp>.pdf`

---

## Project Structure

```
autopwn/
├── autopwn.py              # Entry point — parallel orchestration
├── modules/
│   ├── recon.py            # DNS, WHOIS, zone transfer
│   ├── portscan.py         # Nmap wrapper, 20 high-risk port rules
│   ├── webscan.py          # Sensitive paths, SQLi, open redirect
│   ├── headers.py          # HTTP security header audit
│   └── ssl_check.py        # Certificate & protocol checks
├── core/
│   ├── aggregator.py       # Normalises findings → Finding dataclass
│   ├── scorer.py           # CVSSv3 severity classification
│   └── reporter.py         # ReportLab PDF generation
├── wordlists/              # Reserved for path bruteforce wordlists
├── reports/                # PDF output (git-ignored)
└── requirements.txt
```

---

## CVSSv3 Severity Scale

| Score | Severity | Examples |
|-------|----------|---------|
| 9.0 – 10.0 | **CRITICAL** | SQLi, exposed .env, SMB/RDP open, MongoDB no-auth |
| 7.0 – 8.9  | **HIGH** | HSTS missing, expired SSL cert, FTP open |
| 4.0 – 6.9  | **MEDIUM** | Missing CSP/X-Frame-Options, admin panel exposed |
| 0.1 – 3.9  | **LOW** | Referrer-Policy missing, server header disclosure |
| 0.0        | **INFO** | DNS records, open ports summary, WHOIS data |

---

## Legal Disclaimer

> This tool is for **authorised security testing only**.
> Only run AutoPwn against systems you own or have **explicit written permission** to test.
> Unauthorised use is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.

---

*Built with Python — asyncio · aiohttp · python-nmap · dnspython · cryptography · ReportLab*
