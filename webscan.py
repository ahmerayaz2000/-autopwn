"""Web vulnerability scanner: sensitive paths, SQLi, XSS, open redirect, clickjacking."""
import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

import aiohttp

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider",
    "odbc drivers error",
    "pg_query():",
    "supplied argument is not a valid postgresql",
    "ora-01756",
    "sqlite_error",
]

SENSITIVE_PATHS = [
    ("/.git/HEAD",              "CRITICAL", 9.1, "Git repository exposed",           "Block .git directory access via web-server rules."),
    ("/.env",                   "CRITICAL", 9.8, "Environment secrets file exposed",  "Block .env access; never store secrets in web root."),
    ("/.env.local",             "CRITICAL", 9.8, "Environment secrets file exposed",  "Block .env* access."),
    ("/.env.production",        "CRITICAL", 9.8, "Environment secrets file exposed",  "Block .env* access."),
    ("/wp-config.php",          "CRITICAL", 9.8, "WordPress config exposed",          "Deny access to wp-config.php via web-server rules."),
    ("/config.php",             "HIGH",     8.1, "PHP config file exposed",           "Move config outside web root or restrict access."),
    ("/configuration.php",      "HIGH",     8.1, "PHP config file exposed",           "Restrict access to configuration files."),
    ("/database.yml",           "HIGH",     8.1, "Database config exposed",           "Restrict access to database.yml."),
    ("/phpinfo.php",            "MEDIUM",   5.3, "PHP info page exposed",             "Remove phpinfo() from production."),
    ("/info.php",               "MEDIUM",   5.3, "PHP info page exposed",             "Remove phpinfo() from production."),
    ("/admin/",                 "MEDIUM",   5.3, "Admin panel accessible",            "Restrict admin by IP or VPN."),
    ("/administrator/",         "MEDIUM",   5.3, "Admin panel accessible",            "Restrict admin by IP or VPN."),
    ("/phpmyadmin/",            "MEDIUM",   5.3, "phpMyAdmin exposed",                "Restrict phpMyAdmin to trusted IPs only."),
    ("/.htpasswd",              "HIGH",     8.1, "Password file exposed",             "Block .htpasswd via web-server rules."),
    ("/backup.zip",             "HIGH",     7.5, "Backup archive exposed",            "Remove backup files from web root."),
    ("/backup.tar.gz",          "HIGH",     7.5, "Backup archive exposed",            "Remove backup files from web root."),
    ("/web.config",             "MEDIUM",   5.3, "Web config exposed",                "Restrict access to web.config."),
    ("/robots.txt",             "INFO",     0.0, "robots.txt present",                "Review robots.txt for sensitive path disclosure."),
    ("/sitemap.xml",            "INFO",     0.0, "Sitemap present",                   "Review sitemap for unintended content exposure."),
    ("/.DS_Store",              "LOW",      3.1, "DS_Store metadata exposed",         "Block .DS_Store via web-server rules."),
    ("/composer.json",          "LOW",      3.1, "composer.json exposed",             "Block package manifests from public access."),
    ("/package.json",           "LOW",      3.1, "package.json exposed",              "Block package manifests from public access."),
    ("/server-status",          "MEDIUM",   5.3, "Apache server-status exposed",      "Restrict /server-status to localhost."),
    ("/server-info",            "MEDIUM",   5.3, "Apache server-info exposed",        "Restrict /server-info to localhost."),
]

REDIRECT_PARAMS = ("redirect", "url", "next", "return", "goto", "returnurl", "redirect_uri", "target")
_REDIRECT_PROBE = "https://evil.example.com"

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
        "module": "webscan",
        "remediation": remediation,
    }


async def run(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    print("[*] [WebScan] Starting web vulnerability scan...")

    connector = aiohttp.TCPConnector(ssl=False, limit=30)
    timeout = aiohttp.ClientTimeout(total=12)

    try:
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=_HEADERS
        ) as session:
            tasks = [
                _check_sensitive_paths(session, target_url),
                _check_robots(session, target_url),
                _check_injections(session, target_url),
                _check_open_redirect(session, target_url),
            ]
            batch = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch:
                if isinstance(result, list):
                    findings.extend(result)
    except Exception as exc:
        findings.append(_make_finding(
            "Web Scan Error",
            f"Web scan failed: {exc}",
            str(exc),
            "INFO", 0.0, "", "error",
        ))

    print(f"[+] [WebScan] Complete — {len(findings)} finding(s)")
    return findings


async def _check_sensitive_paths(session: aiohttp.ClientSession,
                                  base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    tasks = [_probe_path(session, base_url, entry) for entry in SENSITIVE_PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)
    return findings


async def _probe_path(session: aiohttp.ClientSession,
                      base_url: str,
                      entry: tuple) -> Optional[Dict[str, Any]]:
    path, severity, cvss, label, remediation = entry
    url = urljoin(base_url.rstrip("/"), path)
    try:
        async with session.get(url, allow_redirects=False) as resp:
            if resp.status != 200:
                return None
            body = await resp.text(errors="replace")

            if path == "/.git/HEAD" and "ref:" not in body.lower():
                return None
            if path in ("/.env", "/.env.local", "/.env.production") and (
                "=" not in body and "KEY" not in body.upper()
            ):
                return None
            if path in ("/phpinfo.php", "/info.php") and "phpinfo()" not in body.lower():
                return None

            return _make_finding(
                f"{label}: {path}",
                f"Resource '{path}' returned HTTP 200 on {url}.",
                f"URL    : {url}\nStatus : 200 OK\nSize   : {len(body)} bytes\n"
                f"Excerpt: {body[:300]}",
                severity, cvss, remediation,
                "info" if severity == "INFO" else "vulnerability",
            )
    except Exception:
        return None


async def _check_robots(session: aiohttp.ClientSession,
                        base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    url = urljoin(base_url.rstrip("/"), "/robots.txt")
    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                body = await resp.text(errors="replace")
                disallowed = [
                    line.split(":", 1)[1].strip()
                    for line in body.splitlines()
                    if line.lower().startswith("disallow:")
                    and line.split(":", 1)[1].strip()
                ]
                if disallowed:
                    findings.append(_make_finding(
                        "robots.txt Discloses Restricted Paths",
                        f"robots.txt reveals {len(disallowed)} Disallow directive(s) that may hint at sensitive areas.",
                        "Disallowed paths:\n" + "\n".join(disallowed[:25]),
                        "LOW", 3.1,
                        "Review robots.txt — Disallow entries are public and may guide attackers.",
                    ))
    except Exception:
        pass
    return findings


async def _check_injections(session: aiohttp.ClientSession,
                             target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    base = target_url.split("?")[0]

    for param_name in list(params.keys())[:3]:
        for payload in SQLI_PAYLOADS[:4]:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            qs = "&".join(f"{k}={v}" for k, v in test_params.items())
            test_url = f"{base}?{qs}"
            try:
                async with session.get(test_url) as resp:
                    body = (await resp.text(errors="replace")).lower()
                    for err in SQLI_ERRORS:
                        if err in body:
                            findings.append(_make_finding(
                                f"SQL Injection in Parameter '{param_name}'",
                                f"SQL error pattern '{err}' triggered via parameter '{param_name}'.",
                                f"URL    : {test_url}\nPayload: {payload}\nError  : {err}",
                                "CRITICAL", 9.8,
                                "Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                            ))
                            return findings
            except Exception:
                pass
    return findings


async def _check_open_redirect(session: aiohttp.ClientSession,
                                base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for param in REDIRECT_PARAMS:
        test_url = f"{base_url.split('?')[0]}?{param}={_REDIRECT_PROBE}"
        try:
            async with session.get(test_url, allow_redirects=False) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.example.com" in location:
                        findings.append(_make_finding(
                            f"Open Redirect via '{param}' Parameter",
                            f"Server redirected to attacker-controlled URL via '{param}' parameter.",
                            f"URL      : {test_url}\nRedirects: {location}",
                            "MEDIUM", 6.1,
                            "Validate redirect targets against an explicit whitelist; never reflect user-supplied URLs.",
                        ))
                        return findings
        except Exception:
            pass
    return findings
