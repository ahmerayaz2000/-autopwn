#!/usr/bin/env python3
"""AutoPwn - Automated Web Penetration Testing Tool"""
import asyncio
import sys
import os
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from modules import recon, portscan, webscan, headers, ssl_check
from core import aggregator, scorer, reporter

BANNER = r"""
    ___         _        ____
   / _ \ _  _ | |_  ___|  _ \ __ __ __ _ __
  | |_| | || ||  _|/ _ \| |_) |\ V  V /| '_ \
   \___/ \_,_| \__|\___/|____/  \_/\_/ | | | |
                                        |_| |_|
        AutoPwn v1.0  -  Automated Web Pentest
        For authorized security testing ONLY.
"""


async def run_scan(target_url: str) -> None:
    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "https://" + target_url
        parsed = urlparse(target_url)

    hostname = parsed.hostname
    if not hostname:
        print("[!] Invalid URL. Example: python autopwn.py https://example.com")
        sys.exit(1)

    start_time = datetime.now()
    print(f"[*] Target URL  : {target_url}")
    print(f"[*] Hostname    : {hostname}")
    print(f"[*] Scan Start  : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] Modules     : Recon | Port Scan | Web Scan | Headers | SSL/TLS")
    print("[*] Mode        : Parallel (5 concurrent modules)")
    print("-" * 60)

    loop = asyncio.get_event_loop()

    with ThreadPoolExecutor(max_workers=2) as executor:
        tasks = [
            recon.run(hostname),
            loop.run_in_executor(executor, portscan.run_sync, hostname),
            webscan.run(target_url),
            headers.run(target_url),
            ssl_check.run(hostname),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    print("\n" + "-" * 60)
    print("[*] All modules complete. Aggregating results...")

    module_names = ["recon", "portscan", "webscan", "headers", "ssl"]
    results_map = {module_names[i]: results[i] for i in range(len(results))}

    all_findings = aggregator.aggregate(results_map)
    scored_findings = scorer.score(all_findings)
    summary = scorer.get_risk_summary(scored_findings)

    elapsed = (datetime.now() - start_time).seconds

    print(f"\n{'='*60}")
    print("  SCAN RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"  Total Findings : {summary['total_findings']}")
    print(f"  Vulnerabilities: {summary['vuln_count']}")
    print(f"  Critical       : {summary['counts']['CRITICAL']}")
    print(f"  High           : {summary['counts']['HIGH']}")
    print(f"  Medium         : {summary['counts']['MEDIUM']}")
    print(f"  Low            : {summary['counts']['LOW']}")
    print(f"  Info           : {summary['counts']['INFO']}")
    print(f"  Overall Risk   : {summary['overall_rating']}")
    print(f"  Scan Duration  : {elapsed}s")
    print(f"{'='*60}")

    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join("reports", f"autopwn_{hostname}_{timestamp}.pdf")

    reporter.generate(scored_findings, target_url, report_path)

    print(f"\n[+] PDF Report  : {report_path}")
    print(f"[+] Scan End    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n[!] DISCLAIMER: Use only on systems you own or have explicit written permission to test.")


def main() -> None:
    if len(sys.argv) != 2:
        print(BANNER)
        print("Usage  : python autopwn.py <target_url>")
        print("Example: python autopwn.py https://example.com")
        sys.exit(1)

    print(BANNER)
    asyncio.run(run_scan(sys.argv[1]))


if __name__ == "__main__":
    main()
