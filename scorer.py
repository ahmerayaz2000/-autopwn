"""CVSSv3-based severity normalisation and risk summary."""
from typing import Dict, List

from core.aggregator import Finding

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_CVSS_TO_SEVERITY = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFO"),
]


def score(findings: List[Finding]) -> List[Finding]:
    """Re-classify severity from CVSS score so labels stay consistent."""
    for f in findings:
        for threshold, label in _CVSS_TO_SEVERITY:
            if f.cvss >= threshold:
                f.severity = label
                break
    return findings


def get_risk_summary(findings: List[Finding]) -> Dict:
    counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    total_cvss = 0.0
    vuln_count = 0

    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.cvss > 0.0:
            total_cvss += f.cvss
            vuln_count += 1

    avg_score = round(total_cvss / vuln_count, 1) if vuln_count else 0.0

    overall = "INFO"
    for label in SEVERITY_ORDER:
        if counts.get(label, 0) > 0:
            overall = label
            break

    return {
        "counts": counts,
        "avg_cvss": avg_score,
        "overall_rating": overall,
        "total_findings": len(findings),
        "vuln_count": vuln_count,
    }
