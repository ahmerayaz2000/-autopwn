"""Normalise raw module output into a unified list of Finding objects."""
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Finding:
    title: str
    description: str
    evidence: str
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    cvss: float
    module: str
    remediation: str
    finding_type: str = "vulnerability"   # vulnerability | info | error


def aggregate(results: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    for module_name, module_result in results.items():
        if isinstance(module_result, BaseException):
            findings.append(Finding(
                title=f"Module Crashed: {module_name}",
                description=f"Module '{module_name}' raised an unhandled exception: {module_result}",
                evidence=str(module_result),
                severity="INFO",
                cvss=0.0,
                module=module_name,
                remediation="",
                finding_type="error",
            ))
            continue

        if not isinstance(module_result, list):
            continue

        for item in module_result:
            if not isinstance(item, dict):
                continue
            findings.append(Finding(
                title=item.get("title", "Unknown Finding"),
                description=item.get("description", ""),
                evidence=item.get("evidence", ""),
                severity=item.get("severity", "INFO").upper(),
                cvss=float(item.get("cvss", 0.0)),
                module=item.get("module", module_name),
                remediation=item.get("remediation", ""),
                finding_type=item.get("type", "vulnerability"),
            ))

    # Primary sort: CVSS descending; secondary: severity label
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (-f.cvss, severity_rank.get(f.severity, 5)))
    return findings
