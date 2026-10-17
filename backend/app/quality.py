from app.analysis import FindingData


def evaluate_quality_gate(findings: list[FindingData], summary: dict, fail_on_severity: str = "high") -> dict:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    threshold = order[fail_on_severity]
    blocking = [item for item in findings if order.get(item.severity, 4) <= threshold]
    reasons = [f"{item.rule_id} ({item.severity})" for item in blocking]
    if summary.get("syntax_valid") is False:
        reasons.append("Syntax validation failed")
    return {
        "passed": not reasons,
        "threshold": fail_on_severity,
        "reasons": reasons,
        "finding_count": len(findings),
        "note": "A pass means configured checks found no blocking findings; it is not proof of correctness.",
    }
