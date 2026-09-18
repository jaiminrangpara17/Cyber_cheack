"""Explainable risk scoring."""
SEVERITY_WEIGHTS = {"low": 5, "medium": 15, "high": 25, "critical": 40}
TYPE_MINIMUMS = {
    "impersonation": 30,
    "lookalike_domain": 30,
    "brand_keyword_in_unrelated_domain": 30,
    "brand_keyword_in_subdomain": 30,
    "at_symbol": 30,
    "embedded_credentials": 25,
    "ip_address_domain": 25,
    "suspicious_keyword": 20,
}


def calculate_risk(findings, impersonation_result=None):
    score = 0
    for finding in findings:
        severity = finding.get("severity", "low")
        weight = SEVERITY_WEIGHTS.get(severity, 5)
        weight = max(weight, TYPE_MINIMUMS.get(finding.get("type", ""), 0))
        score += weight

    # Similarity is evidence used to create an impersonation finding; do not
    # add the raw 0-100 similarity score a second time.
    score = min(100, max(0, int(score)))

    if score <= 20:
        level = "LOW"
        message = "Looks okay. No major suspicious signals were detected."
    elif score <= 50:
        level = "MEDIUM"
        message = "Something about this link looks unusual."
    elif score <= 80:
        level = "HIGH"
        message = "Multiple suspicious signals were detected. Check the website before continuing."
    else:
        level = "CRITICAL"
        message = "Strong suspicious indicators were detected. Avoid entering sensitive information until you verify the website."

    return {"score": score, "level": level, "message": message}
