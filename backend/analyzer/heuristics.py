"""Explainable URL heuristics. These checks never visit the URL."""
import re


SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".link", ".work", ".date", ".party", ".gq", ".tk"
}
SUSPICIOUS_KEYWORDS = {
    "login", "security", "verify", "update", "confirm", "account",
    "bank", "pay", "reward", "free", "gift"
}


def run_heuristics(url_info: dict, url_str: str) -> list[dict]:
    findings = []
    domain = (url_info.get("domain") or "").lower()
    subdomains = url_info.get("subdomains") or []
    is_ip = bool(url_info.get("is_ip"))
    scheme = (url_info.get("scheme") or "").lower()

    if is_ip:
        findings.append({
            "type": "ip_address_domain",
            "message": "The URL uses an IP address instead of a domain name.",
            "severity": "high",
        })

    if len(subdomains) > 2:
        findings.append({
            "type": "excessive_subdomains",
            "message": f"The URL has {len(subdomains)} subdomain levels, which is unusual.",
            "severity": "medium",
        })

    hyphen_count = domain.count("-")
    if hyphen_count > 2:
        findings.append({
            "type": "excessive_hyphens",
            "message": "The domain contains many hyphens.",
            "severity": "medium",
        })
    elif hyphen_count > 0:
        findings.append({
            "type": "suspicious_hyphens",
            "message": "The domain contains hyphens, which are sometimes used in suspicious links.",
            "severity": "low",
        })

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            findings.append({
                "type": "suspicious_tld",
                "message": f"The domain uses the '{tld}' top-level domain, which can be associated with suspicious sites.",
                "severity": "medium",
            })
            break

    for keyword in sorted(SUSPICIOUS_KEYWORDS, key=len, reverse=True):
        if re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", domain):
            findings.append({
                "type": "suspicious_keyword",
                "message": f"The domain contains the keyword '{keyword}', which may be trying to appear trustworthy.",
                "severity": "high" if is_ip else "medium",
            })

    if len(url_str) > 100:
        findings.append({
            "type": "long_url",
            "message": "The URL is unusually long.",
            "severity": "low",
        })

    if url_info.get("has_credentials"):
        findings.append({
            "type": "embedded_credentials",
            "message": "The URL contains embedded username or password information.",
            "severity": "high",
        })

    if "@" in url_str:
        findings.append({
            "type": "at_symbol",
            "message": "The URL contains an '@' symbol, which can be used in redirect tricks.",
            "severity": "high",
        })

    if "%" in url_str:
        findings.append({
            "type": "url_encoding",
            "message": "The URL contains encoded characters, which may hide the real destination.",
            "severity": "low",
        })

    if "xn--" in domain:
        findings.append({
            "type": "punycode_domain",
            "message": "The domain uses an internationalized (punycode) representation.",
            "severity": "medium",
        })

    # A real port is available from url_parser; 80/443 are standard.
    port = url_info.get("port")
    if port is not None and port not in {80, 443}:
        findings.append({
            "type": "non_standard_port",
            "message": "The URL uses a non-standard port number.",
            "severity": "low",
        })

    if scheme == "http":
        findings.append({
            "type": "http_scheme",
            "message": "The URL uses HTTP instead of HTTPS.",
            "severity": "low",
        })

    return findings
