"""Explainable brand/domain similarity checks."""
from difflib import SequenceMatcher

BRANDS = {
    "paypal": {"name": "PayPal", "domain": "paypal.com"},
    "amazon": {"name": "Amazon", "domain": "amazon.com"},
    "google": {"name": "Google", "domain": "google.com"},
    "microsoft": {"name": "Microsoft", "domain": "microsoft.com"},
    "apple": {"name": "Apple", "domain": "apple.com"},
    "facebook": {"name": "Facebook", "domain": "facebook.com"},
    "netflix": {"name": "Netflix", "domain": "netflix.com"},
    "instagram": {"name": "Instagram", "domain": "instagram.com"},
    "linkedin": {"name": "LinkedIn", "domain": "linkedin.com"},
    "twitter": {"name": "Twitter / X", "domain": "twitter.com"},
}

COMMON_TLDS = {"com", "net", "org", "xyz", "top", "click", "link", "work", "date", "party", "gq", "tk", "info", "biz"}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                current[-1] + 1,
                previous[j] + 1,
                previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]


def _base_label(domain: str) -> str:
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return parts[0] if parts else ""
    return parts[-2]


def _is_official_or_subdomain(domain: str, official: str) -> bool:
    return domain == official or domain.endswith("." + official)


def detect_impersonation(domain: str, url_str: str = "") -> dict:
    result = {"possible_brand": None, "similarity_score": 0, "findings": []}
    domain = (domain or "").lower().rstrip(".")
    if not domain:
        return result

    labels = [part for part in domain.split(".") if part]
    words = []
    for label in labels:
        words.extend([w for w in label.replace("-", ".").split(".") if w and w not in COMMON_TLDS])

    for brand_key, brand_info in BRANDS.items():
        official = brand_info["domain"]
        brand_name = brand_info["name"]
        if _is_official_or_subdomain(domain, official):
            continue

        # Brand keyword anywhere in an unrelated hostname.
        if brand_key in domain:
            result.update(possible_brand=brand_name, similarity_score=80)
            result["findings"] = [
                {
                    "type": "impersonation",
                    "message": f"Possible impersonation of {brand_name} detected.",
                    "severity": "high",
                },
                {
                    "type": "brand_keyword_in_unrelated_domain",
                    "message": f"The domain contains '{brand_key}' but is not '{official}'.",
                    "severity": "high",
                },
            ]
            return result

        best_word = ""
        best_ratio = 0.0
        for word in words:
            ratio = SequenceMatcher(None, word, brand_key).ratio()
            if ratio > best_ratio:
                best_ratio, best_word = ratio, word

        distance = levenshtein(best_word, brand_key) if best_word else 999
        if best_word and best_word != brand_key and distance <= 2 and best_ratio >= 0.70:
            similarity = round(best_ratio * 100)
            result.update(possible_brand=brand_name, similarity_score=similarity)
            result["findings"] = [{
                "type": "lookalike_domain",
                "message": f"The domain word '{best_word}' closely resembles '{brand_key}' ({brand_name}).",
                "severity": "high",
            }]
            return result

        # Brand used in a subdomain while the registrable-looking base is unrelated.
        if len(labels) > 2 and any(brand_key in label for label in labels[:-2]):
            result.update(possible_brand=brand_name, similarity_score=70)
            result["findings"] = [{
                "type": "brand_keyword_in_subdomain",
                "message": f"A subdomain contains '{brand_key}', but the base domain is unrelated.",
                "severity": "high",
            }]
            return result

    return result
