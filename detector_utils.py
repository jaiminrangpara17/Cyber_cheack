"""
=================

A self-contained, dependency-free URL security feature extractor.

This module performs *structural* (offline) analysis of a raw, untrusted URL
string and returns a deterministic risk assessment dictionary.

It NEVER performs network activity:
    * no DNS resolution
    * no HTTP(S) requests
    * no third-party API calls
    * no execution of the URL

Public API
----------
    from detector_utils import analyze_url

    result = analyze_url("google.com")

Returned schema (always exactly these keys)::

    {
        "url": str,          # normalized URL
        "hostname": str,     # extracted hostname only
        "risk_score": int,   # 0 - 100
        "verdict": str,      # "SAFE" | "SUSPICIOUS" | "DANGEROUS"
        "warnings": list     # list[str], human readable
    }
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

__all__ = ["analyze_url"]


# ---------------------------------------------------------------------------
# Configuration constants (tweak here — scoring stays deterministic)
# ---------------------------------------------------------------------------

#: Scheme prefixes that are accepted "as-is" during normalization.
_ACCEPTED_SCHEME_PREFIXES: Tuple[str, ...] = ("http://", "https://")

#: Scheme prepended when the raw input has no explicit http/https scheme.
_DEFAULT_SCHEME: str = "https://"

#: Free / frequently abused top-level domains (heuristic signal only).
SUSPICIOUS_TLDS: frozenset = frozenset(
    {"xyz", "top", "buzz", "club", "tk", "ml", "ga"}
)

#: Point values for each heuristic.
POINTS_HTTP: int = 25
POINTS_IPV4_HOST: int = 40
POINTS_SUSPICIOUS_TLD: int = 20
POINTS_LONG_URL: int = 10
POINTS_MANY_HYPHENS: int = 15
POINTS_AT_SYMBOL: int = 30

#: Thresholds / limits.
MAX_RISK_SCORE: int = 100
LONG_URL_THRESHOLD: int = 75          # characters (strictly greater than)
HYPHEN_THRESHOLD: int = 2             # 2 or more hyphens in hostname

#: Verdict labels (exact strings required by the backend contract).
VERDICT_SAFE: str = "SAFE"
VERDICT_SUSPICIOUS: str = "SUSPICIOUS"
VERDICT_DANGEROUS: str = "DANGEROUS"

#: Verdict boundaries.
SUSPICIOUS_THRESHOLD: int = 25        # score >= 25 -> at least SUSPICIOUS
DANGEROUS_THRESHOLD: int = 60         # score >= 60 -> DANGEROUS

#: Risk score assigned when the URL cannot be parsed into a usable hostname.
INVALID_URL_SCORE: int = MAX_RISK_SCORE

#: Characters permitted in a plausible hostname (already lower-cased by
#: urlparse). Colons are allowed so bracket-stripped IPv6 hosts still pass.
_HOSTNAME_RE = re.compile(r"^[a-z0-9._:\-]+$")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def normalize_url(raw_url: str) -> str:
    """Trim whitespace and guarantee an explicit http:// or https:// scheme.

    ``"  google.com "``  ->  ``"https://google.com"``
    ``"http://a.com"``   ->  ``"http://a.com"``   (scheme left untouched)

    Args:
        raw_url: The raw, untrusted URL string.

    Returns:
        The normalized URL string (may be empty if the input was blank).
    """
    candidate = raw_url.strip()
    if not candidate:
        return ""

    if candidate.lower().startswith(_ACCEPTED_SCHEME_PREFIXES):
        return candidate

    return _DEFAULT_SCHEME + candidate


def _extract_hostname(normalized_url: str) -> Optional[str]:
    """Return the lower-cased hostname, or ``None`` if it cannot be extracted.

    Uses the standard library parser only — no fragile manual string splitting.
    """
    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname  # already lower-cased, port/userinfo removed
    except ValueError:
        # urlparse raises on things like malformed IPv6 literals or bad ports.
        return None

    if not hostname:
        return None

    hostname = hostname.strip()
    if not hostname or not _HOSTNAME_RE.match(hostname):
        return None

    return hostname


def _get_scheme(normalized_url: str) -> str:
    """Return the URL scheme in lower case (empty string if unparseable)."""
    try:
        return urlparse(normalized_url).scheme.lower()
    except ValueError:
        return ""


def is_ipv4_address(hostname: str) -> bool:
    """True only when *hostname* is a literal IPv4 address.

    Uses :func:`ipaddress.ip_address` instead of a permissive regex so that
    normal domains containing digits (e.g. ``3m.com``, ``web3.example.net``)
    are never mis-flagged.
    """
    try:
        return isinstance(ipaddress.ip_address(hostname), ipaddress.IPv4Address)
    except ValueError:
        return False


def _get_tld(hostname: str) -> str:
    """Return the final label of the hostname (without the dot), lower-cased."""
    if "." not in hostname:
        return ""
    return hostname.rsplit(".", 1)[-1].lower()


def classify_risk(risk_score: int) -> str:
    """Map a capped risk score onto the exact verdict strings.

    ``score < 25`` -> SAFE, ``25 <= score < 60`` -> SUSPICIOUS,
    ``score >= 60`` -> DANGEROUS.
    """
    if risk_score >= DANGEROUS_THRESHOLD:
        return VERDICT_DANGEROUS
    if risk_score >= SUSPICIOUS_THRESHOLD:
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE


def _build_result(
    url: str,
    hostname: str,
    risk_score: int,
    warnings: List[str],
) -> Dict[str, Any]:
    """Assemble the standardized output dictionary (score capped + verdict)."""
    capped = max(0, min(int(risk_score), MAX_RISK_SCORE))
    return {
        "url": url,
        "hostname": hostname,
        "risk_score": capped,
        "verdict": classify_risk(capped),
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Individual heuristics
# Each returns (points, warning_or_None) so the caller can aggregate them all.
# ---------------------------------------------------------------------------

def _check_insecure_scheme(scheme: str) -> Tuple[int, Optional[str]]:
    """Heuristic 1 — plain HTTP instead of HTTPS."""
    if scheme == "http":
        return (
            POINTS_HTTP,
            "URL uses HTTP instead of HTTPS, so traffic is not encrypted. "
            "(Note: HTTPS alone does not prove a site is legitimate.)",
        )
    return 0, None


def _check_ip_host(hostname: str) -> Tuple[int, Optional[str]]:
    """Heuristic 2 — hostname is a direct IPv4 address."""
    if is_ipv4_address(hostname):
        return (
            POINTS_IPV4_HOST,
            "URL uses a direct IPv4 address instead of a domain name.",
        )
    return 0, None


def _check_suspicious_tld(hostname: str) -> Tuple[int, Optional[str]]:
    """Heuristic 3 — frequently abused / free top-level domain."""
    tld = _get_tld(hostname)
    if tld and tld in SUSPICIOUS_TLDS:
        return (
            POINTS_SUSPICIOUS_TLD,
            f"Domain uses a potentially suspicious or frequently abused TLD: "
            f".{tld} (this alone does not mean the site is malicious).",
        )
    return 0, None


def _check_url_length(normalized_url: str) -> Tuple[int, Optional[str]]:
    """Heuristic 4 — excessive overall URL length."""
    if len(normalized_url) > LONG_URL_THRESHOLD:
        return (
            POINTS_LONG_URL,
            f"URL is unusually long ({len(normalized_url)} characters) and may "
            f"contain obfuscated or hidden parameters.",
        )
    return 0, None


def _check_hyphens(hostname: str) -> Tuple[int, Optional[str]]:
    """Heuristic 5 — two or more hyphens in the hostname."""
    hyphen_count = hostname.count("-")
    if hyphen_count >= HYPHEN_THRESHOLD:
        return (
            POINTS_MANY_HYPHENS,
            f"Domain contains multiple hyphens ({hyphen_count}), which can be "
            f"associated with deceptive or typosquatted domains.",
        )
    return 0, None


def _check_at_symbol(*url_variants: str) -> Tuple[int, Optional[str]]:
    """Heuristic 6 — '@' obfuscation trick.

    Checked against the raw *and* normalized URL strings so the signal can
    never be lost during hostname extraction.
    """
    if any("@" in variant for variant in url_variants if variant):
        return (
            POINTS_AT_SYMBOL,
            "URL contains '@', which can be used to obscure the actual "
            "destination (text before '@' may be treated as credentials).",
        )
    return 0, None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> Dict[str, Any]:
    """Analyze a raw URL string with offline structural security heuristics.

    The input is treated as untrusted: non-string, empty, and malformed values
    are handled gracefully instead of raising.

    Args:
        url: The raw URL string to analyze (e.g. ``"google.com"``).

    Returns:
        A dictionary with the keys ``url``, ``hostname``, ``risk_score``,
        ``verdict`` and ``warnings``. All applicable heuristics are evaluated,
        so ``warnings`` lists every triggered signal.
    """
    # --- Defensive input handling -----------------------------------------
    if not isinstance(url, str):
        return _build_result(
            url="",
            hostname="",
            risk_score=INVALID_URL_SCORE,
            warnings=[
                "Input was not a string URL.",
                "Unable to extract a valid hostname from the URL.",
            ],
        )

    raw_url = url
    normalized_url = normalize_url(raw_url)

    if not normalized_url:
        return _build_result(
            url="",
            hostname="",
            risk_score=INVALID_URL_SCORE,
            warnings=[
                "URL is empty or contains only whitespace.",
                "Unable to extract a valid hostname from the URL.",
            ],
        )

    hostname = _extract_hostname(normalized_url)
    if hostname is None:
        # Still report the '@' signal if present — it is a strong indicator.
        warnings: List[str] = ["Unable to extract a valid hostname from the URL."]
        at_points, at_warning = _check_at_symbol(raw_url, normalized_url)
        if at_warning:
            warnings.append(at_warning)
        return _build_result(
            url=normalized_url,
            hostname="",
            risk_score=INVALID_URL_SCORE,
            warnings=warnings,
        )

    scheme = _get_scheme(normalized_url)

    # --- Run every heuristic (never short-circuit) ------------------------
    findings: List[Tuple[int, Optional[str]]] = [
        _check_insecure_scheme(scheme),                 # Heuristic 1
        _check_ip_host(hostname),                       # Heuristic 2
        _check_suspicious_tld(hostname),                # Heuristic 3
        _check_url_length(normalized_url),              # Heuristic 4
        _check_hyphens(hostname),                       # Heuristic 5
        _check_at_symbol(raw_url, normalized_url),      # Heuristic 6
    ]

    risk_score = 0
    warnings = []
    for points, warning in findings:
        if points:
            risk_score += points
        if warning:
            warnings.append(warning)

    return _build_result(
        url=normalized_url,
        hostname=hostname,
        risk_score=risk_score,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Manual test / demo block  (no network access is performed)
# ---------------------------------------------------------------------------

def _print_report(result: Dict[str, Any]) -> None:
    """Pretty-print an analysis result for terminal inspection."""
    print(f"URL:        {result['url'] or '(empty)'}")
    print(f"Hostname:   {result['hostname'] or '(none)'}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Verdict:    {result['verdict']}")
    if result["warnings"]:
        print("Warnings:")
        for warning in result["warnings"]:
            print(f"  - {warning}")
    else:
        print("Warnings:   none")
    print("-" * 72)


if __name__ == "__main__":
    demo_urls = [
        # Test 1 — legitimate
        "https://www.google.com",
        # Test 2 — suspicious (HTTP + suspicious TLD + hyphens)
        "http://example-update-login.xyz/account",
        # Test 3 — clearly dangerous (HTTP + IPv4 + '@' + long URL)
        "http://192.168.1.10/paypal-update-account-login@evil.xyz/very-long-path",
        # Extra edge cases
        "google.com",
        "",
        "   ",
        "http://user@example.com",
        "https://example.com/@test",
        "https://paypal-update-account-login.xyz",
        "http://192.168.1.1/login",
        "http://[2001:db8::1]/login",  # IPv6 literal
        "http://example.com:8080/path" , 
        ]