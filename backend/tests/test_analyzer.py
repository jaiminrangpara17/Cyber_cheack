#!/usr/bin/env python3
"""Local, dependency-free smoke tests for CyberCheck's analyzer and SQLite layer."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from analyzer.heuristics import run_heuristics
from analyzer.impersonation import detect_impersonation
from analyzer.risk_engine import calculate_risk
from analyzer.url_parser import parse_url


def analyze(url):
    info = parse_url(url)
    if not info["valid"]:
        return info, None, None
    findings = run_heuristics(info, url)
    impersonation = detect_impersonation(info["domain"], url)
    findings.extend(impersonation["findings"])
    return info, impersonation, calculate_risk(findings, impersonation)


def main():
    info, imp, risk = analyze("https://example.com/about")
    assert info["valid"] and risk["level"] == "LOW"

    info, imp, risk = analyze("https://paypa1-security-example.xyz/login")
    assert imp["possible_brand"] == "PayPal"
    assert risk["score"] >= 30 and risk["level"] in {"HIGH", "CRITICAL"}

    info, imp, risk = analyze("https://paypal.com")
    assert imp["possible_brand"] is None
    assert risk["score"] == 0

    assert parse_url("javascript:alert(1)")["valid"] is False
    assert parse_url("mailto:test@example.com")["valid"] is False
    assert parse_url("https://example.com:abc")["valid"] is False

    info, _, risk = analyze("https://user:pass@example.com/login")
    assert info["has_credentials"] is True
    assert risk["score"] >= 25

    info, _, risk = analyze("https://127.0.0.1:8080/login")
    assert info["is_ip"] is True
    assert risk["score"] >= 25

    print("All analyzer smoke tests passed.")


if __name__ == "__main__":
    main()
