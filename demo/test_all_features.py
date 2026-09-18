#!/usr/bin/env python3
"""Smoke-test CyberCheck's local Flask API and the five core analysis flows."""
import requests

BASE = "http://127.0.0.1:5000"


def scan(name, url, source):
    print(f"\n=== {name} ===")
    response = requests.post(
        f"{BASE}/api/scan",
        json={"url": url, "source": source},
        timeout=5,
    )
    response.raise_for_status()
    data = response.json()

    print(f"URL: {url}")
    print(f"Risk: {data['risk_score']}/100 — {data['risk_level']}")
    print(f"Message: {data['message']}")

    if data.get("impersonated_brand"):
        print(f"⚠ Possible impersonation: {data['impersonated_brand']}")

    for finding in data.get("findings", []):
        print(f"  • {finding['severity'].upper()}: {finding['message']}")

    return data


def main():
    health = requests.get(f"{BASE}/api/health", timeout=3)
    health.raise_for_status()
    print("Health:", health.json())

    examples = [
        ("1. IMPERSONATION DETECTOR", "https://paypa1-security-example.xyz/verify", "popup"),
        ("2. SMART WARNING LEVELS (LOW)", "https://example.com/about", "popup"),
        ("2. SMART WARNING LEVELS (MEDIUM)", "https://example-login.xyz/", "popup"),
        ("2. SMART WARNING LEVELS (HIGH)", "https://amazon-update-verify.xyz/login", "popup"),
        ("2. SMART WARNING LEVELS (CRITICAL)", "https://paypa1-security-example.xyz/login", "popup"),
        ("3. RIGHT-CLICK CHECK", "https://paypa1-security-example.xyz/login", "context"),
        ("4. COPY LINK AUTO CHECK", "https://microsoft-account-verify.xyz/update", "clipboard"),
        ("5. QR CODE ANALYSIS", "https://apple-id-verify.xyz/signin", "qr"),
    ]

    for name, url, source in examples:
        scan(name, url, source)

    history = requests.get(f"{BASE}/api/history?limit=3", timeout=5)
    history.raise_for_status()
    records = history.json()
    print(f"\n=== HISTORY ({len(records)} records returned) ===")
    for item in records:
        print(
            f"  {item['timestamp']} | {item['url']} | "
            f"Score: {item['risk_score']} | {item['risk_level']}"
        )


if __name__ == "__main__":
    main()
