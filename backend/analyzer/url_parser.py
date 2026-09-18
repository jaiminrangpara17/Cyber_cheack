"""Safe URL parsing helpers. No network requests are made here."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


ALLOWED_SCHEMES = {"http", "https"}


def parse_url(url_str: str) -> dict:
    original = (url_str or "").strip()
    result = {
        "original": original,
        "scheme": None,
        "netloc": None,
        "domain": None,
        "path": None,
        "normalized_url": None,
        "subdomains": [],
        "is_ip": False,
        "port": None,
        "has_credentials": False,
        "valid": False,
        "error": None,
    }

    if not original:
        result["error"] = "URL is empty."
        return result

    candidate = original
    # Reject explicit non-HTTP(S) schemes before adding the default HTTPS scheme.
    explicit_scheme = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", candidate)
    if explicit_scheme and explicit_scheme.group(1).lower() not in ALLOWED_SCHEMES:
        result["error"] = "Only HTTP and HTTPS URLs are supported."
        return result
    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            result["error"] = "Only HTTP and HTTPS URLs are supported."
            return result

        # Hostname is checked before port so non-HTTP(S) or hostless input
        # cannot raise a misleading port parsing error.
        hostname = parsed.hostname
        if not hostname:
            result["error"] = "URL does not contain a valid hostname."
            return result

        try:
            port = parsed.port
        except ValueError:
            result["error"] = "URL contains an invalid port number."
            return result

        domain = hostname.rstrip(".").lower()
        if not domain:
            result["error"] = "URL does not contain a valid domain."
            return result

        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            is_ip = False

        result["scheme"] = scheme
        result["netloc"] = parsed.netloc
        result["domain"] = domain
        result["path"] = parsed.path or "/"
        result["port"] = port
        result["has_credentials"] = bool(parsed.username is not None or parsed.password is not None)
        result["is_ip"] = is_ip

        # A hostname such as www.example.com has one subdomain level.
        if not is_ip:
            parts = domain.split(".")
            if len(parts) >= 3:
                result["subdomains"] = parts[:-2]

        # Keep query/fragment out of the normalized URL to make stored results stable.
        netloc = parsed.netloc
        normalized = urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
        result["normalized_url"] = normalized
        result["valid"] = True
    except ValueError as exc:
        result["error"] = f"Malformed URL: {exc}"
    except Exception as exc:
        result["error"] = "Malformed URL."

    return result
