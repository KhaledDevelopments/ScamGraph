"""Find common indicators in plain text without making network requests."""

import re
from ipaddress import ip_address
from urllib.parse import urlsplit

URL_PATTERN = r"\bhttps?://[^\s<>\"'`\u201c\u201d\u2018\u2019]+"
DOMAIN_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
EMAIL_LOCAL_PART = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
EMAIL_PATTERN = (
    rf"(?<![\w.+@-]){EMAIL_LOCAL_PART}(?:\.{EMAIL_LOCAL_PART})*"
    rf"@(?:{DOMAIN_LABEL}\.)+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])?"
    r"(?![\w@-])"
)
# Consume URLs as a whole so userinfo/query text is not mistaken for an email.
INDICATOR_PATTERN = re.compile(
    rf"(?P<url>{URL_PATTERN})|(?P<email>{EMAIL_PATTERN})", re.IGNORECASE
)


def _trim_url_punctuation(url: str) -> str:
    """Remove surrounding prose punctuation, preserving balanced URL brackets."""
    bracket_pairs = {")": "(", "]": "[", "}": "{"}
    # Count each bracket once, then move an index instead of repeatedly copying
    # and rescanning the full URL for every trailing character.
    excess = {
        closing: url.count(closing) - url.count(opening)
        for closing, opening in bracket_pairs.items()
    }
    end = len(url)
    while end:
        last = url[end - 1]
        if last in ".,;:!?":
            end -= 1
        elif excess.get(last, 0) > 0:
            excess[last] -= 1
            end -= 1
        else:
            break
    return url[:end]


def extract_indicators(content: str) -> dict[str, list[str]]:
    """Extract HTTP(S) URLs, common emails, and their domains in encounter order.

    Domain names are lowercased; subdomains are retained. IP-based links stay
    in `urls`, but their IP addresses are not included in `domains`.
    """
    urls: list[str] = []
    emails: list[str] = []
    domains: list[str] = []

    for match in INDICATOR_PATTERN.finditer(content):
        if match.group("url"):
            url = _trim_url_punctuation(match.group("url"))
            try:
                parsed = urlsplit(url)
                hostname = parsed.hostname
                # Accessing port also checks for invalid/out-of-range ports.
                _ = parsed.port
            except ValueError:
                continue
            if not hostname:
                continue

            urls.append(url)
            hostname = hostname.lower().rstrip(".")
            try:
                ip_address(hostname)
            except ValueError:
                domains.append(hostname)
        else:
            local_part, domain = match.group("email").rsplit("@", 1)
            domain = domain.lower()
            emails.append(f"{local_part}@{domain}")
            domains.append(domain)

    # Dictionaries remove duplicates while preserving the first occurrence.
    return {
        "emails": list(dict.fromkeys(emails)),
        "urls": list(dict.fromkeys(urls)),
        "domains": list(dict.fromkeys(domains)),
    }
