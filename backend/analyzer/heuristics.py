"""Small, explainable English-language warning checks; no network access."""

import re
from urllib.parse import urlsplit

HEURISTIC_RULES = {
    "urgency": (5, "low", "Message uses urgency or threatens account access."),
    "credential_request": (10, "medium", "Message asks for credentials or a sign-in."),
    "domain_impersonation": (15, "medium", "Possible organization impersonation."),
}

# Deliberately small initial mapping. Source: https://www.unb.ca/
ORGANIZATIONS = {"UNB": (r"\b(?:UNB|University of New Brunswick)\b", "unb.ca")}
URGENCY = re.compile(
    r"\b(?:act now|urgent(?:ly)?|immediately|final (?:warning|notice)|"
    r"account\s+(?:(?:has been|will be|is)\s+)?(?:suspended|locked|closed))\b",
    re.IGNORECASE,
)
CREDENTIALS = re.compile(
    r"\b(?:(?:enter|provide|confirm|verify|send|share)\s+(?:your\s+)?"
    r"(?:password|credentials|login details|sign-in details|verification code|"
    r"one-time (?:password|code))|(?:sign|log)\s*in\s+"
    r"(?:here|now|immediately|to (?:verify|confirm|restore|keep)))\b",
    re.IGNORECASE,
)
NEGATION = re.compile(r"\b(?:never|do not|don't|don’t|not to)\b", re.IGNORECASE)


def _positive_match(pattern: re.Pattern, text: str) -> re.Match | None:
    for match in pattern.finditer(text):
        # Avoid common safety advice such as "never share your password".
        prefix = re.split(r"[.!?\n]", text[: match.start()])[-1]
        if not NEGATION.search(prefix[-60:]):
            return match
    return None


def _finding(kind: str, matched_text: str, **details) -> dict:
    score, severity, description = HEURISTIC_RULES[kind]
    return {
        "type": kind,
        "severity": severity,
        "score": score,
        "description": description,
        "matched_text": matched_text,
        **details,
    }


def analyze_heuristics(content: str, urls: list[str]) -> list[dict]:
    """Check message language and the first URL; award each rule at most once."""
    # Mask links and emails so their words do not become message claims.
    text = re.sub(
        r"https?://\S+|\b\S+@\S+",
        lambda m: " " * len(m[0]),
        content,
        flags=re.IGNORECASE,
    )
    findings = []
    for kind, pattern in (("urgency", URGENCY), ("credential_request", CREDENTIALS)):
        match = _positive_match(pattern, text)
        if match:
            findings.append(_finding(kind, content[match.start() : match.end()]))
    if not urls:
        return findings
    try:
        parsed = urlsplit(urls[0])
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return findings
    if parsed.scheme.lower() not in ("http", "https") or not host:
        return findings
    for organization, (pattern, official_domain) in ORGANIZATIONS.items():
        mention = re.search(pattern, text, re.IGNORECASE)
        if (
            mention
            and host != official_domain
            and not host.endswith("." + official_domain)
        ):
            findings.append(
                _finding(
                    "domain_impersonation",
                    content[mention.start() : mention.end()],
                    organization=organization,
                    url=urls[0],
                    domain=host,
                    expected_domain=official_domain,
                    description=f"Message mentions {organization}, but the first link uses "
                    f"{host} rather than {official_domain} or its subdomains. "
                    "This mismatch is a warning sign, not proof of impersonation.",
                )
            )
            break
    return findings
