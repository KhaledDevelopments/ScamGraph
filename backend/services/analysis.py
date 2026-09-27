"""Translate provider results into evidence for the shared scoring model."""

from typing import Any

from analyzer.extractor import extract_indicators
from providers import urlhaus
from providers.virustotal import lookup_urls
from services.scoring import calculate_risk


def analyze_content(content: str) -> dict[str, Any]:
    """Extract message indicators and score only the first URL's evidence."""
    indicators = extract_indicators(content)
    reports = lookup_urls(indicators["urls"])
    urlhaus_reports = urlhaus.lookup_urls(indicators["urls"])
    report = reports[0] if reports else None
    malicious_count = (
        report["stats"]["malicious"]
        if report is not None and report["status"] == "ok"
        else None
    )
    # Wire future providers here. Client-supplied flags must not establish risk.
    result = calculate_risk(
        virustotal_malicious_count=malicious_count,
        urlhaus_malicious=urlhaus_reports[0]["malicious"] if urlhaus_reports else None,
    )
    return {
        "indicators": indicators,
        "threat_intelligence": {"virustotal": reports, "urlhaus": urlhaus_reports},
        "assessment": {
            **result,
            "assessed_url": report["indicator"] if report else None,
            "scope": "First extracted URL only; this is not a verdict on the whole message.",
        },
    }
