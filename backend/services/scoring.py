"""Score message warning signs and server-collected evidence for the first URL.

None means unchecked or unavailable, not a negative finding.
VirusTotal consensus counts malicious verdicts only.
"""

from typing import Any

from analyzer.heuristics import HEURISTIC_RULES

MAX_RISK_SCORE = 100
VENDOR_CONSENSUS_THRESHOLD = 3
RECENT_DOMAIN_DAYS = 30


def risk_level(score: int) -> str:
    """Return the display band for a score on the 0-100 scale."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "SUSPICIOUS"
    return "LOW"


def calculate_risk(
    *,
    virustotal_malicious_count: int | None = None,
    urlhaus_malicious: bool | None = None,
    google_safe_browsing_flagged: bool | None = None,
    domain_age_days: int | None = None,
    suspicious_ip: bool | None = None,
    connected_to_malicious_entity: bool | None = None,
    heuristic_types: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Combine provider signals and local findings without assuming missing is clean.

    All inputs must come from server-side evidence collection. Integer inputs
    must be nonnegative; boolean inputs distinguish a checked negative (False)
    from an unavailable check (None). Invalid evidence raises ValueError.
    """
    evidence = {
        "virustotal_malicious_count": virustotal_malicious_count,
        "urlhaus_malicious": urlhaus_malicious,
        "google_safe_browsing_flagged": google_safe_browsing_flagged,
        "domain_age_days": domain_age_days,
        "suspicious_ip": suspicious_ip,
        "connected_to_malicious_entity": connected_to_malicious_entity,
    }
    for name, value in evidence.items():
        if value is None:
            continue
        if name in ("virustotal_malicious_count", "domain_age_days"):
            # bool subclasses int, but True is not a valid count or domain age.
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer or None")
        elif type(value) is not bool:
            raise ValueError(f"{name} must be a boolean or None")

    vt_malicious = (
        None if virustotal_malicious_count is None else virustotal_malicious_count > 0
    )
    # Providers share the same reputation signal, so agreement never awards
    # +35 twice. A negative result requires both checks to have completed.
    if vt_malicious is True or urlhaus_malicious is True:
        reputation = True
    elif vt_malicious is False and urlhaus_malicious is False:
        reputation = False
    else:
        reputation = None

    vendor_consensus = (
        None
        if virustotal_malicious_count is None
        else virustotal_malicious_count >= VENDOR_CONSENSUS_THRESHOLD
    )
    recent_domain = (
        None if domain_age_days is None else domain_age_days < RECENT_DOMAIN_DAYS
    )
    rules = [
        ("known_malicious", 35, reputation, "Known malicious URL/domain"),
        (
            "vendor_consensus",
            20,
            vendor_consensus,
            f"At least {VENDOR_CONSENSUS_THRESHOLD} VirusTotal vendors classify the URL as malicious",
        ),
        (
            "google_unsafe",
            20,
            google_safe_browsing_flagged,
            "Google flags the URL as unsafe",
        ),
        (
            "recent_domain",
            10,
            recent_domain,
            f"Domain registered less than {RECENT_DOMAIN_DAYS} days ago",
        ),
        (
            "suspicious_infrastructure",
            10,
            suspicious_ip,
            "Suspicious or known-bad hosting/IP",
        ),
        (
            "malicious_relationship",
            5,
            connected_to_malicious_entity,
            "Connected to a known malicious entity",
        ),
    ]
    for kind in dict.fromkeys(heuristic_types):
        if kind not in HEURISTIC_RULES:
            raise ValueError(f"Unknown heuristic: {kind}")
        weight, _, description = HEURISTIC_RULES[kind]
        rules.append((kind, weight, True, description))
    breakdown = [
        {
            "signal": name,
            "points": weight if matched is True else 0,
            "possible_points": weight,
            "status": (
                "unknown"
                if matched is None
                else "matched"
                if matched
                else "not_matched"
            ),
        }
        for name, weight, matched, _ in rules
    ]
    score = min(sum(item["points"] for item in breakdown), MAX_RISK_SCORE)
    level = risk_level(score)
    level_reason = None
    if (reputation is True or google_safe_browsing_flagged is True) and level in {
        "LOW",
        "SUSPICIOUS",
    }:
        level = "HIGH"
        level_reason = (
            "A threat provider flagged this URL as malicious or unsafe, so the "
            "risk level is at least HIGH. The numeric score still totals only "
            "the matched evidence."
        )
    missing = [name for name, value in evidence.items() if value is None]
    if len(missing) == len(evidence) and not heuristic_types:
        assessment_status = "unavailable"
    elif missing:
        assessment_status = "partial"
    else:
        assessment_status = "complete"

    return {
        "risk_score": score,
        "risk_level": level,
        "risk_level_reason": level_reason,
        "indicators": [
            f"{description} (+{weight})"
            for _, weight, matched, description in rules
            if matched is True
        ],
        "score_breakdown": breakdown,
        "evidence": evidence,
        "assessment_status": assessment_status,
        "missing_evidence": missing,
        "assessment_note": (
            "Score reflects available evidence, not a probability or guarantee of safety. "
            "Unchecked signals add no points."
            " Local language and domain checks are warning signs, not proof of a scam."
            + (f" {level_reason}" if level_reason else "")
        ),
    }
