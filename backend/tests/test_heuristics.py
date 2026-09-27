import pytest
from fastapi.testclient import TestClient

from analyzer.heuristics import analyze_heuristics
from main import app
from services.scoring import calculate_risk


@pytest.mark.parametrize(
    "text, kind",
    [
        ("Your account has been suspended.", "urgency"),
        ("Final notice: act NOW!", "urgency"),
        ("Please VERIFY YOUR PASSWORD", "credential_request"),
        ("Sign in to restore access", "credential_request"),
        ("Enter your verification code", "credential_request"),
    ],
)
def test_language_findings_preserve_evidence(text, kind):
    findings = analyze_heuristics(text, [])
    assert len(findings) == 1
    assert findings[0]["type"] == kind
    assert findings[0]["matched_text"] in text


@pytest.mark.parametrize(
    "text",
    [
        "Have a nice day!",
        "Never share your password.",
        "Do not enter your credentials.",
        "Don't send your password.",
        "https://example.test/urgent/UNB",
        "urgent@unb.ca",
        "We use password managers.",
    ],
)
def test_benign_or_negated_phrases(text):
    assert analyze_heuristics(text, []) == []


def test_repeated_phrases_award_each_rule_once():
    findings = analyze_heuristics(
        "Act now! Act now! Enter your password. Enter your password.", []
    )
    assert len(findings) == 2
    assert sum(f["score"] for f in findings) == 15


@pytest.mark.parametrize(
    "url",
    [
        "https://unb.ca",
        "https://login.unb.ca/path",
        "https://UNB.CA./",
    ],
)
def test_official_domain_and_subdomains(url):
    assert analyze_heuristics("UNB student news", [url]) == []


@pytest.mark.parametrize(
    "url",
    [
        "https://unb.ca.attacker.test",
        "https://notunb.ca",
        "https://unb.ca@attacker.test",
        "https://unb-secure-login.test",
        "https://192.0.2.1",
    ],
)
def test_domain_mismatch_uses_hostname_boundaries(url):
    finding = analyze_heuristics("University of New Brunswick account", [url])[0]
    assert finding["type"] == "domain_impersonation"
    assert finding["url"] == url
    assert finding["expected_domain"] == "unb.ca"


def test_impersonation_requires_explicit_mention_and_first_url_only():
    assert (
        analyze_heuristics(
            "https://unb-secure-login.test", ["https://unb-secure-login.test"]
        )
        == []
    )
    assert analyze_heuristics("UNB news", ["https://unb.ca", "https://evil.test"]) == []
    assert analyze_heuristics("UNB news", []) == []
    assert analyze_heuristics("UNB news", ["https://["]) == []


def test_scoring_deduplicates_local_rules_and_caps_total():
    assert calculate_risk(heuristic_types=("urgency", "urgency"))["risk_score"] == 5
    result = calculate_risk(
        virustotal_malicious_count=3,
        google_safe_browsing_flagged=True,
        domain_age_days=1,
        suspicious_ip=True,
        heuristic_types=("urgency", "credential_request", "domain_impersonation"),
    )
    assert result["risk_score"] == 100
    with pytest.raises(ValueError):
        calculate_risk(heuristic_types=("invented",))


def test_endpoint_produces_local_evidence_without_provider_keys():
    data = (
        TestClient(app)
        .post(
            "/analyze",
            json={
                "content": "UNB: Your account has been suspended. Enter your password at https://example.test/login"
            },
        )
        .json()
    )
    result = data["assessment"]
    assert result["risk_score"] == 30
    assert result["risk_level"] == "SUSPICIOUS"
    assert result["assessment_status"] == "partial"
    assert len(result["heuristic_findings"]) == 3
    assert sum(item["points"] for item in result["score_breakdown"]) == 30
    assert data["threat_intelligence"]["urlhaus"][0]["status"] == "not_configured"


def test_client_cannot_inject_heuristic_scores():
    result = (
        TestClient(app)
        .post(
            "/analyze",
            json={
                "content": "Hello",
                "heuristic_types": ["urgency"],
                "heuristic_findings": [{"type": "urgency", "score": 100}],
            },
        )
        .json()["assessment"]
    )
    assert result["risk_score"] == 0
    assert result["heuristic_findings"] == []
    assert result["assessment_status"] == "unavailable"


def test_many_negated_phrases_do_not_hide_later_positive_match():
    text = "Never act now. " * 6_000 + "Please act now."
    findings = analyze_heuristics(text, [])
    assert len(findings) == 1
    assert findings[0]["type"] == "urgency"
    assert findings[0]["matched_text"] == "act now"


def test_negation_window_does_not_cross_sentence_boundary():
    findings = analyze_heuristics("Never share secrets. Enter your password.", [])
    assert [finding["type"] for finding in findings] == ["credential_request"]
