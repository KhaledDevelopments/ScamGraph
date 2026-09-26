import pytest

from services.scoring import calculate_risk, risk_level


@pytest.mark.parametrize(
    "score, level",
    [
        (0, "LOW"),
        (24, "LOW"),
        (25, "SUSPICIOUS"),
        (49, "SUSPICIOUS"),
        (50, "HIGH"),
        (74, "HIGH"),
        (75, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_risk_band_boundaries(score, level):
    assert risk_level(score) == level


def test_missing_evidence_is_unavailable():
    result = calculate_risk()
    assert result["assessment_status"] == "unavailable"
    assert len(result["missing_evidence"]) == 6
    assert all(item["status"] == "unknown" for item in result["score_breakdown"])


@pytest.mark.parametrize("count, score", [(0, 0), (1, 35), (2, 35), (3, 55)])
def test_vendor_consensus(count, score):
    result = calculate_risk(virustotal_malicious_count=count)
    assert result["risk_score"] == score
    assert result["assessment_status"] == "partial"


def test_providers_do_not_double_count_reputation():
    result = calculate_risk(virustotal_malicious_count=1, urlhaus_malicious=True)
    assert result["risk_score"] == 35


@pytest.mark.parametrize("age, score", [(0, 10), (29, 10), (30, 0)])
def test_domain_age_boundary(age, score):
    assert calculate_risk(domain_age_days=age)["risk_score"] == score


def test_all_positive_signals_reach_maximum():
    result = calculate_risk(
        virustotal_malicious_count=3,
        urlhaus_malicious=True,
        google_safe_browsing_flagged=True,
        domain_age_days=1,
        suspicious_ip=True,
        connected_to_malicious_entity=True,
    )
    assert result["risk_score"] == 100
    assert result["assessment_status"] == "complete"
    assert result["missing_evidence"] == []


def test_checked_negatives_are_distinct_from_unknown():
    result = calculate_risk(
        virustotal_malicious_count=0,
        urlhaus_malicious=False,
        google_safe_browsing_flagged=False,
        domain_age_days=365,
        suspicious_ip=False,
        connected_to_malicious_entity=False,
    )
    assert result["risk_score"] == 0
    assert result["assessment_status"] == "complete"
    assert all(item["status"] == "not_matched" for item in result["score_breakdown"])


@pytest.mark.parametrize("name", ["virustotal_malicious_count", "domain_age_days"])
@pytest.mark.parametrize("value", [-1, True, 1.5, "3"])
def test_rejects_invalid_numeric_evidence(name, value):
    with pytest.raises(ValueError):
        calculate_risk(**{name: value})


@pytest.mark.parametrize(
    "name",
    [
        "urlhaus_malicious",
        "google_safe_browsing_flagged",
        "suspicious_ip",
        "connected_to_malicious_entity",
    ],
)
@pytest.mark.parametrize("value", [0, 1, "false"])
def test_rejects_invalid_boolean_evidence(name, value):
    with pytest.raises(ValueError):
        calculate_risk(**{name: value})
