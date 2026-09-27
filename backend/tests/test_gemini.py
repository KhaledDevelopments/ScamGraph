import json
from copy import deepcopy

import httpx
import pytest

from analyzer.heuristics import analyze_heuristics
from providers import gemini
from services.scoring import calculate_risk


@pytest.fixture
def assessment():
    return calculate_risk()


@pytest.fixture
def indicators():
    return {"urls": ["https://example.com"], "domains": ["example.com"], "emails": []}


def success(text="Explanation from the recorded evidence."):
    return httpx.Response(
        200,
        json={
            "candidates": [
                {"finishReason": "STOP", "content": {"parts": [{"text": text}]}}
            ]
        },
    )


@pytest.fixture
def requests(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    calls = []

    def post(*args, **kwargs):
        calls.append((args, kwargs))
        return success(f"Explanation {len(calls)}.")

    monkeypatch.setattr(gemini.httpx, "post", post)
    return calls


def test_no_credentials_preserves_unknown_without_inventing_safety(
    assessment, indicators
):
    result = gemini.explain("Hello", assessment, indicators)

    assert result["source"] == "fallback"
    assert result["status"] == "ok"
    assert "risk is unknown" in result["explanation"].lower()
    assert "could not be completed" in result["explanation"]
    assert "legitimate" not in result["explanation"]
    assert "official" not in result["explanation"]
    assert not gemini._cache


def test_generic_urgency_uses_actual_finding_without_fabricating_account_claims():
    content = "Act now to see our newsletter."
    findings = analyze_heuristics(content, [])
    assessment = {
        **calculate_risk(heuristic_types=("urgency",)),
        "heuristic_findings": findings,
    }

    explanation = gemini.explain(content, assessment, {})["explanation"]

    assert findings[0]["description"] in explanation
    assert explanation.count(findings[0]["description"]) == 1
    assert "could not be completed" in explanation
    for fabricated_claim in ("student", "suspended", "false urgency", "password"):
        assert fabricated_claim not in explanation.lower()


def test_domain_mismatch_retains_recorded_qualification():
    content = "UNB newsletter: https://example.com"
    findings = analyze_heuristics(content, ["https://example.com"])
    assessment = {
        **calculate_risk(heuristic_types=("domain_impersonation",)),
        "heuristic_findings": findings,
    }

    explanation = gemini.explain(content, assessment, {})["explanation"]

    assert findings[0]["description"] in explanation
    assert "not proof of impersonation" in explanation
    assert "unauthorized" not in explanation


def test_complete_clean_assessment_is_not_a_guarantee_of_safety():
    assessment = calculate_risk(
        virustotal_malicious_count=0,
        urlhaus_malicious=False,
        google_safe_browsing_flagged=False,
        domain_age_days=365,
        suspicious_ip=False,
        connected_to_malicious_entity=False,
    )

    explanation = gemini.explain("Hello", assessment, {})["explanation"]

    assert "No warning signs were reported" in explanation
    assert "do not guarantee" in explanation
    assert "legitimate" not in explanation
    assert "official" not in explanation
    assert "could not be completed" not in explanation


def test_direct_threat_level_reason_is_preserved_even_with_lower_score(indicators):
    assessment = {
        **calculate_risk(google_safe_browsing_flagged=True),
        "risk_level": "HIGH",
        "risk_level_reason": "A direct threat match sets a minimum HIGH risk level.",
    }

    explanation = gemini.explain("Check this link", assessment, indicators)[
        "explanation"
    ]

    assert "HIGH risk" in explanation
    assert assessment["risk_level_reason"] in explanation
    assert "Google flags the URL as unsafe" in explanation
    assert "Avoid the links" in explanation
    assert "could not be completed" in explanation


def test_high_score_without_recorded_findings_does_not_invent_vendor_results():
    assessment = {
        "risk_score": 60,
        "risk_level": "HIGH",
        "assessment_status": "partial",
        "indicators": [],
    }

    explanation = gemini.explain("Hello", assessment, {})["explanation"]

    assert "HIGH" in explanation
    assert "vendor" not in explanation
    assert "malicious" not in explanation
    assert "could not be completed" in explanation


def test_success_is_cached_and_prompt_contains_full_evidence(
    requests, assessment, indicators
):
    assessment["risk_level_reason"] = "Direct match determines the level."
    result = gemini.explain("Hello", assessment, indicators)
    cached = gemini.explain("Hello", assessment, indicators)

    assert result == cached
    assert result == {
        "provider": "gemini",
        "status": "ok",
        "source": "gemini",
        "explanation": "Explanation 1.",
    }
    assert len(requests) == 1
    args, kwargs = requests[0]
    assert args == (gemini.GEMINI_URL,)
    assert kwargs["params"] == {"key": "test-key"}
    assert kwargs["timeout"] == 8.0
    prompt = kwargs["json"]["contents"][0]["parts"][0]["text"]
    assert "risk is unknown" in prompt
    assert "unavailable check is not a clean" in prompt
    assert "untrusted data" in prompt
    data = json.loads(prompt.split("Assessment data:\n", 1)[1])
    assert data == {
        "message": "Hello",
        "assessment": assessment,
        "indicators": indicators,
    }
    assert "test-key" not in repr(gemini._cache)


@pytest.mark.parametrize(
    "changed", ["evidence", "findings", "status", "indicators", "text"]
)
def test_cache_separates_changed_evidence_at_the_same_score(
    requests, assessment, indicators, changed
):
    first = gemini.explain("Hello", assessment, indicators)
    new_assessment = deepcopy(assessment)
    new_indicators = deepcopy(indicators)
    content = "Hello"
    if changed == "evidence":
        new_assessment["evidence"]["google_safe_browsing_flagged"] = False
    elif changed == "findings":
        new_assessment["heuristic_findings"] = [{"description": "Different finding."}]
    elif changed == "status":
        new_assessment["assessment_status"] = "partial"
    elif changed == "indicators":
        new_indicators["urls"] = ["https://example.org"]
    else:
        content = " Hello "

    second = gemini.explain(content, new_assessment, new_indicators)

    assert new_assessment["risk_score"] == assessment["risk_score"]
    assert len(requests) == 2
    assert second["explanation"] != first["explanation"]


def test_cache_ignores_dictionary_key_order(requests, assessment, indicators):
    gemini.explain("Hello", assessment, indicators)
    reordered = dict(reversed(list(assessment.items())))
    reordered["evidence"] = dict(reversed(list(assessment["evidence"].items())))

    gemini.explain("Hello", reordered, dict(reversed(list(indicators.items()))))

    assert len(requests) == 1


def test_cache_does_not_cross_credentials_or_disabled_provider(
    monkeypatch, requests, assessment, indicators
):
    gemini.explain("Hello", assessment, indicators)
    monkeypatch.setenv("GEMINI_API_KEY", "different-test-key")
    gemini.explain("Hello", assessment, indicators)
    monkeypatch.delenv("GEMINI_API_KEY")

    disabled = gemini.explain("Hello", assessment, indicators)

    assert len(requests) == 2
    assert disabled["source"] == "fallback"


def test_success_cache_expires(monkeypatch, requests, assessment, indicators):
    now = [100.0]
    monkeypatch.setattr(gemini, "monotonic", lambda: now[0])
    first = gemini.explain("Hello", assessment, indicators)
    now[0] += gemini.CACHE_TTL - 1
    assert gemini.explain("Hello", assessment, indicators) == first
    now[0] += 1

    after_expiry = gemini.explain("Hello", assessment, indicators)

    assert len(requests) == 2
    assert after_expiry["explanation"] != first["explanation"]


def test_cache_is_bounded_and_keeps_recently_used_entries(
    monkeypatch, requests, assessment, indicators
):
    monkeypatch.setattr(gemini, "MAX_CACHE_ENTRIES", 2)
    first = gemini.explain("First", assessment, indicators)
    gemini.explain("Second", assessment, indicators)
    assert gemini.explain("First", assessment, indicators) == first
    gemini.explain("Third", assessment, indicators)

    assert len(gemini._cache) == 2
    assert gemini.explain("First", assessment, indicators) == first
    assert len(requests) == 3
    gemini.explain("Second", assessment, indicators)
    assert len(requests) == 4
    assert len(gemini._cache) == 2


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_http_failure_falls_back_but_next_request_can_recover(
    monkeypatch, assessment, indicators, status
):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    responses = iter([httpx.Response(status), success("Recovered explanation.")])
    monkeypatch.setattr(gemini.httpx, "post", lambda *a, **k: next(responses))

    fallback = gemini.explain("Hello", assessment, indicators)
    assert not gemini._cache
    recovered = gemini.explain("Hello", assessment, indicators)

    assert fallback["source"] == "fallback"
    assert "Risk is unknown" in fallback["explanation"]
    assert recovered["source"] == "gemini"
    assert recovered["explanation"] == "Recovered explanation."


@pytest.mark.parametrize("error", [httpx.ReadTimeout, httpx.ConnectError])
def test_transport_errors_fall_back(monkeypatch, assessment, indicators, error):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def post(*args, **kwargs):
        raise error("Provider unavailable")

    monkeypatch.setattr(gemini.httpx, "post", post)

    result = gemini.explain("Hello", assessment, indicators)

    assert result["source"] == "fallback"
    assert not gemini._cache


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"candidates": []},
        {"candidates": [None]},
        {"candidates": [{"content": []}]},
        {"candidates": [{"content": {"parts": {}}}]},
        {"candidates": [{"content": {"parts": [None]}}]},
        {"candidates": [{"content": {"parts": [{"text": 5}]}}]},
        {"candidates": [{"content": {"parts": [{"text": "  "}]}}]},
        {"candidates": [{"content": {"parts": [{"functionCall": {}}]}}]},
        {
            "candidates": [
                {
                    "finishReason": "SAFETY",
                    "content": {"parts": [{"text": "Blocked content"}]},
                }
            ]
        },
        {
            "candidates": [
                {
                    "finishReason": "MAX_TOKENS",
                    "content": {"parts": [{"text": "Incomplete response"}]},
                }
            ]
        },
    ],
)
def test_malformed_empty_or_blocked_payload_falls_back(
    monkeypatch, assessment, indicators, payload
):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        gemini.httpx, "post", lambda *a, **k: httpx.Response(200, json=payload)
    )

    result = gemini.explain("Hello", assessment, indicators)

    assert result["source"] == "fallback"
    assert not gemini._cache


def test_invalid_json_falls_back(monkeypatch, assessment, indicators):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        gemini.httpx, "post", lambda *a, **k: httpx.Response(200, content=b"not json")
    )

    assert gemini.explain("Hello", assessment, indicators)["source"] == "fallback"
    assert not gemini._cache


def test_response_joins_text_parts_without_thought_parts(
    monkeypatch, assessment, indicators
):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": "Private reasoning", "thought": True},
                        {"text": " First sentence. "},
                        {"text": "Second sentence."},
                    ]
                }
            }
        ]
    }
    monkeypatch.setattr(
        gemini.httpx, "post", lambda *a, **k: httpx.Response(200, json=payload)
    )

    result = gemini.explain("Hello", assessment, indicators)

    assert result["source"] == "gemini"
    assert result["explanation"] == "First sentence.\nSecond sentence."


def test_programming_errors_are_not_silently_swallowed(
    monkeypatch, assessment, indicators
):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def post(*args, **kwargs):
        raise AssertionError("Mock or implementation error")

    monkeypatch.setattr(gemini.httpx, "post", post)

    with pytest.raises(AssertionError, match="Mock or implementation error"):
        gemini.explain("Hello", assessment, indicators)
