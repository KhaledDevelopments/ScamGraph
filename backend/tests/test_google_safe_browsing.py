import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from providers import google_safe_browsing as gsb

URL = "https://example.test/file?a=1&b=2"
REPORT = {
    "matches": [
        {"threatType": "SOCIAL_ENGINEERING"},
        {"threatType": "MALWARE"},
        {"threatType": "MALWARE"},
    ]
}


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    clock = [100.0]
    monkeypatch.setattr(gsb, "monotonic", lambda: clock[0])
    calls = []

    def respond(response):
        def post(url, **kwargs):
            calls.append((url, kwargs))
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(gsb.httpx, "post", post)

    respond(httpx.Response(200, json=REPORT))
    return respond, calls, clock


def test_request_and_threat_match(provider):
    _, calls, _ = provider
    result = gsb.lookup_url(URL)
    assert result["status"] == "ok"
    assert result["flagged"] is True
    assert result["threat_types"] == ["MALWARE", "SOCIAL_ENGINEERING"]
    assert len(calls) == 1
    endpoint, request = calls[0]
    assert endpoint == gsb.SAFE_BROWSING_URL
    assert request["params"] == {"key": "test-key"}
    assert request["timeout"] == 5.0
    assert request["json"]["threatInfo"]["threatEntries"] == [{"url": URL}]
    assert request["json"]["threatInfo"]["threatEntryTypes"] == ["URL"]


@pytest.mark.parametrize("key", ["", "   "])
def test_missing_key_stays_unknown(provider, monkeypatch, key):
    _, calls, _ = provider
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", key)
    result = gsb.lookup_url(URL)
    assert result["status"] == "not_configured"
    assert result["flagged"] is None
    assert calls == []


@pytest.mark.parametrize("payload", [{}, {"matches": []}])
def test_empty_matches_are_checked_negative(provider, payload):
    respond, _, _ = provider
    respond(httpx.Response(200, json=payload))
    result = gsb.lookup_url(URL)
    assert result["status"] == "not_found"
    assert result["flagged"] is False
    assert result["threat_types"] is None


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401),
        httpx.Response(403),
        httpx.Response(404),
        httpx.Response(500),
        httpx.Response(302),
        httpx.Response(200, text="bad json"),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={"matches": None}),
        httpx.Response(200, json={"matches": {}}),
        httpx.Response(200, json={"matches": [None]}),
        httpx.Response(200, json={"matches": [{}]}),
        httpx.Response(200, json={"matches": [{"threatType": 1}]}),
        httpx.Response(200, json={"matches": [{"threatType": " "}]}),
        httpx.ReadTimeout("timeout"),
        httpx.ConnectError("offline"),
    ],
)
def test_failure_stays_unknown_and_is_not_cached(provider, response):
    respond, _, _ = provider
    respond(response)
    result = gsb.lookup_url(URL)
    assert result["status"] == "unavailable"
    assert result["flagged"] is None
    assert not gsb._cache


@pytest.mark.parametrize(
    "payload, flagged", [(REPORT, True), ({}, False), ({"matches": []}, False)]
)
def test_cache_copies_results_and_expires(provider, payload, flagged):
    respond, calls, clock = provider
    respond(httpx.Response(200, json=payload))
    result = gsb.lookup_url(URL)
    result["flagged"] = "modified"
    if result["threat_types"]:
        result["threat_types"].append("modified")
    cached = gsb.lookup_url(URL)
    assert cached["flagged"] is flagged
    assert "modified" not in (cached["threat_types"] or [])
    assert len(calls) == 1
    clock[0] += gsb.CACHE_TTL
    gsb.lookup_url(URL)
    assert len(calls) == 2


def test_cache_is_bounded_and_separated_by_api_key(provider, monkeypatch):
    _, calls, _ = provider
    monkeypatch.setattr(gsb, "MAX_CACHE_ENTRIES", 2)
    gsb.lookup_url(URL)
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "different-key")
    gsb.lookup_url(URL)
    gsb.lookup_url("https://second.test")
    assert len(calls) == 3
    assert len(gsb._cache) == 2
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    gsb.lookup_url(URL)
    assert len(calls) == 4


def test_rate_limit_cooldown(provider):
    respond, calls, clock = provider
    respond(httpx.Response(429))
    assert gsb.lookup_url(URL)["status"] == "rate_limited"
    assert gsb.lookup_url(URL)["flagged"] is None
    assert len(calls) == 1
    assert not gsb._cache
    clock[0] += 60
    respond(httpx.Response(200, json=REPORT))
    assert gsb.lookup_url(URL)["flagged"] is True
    assert len(calls) == 2


def test_only_first_unique_url_is_checked(provider):
    _, calls, _ = provider
    assert gsb.lookup_urls([]) == []
    results = gsb.lookup_urls([URL, URL, "https://second.test"])
    assert [result["status"] for result in results] == ["ok", "skipped"]
    assert results[1]["flagged"] is None
    assert len(calls) == 1


@pytest.mark.parametrize(
    "payload, evidence, score, level",
    [
        (REPORT, True, 20, "HIGH"),
        ({}, False, 0, "LOW"),
        ({"matches": []}, False, 0, "LOW"),
        ({"matches": [None]}, None, 0, "LOW"),
    ],
)
def test_endpoint_uses_provider_evidence(provider, payload, evidence, score, level):
    respond, _, _ = provider
    respond(httpx.Response(200, json=payload))
    response = TestClient(app).post(
        "/analyze",
        json={
            "content": f"{URL} https://second.test",
            "google_safe_browsing_flagged": True,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assessment = data["assessment"]
    assert assessment["evidence"]["google_safe_browsing_flagged"] is evidence
    assert assessment["risk_score"] == score
    assert assessment["risk_level"] == level
    assert assessment["assessed_url"] == URL
    assert data["threat_intelligence"]["google_safe_browsing"][1]["status"] == "skipped"
