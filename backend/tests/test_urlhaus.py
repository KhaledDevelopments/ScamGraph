import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from providers import urlhaus

URL = "https://example.test/file?a=1&b=2"
REPORT = {
    "query_status": "ok",
    "url_status": "offline",
    "threat": "malware_download",
    "tags": ["test"],
    "date_added": "2026-01-01 00:00:00 UTC",
}


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test-key")
    clock = [100.0]
    monkeypatch.setattr(urlhaus, "monotonic", lambda: clock[0])
    calls = []

    def respond(response):
        def post(url, **kwargs):
            calls.append((url, kwargs))
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(urlhaus.httpx, "post", post)

    respond(httpx.Response(200, json=REPORT))
    return respond, calls, clock


def test_request_and_historical_match(provider):
    _, calls, _ = provider
    result = urlhaus.lookup_url(URL)
    assert result["malicious"] is True
    assert result["url_status"] == "offline"
    assert calls == [
        (
            urlhaus.URLHAUS_URL,
            {
                "headers": {"Auth-Key": "test-key"},
                "data": {"url": URL},
                "timeout": 5.0,
                "follow_redirects": False,
            },
        )
    ]


@pytest.mark.parametrize("key", ["", "   "])
def test_missing_key(monkeypatch, key):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", key)
    assert urlhaus.lookup_url(URL)["status"] == "not_configured"


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
        httpx.Response(200, json={"query_status": "ok"}),
        httpx.Response(200, json={"query_status": "invalid_url"}),
        httpx.Response(200, json={**REPORT, "tags": "bad"}),
        httpx.Response(200, json={**REPORT, "url_status": []}),
        httpx.ReadTimeout("timeout"),
        httpx.ConnectError("offline"),
    ],
)
def test_failure_stays_unknown(provider, response):
    respond, _, _ = provider
    respond(response)
    result = urlhaus.lookup_url(URL)
    assert result["status"] == "unavailable"
    assert result["malicious"] is None
    assert not urlhaus._cache


@pytest.mark.parametrize(
    "payload, expected", [(REPORT, True), ({"query_status": "no_results"}, False)]
)
def test_cache_and_expiry(provider, payload, expected):
    respond, calls, clock = provider
    respond(httpx.Response(200, json=payload))
    result = urlhaus.lookup_url(URL)
    assert result["malicious"] is expected
    result["malicious"] = "modified"
    assert urlhaus.lookup_url(URL)["malicious"] is expected
    assert len(calls) == 1
    clock[0] += urlhaus.CACHE_TTL
    urlhaus.lookup_url(URL)
    assert len(calls) == 2


def test_cache_bounded_and_separated_by_key(provider, monkeypatch):
    _, calls, _ = provider
    monkeypatch.setattr(urlhaus, "MAX_CACHE_ENTRIES", 2)
    urlhaus.lookup_url(URL)
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "different-key")
    urlhaus.lookup_url(URL)
    urlhaus.lookup_url("https://second.test")
    assert len(calls) == 3
    assert len(urlhaus._cache) == 2


def test_rate_limit_cooldown(provider):
    respond, calls, clock = provider
    respond(httpx.Response(429))
    assert urlhaus.lookup_url(URL)["status"] == "rate_limited"
    assert urlhaus.lookup_url(URL)["malicious"] is None
    assert len(calls) == 1
    clock[0] += 60
    respond(httpx.Response(200, json=REPORT))
    assert urlhaus.lookup_url(URL)["malicious"] is True


def test_only_first_unique_url_checked(provider):
    _, calls, _ = provider
    assert urlhaus.lookup_urls([]) == []
    results = urlhaus.lookup_urls([URL, URL, "https://second.test"])
    assert [r["status"] for r in results] == ["ok", "skipped"]
    assert results[1]["malicious"] is None
    assert len(calls) == 1


@pytest.mark.parametrize(
    "payload, evidence, score",
    [
        (REPORT, True, 35),
        ({"query_status": "no_results"}, False, 0),
        ({"query_status": "invalid_url"}, None, 0),
    ],
)
def test_endpoint_uses_urlhaus_evidence(provider, payload, evidence, score):
    respond, _, _ = provider
    respond(httpx.Response(200, json=payload))
    data = (
        TestClient(app)
        .post(
            "/analyze",
            json={
                "content": f"{URL} https://second.test",
                "urlhaus_malicious": True,
            },
        )
        .json()
    )
    assert data["assessment"]["evidence"]["urlhaus_malicious"] is evidence
    assert data["assessment"]["risk_score"] == score
    assert data["assessment"]["assessed_url"] == URL
    assert data["threat_intelligence"]["urlhaus"][1]["status"] == "skipped"
