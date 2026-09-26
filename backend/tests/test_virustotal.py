import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from services import virustotal

URL = "https://example.test/login?a=1&b=2"
STATS = {"malicious": 2, "suspicious": 1, "harmless": 60, "undetected": 10}
REPORT = {
    "data": {
        "attributes": {"last_analysis_stats": STATS, "last_analysis_date": 1700000000}
    }
}


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-only-key")
    clock = [100.0]
    monkeypatch.setattr(virustotal, "monotonic", lambda: clock[0])
    calls = []

    def respond(response):
        def get(url, **kwargs):
            calls.append((url, kwargs))
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(virustotal.httpx, "get", get)

    respond(httpx.Response(200, json=REPORT))
    return respond, calls, clock


def test_encodes_identifier_and_normalizes_report(provider):
    _, calls, _ = provider
    result = virustotal.lookup_url(URL)
    assert result == {
        "provider": "virustotal",
        "indicator": URL,
        "status": "ok",
        "stats": STATS,
        "last_analysis_date": 1700000000,
    }
    request_url, options = calls[0]
    identifier = request_url.rsplit("/", 1)[1]
    assert request_url.startswith(virustotal.VIRUSTOTAL_URL + "/")
    assert "=" not in identifier
    assert (
        base64.urlsafe_b64decode(identifier + "=" * (-len(identifier) % 4)).decode()
        == URL
    )
    assert options == {
        "headers": {"x-apikey": "test-only-key"},
        "timeout": 5.0,
        "follow_redirects": False,
    }


@pytest.mark.parametrize("key", [None, "", "   "])
def test_missing_key_makes_no_request(monkeypatch, key):
    if key is not None:
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", key)
    assert virustotal.lookup_url(URL)["status"] == "not_configured"


@pytest.mark.parametrize(
    "code,status",
    [
        (404, "not_found"),
        (429, "rate_limited"),
        (301, "unavailable"),
        (400, "unavailable"),
        (401, "unavailable"),
        (403, "unavailable"),
        (500, "unavailable"),
        (503, "unavailable"),
    ],
)
def test_http_errors_are_normalized(provider, code, status):
    respond, _, _ = provider
    respond(
        httpx.Response(code, json={"error": {"message": "private upstream detail"}})
    )
    assert virustotal.lookup_url(URL) == {
        "provider": "virustotal",
        "indicator": URL,
        "status": status,
        "stats": None,
        "last_analysis_date": None,
    }


@pytest.mark.parametrize(
    "error", [httpx.ReadTimeout("timeout"), httpx.ConnectError("offline")]
)
def test_network_errors_are_unavailable(provider, error):
    respond, _, _ = provider
    respond(error)
    assert virustotal.lookup_url(URL)["status"] == "unavailable"


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"data": None},
        {"data": []},
        {"data": {"attributes": None}},
        {"data": {"attributes": []}},
        {"data": {"attributes": {}}},
        {"data": {"attributes": {"last_analysis_stats": None}}},
        {"data": {"attributes": {"last_analysis_stats": []}}},
        {"data": {"attributes": {"last_analysis_stats": {}}}},
    ],
)
def test_invalid_report_shapes_are_unavailable(provider, payload):
    respond, _, _ = provider
    respond(httpx.Response(200, json=payload))
    result = virustotal.lookup_url(URL)
    assert result["status"] == "unavailable"
    assert result["stats"] is None


@pytest.mark.parametrize("value", [None, "0", -1, True, 1.5])
def test_invalid_counts_are_not_reported_as_clean(provider, value):
    respond, _, _ = provider
    payload = deepcopy(REPORT)
    payload["data"]["attributes"]["last_analysis_stats"]["malicious"] = value
    respond(httpx.Response(200, json=payload))
    assert virustotal.lookup_url(URL)["status"] == "unavailable"


def test_invalid_json_is_unavailable(provider):
    respond, _, _ = provider
    respond(httpx.Response(200, text="not JSON"))
    assert virustotal.lookup_url(URL)["status"] == "unavailable"


def test_missing_date_is_allowed_but_invalid_date_is_not(provider):
    respond, _, _ = provider
    payload = deepcopy(REPORT)
    del payload["data"]["attributes"]["last_analysis_date"]
    respond(httpx.Response(200, json=payload))
    result = virustotal.lookup_url(URL)
    assert result["status"] == "ok"
    assert result["last_analysis_date"] is None
    payload["data"]["attributes"]["last_analysis_date"] = "yesterday"
    respond(httpx.Response(200, json=payload))
    assert virustotal.lookup_url(URL + "x")["status"] == "unavailable"


def test_cache_reuses_reports_without_sharing_mutable_results(provider):
    _, calls, clock = provider
    result = virustotal.lookup_url(URL)
    result["stats"]["malicious"] = 999
    assert virustotal.lookup_url(URL)["stats"]["malicious"] == 2
    assert len(calls) == 1
    clock[0] += virustotal.CACHE_TTL
    assert virustotal.lookup_url(URL)["status"] == "ok"
    assert len(calls) == 2


def test_not_found_is_cached_but_failures_are_not(provider):
    respond, calls, _ = provider
    respond(httpx.Response(404))
    virustotal.lookup_url(URL)
    virustotal.lookup_url(URL)
    assert len(calls) == 1
    respond(httpx.Response(503))
    virustotal.lookup_url(URL + "x")
    virustotal.lookup_url(URL + "x")
    assert len(calls) == 3


def test_cache_is_bounded_and_separated_by_key(provider, monkeypatch):
    _, calls, _ = provider
    monkeypatch.setattr(virustotal, "MAX_CACHE_ENTRIES", 2)
    for i in range(3):
        virustotal.lookup_url(URL + str(i))
    assert len(virustotal._cache) == 2
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "another-test-key")
    virustotal.lookup_url(URL + "2")
    assert len(calls) == 4


def test_rate_limit_is_shared_by_concurrent_requests(provider):
    _, calls, clock = provider
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(
            executor.map(virustotal.lookup_url, [URL + str(i) for i in range(6)])
        )
    assert len(calls) == 4
    assert sum(result["status"] == "rate_limited" for result in results) == 2
    clock[0] += 60
    assert virustotal.lookup_url(URL + "new")["status"] == "ok"


def test_provider_429_causes_cooldown(provider):
    respond, calls, clock = provider
    respond(httpx.Response(429))
    assert virustotal.lookup_url(URL)["status"] == "rate_limited"
    respond(httpx.Response(200, json=REPORT))
    assert virustotal.lookup_url(URL + "new")["status"] == "rate_limited"
    assert len(calls) == 1
    clock[0] += 60
    assert virustotal.lookup_url(URL + "new")["status"] == "ok"


def test_only_first_unique_url_is_checked(provider):
    _, calls, _ = provider
    assert virustotal.lookup_urls([]) == []
    results = virustotal.lookup_urls([URL, URL, URL + "other"])
    assert [result["status"] for result in results] == ["ok", "skipped"]
    assert len(calls) == 1


@pytest.mark.parametrize(
    "code,status",
    [(200, "ok"), (404, "not_found"), (429, "rate_limited"), (503, "unavailable")],
)
def test_analyze_keeps_indicators_when_provider_fails(provider, code, status):
    respond, _, _ = provider
    respond(httpx.Response(code, json=REPORT))
    with TestClient(app) as client:
        response = client.post("/analyze", json={"content": URL})
    assert response.status_code == 200
    assert response.json()["indicators"]["urls"] == [URL]
    assert response.json()["threat_intelligence"]["virustotal"][0]["status"] == status


def test_analyze_without_key_returns_indicators():
    with TestClient(app) as client:
        response = client.post("/analyze", json={"content": URL})
    assert response.status_code == 200
    assert response.json()["indicators"]["urls"] == [URL]
    assert (
        response.json()["threat_intelligence"]["virustotal"][0]["status"]
        == "not_configured"
    )
