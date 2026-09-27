import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from providers import ipinfo

REPORT = {
    "ip": "8.8.8.8",
    "country": "United States",
    "country_code": "US",
    "asn": "AS15169",
    "as_name": "Google LLC",
    "as_domain": "google.com",
}


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setenv("IPINFO_TOKEN", "test-token")
    calls = []
    clock = [100.0]
    monkeypatch.setattr(ipinfo, "monotonic", lambda: clock[0])

    def respond(response):
        def get(url, **kwargs):
            calls.append((url, kwargs))
            if url == ipinfo.DNS_URL:
                return httpx.Response(
                    200, json={"Status": 0, "Answer": [{"type": 1, "data": "8.8.8.8"}]}
                )
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(ipinfo.httpx, "get", get)

    respond(httpx.Response(200, json=REPORT))
    return respond, calls, clock


def test_no_token_does_not_resolve():
    assert ipinfo.lookup_url("https://example.com")["status"] == "not_configured"


def test_domain_resolves_and_queries_fixed_endpoints(provider):
    _, calls, _ = provider
    result = ipinfo.lookup_url("https://example.com/private?x=1")
    assert result["status"] == "ok"
    assert result["ip"] == "8.8.8.8"
    assert calls[0][1]["params"] == {"name": "example.com", "type": "A"}
    assert calls[1][0] == "https://api.ipinfo.io/lite/8.8.8.8"
    assert calls[1][1]["params"] == {"token": "test-token"}
    assert all(c[1]["timeout"] == 5 and not c[1]["follow_redirects"] for c in calls)


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "[::1]",
        "localhost",
        "host.local",
        "224.0.0.1",
    ],
)
def test_nonpublic_targets_do_not_trigger_requests(provider, host):
    _, calls, _ = provider
    assert ipinfo.lookup_url(f"http://{host}")["status"] == "non_public"
    assert calls == []


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401),
        httpx.Response(403),
        httpx.Response(500),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={}),
        httpx.Response(200, json={**REPORT, "ip": "1.1.1.1"}),
        httpx.Response(200, text="bad json"),
        httpx.ReadTimeout("timeout"),
    ],
)
def test_failed_lookup_is_unavailable(provider, response):
    respond, _, _ = provider
    respond(response)
    assert ipinfo.lookup_url("https://8.8.8.8")["status"] == "unavailable"


def test_cache_expiry_bound_and_token_separation(provider, monkeypatch):
    _, calls, clock = provider
    url = "https://8.8.8.8"
    ipinfo.lookup_url(url)["country"] = "changed"
    assert ipinfo.lookup_url(url)["country"] == "United States"
    assert len(calls) == 1
    clock[0] += ipinfo.CACHE_TTL
    ipinfo.lookup_url(url)
    assert len(calls) == 2
    monkeypatch.setattr(ipinfo, "MAX_CACHE_ENTRIES", 1)
    monkeypatch.setenv("IPINFO_TOKEN", "another-token")
    ipinfo.lookup_url(url)
    assert len(calls) == 3
    assert len(ipinfo._cache) == 1


def test_cooldown(provider):
    respond, calls, clock = provider
    respond(httpx.Response(429))
    assert ipinfo.lookup_url("https://8.8.8.8")["status"] == "rate_limited"
    ipinfo.lookup_url("https://8.8.8.8")
    assert len(calls) == 1
    clock[0] += 60
    respond(httpx.Response(200, json=REPORT))
    assert ipinfo.lookup_url("https://8.8.8.8")["status"] == "ok"


def test_ipv6_fallback(monkeypatch, provider):
    address = "2001:4860:4860::8888"

    def get(url, **kwargs):
        if url == ipinfo.DNS_URL:
            answers = (
                []
                if kwargs["params"]["type"] == "A"
                else [{"type": 28, "data": address}]
            )
            return httpx.Response(200, json={"Status": 0, "Answer": answers})
        return httpx.Response(200, json={**REPORT, "ip": address})

    monkeypatch.setattr(ipinfo.httpx, "get", get)
    assert ipinfo.lookup_url("https://example.com")["ip"] == address


@pytest.mark.parametrize(
    "payload",
    [
        {"Status": 3},
        {"Status": 0, "Answer": [{"type": 1, "data": "127.0.0.1"}]},
        {"Status": 0, "Answer": None},
    ],
)
def test_dns_failure_or_private_answer(monkeypatch, provider, payload):
    def get(url, **kwargs):
        assert url == ipinfo.DNS_URL
        return httpx.Response(200, json=payload)

    monkeypatch.setattr(ipinfo.httpx, "get", get)
    assert ipinfo.lookup_url("https://example.com")["status"] == "unresolved"


def test_endpoint_enrichment_does_not_change_risk(provider):
    data = (
        TestClient(app)
        .post("/analyze", json={"content": "https://8.8.8.8 https://1.1.1.1"})
        .json()
    )
    reports = data["threat_intelligence"]["ipinfo"]
    assert [r["status"] for r in reports] == ["ok", "skipped"]
    assert data["assessment"]["risk_score"] == 0
    assert data["assessment"]["evidence"]["suspicious_ip"] is None
    assert ipinfo.lookup_urls([]) == []
