from datetime import datetime, timezone

import httpx
import pytest

from providers import rdap

SAMPLE_URL = "https://sub.phishing-example.test/login"
MOCK_NOW = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def setup_rdap(monkeypatch):
    monkeypatch.setenv("RDAP_DISABLED", "0")
    monkeypatch.setattr(rdap, "_now_fn", lambda: MOCK_NOW)
    monkeypatch.setattr(rdap, "_cache", rdap.OrderedDict())
    monkeypatch.setattr(rdap, "_cooldown_until", 0.0)


def mock_rdap_payload(
    reg_date="2026-09-20T10:00:00Z", registrar_name="FastRegistrar Inc"
):
    return {
        "objectClassName": "domain",
        "handle": "12345_DOMAIN",
        "ldhName": "PHISHING-EXAMPLE.TEST",
        "events": [
            {"eventAction": "registration", "eventDate": reg_date},
            {"eventAction": "expiration", "eventDate": "2027-09-20T10:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", registrar_name],
                    ],
                ],
            }
        ],
    }


def test_rdap_recent_domain_detection(monkeypatch):
    # Registered 7 days before MOCK_NOW
    payload = mock_rdap_payload(reg_date="2026-09-20T12:00:00Z")
    monkeypatch.setattr(
        rdap.httpx,
        "get",
        lambda *args, **kwargs: httpx.Response(200, json=payload),
    )

    result = rdap.lookup_url(SAMPLE_URL)
    assert result["status"] == "ok"
    assert result["domain"] == "phishing-example.test"
    assert result["registration_date"] == "2026-09-20"
    assert result["domain_age_days"] == 7
    assert result["recent_domain"] is True
    assert result["registrar"] == "FastRegistrar Inc"


def test_rdap_older_domain_detection(monkeypatch):
    # Registered in 2020 (over 2000 days ago)
    payload = mock_rdap_payload(reg_date="2020-01-01T00:00:00Z")
    monkeypatch.setattr(
        rdap.httpx,
        "get",
        lambda *args, **kwargs: httpx.Response(200, json=payload),
    )

    result = rdap.lookup_url("https://legit-service.test/home")
    assert result["status"] == "ok"
    assert result["domain_age_days"] > 365
    assert result["recent_domain"] is False


def test_rdap_not_found_status(monkeypatch):
    monkeypatch.setattr(
        rdap.httpx,
        "get",
        lambda *args, **kwargs: httpx.Response(404),
    )

    result = rdap.lookup_url("https://unregistered-domain.invalid/page")
    assert result["status"] == "not_found"
    assert result["domain_age_days"] is None
    assert result["recent_domain"] is None


def test_rdap_rate_limiting_cooldown(monkeypatch):
    monkeypatch.setattr(
        rdap.httpx,
        "get",
        lambda *args, **kwargs: httpx.Response(429),
    )

    result = rdap.lookup_url(SAMPLE_URL)
    assert result["status"] == "rate_limited"

    # Second call should immediately return rate_limited from cooldown without network call
    called = []
    monkeypatch.setattr(rdap.httpx, "get", lambda *args, **kwargs: called.append(True))
    result2 = rdap.lookup_url(SAMPLE_URL)
    assert result2["status"] == "rate_limited"
    assert len(called) == 0


def test_rdap_non_public_and_ip_links():
    assert rdap.lookup_url("https://192.168.1.1/login")["status"] == "non_public"
    assert rdap.lookup_url("https://localhost/test")["status"] == "non_public"
    assert rdap.lookup_url("https://server.local/page")["status"] == "non_public"


def test_rdap_multiple_urls_skips_subsequent(monkeypatch):
    payload = mock_rdap_payload()
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        return httpx.Response(200, json=payload)

    monkeypatch.setattr(rdap.httpx, "get", get)
    results = rdap.lookup_urls(
        [
            "https://first.example.test/a",
            "https://second.example.test/b",
        ]
    )
    assert len(results) == 2
    assert results[0]["status"] == "ok"
    assert results[1]["status"] == "skipped"
    assert len(calls) == 1


def test_rdap_caching(monkeypatch):
    payload = mock_rdap_payload()
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        return httpx.Response(200, json=payload)

    monkeypatch.setattr(rdap.httpx, "get", get)
    res1 = rdap.lookup_url("https://alpha.example.test/path1")
    res2 = rdap.lookup_url("https://beta.example.test/path2")

    assert res1["status"] == "ok"
    assert res2["status"] == "ok"
    # Both URLs have registered domain 'example.test', so cache key hits!
    assert len(calls) == 1
