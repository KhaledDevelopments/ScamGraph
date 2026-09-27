from collections import OrderedDict

import pytest

from providers import gemini, google_safe_browsing, ipinfo, urlhaus, virustotal


@pytest.fixture(autouse=True)
def isolate_providers(monkeypatch):
    """Never use developer credentials or send live provider requests in tests."""
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(gemini, "_cache", OrderedDict())
    for provider in (ipinfo, google_safe_browsing):
        monkeypatch.setattr(provider, "_cache", provider.OrderedDict())
        monkeypatch.setattr(provider, "_cooldown_until", 0.0)

    def forbid_live_request(*args, **kwargs):
        raise AssertionError("Mock provider HTTP requests in this test")

    monkeypatch.setattr(virustotal.httpx, "get", forbid_live_request)
    monkeypatch.setattr(virustotal, "_cache", virustotal.OrderedDict())
    monkeypatch.setattr(virustotal, "_request_times", virustotal.deque())
    monkeypatch.setattr(virustotal, "_cooldown_until", 0.0)
    monkeypatch.setattr(urlhaus.httpx, "post", forbid_live_request)
    monkeypatch.setattr(urlhaus, "_cache", urlhaus.OrderedDict())
    monkeypatch.setattr(urlhaus, "_cooldown_until", 0.0)
