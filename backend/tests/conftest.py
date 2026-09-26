import pytest

from providers import virustotal


@pytest.fixture(autouse=True)
def isolate_virustotal(monkeypatch):
    """Never use developer credentials or send live provider requests in tests."""
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    def forbid_live_request(*args, **kwargs):
        raise AssertionError("Mock VirusTotal HTTP requests in this test")

    monkeypatch.setattr(virustotal.httpx, "get", forbid_live_request)
    monkeypatch.setattr(virustotal, "_cache", virustotal.OrderedDict())
    monkeypatch.setattr(virustotal, "_request_times", virustotal.deque())
    monkeypatch.setattr(virustotal, "_cooldown_until", 0.0)
