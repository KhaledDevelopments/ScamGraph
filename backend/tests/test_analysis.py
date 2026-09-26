import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from providers import virustotal

client = TestClient(app)


@pytest.mark.parametrize("malicious, score", [(0, 0), (2, 35), (3, 55)])
def test_endpoint_scores_extracted_url_and_skips_remaining(
    monkeypatch, malicious, score
):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": malicious,
                            "suspicious": 0,
                            "harmless": 1,
                            "undetected": 1,
                        },
                    }
                }
            },
        )

    monkeypatch.setattr(virustotal.httpx, "get", get)
    response = client.post(
        "/analyze",
        json={
            "content": "Visit https://example.com/login or https://second.test",
            "virustotal_malicious_count": 100,
            "google_safe_browsing_flagged": True,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert calls == [
        f"{virustotal.VIRUSTOTAL_URL}/{virustotal._url_id('https://example.com/login')}"
    ]
    assert data["assessment"]["risk_score"] == score
    assert data["assessment"]["assessment_status"] == "partial"
    assert data["assessment"]["assessed_url"] == "https://example.com/login"
    assert data["assessment"]["evidence"]["google_safe_browsing_flagged"] is None
    assert data["threat_intelligence"]["virustotal"][1]["status"] == "skipped"
    assert len(data["indicators"]["urls"]) == 2


@pytest.mark.parametrize("status", [401, 404, 429, 500])
def test_provider_failure_does_not_become_negative_evidence(monkeypatch, status):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        virustotal.httpx, "get", lambda *a, **kw: httpx.Response(status)
    )
    data = client.post("/analyze", json={"content": "https://example.test"}).json()
    assert data["assessment"]["assessment_status"] == "unavailable"
    assert data["assessment"]["evidence"]["virustotal_malicious_count"] is None


def test_missing_key_keeps_risk_unknown():
    data = client.post("/analyze", json={"content": "https://example.test"}).json()
    assert data["assessment"]["assessment_status"] == "unavailable"
    assert data["threat_intelligence"]["virustotal"][0]["status"] == "not_configured"
