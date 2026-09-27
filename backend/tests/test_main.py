import pytest
from fastapi.testclient import TestClient

from main import MAX_CONTENT_LENGTH, app

client = TestClient(app)


def test_analyze_receives_content_without_changing_it():
    content = "  Your account has been suspended.\nVerify your details.  "

    response = client.post("/analyze", json={"content": content})

    assert response.status_code == 200
    data = response.json()
    assessment = data.pop("assessment")
    assert assessment["assessment_status"] == "partial"
    assert assessment["risk_score"] == 5
    assert assessment["assessed_url"] is None
    assert data == {
        "message": "Content received",
        "content": content,
        "indicators": {"emails": [], "urls": [], "domains": []},
        "threat_intelligence": {
            "virustotal": [],
            "urlhaus": [],
            "google_safe_browsing": [],
            "ipinfo": [],
        },
    }


def test_analyze_returns_extracted_indicators():
    content = "Contact support@example.com or visit https://example.com/login."

    response = client.post("/analyze", json={"content": content})

    assert response.status_code == 200
    assert response.json()["content"] == content
    assert response.json()["indicators"] == {
        "emails": ["support@example.com"],
        "urls": ["https://example.com/login"],
        "domains": ["example.com"],
    }


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"content": ""},
        {"content": " \n\t "},
        {"content": None},
        {"content": 123},
        {"content": True},
        {"content": ["message"]},
        {"content": {"text": "message"}},
    ],
)
def test_analyze_rejects_invalid_content(payload):
    response = client.post("/analyze", json=payload)

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "content"]


def test_analyze_rejects_malformed_json():
    response = client.post(
        "/analyze",
        content='{"content":',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173"])
def test_frontend_can_make_json_post_requests(origin):
    preflight = client.options(
        "/analyze",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == origin
    assert "POST" in preflight.headers["access-control-allow-methods"]

    response = client.post(
        "/analyze", json={"content": "Test message"}, headers={"Origin": origin}
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin


def test_unlisted_origin_does_not_receive_cors_permission():
    response = client.options(
        "/analyze",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize("endpoint", ["/analyze", "/explain"])
@pytest.mark.parametrize("content", [" " * 10, "a" * (MAX_CONTENT_LENGTH + 1)])
def test_endpoints_reject_blank_or_oversized_content_before_processing(
    endpoint, content, monkeypatch
):
    def unexpected_processing(*args):
        raise AssertionError("Invalid content must not be processed")

    monkeypatch.setattr("main.analyze_content", unexpected_processing)
    monkeypatch.setattr("main.gemini.explain", unexpected_processing)
    response = client.post(
        endpoint, json={"content": content, "assessment": {}, "indicators": {}}
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "content"]


def test_analyze_accepts_content_at_limit():
    content = "word " * (MAX_CONTENT_LENGTH // 5)
    response = client.post("/analyze", json={"content": content})
    assert response.status_code == 200
    assert response.json()["content"] == content


def test_explain_preserves_unavailable_assessment_without_provider_keys():
    analysis = client.post(
        "/analyze", json={"content": "Read https://unknown-example.invalid/login"}
    ).json()
    assert analysis["assessment"]["assessment_status"] == "unavailable"
    response = client.post(
        "/explain",
        json={key: analysis[key] for key in ("content", "assessment", "indicators")},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["source"] == "fallback"
    assert "legitimate" not in result["explanation"].lower()
    assert "unknown" in result["explanation"].lower()
