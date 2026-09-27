"""Generate a plain-English explanation of an assessment using Gemini."""

import os

import httpx

GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-3.8-flash:generateContent"
)


def _build_prompt(content: str, assessment: dict, indicators: dict) -> str:
    matched = [i for i in assessment.get("indicators", []) if i]
    missing = assessment.get("missing_evidence", [])
    return (
        "You are explaining a phishing/scam risk assessment to a non-technical user. "
        "Be concise (2-4 sentences), plain language, no jargon. "
        "Do not invent facts beyond what is given below.\n\n"
        f"Original message: {content!r}\n"
        f"Extracted URLs: {indicators.get('urls', [])}\n"
        f"Extracted domains: {indicators.get('domains', [])}\n"
        f"Risk level: {assessment.get('risk_level')} ({assessment.get('risk_score')}/100)\n"
        f"Assessment status: {assessment.get('assessment_status')}\n"
        f"Matched risk indicators: {matched}\n"
        f"Checks that could not be completed: {missing}\n\n"
        "Explain in plain language why this is or isn't suspicious, based only on the above."
    )


def _error_result(status: str) -> dict:
    return {"provider": "gemini", "status": status, "explanation": None}


def explain(content: str, assessment: dict, indicators: dict) -> dict:
    """Ask Gemini to explain an already-computed assessment. Never invents risk data."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return _error_result("not_configured")

    prompt = _build_prompt(content, assessment, indicators)
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 800, "thinkingConfig": {"thinkingBudget": 0}},
    }

    try:
        response = httpx.post(
            GEMINI_URL,
            params={"key": api_key},
            json=body,
            timeout=10.0,
        )
    except httpx.HTTPError:
        return _error_result("unavailable")

    if response.status_code == 429:
        return _error_result("rate_limited")
    if response.status_code != 200:
        return _error_result("unavailable")

    try:
        payload = response.json()
        text = payload["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, ValueError, TypeError):
        return _error_result("unavailable")

    if not isinstance(text, str) or not text.strip():
        return _error_result("unavailable")

    return {"provider": "gemini", "status": "ok", "explanation": text.strip()}

    #This ensures that the AI does not make things up on it's own and rely on the data already collected from all of the API calls.