"""Look up URLs against Google Safe Browsing's threat lists."""

import os
from collections import OrderedDict
from copy import deepcopy
from threading import Lock
from time import monotonic

import httpx

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
CACHE_TTL = 15 * 60
MAX_CACHE_ENTRIES = 128
_lock = Lock()
_cache: OrderedDict[tuple[str, str], tuple[float, dict]] = OrderedDict()
_cooldown_until = 0.0


def _result(url: str, status: str) -> dict:
    return {
        "provider": "google_safe_browsing",
        "indicator": url,
        "status": status,
        "flagged": False if status == "not_found" else None,
        "threat_types": None,
    }


def _report_result(url: str, payload: object) -> dict:
    if not isinstance(payload, dict):
        return _result(url, "unavailable")
    matches = payload.get("matches")
    if matches is None:
        # An empty body/object means Safe Browsing checked and found nothing.
        return _result(url, "not_found")
    if not isinstance(matches, list) or not all(
        isinstance(m, dict) and isinstance(m.get("threatType"), str) for m in matches
    ):
        return _result(url, "unavailable")
    threat_types = sorted({m["threatType"] for m in matches})
    return {
        "provider": "google_safe_browsing",
        "indicator": url,
        "status": "ok",
        "flagged": True,
        "threat_types": threat_types,
    }


def lookup_url(url: str) -> dict:
    """Cache matches and misses; failed checks remain unknown."""
    global _cooldown_until
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return _result(url, "not_configured")

    cache_key = (api_key, url)
    with _lock:
        now = monotonic()
        cached = _cache.get(cache_key)
        if cached is not None:
            if now < cached[0]:
                _cache.move_to_end(cache_key)
                return deepcopy(cached[1])
            del _cache[cache_key]
        if now < _cooldown_until:
            return _result(url, "rate_limited")

    body = {
        "client": {"clientId": "scamgraph", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = httpx.post(
            SAFE_BROWSING_URL,
            params={"key": api_key},
            json=body,
            timeout=5.0,
        )
    except httpx.HTTPError:
        return _result(url, "unavailable")

    if response.status_code == 429:
        with _lock:
            _cooldown_until = max(_cooldown_until, monotonic() + 60)
        return _result(url, "rate_limited")
    if response.status_code != 200:
        return _result(url, "unavailable")

    try:
        result = _report_result(url, response.json())
    except ValueError:
        return _result(url, "unavailable")

    if result["status"] in {"ok", "not_found"}:
        with _lock:
            _cache[cache_key] = (monotonic() + CACHE_TTL, deepcopy(result))
            _cache.move_to_end(cache_key)
            while len(_cache) > MAX_CACHE_ENTRIES:
                _cache.popitem(last=False)
    return result


def lookup_urls(urls: list[str]) -> list[dict]:
    unique_urls = list(dict.fromkeys(urls))
    if not unique_urls:
        return []
    return [lookup_url(unique_urls[0])] + [
        _result(url, "skipped") for url in unique_urls[1:]
    ]