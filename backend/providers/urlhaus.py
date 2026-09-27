"""Look up existing URLhaus records without visiting or submitting URLs."""

import os
from collections import OrderedDict
from copy import deepcopy
from threading import Lock
from time import monotonic

import httpx

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
CACHE_TTL = 15 * 60
MAX_CACHE_ENTRIES = 128
_lock = Lock()
_cache: OrderedDict[tuple[str, str], tuple[float, dict]] = OrderedDict()
_cooldown_until = 0.0


def _result(url: str, status: str) -> dict:
    return {
        "provider": "urlhaus",
        "indicator": url,
        "status": status,
        "malicious": False if status == "not_found" else None,
        "url_status": None,
        "threat": None,
        "tags": None,
        "date_added": None,
    }


def _report_result(url: str, payload: object) -> dict:
    if not isinstance(payload, dict):
        return _result(url, "unavailable")
    if payload.get("query_status") == "no_results":
        return _result(url, "not_found")
    if (
        payload.get("query_status") != "ok"
        or payload.get("threat") != "malware_download"
        or payload.get("url_status") not in ("online", "offline", "unknown")
    ):
        return _result(url, "unavailable")
    tags = payload.get("tags")
    date_added = payload.get("date_added")
    if tags is not None and (
        not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags)
    ):
        return _result(url, "unavailable")
    if date_added is not None and not isinstance(date_added, str):
        return _result(url, "unavailable")
    return {
        **_result(url, "ok"),
        "malicious": True,
        "url_status": payload["url_status"],
        "threat": payload["threat"],
        "tags": tags,
        "date_added": date_added,
    }


def lookup_url(url: str) -> dict:
    """Cache matches and misses; failed checks remain unknown."""
    global _cooldown_until
    auth_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        return _result(url, "not_configured")
    cache_key = (auth_key, url)
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

    try:
        response = httpx.post(
            URLHAUS_URL,
            headers={"Auth-Key": auth_key},
            data={"url": url},
            timeout=5.0,
            follow_redirects=False,
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
