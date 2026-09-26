import base64
import os
from collections import OrderedDict, deque
from copy import deepcopy
from threading import Lock
from time import monotonic

import httpx

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
CACHE_TTL = 15 * 60
MAX_CACHE_ENTRIES = 128
REQUESTS_PER_MINUTE = 4

# Shared by requests in this backend process. Run one worker for the prototype.
_lock = Lock()
_cache: OrderedDict[tuple[str, str], tuple[float, dict]] = OrderedDict()
_request_times: deque[float] = deque()
_cooldown_until = 0.0


def _url_id(url: str) -> str:
    """Convert a URL into VirusTotal's URL-safe Base64 identifier."""
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def lookup_url(url: str) -> dict:
    """Retrieve an existing report, with a bounded cache and shared rate limit."""
    global _cooldown_until

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return _error_result(url, "not_configured")

    cache_key = (api_key, url)
    with _lock:
        now = monotonic()
        cached = _cache.get(cache_key)
        if cached is not None:
            expires_at, result = cached
            if now < expires_at:
                _cache.move_to_end(cache_key)
                return deepcopy(result)
            del _cache[cache_key]

        while _request_times and now - _request_times[0] >= 60:
            _request_times.popleft()
        if now < _cooldown_until or len(_request_times) >= REQUESTS_PER_MINUTE:
            return _error_result(url, "rate_limited")
        # Reserve a slot before the network call, including concurrent requests.
        _request_times.append(now)

    try:
        response = httpx.get(
            f"{VIRUSTOTAL_URL}/{_url_id(url)}",
            headers={"x-apikey": api_key},
            timeout=5.0,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return _error_result(url, "unavailable")

    if response.status_code == 404:
        result = _error_result(url, "not_found")
    elif response.status_code == 429:
        with _lock:
            _cooldown_until = max(_cooldown_until, monotonic() + 60)
        return _error_result(url, "rate_limited")
    elif response.status_code != 200:
        return _error_result(url, "unavailable")
    else:
        try:
            result = _report_result(url, response.json())
        except ValueError:
            return _error_result(url, "unavailable")

    if result["status"] in {"ok", "not_found"}:
        with _lock:
            _cache[cache_key] = (monotonic() + CACHE_TTL, deepcopy(result))
            _cache.move_to_end(cache_key)
            while len(_cache) > MAX_CACHE_ENTRIES:
                _cache.popitem(last=False)
    return result


def lookup_urls(urls: list[str]) -> list[dict]:
    """Check only the first unique URL per message to conserve the free quota."""
    unique_urls = list(dict.fromkeys(urls))
    if not unique_urls:
        return []
    return [lookup_url(unique_urls[0])] + [
        _error_result(url, "skipped") for url in unique_urls[1:]
    ]


def _report_result(url: str, payload: object) -> dict:
    """Treat incomplete reports as unavailable, never as zero detections."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        return _error_result(url, "unavailable")
    attributes = payload["data"].get("attributes")
    if not isinstance(attributes, dict):
        return _error_result(url, "unavailable")
    stats = attributes.get("last_analysis_stats")
    categories = ("malicious", "suspicious", "harmless", "undetected")
    if not isinstance(stats, dict) or not all(
        _is_nonnegative_int(stats.get(category)) for category in categories
    ):
        return _error_result(url, "unavailable")
    analysis_date = attributes.get("last_analysis_date")
    if analysis_date is not None and not _is_nonnegative_int(analysis_date):
        return _error_result(url, "unavailable")
    return {
        "provider": "virustotal",
        "indicator": url,
        "status": "ok",
        "stats": {category: stats[category] for category in categories},
        "last_analysis_date": analysis_date,
    }


def _is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _error_result(url: str, status: str) -> dict:
    return {
        "provider": "virustotal",
        "indicator": url,
        "status": status,
        "stats": None,
        "last_analysis_date": None,
    }
