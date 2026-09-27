"""Country/ASN context for one public IP; never a malicious-IP verdict."""

import os
from collections import OrderedDict
from copy import deepcopy
from ipaddress import ip_address
from threading import Lock
from time import monotonic
from urllib.parse import urlsplit

import httpx

IPINFO_URL = "https://api.ipinfo.io/lite"
DNS_URL = "https://cloudflare-dns.com/dns-query"
CACHE_TTL = 900
MAX_CACHE_ENTRIES = 128
_cache: OrderedDict = OrderedDict()
_lock = Lock()
_cooldown_until = 0.0


def _result(url, status, **fields):
    return {
        "provider": "ipinfo",
        "indicator": url,
        "status": status,
        "ip": None,
        "hostname": None,
        "country": None,
        "country_code": None,
        "asn": None,
        "as_name": None,
        "as_domain": None,
        **fields,
    }


def _public_ip(value):
    try:
        address = ip_address(value)
        return str(address) if address.is_global and not address.is_multicast else None
    except ValueError:
        return None


def _resolve(host):
    """Use bounded DNS requests; prefer A, then AAAA. Never visit the host."""
    for record_type, number in (("A", 1), ("AAAA", 28)):
        response = httpx.get(
            DNS_URL,
            params={"name": host, "type": record_type},
            headers={"Accept": "application/dns-json"},
            timeout=5.0,
            follow_redirects=False,
        )
        if response.status_code != 200:
            return None
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("Status") != 0:
            return None
        answers = payload.get("Answer", [])
        if not isinstance(answers, list):
            return None
        for answer in answers:
            if isinstance(answer, dict) and answer.get("type") == number:
                value = answer.get("data")
                if isinstance(value, str) and (address := _public_ip(value)):
                    return address
    return None


def lookup_url(url: str) -> dict:
    global _cooldown_until
    token = os.getenv("IPINFO_TOKEN", "").strip()
    if not token:
        return _result(url, "not_configured")
    cache_key = (token, url)
    with _lock:
        now = monotonic()
        cached = _cache.get(cache_key)
        if cached and now < cached[0]:
            _cache.move_to_end(cache_key)
            return deepcopy(cached[1])
        if now < _cooldown_until:
            return _result(url, "rate_limited")
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme not in ("http", "https") or not host or "%" in host:
            return _result(url, "unavailable")
        try:
            ip_address(host)
            address = _public_ip(host)
            if address is None:
                return _result(url, "non_public", hostname=host)
        except ValueError:
            if "." not in host or host.endswith((".localhost", ".local", ".internal")):
                return _result(url, "non_public", hostname=host)
            address = _resolve(host.encode("idna").decode("ascii"))
        if not address:
            return _result(url, "unresolved", hostname=host)
        response = httpx.get(
            f"{IPINFO_URL}/{address}",
            params={"token": token},
            timeout=5.0,
            follow_redirects=False,
        )
        if response.status_code == 429:
            with _lock:
                _cooldown_until = max(_cooldown_until, monotonic() + 60)
            return _result(url, "rate_limited", hostname=host, ip=address)
        if response.status_code != 200:
            return _result(url, "unavailable", hostname=host, ip=address)
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("ip") != address:
            return _result(url, "unavailable", hostname=host, ip=address)
        fields = ("country", "country_code", "asn", "as_name", "as_domain")
        if not all(
            isinstance(payload.get(key), str) and payload[key] for key in fields
        ):
            return _result(url, "unavailable", hostname=host, ip=address)
        result = _result(
            url,
            "ok",
            hostname=host,
            ip=address,
            **{key: payload[key] for key in fields},
        )
    except (httpx.HTTPError, ValueError, UnicodeError):
        return _result(url, "unavailable")
    with _lock:
        _cache[cache_key] = (monotonic() + CACHE_TTL, deepcopy(result))
        _cache.move_to_end(cache_key)
        while len(_cache) > MAX_CACHE_ENTRIES:
            _cache.popitem(last=False)
    return result


def lookup_urls(urls: list[str]) -> list[dict]:
    unique = list(dict.fromkeys(urls))
    return (
        ([lookup_url(unique[0])] + [_result(url, "skipped") for url in unique[1:]])
        if unique
        else []
    )
