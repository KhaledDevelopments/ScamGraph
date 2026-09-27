"""Registration Data Access Protocol (RDAP) domain age lookup."""

import os
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
from ipaddress import ip_address
from threading import Lock
from time import monotonic
from urllib.parse import urlsplit

import httpx

RDAP_URL = "https://rdap.org/domain"
CACHE_TTL = 900
MAX_CACHE_ENTRIES = 128
RECENT_DOMAIN_DAYS = 30
_cache: OrderedDict = OrderedDict()
_lock = Lock()
_cooldown_until = 0.0
_now_fn = lambda: datetime.now(timezone.utc)


def _result(url: str, status: str, **fields) -> dict:
    return {
        "provider": "rdap",
        "indicator": url,
        "status": status,
        "domain": None,
        "registration_date": None,
        "domain_age_days": None,
        "recent_domain": None,
        "registrar": None,
        **fields,
    }


def _registered_domain(hostname: str) -> str:
    """Extract registrable domain from hostname without external dependencies."""
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    two_part_tlds = {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "com.br",
        "org.br",
        "gov.br",
        "co.jp",
        "ne.jp",
        "or.jp",
        "co.kr",
        "ne.kr",
        "com.mx",
        "org.mx",
        "co.za",
        "org.za",
    }
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _parse_event_date(date_str: str) -> datetime | None:
    if not isinstance(date_str, str) or not date_str.strip():
        return None
    try:
        clean = date_str.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _extract_registration_date(events: list) -> tuple[str | None, int | None]:
    """Find registration date in RDAP events and calculate age in days."""
    if not isinstance(events, list):
        return None, None
    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower()
        if action in ("registration", "created"):
            raw_date = event.get("eventDate")
            dt = _parse_event_date(raw_date)
            if dt is not None:
                now = _now_fn()
                days = max(0, (now - dt).days)
                return dt.strftime("%Y-%m-%d"), days
    return None, None


def _extract_registrar(entities: list) -> str | None:
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles", [])
        if isinstance(roles, list) and "registrar" in roles:
            vcard = entity.get("vcardArray")
            if (
                isinstance(vcard, list)
                and len(vcard) >= 2
                and isinstance(vcard[1], list)
            ):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        val = str(item[3]).strip()
                        if val:
                            return val
            handle = entity.get("handle")
            if isinstance(handle, str) and handle.strip():
                return handle.strip()
    return None


def lookup_url(url: str) -> dict:
    global _cooldown_until
    if os.getenv("RDAP_DISABLED", "").strip() in ("1", "true", "yes"):
        return _result(url, "not_configured")

    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme not in ("http", "https") or not host or "%" in host:
            return _result(url, "unavailable")
        try:
            ip_address(host)
            return _result(url, "non_public", domain=host)
        except ValueError:
            if "." not in host or host.endswith((".localhost", ".local", ".internal")):
                return _result(url, "non_public", domain=host)
        domain = _registered_domain(host)
    except (ValueError, UnicodeError):
        return _result(url, "unavailable")

    cache_key = domain
    with _lock:
        now = monotonic()
        cached = _cache.get(cache_key)
        if cached and now < cached[0]:
            _cache.move_to_end(cache_key)
            result = deepcopy(cached[1])
            result["indicator"] = url
            return result
        if now < _cooldown_until:
            return _result(url, "rate_limited", domain=domain)

    try:
        response = httpx.get(
            f"{RDAP_URL}/{domain}",
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=5.0,
            follow_redirects=True,
        )
        if response.status_code == 429:
            with _lock:
                _cooldown_until = max(_cooldown_until, monotonic() + 60)
            return _result(url, "rate_limited", domain=domain)
        if response.status_code == 404:
            result = _result(url, "not_found", domain=domain)
        elif response.status_code != 200:
            return _result(url, "unavailable", domain=domain)
        else:
            payload = response.json()
            if not isinstance(payload, dict):
                return _result(url, "unavailable", domain=domain)
            reg_date, age_days = _extract_registration_date(payload.get("events", []))
            registrar = _extract_registrar(payload.get("entities", []))
            is_recent = age_days < RECENT_DOMAIN_DAYS if age_days is not None else None
            result = _result(
                url,
                "ok",
                domain=domain,
                registration_date=reg_date,
                domain_age_days=age_days,
                recent_domain=is_recent,
                registrar=registrar,
            )
    except (httpx.HTTPError, ValueError):
        return _result(url, "unavailable", domain=domain)

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
