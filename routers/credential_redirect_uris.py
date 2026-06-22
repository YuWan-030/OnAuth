from __future__ import annotations

import json
import redis
from typing import Iterable

from sqlalchemy.orm import Session

from database import AppCredential
from middlewares.auth import redis_client

REDIS_CACHE_KEY_PREFIX = "oauth:redirect_uris:"


def _cache_key(client_id: str) -> str:
    return f"{REDIS_CACHE_KEY_PREFIX}{str(client_id or '').strip()}"


def _normalize_redirect_uris(values: Iterable[str] | None) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        uri = str(value or "").strip()
        if uri and uri not in seen:
            seen.add(uri)
            deduped.append(uri)
    return deduped


def _decode_redirect_uris(raw_value: object) -> list[str]:
    if raw_value is None:
        return []

    if isinstance(raw_value, bytes):
        raw_value = raw_value.decode("utf-8", errors="ignore")

    text = str(raw_value or "").strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except Exception:
        pass

    return [item.strip() for item in text.split(",") if item.strip()]


def _sync_redirect_uri_cache(client_id: str, redirect_uris: Iterable[str]) -> None:
    key = _cache_key(client_id)
    values = _normalize_redirect_uris(redirect_uris)
    try:
        if values:
            redis_client.set(key, json.dumps(values, ensure_ascii=False))
        else:
            redis_client.delete(key)
    except Exception:
        # Redis 只作为缓存层，不影响数据库主流程
        return


def load_redirect_uri_whitelist(db: Session, client_id: str) -> list[str]:
    clean_client_id = str(client_id or "").strip()
    if not clean_client_id:
        return []

    credential = db.query(AppCredential).filter(AppCredential.client_id == clean_client_id).first()
    if credential:
        return load_redirect_uri_whitelist_from_credential(credential)

    try:
        cached_values = _decode_redirect_uris(redis_client.get(_cache_key(clean_client_id)))
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        cached_values = []
    if cached_values:
        _sync_redirect_uri_cache(clean_client_id, cached_values)
    return cached_values


def load_redirect_uri_whitelist_from_credential(credential: AppCredential) -> list[str]:
    clean_client_id = str(getattr(credential, "client_id", "") or "").strip()
    if not clean_client_id:
        return []

    stored_values = _decode_redirect_uris(getattr(credential, "redirect_uris_json", None))
    if stored_values:
        _sync_redirect_uri_cache(clean_client_id, stored_values)
        return stored_values

    try:
        cached_values = _decode_redirect_uris(redis_client.get(_cache_key(clean_client_id)))
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        cached_values = []
    if cached_values:
        _sync_redirect_uri_cache(clean_client_id, cached_values)
    return cached_values


def set_redirect_uri_whitelist(credential: AppCredential, redirect_uris: Iterable[str]) -> list[str]:
    values = _normalize_redirect_uris(redirect_uris)
    credential.redirect_uris_json = json.dumps(values, ensure_ascii=False) if values else None
    _sync_redirect_uri_cache(credential.client_id, values)
    return values


def clear_redirect_uri_whitelist(credential: AppCredential) -> None:
    credential.redirect_uris_json = None
    _sync_redirect_uri_cache(credential.client_id, [])

