from __future__ import annotations

import datetime
import json
import secrets

from sqlalchemy.orm import Session

from database import DeveloperGroup, User
from middlewares.auth import redis_client
from utils.role_constants import ROLE_TENANT_ADMIN

TENANT_INVITE_TTL_SECONDS = 7 * 24 * 3600
TENANT_INVITE_KEY_PREFIX = "tenant_invite:"
TENANT_ADMIN_INVITE_TTL_SECONDS = 7 * 24 * 3600
TENANT_ADMIN_INVITE_KEY_PREFIX = "tenant_admin_invite:"
TENANT_ADMIN_INVITE_HISTORY_KEY = "tenant_admin_invite:history"
TENANT_ADMIN_INVITE_RECORD_PREFIX = "tenant_admin_invite:record:"


def _tenant_invite_key(invite_token: str) -> str:
    return f"{TENANT_INVITE_KEY_PREFIX}{str(invite_token or '').strip()}"


def _issue_tenant_invite_payload(group: DeveloperGroup, issuer_username: str, invite_token: str | None = None) -> tuple[str, dict[str, object]]:
    token = (invite_token or secrets.token_urlsafe(24)).strip()
    payload = {
        "group_id": int(getattr(group, "id", 0) or 0),
        "group_name": str(getattr(group, "group_name", "") or ""),
        "group_code": str(getattr(group, "group_code", "") or ""),
        "issuer_username": str(issuer_username or ""),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    redis_client.setex(_tenant_invite_key(token), TENANT_INVITE_TTL_SECONDS, json.dumps(payload, ensure_ascii=False))
    return token, payload


def _load_tenant_invite_payload(invite_token: str) -> dict[str, object] | None:
    raw_value = redis_client.get(_tenant_invite_key(invite_token))
    if not raw_value:
        return None
    raw_text = raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value)
    try:
        payload = json.loads(raw_text)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _tenant_admin_invite_key(invite_code: str) -> str:
    return f"{TENANT_ADMIN_INVITE_KEY_PREFIX}{str(invite_code or '').strip()}"


def _tenant_admin_invite_record_key(invite_code: str) -> str:
    return f"{TENANT_ADMIN_INVITE_RECORD_PREFIX}{str(invite_code or '').strip()}"


def _issue_tenant_admin_invite_payload(issuer_username: str, invite_code: str | None = None) -> tuple[str, dict[str, object]]:
    code = (invite_code or secrets.token_urlsafe(18)).strip()
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(seconds=TENANT_ADMIN_INVITE_TTL_SECONDS)
    payload = {
        "issuer_username": str(issuer_username or ""),
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    _safe_redis_call("setex", _tenant_admin_invite_key(code), TENANT_ADMIN_INVITE_TTL_SECONDS, json.dumps(payload, ensure_ascii=False))
    _safe_redis_call("hset", _tenant_admin_invite_record_key(code), mapping={
        "invite_code": code,
        "issuer_username": payload["issuer_username"],
        "created_at": payload["created_at"],
        "expires_at": payload["expires_at"],
        "status": "active",
        "revoked_at": "",
        "revoked_by": "",
    })
    _safe_redis_call("expire", _tenant_admin_invite_record_key(code), TENANT_ADMIN_INVITE_TTL_SECONDS + 30 * 24 * 3600)
    _safe_redis_call("zadd", TENANT_ADMIN_INVITE_HISTORY_KEY, {code: now.timestamp()})
    return code, payload


def _load_tenant_admin_invite_payload(invite_code: str) -> dict[str, object] | None:
    raw_value = redis_client.get(_tenant_admin_invite_key(invite_code))
    if not raw_value:
        return None
    raw_text = raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value)
    try:
        payload = json.loads(raw_text)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _tenant_admin_invite_record_payload(invite_code: str) -> dict[str, object] | None:
    raw_record = _safe_redis_call("hgetall", _tenant_admin_invite_record_key(invite_code))
    if not raw_record:
        return None
    record: dict[str, object] = {}
    for raw_key, raw_value in raw_record.items():
        key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
        value = raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value)
        record[key] = value
    return record


def _format_invite_time(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except Exception:
        return text
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _safe_redis_call(method_name: str, *args, **kwargs):
    method = getattr(redis_client, method_name, None)
    if not callable(method):
        return None
    try:
        return method(*args, **kwargs)
    except Exception:
        return None


def _mark_tenant_admin_invite_used(invite_code: str, used_by: str | None = None) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    _safe_redis_call("hset", _tenant_admin_invite_record_key(invite_code), mapping={
        "status": "used",
        "used_at": now,
        "used_by": str(used_by or ""),
    })
    _safe_redis_call("expire", _tenant_admin_invite_record_key(invite_code), TENANT_ADMIN_INVITE_TTL_SECONDS + 30 * 24 * 3600)


def _tenant_admin_invite_status(invite_code: str) -> str:
    record = _tenant_admin_invite_record_payload(invite_code) or {}
    status_value = str(record.get("status") or "").strip().lower()
    if status_value == "used":
        return "used"
    if status_value == "revoked":
        return "revoked"
    if _safe_redis_call("get", _tenant_admin_invite_key(invite_code)):
        return "active"
    if record:
        return "expired"
    return "missing"


def _tenant_admin_invite_list(limit: int = 20) -> list[dict[str, object]]:
    limit = max(1, min(int(limit or 20), 100))
    raw_codes = _safe_redis_call("zrevrange", TENANT_ADMIN_INVITE_HISTORY_KEY, 0, limit - 1) or []
    items: list[dict[str, object]] = []
    for raw_code in raw_codes:
        code = raw_code.decode("utf-8") if isinstance(raw_code, bytes) else str(raw_code)
        record = _tenant_admin_invite_record_payload(code) or {}
        items.append({
            "invite_code": code,
            "issuer_username": str(record.get("issuer_username") or ""),
            "created_at": _format_invite_time(str(record.get("created_at") or "")),
            "expires_at": _format_invite_time(str(record.get("expires_at") or "")),
            "status": _tenant_admin_invite_status(code),
            "used_at": _format_invite_time(str(record.get("used_at") or "")),
            "used_by": str(record.get("used_by") or ""),
            "revoked_at": str(record.get("revoked_at") or ""),
            "revoked_by": str(record.get("revoked_by") or ""),
        })
    return items


def _build_user_profile_payload(db: Session, current_user: User) -> dict[str, object]:
    group = getattr(current_user, "group", None)
    if group is None and getattr(current_user, "group_id", None):
        group = db.query(DeveloperGroup).filter(DeveloperGroup.id == current_user.group_id).first()
    role_names = [role.name for role in (current_user.roles or []) if getattr(role, "name", None)]
    return {
        "user_id": int(getattr(current_user, "id", 0) or 0),
        "username": str(getattr(current_user, "username", "") or ""),
        "nickname": str(getattr(current_user, "nickname", "") or getattr(current_user, "username", "") or ""),
        "group_id": int(getattr(group, "id", 0) or 0) if group else None,
        "group_name": getattr(group, "group_name", "") if group else "",
        "group_code": getattr(group, "group_code", "") if group else "",
        "roles": role_names,
        "is_tenant_admin": ROLE_TENANT_ADMIN in role_names,
    }

