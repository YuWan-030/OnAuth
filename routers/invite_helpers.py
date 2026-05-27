from __future__ import annotations

import datetime
import json
import secrets

from sqlalchemy.orm import Session

from database import DeveloperGroup, User
from middlewares.auth import redis_client
from utils.role_constants import ROLE_TENANT_ADMIN
from routers.tenant_admin_invites import (
    _issue_tenant_admin_invite_payload as _db_issue_tenant_admin_invite_payload,
    _load_tenant_admin_invite_payload as _db_load_tenant_admin_invite_payload,
    _tenant_admin_invite_record_payload as _db_tenant_admin_invite_record_payload,
    _tenant_admin_invite_status as _db_tenant_admin_invite_status,
    _tenant_admin_invite_list as _db_tenant_admin_invite_list,
    _mark_tenant_admin_invite_used as _db_mark_tenant_admin_invite_used,
)

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
    return _db_issue_tenant_admin_invite_payload(issuer_username, invite_code=invite_code)


def _load_tenant_admin_invite_payload(invite_code: str) -> dict[str, object] | None:
    return _db_load_tenant_admin_invite_payload(invite_code)


def _tenant_admin_invite_record_payload(invite_code: str) -> dict[str, object] | None:
    return _db_tenant_admin_invite_record_payload(invite_code)


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
    _db_mark_tenant_admin_invite_used(invite_code, used_by=used_by)


def _tenant_admin_invite_status(invite_code: str) -> str:
    return _db_tenant_admin_invite_status(invite_code)


def _tenant_admin_invite_list(limit: int = 20) -> list[dict[str, object]]:
    return _db_tenant_admin_invite_list(limit=limit)


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

