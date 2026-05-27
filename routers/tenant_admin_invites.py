from __future__ import annotations

import datetime
import json
import secrets
from functools import lru_cache
from typing import cast

from sqlalchemy.orm import Session

from database import Base, SessionLocal, TenantAdminInviteRecord, engine
from middlewares.auth import redis_client

TENANT_ADMIN_INVITE_TTL_SECONDS = 7 * 24 * 3600
TENANT_ADMIN_INVITE_KEY_PREFIX = "tenant_admin_invite:"


def _tenant_admin_invite_key(invite_code: str) -> str:
    return f"{TENANT_ADMIN_INVITE_KEY_PREFIX}{str(invite_code or '').strip()}"


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


def _resolve_db(db: Session | None = None) -> tuple[Session, bool]:
    if db is not None:
        return db, False
    session = SessionLocal()
    _ensure_tenant_admin_invite_table_once()
    return session, True


@lru_cache(maxsize=1)
def _ensure_tenant_admin_invite_table_once() -> None:
    try:
        Base.metadata.create_all(bind=engine, tables=(TenantAdminInviteRecord.__table__,))
    except Exception:
        pass


def _serialize_record(record: TenantAdminInviteRecord | None, db: Session | None = None) -> dict[str, object] | None:
    if not record:
        return None

    now = datetime.datetime.now()
    status = str(record.status or "").strip().lower() or "missing"
    if status == "active":
        active_key_exists = bool(_safe_redis_call("get", _tenant_admin_invite_key(record.invite_code)))
        if record.expires_at and record.expires_at <= now:
            status = "expired"
        elif not active_key_exists:
            status = "expired"
        if status == "expired":
            record.status = "expired"
            try:
                if db is not None:
                    db.flush()
            except Exception:
                pass

    return {
        "invite_code": str(record.invite_code or ""),
        "issuer_username": str(record.issuer_username or ""),
        "created_at": _format_invite_time(record.created_at.isoformat() if record.created_at else ""),
        "expires_at": _format_invite_time(record.expires_at.isoformat() if record.expires_at else ""),
        "status": status,
        "used_at": _format_invite_time(record.used_at.isoformat() if record.used_at else ""),
        "used_by": str(record.used_by or ""),
        "revoked_at": _format_invite_time(record.revoked_at.isoformat() if record.revoked_at else ""),
        "revoked_by": str(record.revoked_by or ""),
    }


def _persist_record(
    invite_code: str,
    issuer_username: str,
    created_at: datetime.datetime,
    expires_at: datetime.datetime,
    status: str = "active",
    used_at: datetime.datetime | None = None,
    used_by: str | None = None,
    revoked_at: datetime.datetime | None = None,
    revoked_by: str | None = None,
    db: Session | None = None,
) -> TenantAdminInviteRecord:
    session, owns_session = _resolve_db(db)
    try:
        _ensure_tenant_admin_invite_table_once()
        code = str(invite_code or "").strip()
        record = cast(TenantAdminInviteRecord | None, session.get(TenantAdminInviteRecord, code))
        if not record:
            record = TenantAdminInviteRecord(invite_code=code)
        record.issuer_username = str(issuer_username or "")
        record.created_at = created_at
        record.expires_at = expires_at
        record.status = str(status or "active").strip().lower() or "active"
        record.used_at = used_at
        record.used_by = str(used_by or "").strip() or None
        record.revoked_at = revoked_at
        record.revoked_by = str(revoked_by or "").strip() or None
        session.add(record)
        session.flush()
        if owns_session:
            session.commit()
        return record
    finally:
        if owns_session:
            session.close()


def _issue_tenant_admin_invite_payload(issuer_username: str, invite_code: str | None = None, db: Session | None = None) -> tuple[str, dict[str, object]]:
    code = (invite_code or secrets.token_urlsafe(18)).strip()
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(seconds=TENANT_ADMIN_INVITE_TTL_SECONDS)
    payload = {
        "issuer_username": str(issuer_username or ""),
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    _safe_redis_call("setex", _tenant_admin_invite_key(code), TENANT_ADMIN_INVITE_TTL_SECONDS, json.dumps(payload, ensure_ascii=False))
    _persist_record(
        code,
        issuer_username=str(issuer_username or ""),
        created_at=now.replace(tzinfo=None),
        expires_at=expires_at.replace(tzinfo=None),
        status="active",
        db=db,
    )
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


def _tenant_admin_invite_record_payload(invite_code: str, db: Session | None = None) -> dict[str, object] | None:
    session, owns_session = _resolve_db(db)
    try:
        _ensure_tenant_admin_invite_table_once()
        code = str(invite_code or "").strip()
        record = cast(TenantAdminInviteRecord | None, session.get(TenantAdminInviteRecord, code))
        return _serialize_record(record, db=session)
    finally:
        if owns_session:
            session.close()


def _tenant_admin_invite_status(invite_code: str, db: Session | None = None) -> str:
    payload = _tenant_admin_invite_record_payload(invite_code, db=db)
    return str(payload.get("status") or "missing") if payload else "missing"


def _tenant_admin_invite_list(limit: int = 20, db: Session | None = None) -> list[dict[str, object]]:
    limit = max(1, min(int(limit or 20), 100))
    session, owns_session = _resolve_db(db)
    try:
        _ensure_tenant_admin_invite_table_once()
        query = session.query(TenantAdminInviteRecord).order_by(TenantAdminInviteRecord.created_at.desc()).limit(limit)
        result: list[dict[str, object]] = []
        for record in query.all():
            item = _serialize_record(record, db=session)
            if item:
                result.append(item)
        return result
    finally:
        if owns_session:
            session.close()


def _mark_tenant_admin_invite_used(invite_code: str, used_by: str | None = None, db: Session | None = None) -> None:
    _safe_redis_call("delete", _tenant_admin_invite_key(invite_code))
    session, owns_session = _resolve_db(db)
    try:
        _ensure_tenant_admin_invite_table_once()
        code = str(invite_code or "").strip()
        record = cast(TenantAdminInviteRecord | None, session.get(TenantAdminInviteRecord, code))
        if record:
            record.status = "used"
            record.used_at = datetime.datetime.now()
            record.used_by = str(used_by or "").strip() or None
            session.add(record)
            session.flush()
            if owns_session:
                session.commit()
    finally:
        if owns_session:
            session.close()


def _mark_tenant_admin_invite_revoked(invite_code: str, revoked_by: str | None = None, db: Session | None = None) -> None:
    _safe_redis_call("delete", _tenant_admin_invite_key(invite_code))
    session, owns_session = _resolve_db(db)
    try:
        _ensure_tenant_admin_invite_table_once()
        code = str(invite_code or "").strip()
        record = cast(TenantAdminInviteRecord | None, session.get(TenantAdminInviteRecord, code))
        if record:
            record.status = "revoked"
            record.revoked_at = datetime.datetime.now()
            record.revoked_by = str(revoked_by or "").strip() or None
            session.add(record)
            session.flush()
            if owns_session:
                session.commit()
    finally:
        if owns_session:
            session.close()


