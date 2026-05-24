from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import joinedload

from database import OperationLog, SessionLocal, User
from middlewares.auth import redis_client


def _decode_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


async def operation_log_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method.upper()
    content_type = (request.headers.get("content-type") or "").lower()

    should_log = method in {"POST", "PUT", "DELETE", "PATCH"} and (
        path.startswith("/admin") or path.startswith("/tenant")
    )
    if path.startswith("/admin/audit") or path.startswith("/tenant/audit"):
        should_log = False

    payload_text = None
    if should_log and content_type and (
        "multipart/form-data" not in content_type and "application/octet-stream" not in content_type
    ):
        raw_body = await request.body()
        if raw_body:
            payload_text = raw_body.decode("utf-8", errors="ignore")
            if len(payload_text) > 2048:
                payload_text = payload_text[:2048] + "..."

    response = await call_next(request)

    if not should_log or response.status_code >= 400:
        return response

    effective_session_id = request.cookies.get("sso_session_id")
    if not effective_session_id:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            effective_session_id = auth_header.split(" ", 1)[1]

    if not effective_session_id or not effective_session_id.startswith("sess_"):
        return response

    raw_user_id = redis_client.get(effective_session_id)
    if not raw_user_id:
        return response

    try:
        user_id = int(_decode_value(raw_user_id))
    except ValueError:
        return response

    db = SessionLocal()
    try:
        user_obj = db.query(User).options(joinedload(User.roles)).filter(User.id == user_id).first()
        if not user_obj or not user_obj.is_active:
            return response

        role_names = {role.name for role in user_obj.roles}
        if "tenant_admin" in role_names and "super_admin" not in role_names and "admin" not in role_names:
            actor_role = "tenant_admin"
        else:
            actor_role = "system_admin"

        level = "INFO"
        if method == "DELETE":
            level = "RISK"
        elif method in {"PUT", "PATCH"}:
            level = "WARN"

        action = f"{method} {path}"
        log_item = OperationLog(
            actor_id=user_obj.id,
            actor_username=user_obj.username,
            actor_role=actor_role,
            group_id=user_obj.group_id,
            method=method,
            path=path,
            action=action,
            level=level,
            ip=getattr(request.client, "host", None),
            payload=payload_text,
        )
        db.add(log_item)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    return response

