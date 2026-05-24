from __future__ import annotations

import json
import datetime

import jwt
from fastapi import status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session, joinedload

from config import SECRET_KEY
from database import User, Role, SessionLocal
from middlewares.auth import redis_client
from utils.role_constants import ROLE_SUPER_ADMIN, TENANT_ELEVATED_ROLE_NAMES


def check_user_admin_privilege(session_user_val: str, db: Session) -> bool:
    """
    支持从 Redis 会话中自动识别 User.id (纯数字) 或 Username (字符串),
    检索其是否具备 admin:* 管理权限或属于超级管理员角色。
    """
    if not session_user_val:
        return False

    session_user_val = str(session_user_val).strip()

    try:
        query = db.query(User).options(joinedload(User.roles).joinedload(Role.permissions))

        if session_user_val.isdigit():
            user_obj = query.filter(User.id == int(session_user_val)).first()
        else:
            user_obj = query.filter(User.username == session_user_val).first()

        if not user_obj:
            return False

        for role in user_obj.roles:
            if role.name == ROLE_SUPER_ADMIN:
                return True

            for perm in role.permissions:
                if perm.name and perm.name.startswith("admin:read"):
                    return True

    except Exception:
        return False

    return False


def verify_view_admin_session(auth_token: str) -> bool:
    if not auth_token:
        return False

    db = SessionLocal()
    try:
        if auth_token.startswith("sess_"):
            raw_user_id = redis_client.get(auth_token)
            if not raw_user_id:
                return False
            try:
                user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
            except Exception:
                return False
            user_obj = db.query(User).options(joinedload(User.roles)).filter(User.id == user_id, User.is_active == True).first()
            if not user_obj:
                return False
            return any(role.name == ROLE_SUPER_ADMIN for role in user_obj.roles)

        if redis_client.exists(f"revoked_token:{auth_token}"):
            return False

        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
        userinfo_raw = redis_client.get(f"oauth_userinfo:{auth_token}")
        user_id = None
        username = None

        if userinfo_raw:
            try:
                userinfo = json.loads(userinfo_raw)
                if userinfo.get("user_id") is not None:
                    user_id = int(userinfo.get("user_id"))
                if userinfo.get("username"):
                    username = str(userinfo.get("username")).strip()
            except Exception:
                pass

        sub = payload.get("sub")
        if user_id is None and isinstance(sub, int):
            user_id = sub
        elif user_id is None and isinstance(sub, str) and sub.isdigit():
            user_id = int(sub)
        elif not username and isinstance(sub, str):
            username = sub.strip()

        query = db.query(User).options(joinedload(User.roles)).filter(User.is_active == True)
        if user_id is not None:
            user_obj = query.filter(User.id == user_id).first()
        elif username:
            user_obj = query.filter(User.username == username).first()
        else:
            return False

        if not user_obj:
            return False
        return any(role.name == ROLE_SUPER_ADMIN for role in user_obj.roles)
    except Exception:
        return False
    finally:
        db.close()


def _load_user_from_session(session_user_val: str, db: Session) -> User | None:
    if not session_user_val:
        return None
    session_user_val = str(session_user_val).strip()
    query = db.query(User).options(joinedload(User.roles))
    if session_user_val.isdigit():
        return query.filter(User.id == int(session_user_val)).first()
    return query.filter(User.username == session_user_val).first()


def _is_tenant_admin(user_obj: User | None) -> bool:
    if not user_obj:
        return False
    return any(role.name in TENANT_ELEVATED_ROLE_NAMES for role in user_obj.roles)


def _tenant_access_snapshot(user_obj: User | None):
    if not user_obj:
        return None, "当前账号未找到"

    group = user_obj.group
    if not group:
        return None, "当前账号尚未绑定租户空间"
    if (group.status or "").lower() != "approved":
        return group, "租户空间尚未通过审核"
    if not group.is_active:
        return group, "租户空间已被冻结"
    if group.expire_at and group.expire_at < datetime.datetime.now():
        return group, "租户空间已过期"
    return group, None


def health_payload(database_up: bool, redis_up: bool) -> JSONResponse:
    all_ok = database_up and redis_up
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={
            "status": "ok" if all_ok else "degraded",
            "database": "up" if database_up else "down",
            "redis": "up" if redis_up else "down",
        },
    )


