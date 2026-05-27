from fastapi import APIRouter, Depends, HTTPException, status, Header, Form, Response, Cookie, Request, BackgroundTasks, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, selectinload
from passlib.context import CryptContext
import datetime
import secrets
import time
import re
import json
from typing import cast

# 🌟 引入数据库实体与核心依赖项
from database import get_db, User, Role, DeveloperGroup, Permission
# 🌟 引入 Redis 客户端（保持原功能连通）
from middlewares.auth import redis_client
from middlewares.rbac import RBACChecker
from routers.admin import _generate_group_code
from routers.oauth import revoke_user_oauth_artifacts
from routers.webhook import dispatch_webhook_event
from utils.captcha import verify_captcha
from utils.role_constants import ROLE_SUPER_ADMIN, ROLE_TENANT_ADMIN
from utils.request_utils import (
    extract_client_meta,
    resolve_ip_location,
    record_risk_event,
    is_global_melt_enabled,
    get_login_fail_policy,
    get_login_fail_count,
    increment_login_fail,
    clear_login_fail,
    captcha_required_response,
)

# 🎯 路由配置对齐：将前缀设为全局共用，内部支持平铺管理端与业务端
router = APIRouter(tags=["中台统一账户与动态会话鉴权中心"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

LOGIN_FAIL_THRESHOLD = 3
LOGIN_FAIL_TTL_SECONDS = 600
LOGIN_FAIL_RULE_TYPE = "LOGIN_FAIL_CAPTCHA"
TENANT_APPLY_TTL_SECONDS = 1800
ACCOUNT_LOCK_THRESHOLD = 10
ACCOUNT_LOCK_TTL_SECONDS = 1800
SESSION_TTL_SECONDS = 86400
PASSWORD_MIN_LENGTH = 8
TENANT_INVITE_TTL_SECONDS = 7 * 24 * 3600
TENANT_INVITE_KEY_PREFIX = "tenant_invite:"
TENANT_ADMIN_INVITE_TTL_SECONDS = 7 * 24 * 3600
TENANT_ADMIN_INVITE_KEY_PREFIX = "tenant_admin_invite:"
TENANT_ADMIN_INVITE_HISTORY_KEY = "tenant_admin_invite:history"
TENANT_ADMIN_INVITE_RECORD_PREFIX = "tenant_admin_invite:record:"

USERNAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,31}$")
XSS_PATTERN = re.compile(r"(?i)(<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*img|<\s*svg)")
PASSWORD_COMPLEXITY_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).+$")


def _get_login_fail_policy(db: Session, request: Request, username: str, fail_count: int) -> tuple[int, int]:
    return get_login_fail_policy(
        db=db,
        request=request,
        username=username,
        fail_count=fail_count,
        default_threshold=LOGIN_FAIL_THRESHOLD,
        default_window=LOGIN_FAIL_TTL_SECONDS,
        rule_type=LOGIN_FAIL_RULE_TYPE,
    )


def _account_lock_key(username: str) -> str:
    safe_user = (username or "").strip().lower() or "unknown"
    return f"account_lock:{safe_user}"


def _get_login_fail_count(username: str, client_ip: str) -> int:
    return get_login_fail_count(redis_client, username, client_ip)


def _is_account_locked(username: str) -> bool:
    value = redis_client.get(_account_lock_key(username))
    return bool(value)


def _lock_account(username: str) -> None:
    redis_client.setex(_account_lock_key(username), ACCOUNT_LOCK_TTL_SECONDS, "1")


def _clear_account_lock(username: str) -> None:
    redis_client.delete(_account_lock_key(username))


def _account_locked_response() -> dict:
    return {
        "message": "登录失败次数过多，账户已临时锁定，请稍后重试",
        "account_locked": True,
        "lock_seconds": ACCOUNT_LOCK_TTL_SECONDS,
    }


def _increment_login_fail(username: str, client_ip: str, ttl_seconds: int) -> int:
    return increment_login_fail(redis_client, username, client_ip, ttl_seconds)


def _clear_login_fail(username: str, client_ip: str) -> None:
    clear_login_fail(redis_client, username, client_ip)


def _captcha_required_response(message: str):
    return captcha_required_response(redis_client, message)


def _resolve_current_session_token(request: Request) -> str | None:
    token = request.cookies.get("sso_session_id")
    if token:
        token = str(token).strip()
        if token:
            return token

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token:
            return token

    return None


def _load_user_from_session_value(db: Session, session_value: str | bytes | None) -> User | None:
    raw_value = session_value.decode("utf-8") if isinstance(session_value, bytes) else str(session_value or "").strip()
    if not raw_value:
        return None

    if raw_value.isdigit():
        return db.query(User).filter(User.id == int(raw_value)).first()

    return None


def _resolve_user_group(db: Session, current_user: User) -> DeveloperGroup | None:
    group = getattr(current_user, "group", None)
    if group is not None:
        return group

    group_id = getattr(current_user, "group_id", None)
    if group_id:
        group = db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).first()
        if group:
            return group

    user_id = getattr(current_user, "id", None)
    if user_id:
        return db.query(DeveloperGroup).filter(DeveloperGroup.owner_user_id == user_id).first()

    return None


def _get_current_tenant_group_or_403(db: Session, current_user: User) -> DeveloperGroup:
    group = _resolve_user_group(db, current_user)
    if not group:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="当前账号未绑定租户空间")

    if (getattr(group, "status", "") or "").lower() != "approved":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="租户空间尚未通过审核")

    if not getattr(group, "is_active", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="租户空间已被冻结")

    expire_at = cast(datetime.datetime | None, getattr(group, "expire_at", None))
    if expire_at and expire_at < datetime.datetime.now():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="租户空间已过期")

    return cast(DeveloperGroup, group)


def _validate_password_strength(password: str) -> None:
    text = str(password or "")
    if len(text) < PASSWORD_MIN_LENGTH:
        raise HTTPException(status_code=422, detail=f"密码长度至少 {PASSWORD_MIN_LENGTH} 位")
    if not PASSWORD_COMPLEXITY_RE.fullmatch(text):
        raise HTTPException(status_code=422, detail="密码必须包含大写字母、小写字母、数字和特殊字符")


def _ensure_role(db: Session, role_name: str, description: str, default_perm_names: list[str]) -> Role:
    role = db.query(Role).filter(Role.name == role_name).first()
    if not role:
        role = Role(name=role_name, description=description)
        db.add(role)
        db.flush()

    if default_perm_names:
        current_perm_names = {p.name for p in (role.permissions or [])}
        for perm_name in default_perm_names:
            if perm_name in current_perm_names:
                continue
            perm = db.query(Permission).filter(Permission.name == perm_name).first()
            if perm:
                role.permissions.append(perm)

    db.commit()
    db.refresh(role)
    return role
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _extract_client_meta(request: Request, include_location: bool = True) -> tuple[str, str, bool, str, str, str]:
    return extract_client_meta(request, include_location=include_location)


def _store_session_meta(session_id: str, client_meta: tuple[str, str, bool, str, str, str]):
    client_ip, user_agent, is_mobile, browser, os_name, location = client_meta
    device_type = "mobile" if is_mobile else "desktop"
    login_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    meta_key = f"sess_meta:{session_id}"
    redis_client.hset(meta_key, mapping={
        "ip": client_ip,
        "ua": user_agent,
        "is_mobile": "1" if is_mobile else "0",
        "device_type": device_type,
        "browser": browser,
        "os": os_name,
        "location": location,
        "login_time": login_time
    })
    redis_client.expire(meta_key, SESSION_TTL_SECONDS)


def _enrich_session_location_async(session_id: str, client_ip: str) -> None:
    # Background enrich: avoid blocking login response on external geo lookup.
    if not session_id or not client_ip:
        return
    location = resolve_ip_location(client_ip)
    try:
        redis_client.hset(f"sess_meta:{session_id}", mapping={"location": location})
    except Exception:
        return


def _resolve_device_type_from_meta(meta: dict[str, str]) -> str:
    raw_type = str(meta.get("device_type", "")).strip().lower()
    if raw_type in {"mobile", "desktop"}:
        return raw_type

    raw_mobile = str(meta.get("is_mobile", "")).strip().lower()
    return "mobile" if raw_mobile in {"1", "true", "yes"} else "desktop"


def _purge_session_artifacts(session_id: str, user_id: int | None = None) -> None:
    token_id = str(session_id or "").strip()
    if not token_id:
        return

    redis_client.delete(token_id)
    redis_client.delete(f"sess_meta:{token_id}")
    redis_client.delete(f"rbac:perms:{token_id}")
    if user_id is not None:
        redis_client.srem(f"user:active_sessions:{user_id}", token_id)


def _purge_user_session_artifacts(user_id: int) -> list[str]:
    user_set_key = f"user:active_sessions:{user_id}"
    token_ids = redis_client.smembers(user_set_key) or []
    purged: list[str] = []

    for raw_token_id in token_ids:
        token_id = raw_token_id.decode("utf-8") if isinstance(raw_token_id, bytes) else str(raw_token_id)
        token_id = token_id.strip()
        if not token_id.startswith("sess_"):
            continue
        _purge_session_artifacts(token_id, user_id=user_id)
        purged.append(token_id)

    redis_client.delete(user_set_key)
    return purged

def _record_risk_event(db: Session, request: Request, risk_level: str, action: str = "BLOCK") -> None:
    record_risk_event(db, request, risk_level, action)


def _is_global_melt_enabled(db: Session) -> bool:
    return is_global_melt_enabled(db)


def _get_role(db: Session, role_name: str) -> Role:
    role = db.query(Role).filter(Role.name == role_name).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"系统角色未初始化: {role_name}"
        )
    return role


def _user_has_role(user: User, role_name: str) -> bool:
    return any(role.name == role_name for role in (user.roles or []))

# --- Pydantic 输入模型验证 ---
class UserRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="用户名")
    password: str = Field(..., min_length=8, description="密码，至少8位")
    nickname: str = Field(None, description="昵称")
    group_code: str | None = Field(None, min_length=4, max_length=32, description="租户空间唯一识别码")
    invite_token: str | None = Field(None, min_length=4, max_length=256, description="邀请注册链接令牌")


class TenantAdminRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="用户名")
    password: str = Field(..., min_length=8, description="密码，至少8位")
    nickname: str = Field(None, description="昵称")
    group_name: str = Field(..., min_length=1, max_length=64, description="租户空间名称")
    group_description: str = Field(None, description="租户空间说明")
    invite_code: str = Field(..., min_length=6, max_length=128, description="系统管理员邀请码")


class TenantUserInviteSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="用户名")
    password: str = Field(..., min_length=8, description="密码，至少8位")
    nickname: str = Field(None, description="昵称")
    group_code: str = Field(None, min_length=4, max_length=32, description="租户空间唯一识别码(仅超管可指定)")


class TenantUserFreezeSchema(BaseModel):
    user_id: int = Field(..., description="要冻结的租户内用户ID")


class TenantUserToggleStatusSchema(BaseModel):
    user_id: int = Field(..., description="要启用或冻结的租户内用户ID")
    is_active: bool = Field(..., description="是否启用")


class UserLoginSchema(BaseModel):
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")
    captcha_token: str | None = Field(None, description="验证码 token")
    captcha_code: str | None = Field(None, description="验证码")


class SessionRevokeInput(BaseModel):
    token_id: str = Field(..., min_length=1, description="会话令牌")


class SessionBatchRevokeInput(BaseModel):
    token_ids: list[str] = Field(default_factory=list, description="会话令牌列表")


class SessionRevokeAllInput(BaseModel):
    keep_current: bool = Field(True, description="是否保留当前会话")


def _looks_like_xss(value: str | None) -> bool:
    if not value:
        return False
    text = str(value).strip()
    if not text:
        return False
    if "<" in text or ">" in text:
        return True
    return bool(XSS_PATTERN.search(text))


def _validate_tenant_admin_apply_payload(payload: "TenantAdminRegisterSchema") -> tuple[str, str, str | None, str | None]:
    username = (payload.username or "").strip()
    group_name = (payload.group_name or "").strip()
    nickname = (payload.nickname or "").strip() or None
    group_description = (payload.group_description or "").strip() or None

    if not USERNAME_PATTERN.fullmatch(username):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="用户名格式非法：需以字母开头，仅允许字母/数字/下划线，长度 3-32"
        )

    for field_name, field_value in {
        "username": username,
        "nickname": nickname,
        "group_name": group_name,
        "group_description": group_description,
    }.items():
        if _looks_like_xss(field_value):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"字段存在潜在XSS风险: {field_name}"
            )

    return username, group_name, nickname, group_description

# --- 邀请码与用户画像辅助函数 ---
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
    redis_client.setex(_tenant_admin_invite_key(code), TENANT_ADMIN_INVITE_TTL_SECONDS, json.dumps(payload, ensure_ascii=False))
    redis_client.hset(_tenant_admin_invite_record_key(code), mapping={
        "invite_code": code,
        "issuer_username": payload["issuer_username"],
        "created_at": payload["created_at"],
        "expires_at": payload["expires_at"],
        "status": "active",
        "revoked_at": "",
        "revoked_by": "",
    })
    redis_client.expire(_tenant_admin_invite_record_key(code), TENANT_ADMIN_INVITE_TTL_SECONDS + 30 * 24 * 3600)
    redis_client.zadd(TENANT_ADMIN_INVITE_HISTORY_KEY, {code: now.timestamp()})
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
    raw_record = redis_client.hgetall(_tenant_admin_invite_record_key(invite_code))
    if not raw_record:
        return None
    record: dict[str, object] = {}
    for raw_key, raw_value in raw_record.items():
        key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
        value = raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value)
        record[key] = value
    return record


def _tenant_admin_invite_status(invite_code: str) -> str:
    record = _tenant_admin_invite_record_payload(invite_code) or {}
    status_value = str(record.get("status") or "").strip().lower()
    if status_value == "revoked":
        return "revoked"
    if redis_client.get(_tenant_admin_invite_key(invite_code)):
        return "active"
    if record:
        return "expired"
    return "missing"


def _tenant_admin_invite_list(limit: int = 20) -> list[dict[str, object]]:
    limit = max(1, min(int(limit or 20), 100))
    raw_codes = redis_client.zrevrange(TENANT_ADMIN_INVITE_HISTORY_KEY, 0, limit - 1)
    items: list[dict[str, object]] = []
    for raw_code in raw_codes:
        code = raw_code.decode("utf-8") if isinstance(raw_code, bytes) else str(raw_code)
        record = _tenant_admin_invite_record_payload(code) or {}
        items.append({
            "invite_code": code,
            "issuer_username": str(record.get("issuer_username") or ""),
            "created_at": str(record.get("created_at") or ""),
            "expires_at": str(record.get("expires_at") or ""),
            "status": _tenant_admin_invite_status(code),
            "revoked_at": str(record.get("revoked_at") or ""),
            "revoked_by": str(record.get("revoked_by") or ""),
        })
    return items


@router.get("/admin/tenant_admin/invite_codes", summary="【超管】查看租户管理员邀请码历史")
def list_tenant_admin_invite_codes(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(RBACChecker("admin:create")),
):
    if ROLE_SUPER_ADMIN not in {role.name for role in (current_user.roles or [])}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅超级管理员可查看邀请码历史")

    return {"status": "success", "data": _tenant_admin_invite_list(limit=limit)}


@router.post("/admin/tenant_admin/invite_code/revoke", summary="【超管】作废租户管理员邀请码")
def revoke_tenant_admin_invite_code(
    invite_code: str = Form(..., min_length=4),
    current_user: User = Depends(RBACChecker("admin:create")),
):
    if ROLE_SUPER_ADMIN not in {role.name for role in (current_user.roles or [])}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅超级管理员可作废邀请码")

    invite_code = str(invite_code or "").strip()
    record = _tenant_admin_invite_record_payload(invite_code)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="邀请码不存在或已过期")

    if str(record.get("status") or "").strip().lower() == "revoked":
        return {"status": "success", "message": "邀请码已作废", "data": {"invite_code": invite_code, "status": "revoked"}}

    redis_client.delete(_tenant_admin_invite_key(invite_code))
    redis_client.hset(_tenant_admin_invite_record_key(invite_code), mapping={
        "status": "revoked",
        "revoked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "revoked_by": str(getattr(current_user, "username", "") or ""),
    })
    redis_client.expire(_tenant_admin_invite_record_key(invite_code), 30 * 24 * 3600)
    return {
        "status": "success",
        "message": "邀请码已作废",
        "data": {
            "invite_code": invite_code,
            "status": "revoked",
            "revoked_by": str(getattr(current_user, "username", "") or ""),
        },
    }


@router.get("/auth/register/invite_info", summary="获取邀请注册链接信息")
def get_register_invite_info(
        invite_token: str = Query(..., min_length=4, max_length=256),
        db: Session = Depends(get_db)
):
    payload = _load_tenant_invite_payload(invite_token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="邀请链接已失效或不存在")

    group_id = payload.get("group_id")
    group = db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).first() if group_id is not None else None
    if not group or not group.is_active or (group.status or "").lower() != "approved":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="邀请链接对应的租户空间不可用")

    return {
        "status": "success",
        "data": {
            "group_id": group.id,
            "group_name": group.group_name,
            "group_code": group.group_code,
            "invite_token": invite_token,
            "expires_in_seconds": TENANT_INVITE_TTL_SECONDS,
        }
    }


def _tenant_apply_limit_key(client_ip: str) -> str:
    safe_ip = (client_ip or "-").strip() or "-"
    return f"tenant_apply_lock:{safe_ip}"


def _acquire_tenant_apply_limit(client_ip: str) -> None:
    lock_key = _tenant_apply_limit_key(client_ip)
    accepted = redis_client.set(lock_key, "1", ex=TENANT_APPLY_TTL_SECONDS, nx=True)
    if not accepted:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="同一IP在当前时间窗口内仅允许提交一次租户申请，请稍后再试"
        )

# --- 1. 用户注册接口 ---
@router.post("/auth/register", summary="普通用户注册")
def register_user(payload: UserRegisterSchema, db: Session = Depends(get_db)):
    _validate_password_strength(payload.password)

    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该用户名已被注册，请更换"
        )

    invite_token = str(payload.invite_token or "").strip()
    if not invite_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="普通用户注册必须使用租户空间邀请码")

    invite_payload = _load_tenant_invite_payload(invite_token)
    if not invite_payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="邀请码已失效或不存在")

    invite_group_id = invite_payload.get("group_id")
    group = db.query(DeveloperGroup).filter(DeveloperGroup.id == invite_group_id).first() if invite_group_id is not None else None

    if not group or not group.is_active or (group.status or "").lower() != "approved":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="租户空间不存在、未通过审批或已被停用"
        )

    hashed_password = pwd_context.hash(payload.password)

    new_user = User(
        username=payload.username,
        password_hash=hashed_password,
        nickname=payload.nickname or payload.username,
        is_active=True,
        group_id=group.id
    )

    # 自动归入默认普通用户角色组
    default_role = _ensure_role(db, "standard_user", "普通注册合规用户组", ["read", "write"])
    new_user.roles.append(default_role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    dispatch_webhook_event(
        event_type="user.create",
        payload={
            "user_id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "created_at": str(new_user.created_at),
            "group_id": group.id,
            "group_code": group.group_code
        },
        db=db
    )

    return {
        "status": "success",
        "message": "用户注册成功，并已自动划归至 [standard_user] 权限组",
        "user_id": new_user.id,
        "username": new_user.username,
        "assigned_role": default_role.name,
        "group_id": group.id,
        "group_name": group.group_name
    }

@router.get("/auth/me", summary="获取当前登录用户画像")
def get_current_user_profile(
        current_user: User = Depends(RBACChecker("read")),
        db: Session = Depends(get_db)
):
    return {
        "status": "success",
        "data": _build_user_profile_payload(db, current_user)
    }


@router.post("/auth/register/tenant_admin", summary="租户管理员公开申请")
def register_tenant_admin(
    payload: TenantAdminRegisterSchema,
    request: Request,
    db: Session = Depends(get_db)
):
    _validate_password_strength(payload.password)

    username, group_name, nickname, group_description = _validate_tenant_admin_apply_payload(payload)
    client_ip, _, _, _, _, _ = _extract_client_meta(request)
    _acquire_tenant_apply_limit(client_ip)

    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该用户名已被注册，请更换"
        )

    existing_group = db.query(DeveloperGroup).filter(DeveloperGroup.group_name == group_name).first()
    if existing_group:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该租户空间名称已被占用"
        )

    invite_code = str(payload.invite_code or "").strip()
    if not invite_code:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="租户管理员注册需要系统管理员邀请码")

    invite_payload = _load_tenant_admin_invite_payload(invite_code)
    if not invite_payload:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="系统管理员邀请码无效或已过期")
    invite_issuer_username = str(invite_payload.get("issuer_username") or "")

    if hasattr(redis_client, "delete"):
        redis_client.delete(_tenant_admin_invite_key(invite_code))

    group_code = _generate_group_code(db)
    new_group = DeveloperGroup(
        group_name=group_name,
        description=group_description,
        group_code=group_code,
        owner=username,
        is_active=False,
        status="pending"
    )
    db.add(new_group)
    db.commit()
    db.refresh(new_group)

    hashed_password = pwd_context.hash(payload.password)
    new_user = User(
        username=username,
        password_hash=hashed_password,
        nickname=nickname or username,
        is_active=True,
        group_id=new_group.id
    )

    tenant_admin_role = _ensure_role(
        db,
        "tenant_admin",
        "租户空间管理员",
        ["read", "write", "tenant:user:create", "webhook:create", "webhook:update", "webhook:list", "webhook:delete", "webhook:logs"],
    )
    webhook_perm_names = ["webhook:create", "webhook:update", "webhook:list", "webhook:delete", "webhook:logs"]
    existing_perm_names = {p.name for p in tenant_admin_role.permissions}
    for perm_name in webhook_perm_names:
        if perm_name not in existing_perm_names:
            perm = db.query(Permission).filter(Permission.name == perm_name).first()
            if perm:
                tenant_admin_role.permissions.append(perm)
    db.commit()

    new_user.roles.append(tenant_admin_role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    new_group.owner_user_id = new_user.id
    db.commit()

    dispatch_webhook_event(
        event_type="tenant_admin.create",
        payload={
            "user_id": new_user.id,
            "username": new_user.username,
            "group_id": new_group.id,
            "group_code": new_group.group_code,
            "client_ip": client_ip,
            "invite_issuer_username": invite_issuer_username,
        },
        db=db
    )

    return {
        "status": "success",
        "message": "申请已提交，租户空间已创建并进入待超级管理员审核状态",
        "user_id": new_user.id,
        "username": new_user.username,
        "assigned_role": tenant_admin_role.name,
        "group_id": new_group.id,
        "group_name": new_group.group_name,
        "group_code": new_group.group_code,
        "apply_window_seconds": TENANT_APPLY_TTL_SECONDS
    }


# --- 2. 管理中台核心：用户/管理员登录接口 ---
# 支持多路由别名绑定，共享同一个底层业务闭环
@router.post("/admin/token", summary="【核心】管理员/用户登录并灌注统一会话Cookie")
@router.post("/auth/login", summary="【兼容】用户登录标准接口")
def login_user(
        payload: UserLoginSchema,
        request: Request,
        background_tasks: BackgroundTasks,
        response: Response,
        db: Session = Depends(get_db)
):
    """
    🔒 极简单轨 Session 架构：
    核验用户名密码成功后，向 Redis 灌入随机 Session 令牌。
    通过全局唯一的 sso_session_id Cookie 注入，配合响应体回传，
    让管理后台前端、客户端与 OAuth 授权大厅共享同一套生命周期。
    """
    if _is_global_melt_enabled(db):
        _record_risk_event(db, request, risk_level="high", action="BLOCK")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="全局熔断已开启，登录入口临时关闭，请稍后重试"
        )

    client_meta = _extract_client_meta(request, include_location=False)
    client_ip, user_agent, is_mobile, browser, os_name, _ = client_meta
    if _is_account_locked(payload.username):
        _record_risk_event(db, request, risk_level="high", action="LOCK")
        return JSONResponse(status_code=status.HTTP_423_LOCKED, content=_account_locked_response())

    fail_count = _get_login_fail_count(payload.username, client_ip)
    threshold, window_seconds = _get_login_fail_policy(db, request, payload.username, fail_count)
    if fail_count >= threshold:
        if not verify_captcha(redis_client, payload.captcha_token, payload.captcha_code):
            return _captcha_required_response("登录失败次数过多，请输入验证码")

    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not pwd_context.verify(payload.password, user.password_hash):
        _record_risk_event(db, request, risk_level="high")
        new_count = _increment_login_fail(payload.username, client_ip, window_seconds)
        if new_count >= ACCOUNT_LOCK_THRESHOLD:
            _lock_account(payload.username)
            return JSONResponse(status_code=status.HTTP_423_LOCKED, content=_account_locked_response())
        if new_count >= threshold:
            return _captcha_required_response("登录失败次数过多，请输入验证码")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )

    if not user.is_active:
        _record_risk_event(db, request, risk_level="medium")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="该账户已被冻结，请联系管理员"
        )

    _clear_login_fail(payload.username, client_ip)
    _clear_account_lock(payload.username)

    new_session_id = "sess_" + secrets.token_hex(12)

    redis_client.setex(new_session_id, SESSION_TTL_SECONDS, str(user.id))

    user_set_key = f"user:active_sessions:{user.id}"
    redis_client.sadd(user_set_key, new_session_id)
    redis_client.expire(user_set_key, SESSION_TTL_SECONDS)

    _store_session_meta(new_session_id, client_meta)
    background_tasks.add_task(_enrich_session_location_async, new_session_id, client_ip)

    user_scopes = []
    for role in user.roles:
        if hasattr(role, 'permissions'):
            for perm in role.permissions:
                if perm.name:
                    user_scopes.append(perm.name)

    final_scopes_list = list(set(user_scopes)) if user_scopes else ["read"]

    response.set_cookie(
        key="sso_session_id",
        value=new_session_id,
        httponly=True,  #
        path="/",
        secure=False,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
        expires=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=SESSION_TTL_SECONDS),
    )

    dispatch_webhook_event(
        event_type="auth.login",
        payload={
            "user_id": user.id,
            "username": user.username,
            "ip_address": client_ip,
            "login_at": int(time.time()),
            "entry_point": request.url.path,
            "browser": browser,
            "os": os_name,
            "is_mobile": bool(is_mobile),
            "user_agent": user_agent,
        },
        db=db
    )

    return {
        "status": "success",
        "message": "中台身份核验通过，单轨分布式 Session 会话已成功建立！",
        "token_type": "bearer",
        "sso_session_id": new_session_id,
        "username": user.username,
        "scopes": final_scopes_list
    }


# ==================== 🛠️ 改造核心接口 1：用户退出登录 (单轨 Session 彻底粉碎) ====================
@router.post("/auth/logout", summary="用户退出登录")
@router.get("/admin/logout", summary="【管理端】快捷退出登录视图管线")
def logout_user(
        response: Response,
        authorization: str = Header(None, description="承载标准 Bearer Token 的请求头"),
        sso_session_id_cookie: str = Cookie(None, alias="sso_session_id", description="从 Cookie 缓存池中捕获的唯一会话令牌"),
        sso_session_id_form: str = Form(None, alias="sso_session_id", description="可选：通过表单显式提交的会话ID")
):
    """
    业务逻辑（纯 Session 大一统改造版）：
    1. 多渠道提取当前的 Session ID（Header / Cookie / Form）。
    2. 服务端斩草除根：直接从 Redis 中彻底 delete 掉该 Session ID，瞬间令全网所有端同时下线。
    3. 客户端物理擦除：向响应头下发 delete 指令，强制浏览器抹除 sso_session_id Cookie。
    """
    # 🚀 1. 多渠道自适应清洗唯一的会话钥匙
    target_session_id = None

    if authorization and authorization.startswith("Bearer "):
        target_session_id = authorization.split(" ")[1]
    elif sso_session_id_cookie:
        target_session_id = sso_session_id_cookie
    elif sso_session_id_form:
        target_session_id = sso_session_id_form

    # 🚀 2. 服务端状态粉碎
    if target_session_id and target_session_id.startswith("sess_"):
        # 直接物理删除，让这把钥匙彻底失效，根本不需要维护臃肿的黑名单数据！
        meta_key = f"sess_meta:{target_session_id}"
        raw_user_id = redis_client.get(target_session_id)
        if raw_user_id:
            try:
                user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
            except ValueError:
                user_id = None
            if user_id:
                user_set_key = f"user:active_sessions:{user_id}"
                redis_client.srem(user_set_key, target_session_id)
        redis_client.delete(target_session_id)
        redis_client.delete(meta_key)

    # 🚀 3. 客户端 Cookie 擦除
    # 必须保证 path="/" 与登录时严格对齐，否则浏览器会因为路径不匹配而拒绝擦除！
    response.delete_cookie(
        key="sso_session_id",
        path="/",
        secure=False,   # 本地调试设为 False，与登录接口完全对齐
        httponly=True,
        samesite="lax"
    )

    return {
        "status": "success",
        "message": "单点登录会话已从服务端安全粉碎，浏览器托管的全局 Cookie 凭证已同步完成擦除清空！"
    }



# ==================== 🛠️ 改造核心接口 2：注销账户 (Delete Account - 纯 Session 版) ====================
@router.delete("/auth/unregister", summary="合规性用户账户销户/注销")
def delete_account(
        response: Response,
        confirm_password: str = Form(..., description="高危操作：必须重新验证用户当前密码"),
        authorization: str = Header(None, description="承载标准 Bearer Token 的请求头"),
        sso_session_id_cookie: str = Cookie(None, alias="sso_session_id", description="从 Cookie 中捕获的会话令牌"),
        sso_session_id_form: str = Form(None, alias="sso_session_id", description="从表单中提交的会话令牌"),
        db: Session = Depends(get_db)
):
    """
    业务逻辑（Session 大一统改造版）：
    1. 多渠道自适应提取当前的 Session ID。
    2. 去 Redis 中提取对应的真实用户名，不再解密 JWT。
    3. 严苛核验密码通过后，物理抹除数据库用户实体，并同步粉碎 Redis 会话与浏览器 Cookie。
    """
    # 🚀 1. 多渠道清洗唯一的会话钥匙
    target_session_id = None
    if authorization and authorization.startswith("Bearer "):
        target_session_id = authorization.split(" ")[1]
    elif sso_session_id_cookie:
        target_session_id = sso_session_id_cookie
    elif sso_session_id_form:
        target_session_id = sso_session_id_form

    if not target_session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="身份认证已失效，请重新登录后再执行高危操作")

    # 🚀 2. 从 Redis 统一中控中直接捞取用户名
    username = redis_client.get(target_session_id)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="非法或已过期的会话凭证，拒绝高危执行")

    # 🚀 3. 锁定数据库用户（Redis 里存的是 user_id，兼容旧 username 会话）
    user = _load_user_from_session_value(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="目标账户不存在")

    user_id = int(user.id)
    username_text = str(user.username)

    # 🚀 4. 严苛验证密码
    if not pwd_context.verify(confirm_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="安全审计失败：密码校验错误，拒绝销户请求")

    # 🚀 5. 斩草除根：物理抹除与分布式会话粉碎
    _purge_user_session_artifacts(user_id)
    _purge_session_artifacts(target_session_id, user_id=user_id)
    db.delete(user)
    db.commit()
    dispatch_webhook_event(
        event_type="user.delete",
        payload={
            "user_id": user_id,
            "status": "terminated"
        },
        db=db
    )

    # 强行清洗浏览器托管的 Cookie 凭证（注意 path="/" 的严格对齐）
    response.delete_cookie(
        key="sso_session_id",
        path="/",
        secure=False,
        httponly=True,
        samesite="lax"
    )

    return {
        "status": "success",
        "message": f"用户账户 [{username_text}] 已成功物理销户，相关核心数据及全网 Session 会话已被全面抹除清空。"
    }


# ==================== 🛠️ 改造核心接口 3：修改密码 (Change Password - 纯 Session 版) ====================
@router.post("/auth/change_password", summary="用户修改密码")
def change_password(
        current_password: str = Form(..., description="当前密码"),
        new_password: str = Form(..., min_length=8, description="新密码，至少8位"),
        authorization: str = Header(None, description="承载标准 Bearer Token 的请求头"),
        sso_session_id_cookie: str = Cookie(None, alias="sso_session_id", description="从 Cookie 中捕获的会话令牌"),
        db: Session = Depends(get_db)
):
    """
    业务逻辑（Session 大一统改造版）：
    1. 自适应提取 Session 钥匙。
    2. 基于 Redis 状态机核验身份，通过后更改数据库密码。
    """
    # 🚀 1. 钥匙清洗
    target_session_id = None
    if authorization and authorization.startswith("Bearer "):
        target_session_id = authorization.split(" ")[1]
    elif sso_session_id_cookie:
        target_session_id = sso_session_id_cookie

    if not target_session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="身份认证已失效，请重新登录后再执行操作")

    # 🚀 2. 状态检索
    username = redis_client.get(target_session_id)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="会话已过期或已被吊销，请重新登录")

    # 🚀 3. 密码置换审计（Redis 里存的是 user_id，兼容旧 username 会话）
    user = _load_user_from_session_value(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="目标账户不存在")

    if not pwd_context.verify(current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前密码错误，拒绝修改")

    _validate_password_strength(new_password)

    # 哈希加盐持久化新密码
    user.password_hash = pwd_context.hash(new_password)
    db.commit()

    # 💡 贴心策略（可选）：修改密码后你可以选择将当前用户的 Session 清掉迫使其重新登录，
    # 或者是保持原有连接。这里我们让其保持登录，返回成功：
    return {
        "status": "success",
        "message": f"用户 [{username}] 密码修改成功，新策略已实时并网生效！"
    }

@router.post("/tenant/users/invite", summary="租户管理员邀请创建使用者账号")
def invite_tenant_user(
        payload: TenantUserInviteSchema,
        current_user: User = Depends(RBACChecker("tenant:user:create")),
        db: Session = Depends(get_db)
):
    _validate_password_strength(payload.password)

    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="用户名已存在")

    target_group = None
    if _user_has_role(current_user, "super_admin") and payload.group_code:
        target_group = db.query(DeveloperGroup).filter(DeveloperGroup.group_code == payload.group_code).first()
    else:
        if current_user.group_id:
            target_group = db.query(DeveloperGroup).filter(DeveloperGroup.id == current_user.group_id).first()

    if not target_group or not target_group.is_active or (target_group.status or "").lower() != "approved":
        raise HTTPException(status_code=404, detail="租户空间不存在、未通过审批或已被停用")

    new_user = User(
        username=payload.username,
        password_hash=pwd_context.hash(payload.password),
        nickname=payload.nickname or payload.username,
        is_active=True,
        group_id=target_group.id
    )

    default_role = _ensure_role(db, "standard_user", "普通注册合规用户组", ["read", "write"])
    new_user.roles.append(default_role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    dispatch_webhook_event(
        event_type="tenant_user.invite",
        payload={
            "user_id": new_user.id,
            "username": new_user.username,
            "group_id": target_group.id,
            "group_code": target_group.group_code,
            "invited_by": current_user.username
        },
        db=db
    )

    return {
        "status": "success",
        "message": "使用者账号已创建",
        "user_id": new_user.id,
        "username": new_user.username,
        "group_id": target_group.id,
        "group_name": target_group.group_name
    }


@router.post("/tenant/users/invite_link", summary="租户管理员生成邀请注册链接")
def generate_tenant_user_invite_link(
        current_user: User = Depends(RBACChecker("tenant:user:invite_link")),
        db: Session = Depends(get_db)
):
    group = _get_current_tenant_group_or_403(db, current_user)
    invite_token, payload = _issue_tenant_invite_payload(group, current_user.username)
    return {
        "status": "success",
        "message": "邀请注册链接已生成",
        "data": {
            "invite_token": invite_token,
            "invite_url": f"/register?invite_token={invite_token}&register_type=user",
            "group_id": payload["group_id"],
            "group_name": payload["group_name"],
            "group_code": payload["group_code"],
            "expires_in_seconds": TENANT_INVITE_TTL_SECONDS,
        }
    }


@router.get("/tenant/users/list", summary="租户管理员查看本租户用户列表")
def list_tenant_users(
        current_user: User = Depends(RBACChecker("tenant:user:create")),
        db: Session = Depends(get_db)
):
    group = _get_current_tenant_group_or_403(db, current_user)
    users = (
        db.query(User)
        .options(selectinload(User.roles))
        .filter(User.group_id == group.id)
        .order_by(User.id.desc())
        .all()
    )

    return {
        "status": "success",
        "count": len(users),
        "data": [
            {
                "user_id": user.id,
                "username": user.username,
                "nickname": user.nickname or user.username,
                "email": user.email or "",
                "is_active": bool(user.is_active),
                "frozen_by_role": getattr(user, "frozen_by_role", None) or "",
                "roles": [role.name for role in (user.roles or []) if getattr(role, "name", None)],
                "created_at": user.created_at.strftime("%Y-%m-%d %H:%M:%S") if user.created_at else "-",
            }
            for user in users
        ]
    }


@router.post("/tenant/users/toggle_status", summary="租户管理员启用/冻结本租户用户")
def toggle_tenant_user_status(
        payload: TenantUserToggleStatusSchema,
        current_user: User = Depends(RBACChecker("tenant:user:update")),
        db: Session = Depends(get_db)
):
    group = _get_current_tenant_group_or_403(db, current_user)
    target_user = (
        db.query(User)
        .options(selectinload(User.roles))
        .filter(User.id == payload.user_id, User.group_id == group.id)
        .first()
    )
    if not target_user:
        raise HTTPException(status_code=404, detail="未找到当前租户空间内的目标用户")

    target_user_id = int(getattr(target_user, "id", 0) or 0)
    target_username = str(getattr(target_user, "username", "") or "")
    freeze_origin = str(getattr(target_user, "frozen_by_role", "") or "")

    if target_user_id == int(getattr(current_user, "id", 0) or 0):
        raise HTTPException(status_code=400, detail="不能修改当前登录账号状态")

    if payload.is_active:
        if freeze_origin == "system_admin":
            raise HTTPException(status_code=403, detail="该用户由超级管理员冻结，租户管理员无权启用")
        target_user.is_active = True
        target_user.frozen_by_role = None
        db.commit()
        dispatch_webhook_event(
            event_type="tenant_user.enable",
            payload={
                "user_id": target_user_id,
                "username": target_username,
                "group_id": group.id,
                "group_name": group.group_name,
                "operator": current_user.username,
            },
            db=db
        )
        return {
            "status": "success",
            "message": f"用户 [{target_username}] 已启用",
            "data": {"user_id": target_user_id, "username": target_username, "is_active": True, "frozen_by_role": ""}
        }

    target_user.is_active = False
    target_user.frozen_by_role = "tenant_admin"
    db.commit()
    purged_sessions = _purge_user_session_artifacts(target_user_id)
    revoked_oauth = revoke_user_oauth_artifacts(target_user_id, target_username)
    dispatch_webhook_event(
        event_type="tenant_user.freeze",
        payload={
            "user_id": target_user_id,
            "username": target_username,
            "group_id": group.id,
            "group_name": group.group_name,
            "operator": current_user.username,
            "purged_sessions": purged_sessions,
            "revoked_oauth": revoked_oauth,
        },
        db=db
    )
    return {
        "status": "success",
        "message": f"用户 [{target_username}] 已冻结",
        "data": {
            "user_id": target_user_id,
            "username": target_username,
            "is_active": False,
            "frozen_by_role": "tenant_admin",
            "purged_sessions": purged_sessions,
            "revoked_oauth": revoked_oauth,
        }
    }


@router.post("/tenant/users/freeze", summary="租户管理员冻结本租户用户")
def freeze_tenant_user(
        payload: TenantUserFreezeSchema,
        current_user: User = Depends(RBACChecker("tenant:user:update")),
        db: Session = Depends(get_db)
):
    group = _get_current_tenant_group_or_403(db, current_user)
    target_user = (
        db.query(User)
        .options(selectinload(User.roles))
        .filter(User.id == payload.user_id, User.group_id == group.id)
        .first()
    )
    if not target_user:
        raise HTTPException(status_code=404, detail="未找到当前租户空间内的目标用户")

    target_user_id = int(getattr(target_user, "id", 0) or 0)
    target_username = str(getattr(target_user, "username", "") or "")

    if target_user_id == int(getattr(current_user, "id", 0) or 0):
        raise HTTPException(status_code=400, detail="不能冻结当前登录账号")

    if not target_user.is_active:
        if getattr(target_user, "frozen_by_role", None) == "system_admin":
            raise HTTPException(status_code=403, detail="该用户由超级管理员冻结，租户管理员无权启用")
        purged_sessions = _purge_user_session_artifacts(target_user_id)
        revoked_oauth = revoke_user_oauth_artifacts(target_user_id, target_username)
        return {
            "status": "success",
            "message": f"用户 [{target_username}] 已处于冻结状态",
            "data": {
                "user_id": target_user_id,
                "username": target_username,
                "is_active": target_user.is_active,
                "frozen_by_role": getattr(target_user, "frozen_by_role", "") or "",
                "purged_sessions": purged_sessions,
                "revoked_oauth": revoked_oauth,
            }
        }

    target_user.is_active = False
    target_user.frozen_by_role = "tenant_admin"
    db.commit()

    purged_sessions = _purge_user_session_artifacts(target_user_id)
    revoked_oauth = revoke_user_oauth_artifacts(target_user_id, target_username)

    dispatch_webhook_event(
        event_type="tenant_user.freeze",
        payload={
            "user_id": target_user.id,
            "username": target_username,
            "group_id": group.id,
            "group_name": group.group_name,
            "operator": current_user.username,
            "purged_sessions": purged_sessions,
            "revoked_oauth": revoked_oauth,
        },
        db=db
    )

    return {
        "status": "success",
        "message": f"用户 [{target_username}] 已冻结",
        "data": {
            "user_id": target_user_id,
            "username": target_username,
            "is_active": target_user.is_active,
            "frozen_by_role": "tenant_admin",
            "purged_sessions": purged_sessions,
            "revoked_oauth": revoked_oauth,
        }
    }


# ==================== 🛠️ 改造核心接口 1：用户退出登录 (单轨 Session 彻底粉碎) ====================
@router.post("/auth/logout", summary="用户退出登录")
@router.get("/admin/logout", summary="【管理端】快捷退出登录视图管线")
def logout_user(
        response: Response,
        authorization: str = Header(None, description="承载标准 Bearer Token 的请求头"),
        sso_session_id_cookie: str = Cookie(None, alias="sso_session_id", description="从 Cookie 缓存池中捕获的唯一会话令牌"),
        sso_session_id_form: str = Form(None, alias="sso_session_id", description="可选：通过表单显式提交的会话ID")
):
    """
    业务逻辑（纯 Session 大一统改造版）：
    1. 多渠道提取当前的 Session ID（Header / Cookie / Form）。
    2. 服务端斩草除根：直接从 Redis 中彻底 delete 掉该 Session ID，瞬间令全网所有端同时下线。
    3. 客户端物理擦除：向响应头下发 delete 指令，强制浏览器抹除 sso_session_id Cookie。
    """
    # 🚀 1. 多渠道自适应清洗唯一的会话钥匙
    target_session_id = None

    if authorization and authorization.startswith("Bearer "):
        target_session_id = authorization.split(" ")[1]
    elif sso_session_id_cookie:
        target_session_id = sso_session_id_cookie
    elif sso_session_id_form:
        target_session_id = sso_session_id_form

    # 🚀 2. 服务端状态粉碎
    if target_session_id and target_session_id.startswith("sess_"):
        # 直接物理删除，让这把钥匙彻底失效，根本不需要维护臃肿的黑名单数据！
        meta_key = f"sess_meta:{target_session_id}"
        raw_user_id = redis_client.get(target_session_id)
        if raw_user_id:
            try:
                user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
            except ValueError:
                user_id = None
            if user_id:
                user_set_key = f"user:active_sessions:{user_id}"
                redis_client.srem(user_set_key, target_session_id)
        redis_client.delete(target_session_id)
        redis_client.delete(meta_key)

    # 🚀 3. 客户端 Cookie 擦除
    # 必须保证 path="/" 与登录时严格对齐，否则浏览器会因为路径不匹配而拒绝擦除！
    response.delete_cookie(
        key="sso_session_id",
        path="/",
        secure=False,   # 本地调试设为 False，与登录接口完全对齐
        httponly=True,
        samesite="lax"
    )

    return {
        "status": "success",
        "message": "单点登录会话已从服务端安全粉碎，浏览器托管的全局 Cookie 凭证已同步完成擦除清空！"
    }



# ==================== 🛠️ 改造核心接口 2：注销账户 (Delete Account - 纯 Session 版) ====================
@router.delete("/auth/unregister", summary="合规性用户账户销户/注销")
def delete_account(
        response: Response,
        confirm_password: str = Form(..., description="高危操作：必须重新验证用户当前密码"),
        authorization: str = Header(None, description="承载标准 Bearer Token 的请求头"),
        sso_session_id_cookie: str = Cookie(None, alias="sso_session_id", description="从 Cookie 中捕获的会话令牌"),
        sso_session_id_form: str = Form(None, alias="sso_session_id", description="从表单中提交的会话令牌"),
        db: Session = Depends(get_db)
):
    """
    业务逻辑（Session 大一统改造版）：
    1. 多渠道自适应提取当前的 Session ID。
    2. 去 Redis 中提取对应的真实用户名，不再解密 JWT。
    3. 严苛核验密码通过后，物理抹除数据库用户实体，并同步粉碎 Redis 会话与浏览器 Cookie。
    """
    # 🚀 1. 多渠道清洗唯一的会话钥匙
    target_session_id = None
    if authorization and authorization.startswith("Bearer "):
        target_session_id = authorization.split(" ")[1]
    elif sso_session_id_cookie:
        target_session_id = sso_session_id_cookie
    elif sso_session_id_form:
        target_session_id = sso_session_id_form

    if not target_session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="身份认证已失效，请重新登录后再执行高危操作")

    # 🚀 2. 从 Redis 统一中控中直接捞取用户名
    username = redis_client.get(target_session_id)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="非法或已过期的会话凭证，拒绝高危执行")

    # 🚀 3. 锁定数据库用户（Redis 里存的是 user_id，兼容旧 username 会话）
    user = _load_user_from_session_value(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="目标账户不存在")

    user_id = int(user.id)
    username_text = str(user.username)

    # 🚀 4. 严苛验证密码
    if not pwd_context.verify(confirm_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="安全审计失败：密码校验错误，拒绝销户请求")

    # 🚀 5. 斩草除根：物理抹除与分布式会话粉碎
    _purge_user_session_artifacts(user_id)
    _purge_session_artifacts(target_session_id, user_id=user_id)
    db.delete(user)
    db.commit()
    dispatch_webhook_event(
        event_type="user.delete",
        payload={
            "user_id": user_id,
            "status": "terminated"
        },
        db=db
    )

    # 强行清洗浏览器托管的 Cookie 凭证（注意 path="/" 的严格对齐）
    response.delete_cookie(
        key="sso_session_id",
        path="/",
        secure=False,
        httponly=True,
        samesite="lax"
    )

    return {
        "status": "success",
        "message": f"用户账户 [{username_text}] 已成功物理销户，相关核心数据及全网 Session 会话已被全面抹除清空。"
    }


# ==================== 🛠️ 改造核心接口 3：修改密码 (Change Password - 纯 Session 版) ====================
@router.post("/auth/change_password", summary="用户修改密码")
def change_password(
        current_password: str = Form(..., description="当前密码"),
        new_password: str = Form(..., min_length=8, description="新密码，至少8位"),
        authorization: str = Header(None, description="承载标准 Bearer Token 的请求头"),
        sso_session_id_cookie: str = Cookie(None, alias="sso_session_id", description="从 Cookie 中捕获的会话令牌"),
        db: Session = Depends(get_db)
):
    """
    业务逻辑（Session 大一统改造版）：
    1. 自适应提取 Session 钥匙。
    2. 基于 Redis 状态机核验身份，通过后更改数据库密码。
    """
    # 🚀 1. 钥匙清洗
    target_session_id = None
    if authorization and authorization.startswith("Bearer "):
        target_session_id = authorization.split(" ")[1]
    elif sso_session_id_cookie:
        target_session_id = sso_session_id_cookie

    if not target_session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="身份认证已失效，请重新登录后再执行操作")

    # 🚀 2. 状态检索
    username = redis_client.get(target_session_id)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="会话已过期或已被吊销，请重新登录")

    # 🚀 3. 密码置换审计（Redis 里存的是 user_id，兼容旧 username 会话）
    user = _load_user_from_session_value(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="目标账户不存在")

    if not pwd_context.verify(current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前密码错误，拒绝修改")

    _validate_password_strength(new_password)

    # 哈希加盐持久化新密码
    user.password_hash = pwd_context.hash(new_password)
    db.commit()

    # 💡 贴心策略（可选）：修改密码后你可以选择将当前用户的 Session 清掉迫使其重新登录，
    # 或者是保持原有连接。这里我们让其保持登录，返回成功：
    return {
        "status": "success",
        "message": f"用户 [{username}] 密码修改成功，新策略已实时并网生效！"
    }

def _build_user_profile_payload(db: Session, current_user: User) -> dict[str, object]:
    group = _resolve_user_group(db, current_user)
    roles = [role.name for role in current_user.roles]
    nickname = getattr(current_user, "nickname", None)
    raw_permissions = getattr(current_user, "all_permissions", None)
    permissions = sorted(list(raw_permissions)) if raw_permissions else []
    email = getattr(current_user, "email", None)
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "nickname": nickname,
        "email": email,
        "group_id": group.id if group else None,
        "group_name": group.group_name if group else None,
        "group_code": group.group_code if group else None,
        "group_status": group.status if group else None,
        "group_is_active": group.is_active if group else None,
        "group_review_note": group.review_note if group else None,
        "group_reviewed_at": group.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if group and group.reviewed_at else None,
        "group_expire_at": group.expire_at.strftime("%Y-%m-%d %H:%M:%S") if group and group.expire_at else None,
        "roles": roles,
        "permissions": permissions,
        "is_tenant_admin": "tenant_admin" in roles or "super_admin" in roles
    }
