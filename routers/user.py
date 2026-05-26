import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status, Security, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy.orm import Session
from database import User, get_db
from middlewares.auth import redis_client
import jwt  # 需要安装 PyJWT
import config
from passlib.context import CryptContext
from routers.auth_user import _build_user_profile_payload

router = APIRouter(tags=["用户信息统一管理接口"])

# 使用 FastAPI 自带的 Bearer 规范，它会自动帮你从 Header 中提取 "Bearer <token>"
security = HTTPBearer(auto_error=False)

SECRET_KEY = config.SECRET_KEY
ALGORITHM = config.ALGORITHM
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
PASSWORD_COMPLEXITY_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).+$")


class UserProfileUpdateInput(BaseModel):
    nickname: str | None = Field(None, max_length=64)
    email: EmailStr | None = None


class UserPasswordChangeInput(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


class SessionRevokeInput(BaseModel):
    token_id: str = Field(..., min_length=1)


def _decode_oauth_userinfo(token: str) -> dict | None:
    userinfo_raw = redis_client.get(f"oauth_userinfo:{token}")
    if not userinfo_raw:
        return None
    try:
        return json.loads(userinfo_raw)
    except Exception:
        return None


def _resolve_user_from_session_token(token: str, db: Session) -> Any:
    raw_user_id = redis_client.get(token)
    if not raw_user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="会话已过期，请重新登录")

    try:
        user_id = int(str(raw_user_id))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="会话载荷损坏")

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户不存在或已被冻结")
    return user


def _resolve_user_from_access_token(token: str, db: Session) -> Any:
    if redis_client.exists(f"revoked_token:{token}"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="凭证已失效")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="凭证已过期")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="凭证校验失败")

    user_id = None
    username = None
    sub = payload.get("sub")

    if isinstance(sub, int):
        user_id = sub
    elif isinstance(sub, str) and sub.isdigit():
        user_id = int(sub)
    elif isinstance(sub, str):
        username = sub.strip()

    userinfo = _decode_oauth_userinfo(token)
    if userinfo:
        if user_id is None and userinfo.get("user_id") is not None:
            try:
                user_id = int(userinfo.get("user_id"))
            except Exception:
                user_id = None
        if not username:
            username = str(userinfo.get("username") or "").strip() or None

    user = None
    if user_id is not None:
        user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    elif username:
        user = db.query(User).filter(User.username == username, User.is_active == True).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="当前令牌不绑定终端用户")
    return user


def _require_current_user(credentials: HTTPAuthorizationCredentials, db: Session) -> tuple[User, str]:
    token = str(credentials.credentials or "").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少访问令牌")

    if token.startswith("sess_"):
        user = _resolve_user_from_session_token(token, db)
    else:
        user = _resolve_user_from_access_token(token, db)
    return user, token


def _resolve_credentials_or_cookie(
        credentials: HTTPAuthorizationCredentials | None,
        sso_session_id_cookie: str | None,
) -> HTTPAuthorizationCredentials:
    if credentials and str(credentials.credentials or "").strip():
        return credentials
    if sso_session_id_cookie:
        return HTTPAuthorizationCredentials(scheme="Bearer", credentials=sso_session_id_cookie)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少访问令牌")


def _validate_new_password(new_password: str) -> None:
    if len(new_password or "") < 8:
        raise HTTPException(status_code=422, detail="新密码长度至少 8 位")
    if not PASSWORD_COMPLEXITY_RE.fullmatch(new_password or ""):
        raise HTTPException(status_code=422, detail="新密码必须包含大小写字母、数字和特殊字符")


@router.get("/api/v1/user/get_info", summary="供其他系统调用的获取用户信息接口")
def get_user_info(
        credentials: HTTPAuthorizationCredentials | None = Security(security),
        sso_session_id_cookie: str | None = Cookie(None, alias="sso_session_id"),
        db: Session = Depends(get_db)
):
    resolved_credentials = _resolve_credentials_or_cookie(credentials, sso_session_id_cookie)
    user, _ = _require_current_user(resolved_credentials, db)

    return {
        "status": "success",
        "data": _build_user_profile_payload(db, user)
    }


@router.put("/api/v1/user/profile", summary="【用户中心】更新个人资料")
def update_user_profile(
        payload: UserProfileUpdateInput,
        credentials: HTTPAuthorizationCredentials | None = Security(security),
        sso_session_id_cookie: str | None = Cookie(None, alias="sso_session_id"),
        db: Session = Depends(get_db)
):
    resolved_credentials = _resolve_credentials_or_cookie(credentials, sso_session_id_cookie)
    user, _ = _require_current_user(resolved_credentials, db)

    if payload.nickname is not None:
        user.nickname = payload.nickname.strip() if payload.nickname else None

    if payload.email is not None:
        new_email = str(payload.email).strip().lower() if payload.email else None
        if new_email:
            duplicated = db.query(User).filter(User.email == new_email, User.id != user.id).first()
            if duplicated:
                raise HTTPException(status_code=400, detail="该邮箱已被其他账号使用")
        user.email = new_email

    db.commit()
    db.refresh(user)
    return {
        "status": "success",
        "message": "个人资料更新成功",
        "data": {
            "user_id": user.id,
            "username": user.username,
            "nickname": user.nickname,
            "email": user.email,
        }
    }


@router.post("/api/v1/user/change_password", summary="【用户中心】修改密码")
def change_user_password(
        payload: UserPasswordChangeInput,
        credentials: HTTPAuthorizationCredentials | None = Security(security),
        sso_session_id_cookie: str | None = Cookie(None, alias="sso_session_id"),
        db: Session = Depends(get_db)
):
    resolved_credentials = _resolve_credentials_or_cookie(credentials, sso_session_id_cookie)
    user, token = _require_current_user(resolved_credentials, db)

    if not pwd_context.verify(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="当前密码错误")

    _validate_new_password(payload.new_password)
    user.password_hash = pwd_context.hash(payload.new_password)
    db.commit()

    # 修改密码后注销当前会话令牌，降低会话劫持窗口
    if token.startswith("sess_"):
        redis_client.delete(token)
        redis_client.delete(f"sess_meta:{token}")
        redis_client.srem(f"user:active_sessions:{user.id}", token)
    else:
        redis_client.setex(f"revoked_token:{token}", 86400, "1")

    return {"status": "success", "message": "密码修改成功，请重新登录"}


@router.get("/api/v1/user/sessions", summary="【用户中心】查询我的会话列表")
def list_my_sessions(
        credentials: HTTPAuthorizationCredentials | None = Security(security),
        sso_session_id_cookie: str | None = Cookie(None, alias="sso_session_id"),
        db: Session = Depends(get_db)
):
    resolved_credentials = _resolve_credentials_or_cookie(credentials, sso_session_id_cookie)
    user, current_token = _require_current_user(resolved_credentials, db)
    sessions = []

    def _decode(value, default=""):
        if value is None:
            return default
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)

    def _resolve_device_type_from_meta(meta: dict[str, str]) -> str:
        raw_type = str(meta.get("device_type", "")).strip().lower()
        if raw_type in {"mobile", "desktop"}:
            return raw_type
        raw_mobile = str(meta.get("is_mobile", "")).strip().lower()
        return "mobile" if raw_mobile in {"1", "true", "yes"} else "desktop"

    user_set_key = f"user:active_sessions:{user.id}"
    token_ids = redis_client.smembers(user_set_key) or []
    for token_id in token_ids:
        token_id = _decode(token_id)
        meta_key = f"sess_meta:{token_id}"
        meta_raw = redis_client.hgetall(meta_key) or {}
        meta = {str(_decode(k)): _decode(v) for k, v in meta_raw.items()}
        sessions.append({
            "token_id": token_id,
            "ip": meta.get("ip", "-"),
            "browser": meta.get("browser", "-"),
            "os": meta.get("os", "-"),
            "device_type": _resolve_device_type_from_meta(meta),
            "location": meta.get("location", "-"),
            "login_time": meta.get("login_time", "-"),
            "is_current": token_id == current_token,
        })

    sessions.sort(key=lambda item: (item.get("is_current", False), item.get("login_time", "")), reverse=True)
    return {"status": "success", "count": len(sessions), "data": sessions}


@router.post("/api/v1/user/sessions/revoke", summary="【用户中心】注销指定会话")
def revoke_my_session(
        payload: SessionRevokeInput,
        credentials: HTTPAuthorizationCredentials | None = Security(security),
        sso_session_id_cookie: str | None = Cookie(None, alias="sso_session_id"),
        db: Session = Depends(get_db)
):
    resolved_credentials = _resolve_credentials_or_cookie(credentials, sso_session_id_cookie)
    user, current_token = _require_current_user(resolved_credentials, db)
    token_id = payload.token_id.strip()
    if not token_id.startswith("sess_"):
        raise HTTPException(status_code=400, detail="仅支持注销 session 会话")

    user_set_key = f"user:active_sessions:{user.id}"
    if not redis_client.sismember(user_set_key, token_id):
        raise HTTPException(status_code=403, detail="不允许注销其他用户的会话")

    redis_client.delete(token_id)
    redis_client.delete(f"sess_meta:{token_id}")
    redis_client.srem(user_set_key, token_id)
    return {
        "status": "success",
        "message": "会话已注销",
        "is_current": token_id == current_token,
    }


@router.get("/api/v1/user/permissions", summary="【用户中心】查看我的角色与权限")
def get_my_roles_permissions(
        credentials: HTTPAuthorizationCredentials | None = Security(security),
        sso_session_id_cookie: str | None = Cookie(None, alias="sso_session_id"),
        db: Session = Depends(get_db)
):
    resolved_credentials = _resolve_credentials_or_cookie(credentials, sso_session_id_cookie)
    user, _ = _require_current_user(resolved_credentials, db)
    return {
        "status": "success",
        "data": {
            "user_id": user.id,
            "username": user.username,
            "roles": [role.name for role in user.roles],
            "permissions": sorted(list(user.all_permissions)),
        }
    }