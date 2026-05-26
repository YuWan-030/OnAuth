import json
import os
from typing import Any
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session, selectinload
from database import get_db, User, Role
from middlewares.auth import redis_client
import jwt
import config

RBAC_CACHE_TTL_SECONDS = max(10, int(os.getenv("RBAC_CACHE_TTL_SECONDS", "86400")))
SECRET_KEY = config.SECRET_KEY
ALGORITHM = config.ALGORITHM


def _decode_oauth_userinfo(token: str) -> dict | None:
    userinfo_raw = redis_client.get(f"oauth_userinfo:{token}")
    if not userinfo_raw:
        return None
    try:
        return json.loads(userinfo_raw)
    except Exception:
        return None


def _resolve_user_id_from_access_token(token: str, db: Session) -> int:
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

    if user_id is not None:
        return user_id

    if username:
        user = db.query(User).filter(User.username == username).first()
        if user:
            return int(getattr(user, "id"))

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="当前令牌不绑定终端用户")


class _RolePrincipal:
    def __init__(self, name: str):
        self.name = name


class _UserPrincipal:
    def __init__(
            self,
            user_id: int,
            username: str,
            group_id: int | None,
            role_names: list[str],
            permissions: set[str],
            nickname: str | None = None,
    ):
        self.id = user_id
        self.username = username
        self.nickname = nickname
        self.group_id = group_id
        self.is_active = True
        self.roles = [_RolePrincipal(name) for name in role_names]
        self.is_admin = ("super_admin" in role_names) or ("admin" in role_names)
        self._permissions = permissions

    @property
    def all_permissions(self) -> set[str]:
        return set(self._permissions)


def _rbac_cache_key(session_id: str) -> str:
    return f"rbac:perms:{session_id}"


def _load_cached_permissions(session_id: str) -> tuple[int, _UserPrincipal, set[str]] | None:
    cache_raw = redis_client.get(_rbac_cache_key(session_id))
    if not cache_raw:
        return None
    try:
        data = json.loads(cache_raw)
        user_id = int(data.get("user_id"))
        permissions = set(data.get("permissions") or [])
        principal = _UserPrincipal(
            user_id=user_id,
            username=str(data.get("username") or ""),
            group_id=data.get("group_id"),
            role_names=[str(item) for item in (data.get("role_names") or [])],
            permissions=permissions,
            nickname=(str(data.get("nickname")).strip() if data.get("nickname") is not None else None),
        )
        return user_id, principal, permissions
    except Exception:
        return None


def _save_cached_permissions(session_id: str, principal: _UserPrincipal, permissions: set[str]) -> None:
    ttl = redis_client.ttl(session_id)
    if ttl is None or ttl <= 0:
        ttl = RBAC_CACHE_TTL_SECONDS
    cache_ttl = min(int(ttl), RBAC_CACHE_TTL_SECONDS)
    payload = json.dumps({
        "user_id": principal.id,
        "username": principal.username,
        "nickname": principal.nickname,
        "group_id": principal.group_id,
        "role_names": [r.name for r in principal.roles],
        "permissions": sorted(permissions)
    })
    redis_client.setex(_rbac_cache_key(session_id), cache_ttl, payload)


def _build_user_principal(user: Any, permissions: set[str]) -> _UserPrincipal:
    role_names = [r.name for r in (user.roles or []) if getattr(r, "name", None)]
    return _UserPrincipal(
        user_id=int(user.id),
        username=str(user.username),
        nickname=getattr(user, "nickname", None),
        group_id=getattr(user, "group_id", None),
        role_names=role_names,
        permissions=permissions,
    )


class _RBACBaseChecker:
    def __init__(self, *required_permissions: str, require_all: bool = False):
        self.required_permissions = tuple(p for p in required_permissions if p)
        self.require_all = require_all

    def _has_permission(self, user_permissions: set[str]) -> bool:
        if not self.required_permissions:
            return True
        if self.require_all:
            return all(perm in user_permissions for perm in self.required_permissions)
        return any(perm in user_permissions for perm in self.required_permissions)

    def __call__(self, request: Request, db: Session = Depends(get_db)):
        effective_session_id = request.cookies.get("sso_session_id")
        if not effective_session_id:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                effective_session_id = auth_header.split(" ")[1]

        if not effective_session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="身份凭证已缺失，请重新登录"
            )

        is_session_token = str(effective_session_id).startswith("sess_")
        if is_session_token:
            raw_user_id = redis_client.get(effective_session_id)
            if not raw_user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="会话已过期，请重新登录"
                )
            user_id = int(raw_user_id.decode('utf-8') if isinstance(raw_user_id, bytes) else raw_user_id)
        else:
            user_id = _resolve_user_id_from_access_token(str(effective_session_id), db)

        cached = _load_cached_permissions(effective_session_id)
        if cached and cached[0] == user_id:
            principal = cached[1]
            user_permissions = cached[2]
            if self._has_permission(user_permissions):
                return principal

        # 3. 锁定激活用户
        user = db.query(User).options(
            selectinload(User.roles).selectinload(Role.permissions),
            selectinload(User.extra_permissions)
        ).filter(User.id == user_id, User.is_active == True).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="当前账户已被冻结或不存在"
            )

        raw_permissions = getattr(user, "all_permissions", None)
        user_permissions = set(raw_permissions or [])
        principal = _build_user_principal(user, user_permissions)
        _save_cached_permissions(effective_session_id, principal, user_permissions)

        has_permission = self._has_permission(user_permissions)

        if not has_permission:
            perms_str = " 或 ".join([f"[{p}]" for p in self.required_permissions])
            if self.require_all:
                perms_str = " 且 ".join([f"[{p}]" for p in self.required_permissions])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"安全合规熔断：缺少必要权限，必须具备 {perms_str}"
            )

        # 校验通过，返回 User 对象供路由使用
        return principal


class RBACChecker(_RBACBaseChecker):
    """
    RBAC 权限检查（ANY 语义）：命中任意一个 required_permissions 即放行。
    """

    def __init__(self, *required_permissions: str):
        super().__init__(*required_permissions, require_all=False)


class RBACAllChecker(_RBACBaseChecker):
    """
    RBAC 权限检查（ALL 语义）：必须同时具备全部 required_permissions 才放行。
    """

    def __init__(self, *required_permissions: str):
        super().__init__(*required_permissions, require_all=True)
