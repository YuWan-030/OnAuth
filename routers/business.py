import datetime
import base64
import json
import jwt
from typing import Any
from fastapi import APIRouter, Query, Depends, HTTPException, Header, Form
from sqlalchemy.orm import Session

from config import SECRET_KEY, ALGORITHM
from database import get_db, AppCredential, User
from middlewares.auth import verify_client_token, redis_client
from utils.crypto import verify_secret
from schemas.response_schema import OAuthIntrospectResponseSchema

router = APIRouter(tags=["业务受保护接口"])


def _extract_client_auth(
        authorization: str | None,
        client_id: str | None,
        client_secret: str | None,
) -> tuple[str | None, str | None]:
    if authorization and authorization.startswith("Basic "):
        try:
            encoded = authorization.split(" ", 1)[1]
            decoded = base64.b64decode(encoded).decode("utf-8")
            auth_client_id, auth_client_secret = decoded.split(":", 1)
            return auth_client_id, auth_client_secret
        except Exception:
            return None, None
    return client_id, client_secret


def _verify_client_credentials(
        db: Session,
        authorization: str | None,
        client_id: str | None,
        client_secret: str | None,
) -> Any:
    final_client_id, final_client_secret = _extract_client_auth(authorization, client_id, client_secret)
    if not final_client_id or not final_client_secret:
        raise HTTPException(status_code=401, detail="缺少客户端凭证")

    cred = db.query(AppCredential).filter(AppCredential.client_id == final_client_id).first()
    stored_hash = str(getattr(cred, "client_secret_hash", "")) if cred else None
    if not cred or not verify_secret(final_client_secret, stored_hash):
        raise HTTPException(status_code=401, detail="客户端凭证校验失败")
    return cred


def _parse_scopes(scope_text: str | None) -> set[str]:
    raw = str(scope_text or "")
    tokens = [s.strip() for s in raw.replace(",", " ").split(" ") if s.strip()]
    return set(tokens)


def _get_token_userinfo(access_token: str) -> dict | None:
    cached = redis_client.get(f"oauth_userinfo:{access_token}")
    if not cached:
        return None
    try:
        return json.loads(cached)
    except Exception:
        return None


@router.get("/api/v1/inspect_license", summary="【核心受保护业务接口】校验客户端授权状态")
def inspect_license(app_id: int = Query(...), cred: AppCredential = Depends(verify_client_token)):
    if cred.app_id != app_id:
        raise HTTPException(status_code=403,
                            detail=f"密钥越权违规！当前激活码属于其他应用，无法用于当前程序！")

    now = datetime.datetime.now()
    remaining_days = max(0, (cred.expire_at - now).days) if cred.expire_at else 0
    return {
        "status": "active", "client_id": cred.client_id, "credential_name": cred.credential_name,
        "app_name": cred.app.app_name, "app_id": cred.app_id,
        "scopes": [s.strip() for s in cred.scope.split(",") if s.strip()],
        "expire_date": cred.expire_at.strftime("%Y-%m-%d %H:%M:%S") if cred.expire_at else "永久有效",
        "remaining_info": f"授权订阅状态正常，剩余生命周期: {remaining_days} 天。"
    }


@router.post("/oauth/introspect", summary="【OAuth2】Token 内省 RFC 7662", response_model=OAuthIntrospectResponseSchema)
def oauth_introspect(
        token: str = Form(...),
        token_type_hint: str | None = Form(None),
        authorization: str | None = Header(None),
        client_id: str | None = Form(None),
        client_secret: str | None = Form(None),
        db: Session = Depends(get_db),
):
    cred = _verify_client_credentials(db, authorization, client_id, client_secret)

    if redis_client.exists(f"revoked_token:{token}"):
        return {"active": False}

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return {"active": False}

    token_sub = payload.get("sub")
    if token_sub and token_sub != cred.client_id:
        return {"active": False}

    scope_text = str(payload.get("scope") or "")
    response = {
        "active": True,
        "scope": scope_text,
        "client_id": token_sub,
        "token_type": payload.get("token_type", token_type_hint or "access_token"),
        "exp": payload.get("exp"),
        "iat": payload.get("iat"),
        "iss": payload.get("iss"),
        "sub": token_sub,
    }

    cached_userinfo = _get_token_userinfo(token)
    if cached_userinfo:
        response["username"] = cached_userinfo.get("username")
        response["user_id"] = cached_userinfo.get("user_id")

    return response


@router.get("/oauth/userinfo", summary="【OIDC】用户信息接口")
def oauth_userinfo(
        authorization: str | None = Header(None),
        db: Session = Depends(get_db),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="缺少 Bearer access token")

    access_token = authorization.split(" ", 1)[1].strip()
    if not access_token:
        raise HTTPException(status_code=401, detail="access token 为空")

    if redis_client.exists(f"revoked_token:{access_token}"):
        raise HTTPException(status_code=401, detail="access token 已失效")

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="access token 无效")

    if payload.get("token_type") != "access_token":
        raise HTTPException(status_code=401, detail="仅支持 access token")

    userinfo_cache = _get_token_userinfo(access_token)
    if not userinfo_cache:
        raise HTTPException(status_code=403, detail="当前令牌不包含用户上下文，无法返回 userinfo")

    username = str(userinfo_cache.get("username") or "").strip()
    if not username:
        raise HTTPException(status_code=403, detail="用户上下文缺失")

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="用户不存在或已被冻结")

    return {
        "sub": f"user:{user.id}",
        "preferred_username": user.username,
        "name": user.nickname or user.username,
        "group_id": user.group_id,
        "scope": payload.get("scope", ""),
    }


@router.get("/api/v1/business/orders", summary="【示例业务】受 scope 保护的订单读取接口")
def list_orders(
        cred: AppCredential = Depends(verify_client_token),
):
    allowed = _parse_scopes(getattr(cred, "scope", ""))
    if not ({"read", "orders:read"} & allowed):
        raise HTTPException(status_code=403, detail="缺少 orders:read 或 read scope")

    return {
        "status": "success",
        "data": [
            {"order_id": "ORD-1001", "amount": 99.5, "currency": "CNY", "status": "PAID"},
            {"order_id": "ORD-1002", "amount": 38.0, "currency": "CNY", "status": "PENDING"},
        ],
    }


@router.post("/api/v1/business/orders", summary="【示例业务】受 scope 保护的订单创建接口")
def create_order(
        cred: AppCredential = Depends(verify_client_token),
):
    allowed = _parse_scopes(getattr(cred, "scope", ""))
    if not ({"write", "orders:write"} & allowed):
        raise HTTPException(status_code=403, detail="缺少 orders:write 或 write scope")

    return {
        "status": "success",
        "message": "示例订单创建成功",
        "order_id": "ORD-NEW-DEMO",
    }
