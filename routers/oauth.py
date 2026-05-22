import base64
import json
import datetime
import os
import secrets
import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Form, Cookie, Response, Request, Header
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import time
from database import get_db, AppCredential, User, Role
from middlewares.auth import redis_client
from routers.webhook import dispatch_webhook_event
from utils.crypto import verify_password, create_jwt_token, hash_secret
from config import SECRET_KEY, ALGORITHM

router = APIRouter(tags=["OAuth2标准流"])
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))



@router.get("/oauth/authorize", summary="【OAuth2标准流】授权入口（纯净 Session 终极优化版）")
def oauth_authorize(
        request: Request,
        client_id: str = Query(...),
        response_type: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query("read"),
        state: str = Query(None),

        # 🎯 纯净双轨：只拦截你中台登录时亲手种下的两个 Session Cookie 键名
        sso_session_id: str = Cookie(None),
        session_id: str = Query(None),
        db: Session = Depends(get_db)
):
    if response_type != "code":
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": "目前仅支持 response_type='code' 标准授权码模式。"}
        )

    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred:
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": "非法的客户端申请：client_id 未注册。"}
        )

    # 三层架构熔断合规审计
    current_app = cred.app
    current_group = current_app.group
    if not cred.is_active:
        detail_msg = "安全合规性拒绝：该凭证授权通道已被手工关闭。"
    elif not current_app.is_active:
        detail_msg = f"安全合规性拒绝：独立应用 [{current_app.app_name}] 已被强制下线。"
    elif not current_group.is_active:
        detail_msg = f"安全合规性拒绝：组织空间 [{current_group.group_name}] 已被整体封禁！"
    else:
        detail_msg = None

    if detail_msg:
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": detail_msg}
        )

    # 🚀 【双轨纯 Session 清洗流】
    # 顺位：URL显式传参最高准则 > 旧版或第三方规范(sso_session_id)
    effective_session_id = session_id or sso_session_id

    # ====== 🛠️ 极其干净的本地 Debug 盘点 ======
    print("="*60)
    print(f"📡 [中台看门狗] 最终采信的有效会话 ID: {effective_session_id}")
    # ==========================================

    user_logged_in = None
    if effective_session_id and effective_session_id.startswith("sess_"):
        # ⚡ 纯粹的分布式高速缓存撞击
        raw_user = redis_client.get(effective_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    context = {
        "request": request,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state or "",
        "group_name": current_group.group_name,
        "app_name": current_app.app_name,
        "app_logo": current_app.app_logo
    }

    # 🚨 如果没有任何渠道命中有效的 Redis 会话，踢回登录墙
    if not user_logged_in:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context=context
        )

    # 🚀 完美平滑降落到授权确认舱（Consent Page）
    context.update({
        "username": user_logged_in,
        "session_id": effective_session_id
    })
    return templates.TemplateResponse(
        request=request,
        name="consent.html",
        context=context
    )


@router.post("/oauth/login_submit", summary="内部路由：处理中台登录提交并执行安全认证")
def login_submit(
        response: Response,
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        scope: str = Form(...),
        state: str = Form(None),
        db: Session = Depends(get_db)
):
    # 1. 🔍 捞取核心用户基础信息
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="安全身份审计拒绝：用户名或密码错误，请重新核对")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="合规性安全阻断：当前用户账户已被系统永久冻结或查封")


    # 2. ⚡ 生成传统的 Redis 会话（供 OAuth 授权大厅撞库）
    new_session_id = "sess_" + secrets.token_hex(12)
    redis_client.setex(new_session_id, 86400, str(user.id))
    # 🌟 顺手做个反向索引：把这个 session_id 扔进该用户的活跃会话集合里
    user_set_key = f"user:active_sessions:{user.id}"
    redis_client.sadd(user_set_key, new_session_id)
    redis_client.expire(user_set_key, 86400)  # 保持过期时间一致


    # 3. 🎯 组装目标重定向 URL
    target_url = f"/oauth/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}"
    if state:
        target_url += f"&state={state}"

    dispatch_webhook_event(
        event_type="auth.login",
        payload={
            "user_id": user.id,
            "username": user.username,
            "ip_address": request.client.host,  # 视你如何抓取 IP 而定
            "login_at": int(time.time())
        },
        db=db
    )

    # 4. 🚀 【下发 SSO 凭证】
    response.set_cookie(
        key="sso_session_id",
        value=new_session_id,
        httponly=True,
        path="/",
        secure=False,  # 本地调试设为 False
        samesite="lax"
    )

    return {
        "status": "success",
        "message": "身份核验通过，SSO会话已建立！",
        "redirect_url": target_url
    }
@router.post("/oauth/consent_submit", summary="内部路由：处理用户授权结果")
def consent_submit(
        request: Request,  # 🌟 修复：显式注入标准的 Request 实例
        action: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        scope: str = Form(...),
        state: str = Form(None),
        session_id: str = Form(..., description="接收从上一步 HTML 隐藏表单里提交上来的会话ID"),
        db: Session = Depends(get_db)
):
    if action != "allow":
        cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
        app_name = cred.app.app_name if (cred and cred.app) else "未知应用"
        return templates.TemplateResponse(
            request=request,
            name="deny.html",
            context={
                "request": request,  # 使用标准 Request
                "app_name": app_name,
                "session_id": session_id
            },
            status_code=403
        )

    username = redis_client.get(session_id)
    if not username:
        raise HTTPException(status_code=401, detail="会话已过期，请重新登录")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="关联用户已不存在")

    user_allowed_scopes = set()
    for role in user.roles:
        for perm in role.permissions:
            user_allowed_scopes.add(perm.name)

    requested_scopes = set([s.strip() for s in scope.split(",") if s.strip()])
    final_scopes = requested_scopes.intersection(user_allowed_scopes)

    if not final_scopes:
        raise HTTPException(
            status_code=403,
            detail="安全受限：您当前所在的权限组级别，无法满足该客户端所要求的任何权限范围"
        )

    auth_code = "code_" + secrets.token_hex(16)
    auth_code_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": ",".join(final_scopes),
        "username": username
    }
    redis_client.setex(f"oauth_code:{auth_code}", 600, json.dumps(auth_code_data))

    target_url = f"{redirect_uri}?code={auth_code}"
    if state:
        target_url += f"&state={state}"

    return RedirectResponse(url=target_url, status_code=303)

@router.post("/oauth/token", summary="【OAuth2标准流】统一令牌网关")
def oauth_token_exchange(
        grant_type: str = Form(...),
        client_id: str = Form(None),
        client_secret: str = Form(None),
        authorization: str = Header(None, description="标准 HTTP Basic 认证头"),
        code: str = Form(None),
        refresh_token: str = Form(None),
        db: Session = Depends(get_db)
):
    current_time = datetime.datetime.now()

    if authorization and authorization.startswith("Basic "):
        try:
            base64_str = authorization.split(" ")[1]
            decoded = base64.b64decode(base64_str).decode("utf-8")
            h_client_id, h_client_secret = decoded.split(":", 1)
            client_id = h_client_id
            client_secret = h_client_secret
        except Exception:
            raise HTTPException(status_code=401, detail="HTTP Basic 认证请求头格式解析破损")

    if not client_id or not client_secret:
        raise HTTPException(status_code=401, detail="缺少客户端凭证(Client ID / Secret)")

    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred or cred.client_secret_hash != hash_secret(client_secret):
        raise HTTPException(status_code=401, detail="Client ID 或 Secret 安全不匹配")

    # 🚀【核心漏洞修复：防御层扩展到三层多租户】
    # 无论是客户端凭证、授权码兑换还是令牌刷新，先过硬熔断基线
    current_app = cred.app
    current_group = current_app.group

    if not cred.is_active:
        raise HTTPException(status_code=403, detail="该应用凭证通道已被中台管理员手工阻断")
    if not current_app.is_active:
        raise HTTPException(status_code=403, detail=f"独立应用 [{current_app.app_name}] 已被中台下线熔断")
    if not current_group.is_active:
        raise HTTPException(status_code=403, detail=f"该应用所属的工作室组织 [{current_group.group_name}] 已被整体查封")

    if cred.expire_at and cred.expire_at < current_time:
        raise HTTPException(status_code=403, detail="该中台服务订阅已到期，无法继续签发/刷新凭证")

    if grant_type == "client_credentials":
        token_expire = current_time + datetime.timedelta(days=1)
        if cred.expire_at and token_expire > cred.expire_at:
            token_expire = cred.expire_at

        access_token = create_jwt_token(client_id, cred.scope, token_expire, token_type="access_token")
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": int((token_expire - current_time).total_seconds()),
            "scope": cred.scope
        }

    elif grant_type == "authorization_code":
        if not code:
            raise HTTPException(status_code=400, detail="授权码模式下必须提供 'code' 参数")

        redis_key = f"oauth_code:{code}"
        code_raw = redis_client.get(redis_key)
        if not code_raw:
            raise HTTPException(status_code=400, detail="无效或已被二次使用/已过期的非安全授权码")

        redis_client.delete(redis_key)
        code_info = json.loads(code_raw)

        if code_info["client_id"] != client_id:
            raise HTTPException(status_code=400, detail="安全隔离阻断：串号漏洞拒绝！")

        access_token_expire = current_time + datetime.timedelta(days=1)
        refresh_token_expire = current_time + datetime.timedelta(days=30)

        if cred.expire_at and access_token_expire > cred.expire_at:
            access_token_expire = cred.expire_at
        if cred.expire_at and refresh_token_expire > cred.expire_at:
            refresh_token_expire = cred.expire_at

        target_scope = code_info["scope"]
        access_token = create_jwt_token(client_id, target_scope, access_token_expire, token_type="access_token")
        new_refresh_token = create_jwt_token(client_id, target_scope, refresh_token_expire, token_type="refresh_token")

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": int((access_token_expire - current_time).total_seconds()),
            "scope": target_scope,
            "user_info": {"user": code_info["username"]}
        }

    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="刷新令牌模式下必须传 'refresh_token'")

        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("token_type") != "refresh_token":
                raise HTTPException(status_code=401, detail="非法欺骗：该令牌并非合法的刷新令牌体")

            if payload.get("sub") != client_id:
                raise HTTPException(status_code=401, detail="令牌错位拦截！")

            # 🌟【核心修复点】既然熔断校验已在上方前置拦截完成，这里可以直接安全地重新签发双币令牌
            target_scope = payload.get("scope", "read")
            access_token_expire = current_time + datetime.timedelta(days=1)
            refresh_token_expire = current_time + datetime.timedelta(days=30)

            if cred.expire_at and access_token_expire > cred.expire_at:
                access_token_expire = cred.expire_at
            if cred.expire_at and refresh_token_expire > cred.expire_at:
                refresh_token_expire = cred.expire_at

            new_access_token = create_jwt_token(client_id, target_scope, access_token_expire, token_type="access_token")
            new_refresh_token = create_jwt_token(client_id, target_scope, refresh_token_expire, token_type="refresh_token")

            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "bearer",
                "expires_in": int((access_token_expire - current_time).total_seconds()),
                "scope": target_scope
            }
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="刷新令牌生存周期也已全部结束，请引导用户重新登录授权")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="刷新令牌受损")
    else:
        raise HTTPException(status_code=400, detail="未知的 grant_type 协议参数")

@router.post("/oauth/revoke", summary="【OAuth2标准流】客户端主动注销/撤销指定令牌")
def oauth_revoke_token(
        token: str = Form(..., description="要销毁的 access_token 或 refresh_token"),
        token_type_hint: str = Form("access_token", description="令牌类型暗示"),
        authorization: str = Header(None)
):
    if token:
        redis_client.setex(f"revoked_token:{token}", 86400, "1")
    return {"msg": f"令牌 [{token_type_hint}] 已在中台成功注销并加入全局黑名单废弃库"}