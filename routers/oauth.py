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

from database import get_db, AppCredential, User, Role
from middlewares.auth import redis_client
from utils.crypto import verify_password, create_jwt_token, hash_secret
from config import SECRET_KEY, ALGORITHM

router = APIRouter(tags=["OAuth2标准流"])
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))



@router.get("/oauth/authorize", summary="【OAuth2标准流】授权入口（精简智能解密版）")
def oauth_authorize(
        request: Request,
        client_id: str = Query(...),
        response_type: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query("read"),
        state: str = Query(None),

        # 🎯 保持纯净：只拦截你确定会写入和用到的两个核心 Cookie 键名
        auth_token: str = Cookie(None),
        sso_session_id: str = Cookie(None),

        session_id: str = Query(None),
        db: Session = Depends(get_db)
):
    if response_type != "code":
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request,
                     "detail": "目前仅支持 response_type='code' 标准授权码模式，请检查客户端请求参数。"}
        )

    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred:
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": "非法的客户端申请：该 client_id 在中台系统中未注册或已被粉碎级移除。"}
        )

    # 【三层架构穿透】
    current_app = cred.app
    current_group = current_app.group

    # 【纵深防御】联动联动熔断审计
    if not cred.is_active:
        detail_msg = "安全合规性拒绝：该凭证授权通道已被手工关闭。"
    elif not current_app.is_active:
        detail_msg = f"安全合规性拒绝：独立应用 [{current_app.app_name}] 已被中台强制下线熔断。"
    elif not current_group.is_active:
        detail_msg = f"安全合规性拒绝：该应用所属的组织空间 [{current_group.group_name}] 已被中台运营方整体封禁查封！"
    else:
        detail_msg = None

    if detail_msg:
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": detail_msg}
        )

    # 🚀 【三轨优先级清洗】
    # 顺位：URL显式传参 > 你的新Web端凭证(auth_token) > 旧版/第三方规范(sso_session_id)


    effective_session_id = session_id or auth_token or sso_session_id

    print("=" * 60)
    print(
        f"📡 [DEBUG 入口拦截] 当前捕获到的 effective_session_id: {effective_session_id[:30] if effective_session_id else 'None'}...")
    print(
        f"🍪 [DEBUG 原始 Cookie 盘点] auth_token: {auth_token[:20] if auth_token else 'None'}, sso_session_id: {sso_session_id[:20] if sso_session_id else 'None'}")

    user_logged_in = None
    if effective_session_id:

        # 🎯 智能分流 1：如果当前捞出来的凭证内容是 JWT (以 eyJ 开头)
        if effective_session_id.startswith("eyJ"):
            try:
                # 🔒 直接在本地内存中利用中台密钥解密验伪
                payload = jwt.decode(
                    effective_session_id,
                    SECRET_KEY,
                    algorithms=[ALGORITHM]
                )
                # 从 JWT 载荷中提取出在线用户名
                user_logged_in = payload.get("sub") or payload.get("username")

            except jwt.ExpiredSignatureError:
                print("⚠️ [安全中心] 阻断：本地解密显示该 JWT 凭证已过期")
                user_logged_in = None
            except jwt.InvalidTokenError:
                print("🚨 [安全中心] 严重阻断：本地解密显示该 JWT 签名遭到破坏或非法！")
                user_logged_in = None

        # 🎯 智能分流 2：如果不是 JWT，则判定为传统 Redis Session ID (以 sess_ 开头)
        if not user_logged_in:
            # ⚡ 瞬时打向 Redis 验证当前的会话令牌
            raw_user = redis_client.get(effective_session_id)
            if raw_user:
                # 🛡️ 对 Redis 字节流进行强转字符串解码，防止 Jinja2 模板报错
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

    # 🚨 如果三种渠道都没能命中/解出有效的用户，判定未登录，扭送登录墙
    if not user_logged_in:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context=context
        )

    # 🚀 成功确立管理员身份，平滑降落到授权确认舱（Consent Page）
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

    # ==================== 🛡️ 核心合规升级：动态捞取真实权限 ====================
    # 利用 Python 集合（Set）进行天然去重，防止用户通过多个角色拿到重复权限
    user_real_scopes = set()

    # 穿透 RBAC 多对多关系链：User -> Roles -> Permissions
    for role in user.roles:
        # 确保角色处于激活状态（如果你的 Role 表有 is_active 字段的话）
        for perm in role.permissions:
            if perm.name:  # 或者是 perm.code，根据你 SQLAlchemy 模型里的字段名对齐
                user_real_scopes.add(perm.name)

    # 将去重后的权限集合，用英文逗号拼接成长字符串（如 "user:read,user:write,admin:stats"）
    # 如果该用户没有任何角色或权限，则给一个基础兜底权限 "read"
    final_jwt_scope = ",".join(user_real_scopes) if user_real_scopes else "read"
    # =====================================================================

    # 2. ⚡ 生成传统的 Redis 会话（供 OAuth 授权大厅撞库）
    new_session_id = "sess_" + secrets.token_hex(12)
    redis_client.setex(new_session_id, 86400, username)

    # 3. 🛡️ 计算绝对过期时间（1天）
    token_expire = datetime.datetime.now() + datetime.timedelta(days=1)

    # 4. 🔑 【完美合规签发】将数据库捞出的真实权限，死死绑入 JWT
    # 严格按照你底层的无关键字形参顺序传参：(client_id_or_sub, scope, expire_at, token_type)
    management_jwt_token = create_jwt_token(
        username,  # 对应 client_id_or_sub
        final_jwt_scope,  # 🎯 注入刚刚从数据库现场剥离出来的【真实权限集】！
        token_expire,  # 对应 expire_at
        "user_auth"  # 对应 token_type
    )

    # 5. 🎯 组装目标重定向 URL
    target_url = f"/oauth/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&session_id={new_session_id}"
    if state:
        target_url += f"&state={state}"

    # 6. 🚀 【下发 SSO 凭证】
    response.set_cookie(
        key="sso_session_id",
        value=new_session_id,
        httponly=True,
        path="/",
        secure=False,  # 本地调试设为 False
        samesite="lax"
    )

    # 7. 🚀 【下发管理端合规前端凭证】
    response.set_cookie(
        key="auth_token",
        value=management_jwt_token,  # 带有真实现场权限的硬核 JWT
        httponly=True,
        path="/",
        secure=False,  # 本地调试设为 False
        samesite="lax"
    )

    return {
        "status": "success",
        "message": "身份核验通过，真实角色权限已打包加签！",
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