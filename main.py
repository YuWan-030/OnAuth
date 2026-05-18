import datetime
import hashlib
import os
import secrets
import base64

import json
from fastapi import FastAPI, Depends, HTTPException, Query, Header, Form,Cookie,Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import jwt
import redis

from config import SECRET_KEY, ALGORITHM
# 确保你的 database.py 中包含 App, AppCredential 模型
from database import init_db, get_db, App, AppCredential,User

app = FastAPI(title="企业级标准 OAuth2.0 & License 双轨制融合鉴权平台")

templates = Jinja2Templates(directory="templates")

# 1. 初始化密码加密器上下文（采用工业级高强度 bcrypt 算法）
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 🔒 跨域全放行（支持前端 Web、Flet Web、跨域管理端）
app.add_middleware(
    CORSMiddleware,
    # 显式声明 Flet 客户端可能拉起的本地 Web 端口或中台地址，坚决不使用 "*"
    allow_origins=[
        "https://localhost:8000",
        "https://127.0.0.1:8000",
        "https://localhost:8080",
        "https://127.0.0.1:8080",
        "https://localhost:8081",
        "https://127.0.0.1:8081"
    ],
    allow_credentials=True,  # 允许携带安全 Cookie
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer()


# 🔒 系统管理员专属密钥
ADMIN_TOKEN = os.getenv("PLATFORM_ADMIN_TOKEN")

if not ADMIN_TOKEN:
    print("⚠️ 警告：未检测到管理员访问令牌环境变量 PLATFORM_ADMIN_TOKEN，已自动生成一个随机令牌！请在生产环境中设置一个安全的固定值，并通过环境变量注入！")
    ADMIN_TOKEN = "admin_" + secrets.token_hex(16)

# ==================== 🛠️ OAuth2 内存状态机 (临时存储) ====================
# 1. 授权码池：{ "code_str": { context } } -> 生产环境建议移入 Redis 并设置 TTL
OAUTH_CODE_STORE = {}

# 2. 浏览器 Session 模拟池：{ "session_id": "username" } -> 用于标识当前在中台已登录的用户
# 实际生产中可使用 Cookie 或 Redis Session
# MOCK_USER_SESSIONS = {}

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "127.0.0.1"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=0,
    decode_responses=True # 🌟 核心：设置此项后，读取出来的都是字符串，不需要我们手动 .decode('utf-8')
)

# 3. 令牌黑名单拦截库：存储已被注销、废弃的 token
# REVOKED_TOKEN_BLACKLIST = set()

# --- 工具函数 ---
def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def generate_random_keys():
    return "cli_" + secrets.token_hex(8), "sec_" + secrets.token_hex(16)


def create_jwt_token(client_id: str, scope: str, expire_at: datetime.datetime, token_type: str = "license"):
    exp_timestamp = int(expire_at.timestamp()) if expire_at else 2147483647
    to_encode = {
        "sub": client_id,
        "scope": scope,
        "exp": exp_timestamp,
        "token_type": token_type,
        "expire_date_str": expire_at.strftime("%Y-%m-%d %H:%M:%S") if expire_at else "永久有效",
        "iss": "auth_platform"
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==================== 🛠️ 核心权限校验拦截器 ====================

def verify_admin_rpc(x_admin_token: str = Header(..., alias="X-Admin-Token", description="管理员核心身份令牌")):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="中台权限凭证不合法，拒绝访问管理端！")
    return x_admin_token

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证明文密码是否与数据库中加盐哈希后的密文相匹配"""
    return pwd_context.verify(plain_password, hashed_password)


def verify_client_token(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db)
):
    token = credentials.credentials

    # 🛑 【绝杀关卡】：如果这个 token 在黑名单里，直接当场熔断，判定为非法

    if redis_client.exists(f"revoked_token:{token}"):
        raise HTTPException(status_code=401, detail="凭证安全拒绝：该令牌已被注销")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        client_id = payload.get("sub")
        token_type = payload.get("token_type", "license")

        # 🛑 安全防线 1：严禁直接拿着 refresh_token 访问业务受保护接口
        if token_type == "refresh_token":
            raise HTTPException(status_code=401, detail="安全阻断：不能直接使用刷新令牌访问业务 API")

        cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
        if not cred:
            raise HTTPException(status_code=401, detail="凭证解析成功，但对应的鉴权节点已在数据库中被粉碎级移除")
        if not cred.is_active or not cred.app.is_active:
            raise HTTPException(status_code=403, detail="该授权通道或应用主体已被管理员手工阻断熔断！")

        if cred.expire_at and cred.expire_at < datetime.datetime.now():
            raise HTTPException(status_code=401, detail="您的授权已到期，请及时续费充值！")

        return cred
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="客户端请求携带的令牌已过期失效")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="非法令牌，签名篡改校验未通过")


# ==================== 🔐 接入端开放接口（标准 OAuth2.0 - 免Cookie高兼容版） ====================

@app.get("/oauth/authorize", summary="【OAuth2标准流】授权入口")
def oauth_authorize(
        client_id: str = Query(...),
        response_type: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query("read"),
        state: str = Query(None),
        sso_session_id: str = Cookie(None),
        session_id: str = Query(None),
        db: Session = Depends(get_db)
):
    # 基础校验逻辑保持不变
    if response_type != "code":
        raise HTTPException(status_code=400, detail="目前仅支持 response_type='code' 标准授权码模式")

    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred or not cred.is_active or not cred.app.is_active:
        raise HTTPException(status_code=400, detail="非法的客户端申请，或应用已被中台查封")

    # 双保险捞取当前的有效 Session
    effective_session_id = session_id or sso_session_id

    user_logged_in = None
    if effective_session_id:
        user_logged_in = redis_client.get(effective_session_id)

    # 封装基础的上下文参数（用于向模板传参）
    context = {
        "request": {},  # Jinja2 强制要求上下文中必须包含 FastAPI 的 request 对象，由于此路由未注入，给空字典或注入它即可
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state or "",
        "app_name": cred.app.app_name
    }

    # 阶段 A：用户未登录 -> 渲染并返回登录页面
    if not user_logged_in:
        # 必须传入包含 "request" 的字典，Jinja2 才能正常抓取并渲染
        # 我们用自带的依赖项或临时生成一个伪 request 传递
        from fastapi import Request
        return templates.TemplateResponse(
            name="login.html",
            context={"request": Request({"type": "http"}), **context}
        )

    # 阶段 B：用户已登录 -> 渲染并返回授权确认页
    from fastapi import Request
    context.update({
        "username": user_logged_in,
        "session_id": effective_session_id
    })
    return templates.TemplateResponse(
        name="consent.html",
        context={"request": Request({"type": "http"}), **context}
    )


@app.post("/oauth/login_submit", summary="内部路由：处理中台登录提交并执行安全认证")
def login_submit(
        response: Response,  # 👈 注入 fastapi 的 Response 对象，用来跨域或异构植入 Cookie
        username: str = Form(...),
        password: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        scope: str = Form(...),
        state: str = Form(None),
        db: Session = Depends(get_db)
):
    # 1. 数据库身份安全合规审计
    user = db.query(User).filter(User.username == username).first()

    # 如果验证失败，抛出的 HTTPException 默认会被 FastAPI 转化为标准的 JSON 结构：
    # {"detail": "安全身份审计拒绝：用户名或密码错误，请重新核对"}
    # 这会精准被前端的 fetch catch 到，并展示你漂亮的抖动红框，绝不跳页！
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="安全身份审计拒绝：用户名或密码错误，请重新核对")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="合规性安全阻断：当前用户账户已被系统永久冻结或查封")

    # 2. 身份颁发与会话流转机制
    new_session_id = "sess_" + secrets.token_hex(12)
    redis_client.setex(new_session_id, 86400, username)

    # 3. 构造成功后，前端用于控制跳转的目标 URL
    target_url = f"/oauth/authorize?client_id={client_id}&response_type=code&redirect_uri={redirect_uri}&scope={scope}&session_id={new_session_id}"
    if state:
        target_url += f"&state={state}"

    # 4. 🔒 高级别生产安全属性的 Cookie 设置
    # 此时我们通过参数里的 response 对象直接塞入 Cookie，而不是挂在重定向响应上
    response.set_cookie(
        key="sso_session_id",
        value=new_session_id,
        httponly=True,  # 拦截 XSS 注入窃听
        path="/",
        secure=True,  # 绑定公网 HTTPS 传输加密环境
        samesite="none"  # 跨子域、跨端口无缝握手传递
    )

    # 5. 🎉 核心改动点：登录成功，不再返回 303 Redirect 实体，而是返回一个告诉前端去哪里的 JSON 载荷
    return {
        "status": "success",
        "message": "身份核验通过",
        "redirect_url": target_url
    }


@app.post("/oauth/consent_submit", summary="内部路由：处理用户授权结果")
def consent_submit(
        action: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        scope: str = Form(...),
        state: str = Form(None),
        session_id: str = Form(..., description="接收从上一步 HTML 隐藏表单里提交上来的会话ID"), # 🌟 改为接收 Form 传参
        db: Session = Depends(get_db)

):
    # ==================== 🛡️ 核心拦截点：处理用户点击了“拒绝授权” ====================
    if action != "allow":
        # 1. 顺手捞一下应用名称，用于页面展示，让用户看明白是拒绝了哪个应用
        cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
        app_name = cred.app.app_name if (cred and cred.app) else "未知应用"

        # 2. 从依赖注入里临时构建一个 Request 实例传给 Jinja2 模板
        from fastapi import Request
        return templates.TemplateResponse(
            name="deny.html",
            context={
                "request": Request({"type": "http"}),
                "app_name": app_name,
                "session_id": session_id
            },
            status_code=403  # 依然保持返回 403 状态码，遵循安全的身份规范
        )

    # 这里我们不再从内存状态机里读取用户，而是直接从 Redis 中读取
    # username = MOCK_USER_SESSIONS.get(session_id)

    # 🛠️【Redis 改造】：从 Redis 状态机里精准认出用户
    username = redis_client.get(session_id)
    if not username:
        raise HTTPException(status_code=401, detail="会话已过期，请重新登录")

    # 颁发临时授权码 (Auth Code)
    # auth_code = "code_" + secrets.token_hex(16)
    # OAUTH_CODE_STORE[auth_code] = {
    #     "client_id": client_id,
    #     "redirect_uri": redirect_uri,
    #     "scope": scope,
    #     "username": username,
    #     "expire_at": datetime.datetime.now() + datetime.timedelta(minutes=10) # 确保存储了时效组件
    # }

    # 🛠️【核心修正】：将授权码存入 Redis，并设置过期时间为 10 分钟
    auth_code = "code_" + secrets.token_hex(16)
    auth_code_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "username": username
    }
    # 存入 Redis，设置 10 分钟（600秒）过期
    redis_client.setex(f"oauth_code:{auth_code}", 600, json.dumps(auth_code_data))

    target_url = f"{redirect_uri}?code={auth_code}"
    if state:
        target_url += f"&state={state}"

    return RedirectResponse(url=target_url, status_code=303)


@app.post("/oauth/token", summary="【OAuth2标准流】统一令牌网关")
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

    # 1. 解析 HTTP Basic 认证头
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

    # 2. 校验应用及密钥合法性
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred or cred.client_secret_hash != hash_secret(client_secret):
        raise HTTPException(status_code=401, detail="Client ID 或 Secret 安全不匹配")

    if not cred.is_active or not cred.app.is_active:
        raise HTTPException(status_code=403, detail="该应用凭证或通道已被整体熔断查封")

    # ==================== 模式 A：客户端凭证模式 ====================
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

    # ==================== 模式 B：授权码模式 (已完成 Redis 改造) ====================
    elif grant_type == "authorization_code":
        if not code:
            raise HTTPException(status_code=400, detail="授权码模式下必须提供 'code' 参数")

        # 🧠【Redis 改造点 1】：放弃内存字典，从 Redis 中捞取授权码数据
        redis_key = f"oauth_code:{code}"
        code_raw = redis_client.get(redis_key)

        if not code_raw:
            raise HTTPException(status_code=400, detail="无效或已被二次使用/已过期的非安全授权码")

        # 🧠【Redis 改造点 2】：取出来之后，立刻在 Redis 中将其销毁（严格确保单次有效，防重放攻击）
        redis_client.delete(redis_key)

        # 反序列化为 Python 字典
        code_info = json.loads(code_raw)

        # 🧠【安全强化】：因为 Redis 的 setex 自带物理过期销毁，
        # 原本代码里的 `code_info["expire_at"] < current_time` 判断已经不需要了，Redis 会自动替我们删掉。

        if code_info["client_id"] != client_id:
            raise HTTPException(status_code=400, detail="安全隔离阻断：串号漏洞拒绝！")

        # 计算 Token 过期时间
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

    # ==================== 模式 C：刷新令牌模式 ====================
    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="刷新令牌模式下必须传 'refresh_token'")

        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("token_type") != "refresh_token":
                raise HTTPException(status_code=401, detail="非法欺骗：该令牌并非合法的刷新令牌体")

            if payload.get("sub") != client_id:
                raise HTTPException(status_code=401, detail="令牌错位拦截！")

            target_scope = payload.get("scope", "read")
            access_token_expire = current_time + datetime.timedelta(days=1)
            refresh_token_expire = current_time + datetime.timedelta(days=30)

            if cred.expire_at and access_token_expire > cred.expire_at:
                access_token_expire = cred.expire_at
            if cred.expire_at and refresh_token_expire > cred.expire_at:
                refresh_token_expire = cred.expire_at

            new_access_token = create_jwt_token(client_id, target_scope, access_token_expire, token_type="access_token")
            new_refresh_token = create_jwt_token(client_id, target_scope, refresh_token_expire,
                                                 token_type="refresh_token")

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


# 🌟【标准新增接口】：令牌主动撤销接口 (Token Revocation - RFC 7009)
@app.post("/oauth/revoke", summary="【OAuth2标准流】客户端主动注销/撤销指定令牌")
def oauth_revoke_token(
        token: str = Form(..., description="要销毁的 access_token 或 refresh_token"),
        token_type_hint: str = Form("access_token", description="令牌类型暗示"),
        authorization: str = Header(None)
):
    """
    当第三方系统内的用户点击“退出登录”时，第三方系统异步调用此网关，让颁发的令牌立刻失效。
    """
    if token:
        # 丢进 Redis 并设置一个合理的生存周期（比如 1 天，或者解析 JWT 的 exp 动态计算）
        redis_client.setex(f"revoked_token:{token}", 86400, "1")

    return {"msg": f"令牌 [{token_type_hint}] 已在中台成功注销并加入全局黑名单废弃库"}


# ==================== 🛡️ 业务接口 & 管理中台接口保持原样 ====================
@app.get("/api/v1/inspect_license", summary="【核心受保护业务接口】校验客户端授权状态")
def inspect_license(app_id: int = Query(...), cred: AppCredential = Depends(verify_client_token)):
    if cred.app_id != app_id:
        raise HTTPException(status_code=403,
                            detail=f"密钥越权违规！当前激活码属于应用 [{cred.app.app_name}]，无法用于当前程序！")
    now = datetime.datetime.now()
    remaining_days = max(0, (cred.expire_at - now).days) if cred.expire_at else 0
    return {
        "status": "active", "client_id": cred.client_id, "credential_name": cred.credential_name,
        "app_name": cred.app.app_name, "app_id": cred.app_id,
        "scopes": [s.strip() for s in cred.scope.split(",") if s.strip()],
        "expire_date": cred.expire_at.strftime("%Y-%m-%d %H:%M:%S") if cred.expire_at else "永久有效",
        "remaining_info": f"授权订阅状态正常，剩余生命周期: {remaining_days} 天。"
    }


# 下方原有 /admin/... 系列接口保持代码未变
@app.post("/admin/apps", dependencies=[Depends(verify_admin_rpc)])
def create_app(app_name: str, owner: str = "admin", db: Session = Depends(get_db)):
    new_app = App(app_name=app_name, owner=owner)
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    return {"msg": "应用创建成功", "app_id": new_app.id, "app_name": new_app.app_name}


@app.delete("/admin/apps/{app_id}", dependencies=[Depends(verify_admin_rpc)])
def delete_app(app_id: int, db: Session = Depends(get_db)):
    target_app = db.query(App).filter(App.id == app_id).first()
    if not target_app: raise HTTPException(status_code=404, detail="未找到该应用")
    app_name = target_app.app_name
    db.delete(target_app)
    db.commit()
    return {"msg": f"应用 [{app_name}] 及其名下所有授权凭证已被彻底物理清除"}


@app.put("/admin/apps/{app_id}/status", dependencies=[Depends(verify_admin_rpc)])
def update_app_status(app_id: int, is_active: bool, db: Session = Depends(get_db)):
    target_app = db.query(App).filter(App.id == app_id).first()
    if not target_app: raise HTTPException(status_code=404, detail="未找到该应用")
    target_app.is_active = is_active
    db.commit()
    return {"msg": f"应用 [{target_app.app_name}] 状态已修改为: {'启用' if is_active else '禁用'}"}


@app.post("/admin/apps/{app_id}/credentials", dependencies=[Depends(verify_admin_rpc)])
def create_app_credential(app_id: int, credential_name: str = Query(...), scope: str = "read",
                          valid_days: int = Query(365), db: Session = Depends(get_db)):
    target_app = db.query(App).filter(App.id == app_id).first()
    if not target_app: raise HTTPException(status_code=404, detail="应用不存在")
    client_id, client_secret = generate_random_keys()
    expire_time = datetime.datetime.now() + datetime.timedelta(days=valid_days)
    new_credential = AppCredential(app_id=app_id, credential_name=credential_name, client_id=client_id,
                                   client_secret_hash=hash_secret(client_secret), scope=scope, expire_at=expire_time)
    db.add(new_credential)
    db.commit()
    long_lived_token = create_jwt_token(client_id=client_id, scope=scope, expire_at=expire_time, token_type="license")
    return {"msg": "成功开通授权凭证并生成激活码！", "client_id": client_id, "client_secret": client_secret,
            "expire_at": expire_time.strftime("%Y-%m-%d %H:%M:%S"), "license_key": long_lived_token}


@app.put("/admin/credentials/{client_id}/status", dependencies=[Depends(verify_admin_rpc)])
def update_credential_status(client_id: str, is_active: bool, db: Session = Depends(get_db)):
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred: raise HTTPException(status_code=404, detail="凭证未找到")
    cred.is_active = is_active
    db.commit()
    return {"msg": "凭证开关状态已同步"}


@app.put("/admin/credentials/{client_id}/config", dependencies=[Depends(verify_admin_rpc)])
def update_credential_config(client_id: str, scope: str = Query(...), add_days: int = Query(...),
                             db: Session = Depends(get_db)):
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred: raise HTTPException(status_code=404, detail="凭证未找到")
    cred.scope = scope
    base_time = cred.expire_at if (
                cred.expire_at and cred.expire_at > datetime.datetime.now()) else datetime.datetime.now()
    cred.expire_at = base_time + datetime.timedelta(days=add_days)
    db.commit()
    return {"msg": f"凭证 [{cred.credential_name}] 配置更新成功！"}


@app.delete("/admin/credentials/{client_id}", dependencies=[Depends(verify_admin_rpc)])
def delete_credential(client_id: str, db: Session = Depends(get_db)):
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred: raise HTTPException(status_code=404, detail="凭证不存在")
    db.delete(cred)
    db.commit()
    return {"msg": f"凭证 [{cred.credential_name}] 已被彻底移除"}


@app.get("/admin/apps/list", dependencies=[Depends(verify_admin_rpc)])
def list_all_apps(db: Session = Depends(get_db)):
    apps = db.query(App).all()
    result = []
    for a in apps:
        result.append({
            "app_id": a.id, "app_name": a.app_name, "is_active": a.is_active,
            "credentials": [{"credential_name": c.credential_name, "client_id": c.client_id, "scope": c.scope,
                             "is_active": c.is_active,
                             "expire_at": c.expire_at.strftime("%Y-%m-%d %H:%M:%S") if c.expire_at else "永久有效"} for
                            c in a.credentials]
        })
    return result


init_db()


# 🚀 生产环境安全性：自动化建立公网首个超级管理员/测试用户
def seed_initial_user():
    from database import SessionLocal, User
    from passlib.context import CryptContext

    db = SessionLocal()
    try:
        # 检查是否已经存在测试账号，防止重复插入
        exists = db.query(User).filter(User.username == "admin").first()
        if not exists:
            print("🌱 检测到干净的数据库环境，正在为您初始化创建首个公网演示账号...")
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

            # 🌟 设置你的公网登录初始账号和密码（建议自行修改得更复杂）
            init_username = "admin"
            init_password = "admin@123"  # 🚨 强烈建议在生产环境中修改这个默认密码，并通过环境变量注入更安全的值！

            hashed_pwd = pwd_context.hash(init_password)

            admin_user = User(
                username=init_username,
                password_hash=hashed_pwd,
                nickname="系统超级管理员",
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            print(f"====================================================")
            print(f"🎉 账号初始化成功！公网默认登录凭证如下：")
            print(f"   👤 账号 (Username): {init_username}")
            print(f"   🔑 密码 (Password): {init_password}")
            print(f"⚠️  请在首次成功登录后，尽快通过生产中台修改该默认密码！")
            print(f"====================================================")
    except Exception as e:
        print(f"❌ 初始化用户失败: {e}")
    finally:
        db.close()


# 执行账号注入
seed_initial_user()

if __name__ == "__main__":
    import uvicorn
    import os

    # 📜 自签名证书本地保存的文件名
    CERT_FILE = "./local_server.crt"
    KEY_FILE = "./local_server.key"

    # 🛠️ 检查如果证书不存在，则通过 Python 代码当场动态生成一套
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("⚡ 未检测到本地 SSL 证书，正在通过 Cryptography 引擎为您动态硬核签发自签名证书...")

        import datetime
        import ipaddress  # 🚀 🔥【修复】：引入正确的 IP 地址解析标准库
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # 1. 生成 2048 位的 RSA 私钥
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # 2. 配置证书的主体信息（Subject & Issuer 相同，代表自签名）
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Fujian"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Fuzhou"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSO Local Dev Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "192.168.1.5"),  # 绑定内网主 IP
        ])

        # 3. 构造证书体并注入 SAN 扩展属性
        # 💡 这里已经把错误的 datetime.ip_address 修复为了 ipaddress.ip_address
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))  # 有效期1年
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),  # 🧠 修正成功
                    x509.IPAddress(ipaddress.ip_address("192.168.1.5")),  # 🧠 修正成功
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())  # 使用 SHA256 签名算法
        )

        # 4. 将生成的私钥写入本地文件
        with open(KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # 5. 将生成的证书文件写入本地
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("✅ 工业级本地自签名证书生成完毕！已安全写入当前工作目录。")

    # 🚀 启动 Uvicorn 并直接装载自签名证书
    uvicorn.run(
        "main:app",
        host="0.0.0.0",  # 允许局域网设备跨端访问
        port=8000,
        reload=True,
        ssl_certfile=CERT_FILE,
        ssl_keyfile=KEY_FILE
    )