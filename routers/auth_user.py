from fastapi import APIRouter, Depends, HTTPException, status, Header, Form, Response, Cookie, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import requests
import secrets
import time

# 🌟 引入数据库实体与核心依赖项
from database import get_db, User, Role, DeveloperGroup, Permission
from database import RiskEvent, RiskGlobalSetting
# 🌟 引入 Redis 客户端（保持原功能连通）
from middlewares.auth import redis_client
from middlewares.rbac import RBACChecker
from routers.admin import _generate_group_code
from routers.webhook import dispatch_webhook_event
from utils.captcha import issue_captcha, verify_captcha
from utils.risk_expr import build_risk_context, resolve_login_fail_policy

# 🎯 路由配置对齐：将前缀设为全局共用，内部支持平铺管理端与业务端
router = APIRouter(tags=["中台统一账户与动态会话鉴权中心"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

LOGIN_FAIL_THRESHOLD = 3
LOGIN_FAIL_TTL_SECONDS = 600
LOGIN_FAIL_RULE_TYPE = "LOGIN_FAIL_CAPTCHA"


def _get_login_fail_policy(db: Session, request: Request, username: str, fail_count: int) -> tuple[int, int]:
    client_ip, user_agent, is_mobile, browser, os_name, location = _extract_client_meta(request)
    context = build_risk_context(
        username=username,
        ip=client_ip,
        path=request.url.path,
        user_agent=user_agent,
        browser=browser,
        os=os_name,
        location=location,
        is_mobile=is_mobile,
        fail_count=fail_count
    )
    threshold, window, _ = resolve_login_fail_policy(
        db=db,
        context=context,
        default_threshold=LOGIN_FAIL_THRESHOLD,
        default_window=LOGIN_FAIL_TTL_SECONDS,
        rule_type=LOGIN_FAIL_RULE_TYPE,
        action="CAPTCHA"
    )
    return threshold, window


def _login_fail_key(username: str, client_ip: str) -> str:
    safe_user = (username or "").strip().lower() or "unknown"
    safe_ip = (client_ip or "-").strip()
    return f"login_fail:{safe_user}:{safe_ip}"


def _get_login_fail_count(username: str, client_ip: str) -> int:
    value = redis_client.get(_login_fail_key(username, client_ip))
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _increment_login_fail(username: str, client_ip: str, ttl_seconds: int) -> int:
    key = _login_fail_key(username, client_ip)
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, ttl_seconds)
    return int(count)


def _clear_login_fail(username: str, client_ip: str) -> None:
    redis_client.delete(_login_fail_key(username, client_ip))


def _captcha_required_response(message: str) -> JSONResponse:
    token, image = issue_captcha(redis_client)
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "message": message,
            "captcha_required": True,
            "captcha_token": token,
            "captcha_image": image
        }
    )


def _resolve_ip_location(ip_value: str) -> str:
    if not ip_value or ip_value == "-":
        return "未知"
    private_prefixes = ("10.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "192.168.")
    if ip_value.startswith(private_prefixes):
        return "内网"
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip_value}", params={"fields": "country,regionName,city"}, timeout=1)
        if resp.status_code == 200:
            data = resp.json()
            parts = [data.get("country"), data.get("regionName"), data.get("city")]
            return " ".join([p for p in parts if p]) or "未知"
    except Exception:
        return "未知"
    return "未知"


def _extract_client_meta(request: Request) -> tuple[str, str, bool, str, str, str]:
    ip_raw = request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP") or request.client.host
    ip_value = str(ip_raw) if ip_raw else "-"
    client_ip = (ip_value.split(",")[0].strip() if ip_value else "-")
    user_agent = request.headers.get("User-Agent") or ""
    ua_lower = user_agent.lower()
    is_mobile = any(key in ua_lower for key in ["mobile", "iphone", "android", "ipad"])
    if "edg" in ua_lower or "edge" in ua_lower:
        browser = "Edge"
    elif "chrome" in ua_lower and "safari" in ua_lower:
        browser = "Chrome"
    elif "safari" in ua_lower:
        browser = "Safari"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    else:
        browser = "Unknown"
    if "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os" in ua_lower or "macintosh" in ua_lower:
        os_name = "macOS"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower or "ios" in ua_lower:
        os_name = "iOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    else:
        os_name = "Unknown"
    location = _resolve_ip_location(client_ip)
    return client_ip, user_agent, is_mobile, browser, os_name, location


def _store_session_meta(session_id: str, request: Request):
    client_ip, user_agent, is_mobile, browser, os_name, location = _extract_client_meta(request)
    login_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    meta_key = f"sess_meta:{session_id}"
    redis_client.hset(meta_key, mapping={
        "ip": client_ip,
        "ua": user_agent,
        "is_mobile": "1" if is_mobile else "0",
        "browser": browser,
        "os": os_name,
        "location": location,
        "login_time": login_time
    })
    redis_client.expire(meta_key, 86400)

def _record_risk_event(db: Session, request: Request, risk_level: str, action: str = "BLOCK") -> None:
    client_ip, _, _, _, _, _ = _extract_client_meta(request)
    try:
        db.add(RiskEvent(
            action=action,
            latency_ms=0,
            ip=client_ip,
            path=request.url.path,
            risk_level=risk_level
        ))
        db.commit()
    except Exception:
        db.rollback()


def _is_global_melt_enabled(db: Session) -> bool:
    setting = db.query(RiskGlobalSetting).first()
    return bool(setting and setting.is_melt)

# --- Pydantic 输入模型验证 ---
class UserRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="用户名")
    password: str = Field(..., min_length=6, description="密码，至少6位")
    nickname: str = Field(None, description="昵称")
    group_code: str = Field(..., min_length=4, max_length=32, description="租户空间唯一识别码")


class TenantAdminRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="用户名")
    password: str = Field(..., min_length=6, description="密码，至少6位")
    nickname: str = Field(None, description="昵称")
    group_name: str = Field(..., min_length=1, max_length=64, description="租户空间名称")
    group_description: str = Field(None, description="租户空间说明")


class TenantUserInviteSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="用户名")
    password: str = Field(..., min_length=6, description="密码，至少6位")
    nickname: str = Field(None, description="昵称")
    group_code: str = Field(None, min_length=4, max_length=32, description="租户空间唯一识别码(仅超管可指定)")


class UserLoginSchema(BaseModel):
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")
    captcha_token: str | None = Field(None, description="验证码 token")
    captcha_code: str | None = Field(None, description="验证码")

# --- 1. 用户注册接口 ---
@router.post("/auth/register", summary="普通用户注册")
def register_user(payload: UserRegisterSchema, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该用户名已被注册，请更换"
        )

    group = db.query(DeveloperGroup).filter(DeveloperGroup.group_code == payload.group_code).first()
    if not group or not group.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="租户空间不存在或已被停用"
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
    default_role = _get_role(db, "standard_user")
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


@router.post("/auth/register/tenant_admin", summary="租户管理员注册")
def register_tenant_admin(payload: TenantAdminRegisterSchema, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该用户名已被注册，请更换"
        )

    existing_group = db.query(DeveloperGroup).filter(DeveloperGroup.group_name == payload.group_name).first()
    if existing_group:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该租户空间名称已被占用"
        )

    group_code = _generate_group_code(db)
    new_group = DeveloperGroup(
        group_name=payload.group_name,
        description=payload.group_description,
        group_code=group_code,
        owner=payload.username,
        is_active=False,
        status="pending"
    )
    db.add(new_group)
    db.commit()
    db.refresh(new_group)

    hashed_password = pwd_context.hash(payload.password)
    new_user = User(
        username=payload.username,
        password_hash=hashed_password,
        nickname=payload.nickname or payload.username,
        is_active=True,
        group_id=new_group.id
    )

    tenant_admin_role = _get_role(db, "tenant_admin")
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
            "group_code": new_group.group_code
        },
        db=db
    )

    return {
        "status": "success",
        "message": "租户管理员注册成功，租户空间已创建并进入待超级管理员审核状态",
        "user_id": new_user.id,
        "username": new_user.username,
        "assigned_role": tenant_admin_role.name,
        "group_id": new_group.id,
        "group_name": new_group.group_name,
        "group_code": new_group.group_code
    }


# --- 2. 管理中台核心：用户/管理员登录接口 (精简版单轨 Session 架构) ---
# 支持多路由别名绑定，共享同一个底层业务闭环
@router.post("/admin/token", summary="【核心】管理员/用户登录并灌注统一会话Cookie")
@router.post("/auth/login", summary="【兼容】用户登录标准接口")
def login_user(
        payload: UserLoginSchema,
        request: Request,  # 🌟 核心修正：用于安全抓取真实的客户端公网 IP
        response: Response,  # 🌟 用于下发单轨 HttpOnly Cookie
        db: Session = Depends(get_db)
):
    """
    🔒 极简单轨 Session 架构：
    核验用户名密码成功后，向 Redis 灌入随机 Session 令牌。
    通过全局唯一的 sso_session_id Cookie 注入，配合响应体回传，
    让管理后台前端、Flet 客户端与 OAuth 授权大厅共享同一套生命周期。
    """
    if _is_global_melt_enabled(db):
        _record_risk_event(db, request, risk_level="high", action="BLOCK")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="全局熔断已开启，登录入口临时关闭，请稍后重试"
        )

    client_ip, _, _, _, _, _ = _extract_client_meta(request)
    fail_count = _get_login_fail_count(payload.username, client_ip)
    threshold, window_seconds = _get_login_fail_policy(db, request, payload.username, fail_count)
    if fail_count >= threshold:
        if not verify_captcha(redis_client, payload.captcha_token, payload.captcha_code):
            return _captcha_required_response("登录失败次数过多，请输入验证码")

    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not pwd_context.verify(payload.password, user.password_hash):
        _record_risk_event(db, request, risk_level="high")
        new_count = _increment_login_fail(payload.username, client_ip, window_seconds)
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

    # 1. ⚡ 生成标准的分布式 Session ID（全局唯一标识）
    new_session_id = "sess_" + secrets.token_hex(12)

    # 2. 🗄️ 将状态托管至 Redis 中控（有效期 1 天 = 86400 秒）
    redis_client.setex(new_session_id, 86400, str(user.id))

    # 🌟 顺手做个反向索引：把这个 session_id 扔进该用户的活跃会话集合里
    user_set_key = f"user:active_sessions:{user.id}"
    redis_client.sadd(user_set_key, new_session_id)
    redis_client.expire(user_set_key, 86400)  # 保持过期时间一致

    _store_session_meta(new_session_id, request)

    # 3. 🔑 穿透 RBAC 模型，提取真实的多维权限集合
    user_scopes = []
    for role in user.roles:
        if hasattr(role, 'permissions'):
            for perm in role.permissions:
                if perm.name:
                    user_scopes.append(perm.name)

    final_scopes_list = list(set(user_scopes)) if user_scopes else ["read"]

    # 4. 🚀 【大一统核心】向浏览器强推全网唯一的 sso_session_id Cookie
    response.set_cookie(
        key="sso_session_id",
        value=new_session_id,
        httponly=True,  # 🔒 严格防范 XSS 脚本劫持
        path="/",  # 🌍 跨路由全域共享的生命线
        secure=False,  # 🎯 本地纯 HTTP 调试环境设为 False
        samesite="lax"  # 🎯 保障 Flet 客户端拉起跨域重定向时可以安全携带
    )

    # 5. ⚡ 并网异步下发 Webhook 事件（在安全状态落盘后触发）
    # 防范 Nginx / CDN 代理导致 IP 变成 127.0.0.1，优先解析代理链路中的真实公网 IP
    client_ip = request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()

    dispatch_webhook_event(
        event_type="auth.login",
        payload={
            "user_id": user.id,
            "username": user.username,
            "ip_address": client_ip,  # 👈 穿透代理后的真实 IP，提高事件审计含金量
            "login_at": int(time.time()),
            "entry_point": request.url.path  # 💡 额外增补：告诉订阅方是通过 /admin/token 还是 /auth/login 登入的
        },
        db=db
    )

    # 6. 🏁 【全量闭环】返回精简后的 JSON 响应体
    return {
        "status": "success",
        "message": "中台身份核验通过，单轨分布式 Session 会话已成功建立！",
        "access_token": new_session_id,  # 🛡️ 兼容老代码的垫片
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

    # 支持 Redis 返回的 bytes 类型解码为 str
    if isinstance(username, bytes):
        username = username.decode("utf-8")

    # 🚀 3. 锁定数据库用户
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="目标账户不存在")

    # 🚀 4. 严苛验证密码
    if not pwd_context.verify(confirm_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="安全审计失败：密码校验错误，拒绝销户请求")

    # 🚀 5. 斩草除根：物理抹除与分布式会话粉碎
    db.delete(user)
    db.commit()
    dispatch_webhook_event(
        event_type="user.delete",
        payload={
            "user_id": user.id,
            "status": "terminated"
        },
        db=db
    )

    # 抹除该用户当前的这根 Session 导火索
    redis_client.delete(target_session_id)

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
        "message": f"用户账户 [{username}] 已成功物理销户，相关核心数据及全网 Session 会话已被全面抹除清空。"
    }


# ==================== 🛠️ 改造核心接口 3：修改密码 (Change Password - 纯 Session 版) ====================
@router.post("/auth/change_password", summary="用户修改密码")
def change_password(
        current_password: str = Form(..., description="当前密码"),
        new_password: str = Form(..., min_length=6, description="新密码，至少6位"),
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

    if isinstance(username, bytes):
        username = username.decode("utf-8")

    # 🚀 3. 密码置换审计
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="目标账户不存在")

    if not pwd_context.verify(current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前密码错误，拒绝修改")

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
    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="用户名已存在")

    target_group = None
    if _user_has_role(current_user, "super_admin") and payload.group_code:
        target_group = db.query(DeveloperGroup).filter(DeveloperGroup.group_code == payload.group_code).first()
    else:
        if current_user.group_id:
            target_group = db.query(DeveloperGroup).filter(DeveloperGroup.id == current_user.group_id).first()

    if not target_group or not target_group.is_active:
        raise HTTPException(status_code=404, detail="租户空间不存在或已被停用")

    new_user = User(
        username=payload.username,
        password_hash=pwd_context.hash(payload.password),
        nickname=payload.nickname or payload.username,
        is_active=True,
        group_id=target_group.id
    )

    default_role = _get_role(db, "standard_user")
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


@router.get("/auth/me", summary="获取当前登录用户画像")
def get_current_user_profile(
        current_user: User = Depends(RBACChecker("read"))
):
    group = current_user.group
    roles = [role.name for role in current_user.roles]
    return {
        "status": "success",
        "data": {
            "user_id": current_user.id,
            "username": current_user.username,
            "nickname": current_user.nickname,
            "group_id": group.id if group else None,
            "group_name": group.group_name if group else None,
            "group_code": group.group_code if group else None,
            "group_status": group.status if group else None,
            "group_is_active": group.is_active if group else None,
            "group_review_note": group.review_note if group else None,
            "group_reviewed_at": group.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if group and group.reviewed_at else None,
            "group_expire_at": group.expire_at.strftime("%Y-%m-%d %H:%M:%S") if group and group.expire_at else None,
            "roles": roles,
            "is_tenant_admin": "tenant_admin" in roles or "super_admin" in roles
        }
    }
