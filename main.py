import os
import sys
import asyncio
import logging
import datetime
import jwt

import uvicorn
from fastapi import FastAPI, Request, status, Cookie, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from config import SECRET_KEY
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from routers import oauth, business, admin, auth_user, permission,webhook
from routers import tenant
from utils.ssl_gen import ensure_ssl_certificates
from utils.captcha import issue_captcha
from database import init_db, get_db, User, Role, SessionLocal, OperationLog
from database import RiskRule, RiskEvent, RiskGlobalSetting
from database import SystemAnnouncement
from database import SystemSiteSetting
from middlewares.auth import redis_client
from middlewares.rbac import RBACChecker
from jinja2 import Environment, FileSystemLoader, PrefixLoader
from sqlalchemy.orm import joinedload
from sqlalchemy import func
from utils.risk_expr import validate_match_expression
from schemas.admin_schema import (
    RiskRuleCreateInput,
    RiskRuleUpdateInput,
    RiskRuleStatusInput,
    RiskGlobalMeltInput,
    RiskEventCreateInput,
    AnnouncementCreateInput,
    AnnouncementUpdateInput,
    SiteSettingUpdateInput
)

# 🌟 解决 Windows 平台高频弹出的 WinError 10054 异步连接断开警告
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

app = FastAPI(title="企业级标准 OAuth2.0 & License 双轨制融合鉴权平台", docs_url="/docs", redoc_url=None)

# ==================== 🎯 核心修复：注入并锚定 HTML 模板引擎 ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_LOGO_DIR = os.path.normpath(os.path.join(BASE_DIR, "uploads", "app_logos"))
os.makedirs(APP_LOGO_DIR, exist_ok=True)

# 强行规范路径，防止 Windows 下反斜杠 (\) 与正斜杠 (/) 混用导致匹配失败
ADMIN_WEB_DIR = os.path.normpath(os.path.join(BASE_DIR, "admin_web"))
WEB_DIR = os.path.normpath(os.path.join(BASE_DIR, "user_web"))
TENANT_WEB_DIR = os.path.normpath(os.path.join(BASE_DIR, "tenant_web"))
TEMPLATES_DIR = os.path.normpath(os.path.join(BASE_DIR, "templates"))

# 使用标准 PrefixLoader 隔离命名空间，完美对齐 Windows 路径
jinja2_env = Environment(
    loader=PrefixLoader({
        "admin": FileSystemLoader(ADMIN_WEB_DIR),   # 代码中用 admin/xxx.html
        "user": FileSystemLoader(WEB_DIR),         # 代码中用 user/xxx.html
        "tenant": FileSystemLoader(TENANT_WEB_DIR),
        "shared": FileSystemLoader(TEMPLATES_DIR)   # 代码中用 shared/xxx.html
    }),
    autoescape=True
)

templates = Jinja2Templates(env=jinja2_env)
# =========================================================================

app.mount("/uploads/app_logos", StaticFiles(directory=APP_LOGO_DIR), name="app_logos")


# 🔒 跨域配置保持不变
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://localhost:8000", "https://127.0.0.1:8000",
        "https://localhost:8080", "https://127.0.0.1:8080",
        "https://localhost:8081", "https://127.0.0.1:8081"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🚀 挂载解耦后的路由切片到 FastAPI 核心轨道
app.include_router(oauth.router)
app.include_router(business.router)
app.include_router(admin.router)
app.include_router(auth_user.router)
app.include_router(permission.router)
app.include_router(webhook.router)
app.include_router(tenant.router)


@app.middleware("http")
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
    if should_log and content_type and ("multipart/form-data" not in content_type and "application/octet-stream" not in content_type):
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
        user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
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
            payload=payload_text
        )
        db.add(log_item)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    return response

# ==================== 🛡️ 全局异常拦截硬核防线 ====================
async def handle_error_response(request: Request, status_code: int, detail: str):
    """
    智能分流器：自动判定是给浏览器推网页，还是给前端接口推 JSON
    """
    accept_header = request.headers.get("accept", "")
    requested_with = request.headers.get("x-requested-with", "")

    # 判定规则：只有明确包含 text/html 且不是 Ajax 请求的，才返回错误网页
    is_browser_page_request = "text/html" in accept_header and "application/json" not in accept_header
    if requested_with == "XMLHttpRequest":
        is_browser_page_request = False

    if is_browser_page_request:
        return templates.TemplateResponse(
            request=request,
            name="shared/error.html",
            context={"request": request, "status_code": status_code, "detail": detail},
            status_code=status_code
        )
    else:
        # JSON 格式统一收口
        return JSONResponse(
            status_code=status_code,
            content={
                "status": "fail",
                "code": status_code * 100,
                "message": detail,
                "data": None
            }
        )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """1. 拦截参数校验失败"""
    errors = exc.errors()
    msg = f"参数校验失败: {errors[0]['loc'][-1]} - {errors[0]['msg']}"
    return await handle_error_response(request, 400, msg)


@app.exception_handler(HTTPException)
@app.exception_handler(StarletteHTTPException)
async def global_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """2. 拦截所有业务逻辑和路由错误 (包括 404)"""
    # 如果是 404，自定义你的友好提示
    detail = "您访问的中台核心路由不存在，请核对接口文档！" if exc.status_code == 404 else str(exc.detail)
    return await handle_error_response(request, exc.status_code, detail)


@app.exception_handler(Exception)
async def global_generic_exception_handler(request: Request, exc: Exception):
    """3. 终极兜底：拦截未知 500 崩溃"""
    logging.error(f"🚨 中台核心严重崩溃: {str(exc)}", exc_info=True)
    return await handle_error_response(request, 500, "中台系统执行遭遇阻断，请联系管理员核查日志！")


# ==================== 🛡️ 视图层专属：Cookie 会话前置看门狗 ====================
def check_user_admin_privilege(session_user_val: str, db: Session) -> bool:
    """
    【双轨自适应高性能鉴权中心】
    支持从 Redis 会话中自动识别 User.id (纯数字) 或 Username (字符串),
    并高能检索其是否具备 admin:* 级别的任意管理权限或属于超级管理组。
    """
    if not session_user_val:
        return False

    # 强转为字符串并剥离可能存在的首尾空格
    session_user_val = str(session_user_val).strip()

    try:
        # 1. ⚡ 基础查询组装：使用 joinedload 强行锁死关联数据，防止懒加载在异步线程中死锁
        query = db.query(User).options(
            joinedload(User.roles).joinedload(Role.permissions)
        )

        # 2. 🔀 智能双轨路由选择器
        if session_user_val.isdigit():
            # 如果是纯数字，说明 Redis 存的是 user_id，走主键集群索引 (极快)
            user_obj = query.filter(User.id == int(session_user_val)).first()
        else:
            # 如果包含字母，说明 Redis 存的是 username，走用户名唯一索引
            user_obj = query.filter(User.username == session_user_val).first()

        if not user_obj:
            print(f"⚠️ [鉴权中心] 深度扫描失败：在数据库中未找到标识为 '{session_user_val}' 的合法用户")
            return False

        # 3. 👑 第一层锁：如果是系统级最高权力控制组 (super_admin)，直接物理放行
        for role in user_obj.roles:
            if role.name == "super_admin":
                return True

            # 4. 🔒 第二层锁：精准扫描该角色下是否拥有任何以 "admin:" 开头的核心资产管理权限
            for perm in role.permissions:
                # 🎯 动态匹配 admin:read, admin:create, admin:update, admin:delete 等
                if perm.name and perm.name.startswith("admin:read"):
                    return True

    except Exception as e:
        print(f"🚨 [鉴权中心] 联表权限图谱扫描时遭遇底层异常: {str(e)}")
        return False

    return False


def verify_view_admin_session(auth_token: str) -> bool:
    if not auth_token:
        return False
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("client_id") or payload.get("sub") or payload.get("user_name")
        if username is not None:
            return True
    except jwt.PyJWTError as e:
        return False
    return False


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
    return any(role.name in ["tenant_admin", "super_admin"] for role in user_obj.roles)


def _tenant_access_snapshot(user_obj: User | None):
    if not user_obj:
        return None, "当前账号未找到"

    group = user_obj.group
    if not group:
        return None, "当前租户管理员尚未创建空间，请先前往【申请创建空间】"

    if group.status == "rejected":
        return group, group.review_note or "当前空间申请未通过，请重新提交创建申请"

    if group.status == "pending":
        return group, group.review_note or "当前空间正在等待超级管理员审核"

    if not group.is_active:
        return group, "当前租户空间已被冻结，请联系超级管理员处理"

    if group.expire_at and group.expire_at < datetime.datetime.now():
        return group, "当前租户空间已过期，请联系超级管理员续期"

    return group, None


# ==================== 🎨 Layui 管理端 Web 视图路由（全面升级安全拦截） ====================
@app.get("/admin/permissions", response_class=HTMLResponse, summary="【视图】进入权限节点管理页面")
def permissions_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db) # 注入 DB 用于鉴权
):
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 拦截 1：未登录直接踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # 🚨 拦截 2：核心熔断，如果没有 admin:* 权限，直接将其安全导航回普通 web 空间的主页
    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 验证通过，渲染 admin_web 文件夹下的 permissions.html
    return templates.TemplateResponse(
        request=request,
        name="admin/permissions.html", # 👈 增加了命名空间前缀
        context={"request": request, "username": user_logged_in}
    )

@app.get("/admin/roles", response_class=HTMLResponse, summary="【视图】进入权限组管理页面")
def roles_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="admin/roles.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/notices", response_class=HTMLResponse, summary="【视图】进入系统公告与消息中心")
def announcements_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 系统公告视图（函数名已修正：announcements_page_view）
    🔒 补齐漏洞：加入看门狗防线，防止匿名爬虫直接撞击 /system/announcements 白嫖视图
    """
    user_logged_in = None

    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="admin/notices.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/settings", response_class=HTMLResponse, summary="【视图】进入系统配置中心")
def settings_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 系统设置视图（函数名已修正：settings_page_view）
    🔒 补齐漏洞：加入看门狗防线，防止匿名爬虫直接撞击 /system/settings 白嫖视图
    """
    user_logged_in = None

    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="admin/settings.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/callbacks", response_class=HTMLResponse, summary="【视图】进入回调地址管理中心")
def callbacks_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 回调地址视图（函数名已修正：callbacks_page_view）
    🔒 补齐漏洞：加入看门狗防线，防止匿名爬虫直接撞击 /system/callbacks 白嫖视图
    """
    user_logged_in = None

    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="admin/webhook.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/admin/{page_name}", response_class=HTMLResponse, include_in_schema=False)
def admin_page_view(
        request: Request,
        page_name: str,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    if not check_user_admin_privilege(user_logged_in, db):
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    safe_name = page_name.strip().lstrip("/")
    if not safe_name.endswith(".html"):
        safe_name = f"{safe_name}.html"

    return templates.TemplateResponse(
        request=request,
        name=f"admin/{safe_name}",
        context={"request": request, "username": user_logged_in}
    )


@app.get("/system/audit", response_class=HTMLResponse, summary="【视图】进入审计日志中心")
def audit_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 审计日志视图（函数名已修正：audit_page_view）
    🔒 补齐漏洞：加入看门狗防线，防止匿名爬虫直接撞击 /system/audit 白嫖视图
    """
    user_logged_in = None

    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="admin/audit.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/sessions", response_class=HTMLResponse, summary="【视图】进入在线会话监控中心")
def sessions_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 在线会话视图（函数名已修正：sessions_page_view）
    🔒 补齐漏洞：加入看门狗防线，防止匿名爬虫直接撞击 /system/sessions 白嫖视图
    """
    user_logged_in = None

    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="admin/sessions.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


class SessionRevokeInput(BaseModel):
    token_id: str = Field(..., min_length=1, description="会话令牌")
    username: str | None = Field(None, description="可选：用户名")


class SessionBatchRevokeInput(BaseModel):
    token_ids: list[str] = Field(default_factory=list, description="会话令牌列表")


class SessionRevokeAllInput(BaseModel):
    keep_current: bool = Field(True, description="是否保留当前会话")
    reason: str | None = Field(None, description="下线原因")


@app.get("/system/session", summary="【管理端】获取在线会话列表")
def list_online_sessions(
        page: int = 1,
        limit: int = 10,
        username: str | None = None,
        ip: str | None = None,
        device: str | None = None,
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    username_filter = (username or "").strip()
    ip_filter = (ip or "").strip()
    device_filter = (device or "").strip().lower()

    sessions = []
    for raw_key in redis_client.scan_iter("sess_*"):
        token_id = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
        try:
            key_type = redis_client.type(token_id)
            key_type = key_type.decode("utf-8") if isinstance(key_type, bytes) else str(key_type)
        except Exception:
            continue
        if key_type != "string":
            continue

        raw_user_id = redis_client.get(token_id)
        if not raw_user_id:
            continue
        try:
            user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
        except ValueError:
            continue
        user_obj = db.query(User).filter(User.id == user_id).first()
        if not user_obj:
            continue
        if username_filter and (username_filter not in user_obj.username and username_filter not in token_id):
            continue
        meta_key = f"sess_meta:{token_id}"
        meta_raw = redis_client.hgetall(meta_key) or {}
        meta = { (k.decode("utf-8") if isinstance(k, bytes) else str(k)):
                 (v.decode("utf-8") if isinstance(v, bytes) else str(v))
                 for k, v in meta_raw.items() }
        meta_ip = meta.get("ip", "-")
        meta_is_mobile = meta.get("is_mobile", "0") == "1"
        meta_browser = meta.get("browser", "-")
        meta_login_time = meta.get("login_time", "-")

        if ip_filter and ip_filter not in meta_ip:
            continue
        if device_filter in {"mobile", "desktop"}:
            if device_filter == "mobile" and not meta_is_mobile:
                continue
            if device_filter == "desktop" and meta_is_mobile:
                continue

        sessions.append({
            "token_id": token_id,
            "username": user_obj.username,
            "ip": meta_ip,
            "location": meta.get("location", "-"),
            "is_mobile": meta_is_mobile,
            "browser": meta_browser,
            "os": meta.get("os", "-"),
            "login_time": meta_login_time,
            "ua": meta.get("ua", "")
        })

    total = len(sessions)
    start = (max(page, 1) - 1) * max(limit, 1)
    end = start + max(limit, 1)
    return {
        "code": 200,
        "count": total,
        "data": sessions[start:end]
    }


@app.post("/system/session/revoke", summary="【管理端】强制下线指定会话")
def revoke_online_session(
        payload: SessionRevokeInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    token_id = payload.token_id.strip()
    meta_key = f"sess_meta:{token_id}"
    raw_user_id = redis_client.get(token_id)
    user_id = None
    if raw_user_id:
        try:
            user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
        except ValueError:
            user_id = None
    elif payload.username:
        user_obj = db.query(User).filter(User.username == payload.username).first()
        if user_obj:
            user_id = user_obj.id

    if user_id:
        user_set_key = f"user:active_sessions:{user_id}"
        redis_client.srem(user_set_key, token_id)

    redis_client.delete(token_id)
    redis_client.delete(meta_key)
    return {
        "code": 200,
        "message": "会话已强制下线"
    }


@app.post("/system/session/revoke_batch", summary="【管理端】批量强制下线会话")
def revoke_online_sessions_batch(
        payload: SessionBatchRevokeInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    token_ids = [item.strip() for item in payload.token_ids if item and item.strip().startswith("sess_")]
    if not token_ids:
        return {"code": 200, "message": "没有可处理的会话"}

    for token_id in token_ids:
        meta_key = f"sess_meta:{token_id}"
        raw_user_id = redis_client.get(token_id)
        if raw_user_id:
            try:
                user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
            except ValueError:
                user_id = None
            if user_id:
                user_set_key = f"user:active_sessions:{user_id}"
                redis_client.srem(user_set_key, token_id)
        redis_client.delete(token_id)
        redis_client.delete(meta_key)

    return {
        "code": 200,
        "message": "批量下线完成",
        "count": len(token_ids)
    }


@app.post("/system/session/revoke_all", summary="【管理端】全量会话下线")
def revoke_online_sessions_all(
        payload: SessionRevokeAllInput,
        sso_session_id: str | None = Cookie(None),
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    keep_current = bool(payload.keep_current)
    current_token = (sso_session_id or "").strip()
    revoked_count = 0

    for raw_key in redis_client.scan_iter("sess_*"):
        token_id = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)

        if keep_current and current_token and token_id == current_token:
            continue

        raw_user_id = redis_client.get(token_id)
        if raw_user_id:
            try:
                user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
            except ValueError:
                user_id = None
            if user_id:
                redis_client.srem(f"user:active_sessions:{user_id}", token_id)

        redis_client.delete(token_id)
        redis_client.delete(f"sess_meta:{token_id}")
        revoked_count += 1

    return {
        "code": 200,
        "message": "全部下线完成",
        "count": revoked_count
    }


@app.get("/system/captcha", summary="【公共】获取登录验证码")
def get_login_captcha():
    token, image = issue_captcha(redis_client)
    return {
        "code": 200,
        "data": {
            "token": token,
            "image": image
        }
    }


def _get_or_create_site_setting(db: Session) -> SystemSiteSetting:
    setting = db.query(SystemSiteSetting).first()
    if setting:
        return setting

    setting = SystemSiteSetting(
        site_name="OnAuth 云中台",
        domain="https://localhost:8000",
        copyright=""
    )
    db.add(setting)
    db.commit()
    db.refresh(setting)
    return setting


@app.get("/system/settings/site", summary="【管理端】获取站点基本信息")
def get_site_basic_settings(
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    setting = _get_or_create_site_setting(db)
    return {
        "code": 200,
        "data": {
            "site_name": setting.site_name,
            "domain": setting.domain,
            "copyright": setting.copyright or ""
        }
    }


@app.post("/system/settings/site/update", summary="【管理端】更新站点基本信息")
def update_site_basic_settings(
        payload: SiteSettingUpdateInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    site_name = payload.site_name.strip()
    domain = payload.domain.strip()
    copyright_text = (payload.copyright or "").strip()

    if not site_name:
        raise HTTPException(status_code=400, detail="站点名称不能为空")
    if not domain:
        raise HTTPException(status_code=400, detail="控制台主域名不能为空")

    setting = _get_or_create_site_setting(db)
    setting.site_name = site_name
    setting.domain = domain
    setting.copyright = copyright_text
    setting.updated_by = current_user.username
    db.commit()

    return {
        "code": 200,
        "message": "站点基本信息已保存",
        "data": {
            "site_name": setting.site_name,
            "domain": setting.domain,
            "copyright": setting.copyright or ""
        }
    }


def _normalize_announcement_type(type_value: str) -> str:
    normalized = (type_value or "notice").strip().lower()
    if normalized not in {"notice", "bulletin"}:
        raise HTTPException(status_code=400, detail="公告类型仅支持 notice 或 bulletin")
    return normalized


def _normalize_announcement_status(status_value: str) -> str:
    normalized = (status_value or "published").strip().lower()
    if normalized not in {"published", "draft"}:
        raise HTTPException(status_code=400, detail="公告状态仅支持 published 或 draft")
    return normalized


def _format_announcement_item(item: SystemAnnouncement) -> dict:
    return {
        "id": item.id,
        "title": item.title,
        "content": item.content,
        "type": item.type,
        "is_pinned": item.is_pinned,
        "status": item.status,
        "creator": item.creator,
        "creator_id": item.creator_id,
        "created_at": item.created_at.strftime("%Y-%m-%d %H:%M:%S") if item.created_at else None,
        "updated_at": item.updated_at.strftime("%Y-%m-%d %H:%M:%S") if item.updated_at else None
    }


@app.get("/system/announcement", summary="【管理端】拉取系统公告列表")
def list_system_announcements(
        page: int = 1,
        limit: int = 10,
        title: str | None = None,
        type: str | None = None,
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    query = db.query(SystemAnnouncement)

    title_filter = (title or "").strip()
    if title_filter:
        query = query.filter(SystemAnnouncement.title.contains(title_filter))

    if type:
        normalized_type = _normalize_announcement_type(type)
        query = query.filter(SystemAnnouncement.type == normalized_type)

    total = query.count()
    announcements = query.order_by(
        SystemAnnouncement.is_pinned.desc(),
        SystemAnnouncement.created_at.desc(),
        SystemAnnouncement.id.desc()
    ).offset((max(page, 1) - 1) * max(limit, 1)).limit(max(limit, 1)).all()

    return {
        "code": 200,
        "count": total,
        "data": [_format_announcement_item(item) for item in announcements]
    }


@app.post("/system/announcement/create", summary="【管理端】创建系统公告")
def create_system_announcement(
        payload: AnnouncementCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    title = payload.title.strip()
    content = payload.content.strip()
    if not title:
        raise HTTPException(status_code=400, detail="公告标题不能为空")
    if not content:
        raise HTTPException(status_code=400, detail="公告正文不能为空")

    announcement = SystemAnnouncement(
        title=title,
        content=content,
        type=_normalize_announcement_type(payload.type),
        is_pinned=payload.is_pinned,
        status=_normalize_announcement_status(payload.status),
        creator=current_user.username,
        creator_id=current_user.id
    )
    db.add(announcement)
    db.commit()
    db.refresh(announcement)

    return {
        "code": 200,
        "message": "公告创建成功",
        "data": {
            "id": announcement.id
        }
    }


@app.post("/system/announcement/update", summary="【管理端】更新系统公告")
def update_system_announcement(
        payload: AnnouncementUpdateInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    announcement = db.query(SystemAnnouncement).filter(SystemAnnouncement.id == payload.id).first()
    if not announcement:
        raise HTTPException(status_code=404, detail="公告不存在")

    title = payload.title.strip()
    content = payload.content.strip()
    if not title:
        raise HTTPException(status_code=400, detail="公告标题不能为空")
    if not content:
        raise HTTPException(status_code=400, detail="公告正文不能为空")

    announcement.title = title
    announcement.content = content
    announcement.type = _normalize_announcement_type(payload.type)
    announcement.is_pinned = payload.is_pinned
    announcement.status = _normalize_announcement_status(payload.status)
    db.commit()

    return {
        "code": 200,
        "message": "公告更新成功"
    }


@app.delete("/system/announcement/{announcement_id}", summary="【管理端】删除系统公告")
def delete_system_announcement(
        announcement_id: int,
        current_user: User = Depends(RBACChecker("admin:delete")),
        db: Session = Depends(get_db)
):
    announcement = db.query(SystemAnnouncement).filter(SystemAnnouncement.id == announcement_id).first()
    if not announcement:
        raise HTTPException(status_code=404, detail="公告不存在")

    db.delete(announcement)
    db.commit()
    return {
        "code": 200,
        "message": "公告删除成功"
    }


@app.post("/system/risk/expression/validate", summary="【管理端】校验风控表达式")
def validate_risk_expression(
        payload: dict,
        current_user: User = Depends(RBACChecker("admin:read"))
):
    expression = str(payload.get("match_key") or "").strip()
    ok, err = validate_match_expression(expression)
    if not ok:
        return {
            "code": 400,
            "message": f"表达式不合法: {err}"
        }
    return {
        "code": 200,
        "message": "表达式校验通过"
    }


@app.get("/system/risk/stats", summary="【管理端】风险概览统计")
def get_risk_stats(
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    today_start = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    blocks_today = db.query(RiskEvent).filter(
        RiskEvent.created_at >= today_start,
        RiskEvent.action == "BLOCK"
    ).count()
    rules_active = db.query(RiskRule).filter(RiskRule.status.is_(True)).count()
    avg_latency = db.query(func.avg(RiskEvent.latency_ms)).filter(RiskEvent.created_at >= today_start).scalar() or 0
    return {
        "code": 200,
        "data": {
            "blocks_today": blocks_today,
            "rules_active": rules_active,
            "avg_latency_ms": round(float(avg_latency), 2)
        }
    }


@app.get("/system/risk/rules", summary="【管理端】拉取风控规则列表")
def list_risk_rules(
        page: int = 1,
        limit: int = 10,
        rule_name: str | None = None,
        action_type: str | None = None,
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    query = db.query(RiskRule)
    if rule_name:
        query = query.filter(RiskRule.name.contains(rule_name.strip()))
    if action_type:
        query = query.filter(RiskRule.action == action_type.strip())

    total = query.count()
    rules = query.order_by(RiskRule.id.desc()).offset((max(page, 1) - 1) * max(limit, 1)).limit(max(limit, 1)).all()
    data = [
        {
            "id": rule.id,
            "name": rule.name,
            "rule_type": rule.rule_type,
            "target_key": rule.target_key,
            "match_key": rule.match_key,
            "threshold_count": rule.threshold_count,
            "threshold_window": rule.threshold_window,
            "action": rule.action,
            "status": rule.status,
            "updated_at": rule.updated_at.strftime("%Y-%m-%d %H:%M:%S") if rule.updated_at else None
        }
        for rule in rules
    ]
    return {
        "code": 200,
        "count": total,
        "data": data
    }


@app.post("/system/risk/rules", summary="【管理端】新增风控规则")
def create_risk_rule(
        payload: RiskRuleCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    expression = payload.match_key.strip()
    ok, err = validate_match_expression(expression)
    if not ok:
        raise HTTPException(status_code=400, detail=f"表达式不合法: {err}")

    new_rule = RiskRule(
        name=payload.name.strip(),
        rule_type=payload.rule_type.strip(),
        target_key=(payload.target_key.strip() if payload.target_key else None),
        match_key=expression,
        threshold_count=payload.threshold_count,
        threshold_window=payload.threshold_window,
        action=payload.action.strip(),
        status=payload.status,
        creator_id=current_user.id
    )
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)
    return {
        "code": 200,
        "message": "规则创建成功",
        "data": {
            "id": new_rule.id
        }
    }


@app.put("/system/risk/rules/{rule_id}", summary="【管理端】更新风控规则")
def update_risk_rule(
        rule_id: int,
        payload: RiskRuleUpdateInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    rule = db.query(RiskRule).filter(RiskRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")

    update_data = payload.model_dump(exclude_unset=True)
    if "name" in update_data:
        rule.name = update_data["name"].strip()
    if "rule_type" in update_data:
        rule.rule_type = update_data["rule_type"].strip()
    if "target_key" in update_data:
        rule.target_key = update_data["target_key"].strip() if update_data["target_key"] else None
    if "match_key" in update_data:
        expr_value = update_data["match_key"].strip()
        ok, err = validate_match_expression(expr_value)
        if not ok:
            raise HTTPException(status_code=400, detail=f"表达式不合法: {err}")
        rule.match_key = expr_value
    if "threshold_count" in update_data:
        rule.threshold_count = update_data["threshold_count"]
    if "threshold_window" in update_data:
        rule.threshold_window = update_data["threshold_window"]
    if "action" in update_data:
        rule.action = update_data["action"].strip()
    if "status" in update_data:
        rule.status = update_data["status"]

    db.commit()
    return {
        "code": 200,
        "message": "规则已更新"
    }


@app.delete("/system/risk/rules/{rule_id}", summary="【管理端】删除风控规则")
def delete_risk_rule(
        rule_id: int,
        current_user: User = Depends(RBACChecker("admin:delete")),
        db: Session = Depends(get_db)
):
    rule = db.query(RiskRule).filter(RiskRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")
    db.delete(rule)
    db.commit()
    return {
        "code": 200,
        "message": "规则已删除"
    }


@app.patch("/system/risk/rules/{rule_id}/status", summary="【管理端】切换风控规则状态")
def toggle_risk_rule_status(
        rule_id: int,
        payload: RiskRuleStatusInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    rule = db.query(RiskRule).filter(RiskRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")
    rule.status = payload.status
    db.commit()
    return {
        "code": 200,
        "message": "规则状态已更新",
        "data": {
            "status": rule.status
        }
    }


@app.get("/system/risk/global_melt", summary="【管理端】获取全局熔断状态")
def get_global_melt_state(
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    setting = db.query(RiskGlobalSetting).first()
    is_active = setting.is_melt if setting else False
    return {
        "code": 200,
        "data": {
            "is_active": is_active
        }
    }


@app.put("/system/risk/global_melt", summary="【管理端】更新全局熔断状态")
def update_global_melt_state(
        payload: RiskGlobalMeltInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    setting = db.query(RiskGlobalSetting).first()
    if not setting:
        setting = RiskGlobalSetting(is_melt=payload.is_active)
        db.add(setting)
    else:
        setting.is_melt = payload.is_active
    db.commit()
    return {
        "code": 200,
        "message": "全局熔断状态已更新",
        "data": {
            "is_active": setting.is_melt
        }
    }


@app.post("/system/risk/events", summary="【管理端】写入风控事件")
def create_risk_event(
        payload: RiskEventCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    if payload.rule_id:
        rule = db.query(RiskRule).filter(RiskRule.id == payload.rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="规则不存在")

    event = RiskEvent(
        rule_id=payload.rule_id,
        action=payload.action.strip(),
        latency_ms=payload.latency_ms,
        ip=payload.ip,
        path=payload.path,
        risk_level=(payload.risk_level or "medium").strip()
    )
    db.add(event)
    db.commit()
    return {
        "code": 200,
        "message": "事件已记录"
    }


@app.get("/system/risk", response_class=HTMLResponse, summary="【视图】进入风险事件与安全中心")
def risk_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 风险事件视图（函数名已修正：risk_page_view）
    🔒 补齐漏洞：加入看门狗防线，防止匿名爬虫直接撞击 /system/risk 白嫖视图
    """
    user_logged_in = None

    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="admin/risk.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/admin/users", response_class=HTMLResponse, include_in_schema=False)
def users_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 用户列表视图（函数名已修正：users_page_view）
    🔒 补齐漏洞：加入看门狗防线，防止匿名爬虫直接撞击 /users 白嫖视图
    """
    user_logged_in = None

    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="admin/users.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/admin/groups", response_class=HTMLResponse, summary="【视图】进入顶级组织空间管理大厅")
def admin_groups_page(
        request: Request,
        # 🎯 雷达锁定：直接捕捉全网唯一的 SSO 核心会话 Cookie
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 视图级安全熔断（单轨 Session 升级版）
    💡 状态码防翻车铁律：保持标准的 HTTP_302_FOUND。
    如果未登录或 Session 已经在 Redis 中过期，直接抹除状态并平滑扭送回 /login 登录墙。
    """
    user_logged_in = None

    # 1. ⚡ 安全初审：必须是符合规范的 sess_ 钥匙
    if sso_session_id and sso_session_id.startswith("sess_"):
        # 2. 🗄️ 撞击 Redis 分布式中控
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 判定内鬼：如果 Redis 里没这个人，或者 Cookie 根本就是空的
    if not user_logged_in:
        # 清除可能损坏的旧 Cookie，并安全回弹到登录墙
        response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        return response

    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🔍 3. 顺手捞出完整的数据库用户对象（如果你的 groups.html 模板里需要渲染当前登录的用户名或头像）
    # user_obj = db.query(User).filter(User.username == user_logged_in).first()

    # 🎉 4. 完美通行：将上下文倾泻给 Jinja2 模板
    return templates.TemplateResponse(
        request=request,
        name="admin/groups.html",
        context={
            "request": request,
            "username": user_logged_in  # 传递给前端页面，用来展示类似“欢迎您，admin”的字样
        }
    )


@app.get("/admin/apps", response_class=HTMLResponse, summary="【视图】进入独立应用管理大厅")
def admin_apps_page(
        request: Request,
        # 🎯 核心变轨：雷达全面锁定单轨核心 Cookie
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 独立应用大厅视图看门狗（单轨 Session 版）
    """
    user_logged_in = None

    # 1. ⚡ 钥匙格式基础初审
    if sso_session_id and sso_session_id.startswith("sess_"):
        # 2. 🗄️ 撞击 Redis 验证会话生命周期
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 安全熔断：如果 Redis 里没这个人，说明会话已过期或已被注销
    if not user_logged_in:
        print("⚠️ [应用大厅看门狗] 拒绝匿名访问，正在强制 302 扭送登录墙！")
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 验证通过，将登录态上下文平滑递给 Jinja2 渲染
    return templates.TemplateResponse(
        request=request,
        name="admin/apps.html",
        context={
            "request": request,
            "username": user_logged_in  # 塞给前端页面，方便大壳子右上角展示当前登录的管理员
        }
    )


@app.get("/admin/credentials", response_class=HTMLResponse, summary="【视图】进入凭证与激活码审计大厅")
def admin_credentials_page(
        request: Request,
        # 🎯 核心变轨：雷达全面锁定单轨核心 Cookie
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🛡️ 凭证与激活码审计大厅视图看门狗（单轨 Session 版）
    """
    user_logged_in = None

    # 1. ⚡ 钥匙格式基础初审
    if sso_session_id and sso_session_id.startswith("sess_"):
        # 2. 🗄️ 撞击 Redis 验证会话生命周期
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 安全熔断：如果 Redis 里扑空
    if not user_logged_in:
        print("⚠️ [凭证大厅看门狗] 拒绝匿名访问，正在强制 302 扭送登录墙！")
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 验证通过，平滑放行
    return templates.TemplateResponse(
        request=request,
        name="admin/credentials.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/login", response_class=HTMLResponse, summary="【视图】进入中台统一认证登录终端")
def login_page(
        request: Request,
        # 🎯 核心变轨：雷达全面锁定单轨核心 Cookie
        sso_session_id: str = Cookie(None),
):
    """
    负责统一登录面板的渲染（支持登录态智能反弹）
    """
    user_logged_in = None

    # 1. ⚡ 钥匙格式基础初审
    if sso_session_id and sso_session_id.startswith("sess_"):
        # 2. 🗄️ 撞击 Redis 验证会话生命周期
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🎉 【核心升级】如果解析成功，说明用户明明在线，直接拦截并无感反弹到主页！
    if user_logged_in:
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🚧 只有完全合法的匿名新用户，才放行并无条件渲染统一登录面板
    return templates.TemplateResponse(
        request=request,
        name="admin/login.html",
        context={"request": request}
    )


@app.get("/register", response_class=HTMLResponse, summary="【视图】进入中台统一认证注册终端")
def register_page(
        request: Request,
        # 🎯 核心变轨：雷达全面锁定单轨核心 Cookie
        sso_session_id: str = Cookie(None)
):
    """
    负责统一注册面板的渲染（支持登录态智能反弹，且彻底根治函数重名幽灵 Bug）
    """
    user_logged_in = None

    # 1. ⚡ 钥匙格式基础初审
    if sso_session_id and sso_session_id.startswith("sess_"):
        # 2. 🗄️ 撞击 Redis 验证会话生命周期
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🎉 【核心升级】已经登录的用户不需要再注册新账号，直接反弹到主页！
    if user_logged_in:
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🚧 只有合法的匿名用户，才放行并渲染统一注册面板
    return templates.TemplateResponse(
        request=request,
        name="admin/register.html",
        context={"request": request}
    )


@app.get("/user", response_class=HTMLResponse, include_in_schema=False)
def user_root_view(
        request: Request,
        sso_session_id: str = Cookie(None)
):
    """
    普通用户端默认入口，重定向到个人中心
    """
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    return RedirectResponse(url="/user/profile", status_code=status.HTTP_302_FOUND)


@app.get("/user/{page_name}", response_class=HTMLResponse, include_in_schema=False)
def user_page_view(
        request: Request,
        page_name: str,
        sso_session_id: str = Cookie(None)
):
    """
    普通用户端页面渲染入口，统一会话拦截
    """
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    safe_name = page_name.strip().lstrip("/")
    if not safe_name.endswith(".html"):
        safe_name = f"{safe_name}.html"

    return templates.TemplateResponse(
        request=request,
        name=f"user/{safe_name}",
        context={"request": request, "username": user_logged_in}
    )


@app.get("/tenant", response_class=HTMLResponse, include_in_schema=False)
def tenant_root_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    user_obj = _load_user_from_session(user_logged_in, db)
    if not _is_tenant_admin(user_obj):
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    group, error_message = _tenant_access_snapshot(user_obj)
    if error_message:
        return RedirectResponse(url="/tenant/error", status_code=status.HTTP_302_FOUND)

    return RedirectResponse(url="/tenant/profile", status_code=status.HTTP_302_FOUND)


@app.get("/tenant/{page_name}", response_class=HTMLResponse, include_in_schema=False)
def tenant_page_view(
        request: Request,
        page_name: str,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    user_obj = _load_user_from_session(user_logged_in, db)
    if not _is_tenant_admin(user_obj):
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    group, error_message = _tenant_access_snapshot(user_obj)
    safe_name = page_name.strip().lstrip("/")
    if not safe_name.endswith(".html"):
        safe_name = f"{safe_name}.html"

    if safe_name in ["apply.html", "error.html"]:
        return templates.TemplateResponse(
            request=request,
            name=f"tenant/{safe_name}",
            context={
                "request": request,
                "username": user_logged_in,
                "group": group,
                "error_message": error_message or ""
            }
        )

    if error_message:
        return templates.TemplateResponse(
            request=request,
            name="tenant/error.html",
            context={
                "request": request,
                "username": user_logged_in,
                "group": group,
                "error_message": error_message
            }
        )

    return templates.TemplateResponse(
        request=request,
        name=f"tenant/{safe_name}",
        context={
            "request": request,
            "username": user_logged_in,
            "group": group,
            "error_message": error_message or ""
        }
    )


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def root_intelligent_redirect(
        request: Request,
        # 🎯 核心变轨：雷达全面锁定单轨核心 Cookie
        sso_session_id: str = Cookie(None)
):
    """
    🌍 根路由智能分流防御线（单轨 Session 版）
    """
    user_logged_in = None

    # 1. ⚡ 钥匙格式基础初审
    if sso_session_id and sso_session_id.startswith("sess_"):
        # 2. 🗄️ 撞击 Redis 验证会话生命周期
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 安全拦截：如果未登录或 Session 已失效，用 302 稳稳送回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # 🎉 验证通过：说明老哥已经登录过了，直接平滑降落到中台主页 /index
    return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)


@app.get("/index", response_class=HTMLResponse, include_in_schema=False)
def index_page_view(
        request: Request,
        sso_session_id: str = Cookie(None),
        db: Session = Depends(get_db)
):
    """
    🌍 核心主页双轨制分流机制
    有 admin:* 权限的进入 admin_web/index.html，普通用户进入 web/index.html
    """
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 未登录踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # 🎯 动态鉴权分流
    is_admin = check_user_admin_privilege(user_logged_in, db)

    if is_admin:
        # 👑 管理员：渲染 admin_web 文件夹下的主页
        target_template = "admin/index.html"
    else:
        user_obj = _load_user_from_session(user_logged_in, db)
        if _is_tenant_admin(user_obj):
            target_template = "tenant/index.html"
        else:
            # 👤 普通用户：无感路由到普通 web 文件夹下的主页
            target_template = "user/index.html"

    return templates.TemplateResponse(
        request=request,
        name=target_template,
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page_view(
        request: Request,
        sso_session_id: str = Cookie(None), # 🎯 锁定核心单轨 Cookie
        db: Session = Depends(get_db)
):
    """
    🛡️ 主页大屏路由（函数名已修正：dashboard_page_view）
    🔒 补齐漏洞：加入高强度看门狗防线，防止绕过登录墙直接偷窥运营核心大盘数据
    """
    user_logged_in = None

    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没会话的一律弹回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    has_admin_auth = check_user_admin_privilege(user_logged_in, db)
    if not has_admin_auth:
        print(f"⚠️ [风控警告] 普通用户 {user_logged_in} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    # 🎉 完美通行：渲染动态仪表盘
    return templates.TemplateResponse(
        request=request,
        name="admin/dashboard.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


# =========================================================================

# 初始化数据库结构
init_db()


# 🚀 自动化建立公网首个超级管理员/测试用户数据灌注（全量 RBAC 权限版）
def seed_initial_user():
    from database import SessionLocal, User, Role, Permission, RiskRule
    from passlib.context import CryptContext

    db = SessionLocal()
    try:
        # 🎯 扩充权限网格：全面补齐看门狗（RBACChecker）所需的四大核心管理 Scope
        scopes_to_seed = {
            "read": "全局可读权限",
            "write": "全局可写权限",
            "tenant:user:create": "租户管理端-邀请创建使用者账号",
            "tenant:app:read": "租户管理端-查看本租户应用列表",
            "tenant:app:create": "租户管理端-创建本租户应用",
            "tenant:credential:read": "租户管理端-查看本租户应用凭证",
            "tenant:credential:create": "租户管理端-签发本租户应用凭证",
            "tenant:space:review": "超级管理员-审批租户空间与设置到期时间",
            "webhook:create": "Webhook-创建订阅端点",
            "webhook:update": "Webhook-更新订阅端点",
            "webhook:list": "Webhook-查看订阅端点",
            "webhook:delete": "Webhook-删除订阅端点",
            "webhook:logs": "Webhook-查看投递日志",
            "admin:read": "中台管理端-查看组织、应用、用户、权限能力",
            "admin:create": "中台管理端-创建组织、应用、凭证、角色能力",
            "admin:update": "中台管理端-编辑用户、角色、权限与资产",
            "admin:delete": "中台管理端-物理粉碎抹除组织与凭证高危权限"
        }

        seeded_permissions = {}
        for scope_name, desc in scopes_to_seed.items():
            perm = db.query(Permission).filter(Permission.name == scope_name).first()
            if not perm:
                perm = Permission(name=scope_name, description=desc)
                db.add(perm)
                db.commit()
                db.refresh(perm)
            seeded_permissions[scope_name] = perm

        # 👑 升级最高权力控制组：无缝打包灌入所有全新权限
        admin_role = db.query(Role).filter(Role.name == "super_admin").first()
        if not admin_role:
            admin_role = Role(name="super_admin", description="系统最高权力控制组")
            admin_role.permissions = list(seeded_permissions.values())
            db.add(admin_role)
            db.commit()
            db.refresh(admin_role)
        else:
            # ⚙️ 增量兜底：如果 super_admin 角色已经存在，硬核同步刷入新补齐的权限，防止脏数据卡关
            existing_perm_names = {p.name for p in admin_role.permissions}
            for scope_name, perm_obj in seeded_permissions.items():
                if scope_name not in existing_perm_names:
                    admin_role.permissions.append(perm_obj)
            db.commit()

        if "tenant:space:review" not in {p.name for p in admin_role.permissions}:
            admin_role.permissions.append(seeded_permissions["tenant:space:review"])
            db.commit()

        # 👤 普通注册合规用户组（维持原样：仅限 read 和 write，禁止染指管理端）
        user_role = db.query(Role).filter(Role.name == "standard_user").first()
        if not user_role:
            user_role = Role(name="standard_user", description="普通注册合规用户组")
            user_role.permissions = [seeded_permissions["read"], seeded_permissions["write"]]
            db.add(user_role)
            db.commit()

        # 🧑‍💼 租户管理员角色：允许在自己的租户空间内创建使用者
        tenant_admin_role = db.query(Role).filter(Role.name == "tenant_admin").first()
        if not tenant_admin_role:
            tenant_admin_role = Role(name="tenant_admin", description="租户空间管理员")
            tenant_admin_role.permissions = [
                seeded_permissions["read"],
                seeded_permissions["write"],
                seeded_permissions["tenant:user:create"],
                seeded_permissions["tenant:app:read"],
                seeded_permissions["tenant:app:create"],
                seeded_permissions["tenant:credential:read"],
                seeded_permissions["tenant:credential:create"],
                seeded_permissions["webhook:create"],
                seeded_permissions["webhook:update"],
                seeded_permissions["webhook:list"],
                seeded_permissions["webhook:delete"],
                seeded_permissions["webhook:logs"]
            ]
            db.add(tenant_admin_role)
            db.commit()
        else:
            existing_perm_names = {p.name for p in tenant_admin_role.permissions}
            for perm_name in ["read", "write", "tenant:user:create", "tenant:app:read", "tenant:app:create", "tenant:credential:read", "tenant:credential:create", "webhook:create", "webhook:update", "webhook:list", "webhook:delete", "webhook:logs"]:
                if perm_name not in existing_perm_names:
                    tenant_admin_role.permissions.append(seeded_permissions[perm_name])
            db.commit()

        # 🛡️ 建立终极安全授信管理员主体
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            print("🌱 检测到干净的数据库环境，正在为您初始化创建多维 RBAC 超级演示账号...")
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            init_username = "admin"
            init_password = "admin@123"
            hashed_pwd = pwd_context.hash(init_password)

            admin_user = User(
                username=init_username,
                password_hash=hashed_pwd,
                nickname="系统超级管理员",
                is_active=True
            )
            admin_user.roles.append(admin_role)

            db.add(admin_user)
            db.commit()
            print(f"====================================================")
            print(f"🎉 包含「全量中台管理Scope」的账号初始化成功！")
            print(f"   👤 账号 (Username): {init_username}")
            print(f"   🔑 密码 (Password): {init_password}")
            print(f"   🛡️ 绑定角色组: {admin_role.name}")
            print(f"   🔓 注入总权限数: {len(admin_role.permissions)} 个")
            print(f"====================================================")
        else:
            # ⚙️ 增量兜底：如果 admin 账号已存在，但之前没绑定 super_admin 角色，在此强制追加
            if admin_role not in admin_user.roles:
                admin_user.roles.append(admin_role)
                db.commit()
                print("🔄 [OnAuth RBAC] 成功为已有 admin 账户追补最高权力控制组记录！")

        # 🛡️ 默认风控种子：登录失败触发验证码策略（用于风险中心默认展示）
        login_fail_rule = db.query(RiskRule).filter(
            RiskRule.rule_type == "LOGIN_FAIL_CAPTCHA",
            RiskRule.action == "CAPTCHA"
        ).order_by(RiskRule.id.desc()).first()

        if not login_fail_rule:
            db.add(RiskRule(
                name="登录失败验证码策略(默认)",
                rule_type="LOGIN_FAIL_CAPTCHA",
                target_key="username+ip",
                match_key="fail_count >= 3",
                threshold_count=3,
                threshold_window=600,
                action="CAPTCHA",
                status=True,
                creator_id=admin_user.id if admin_user else None
            ))
            db.commit()

    except Exception as e:
        print(f"❌ 初始化用户及权限组失败: {e}")
    finally:
        db.close()


seed_initial_user()

if __name__ == "__main__":
    CERT_FILE = "./local_server.crt"
    KEY_FILE = "./local_server.key"

    ensure_ssl_certificates(CERT_FILE, KEY_FILE)

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        ssl_certfile=CERT_FILE,
        ssl_keyfile=KEY_FILE
    )
