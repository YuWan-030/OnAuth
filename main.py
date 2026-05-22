import os
import sys
import asyncio
import logging
import jwt

import uvicorn
from fastapi import FastAPI, Request, status, Cookie, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from config import SECRET_KEY
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
# 🚀 引入解耦后的各个核心业务/管理模块路由
from routers import oauth, business, admin, auth_user, permission,webhook
from utils.ssl_gen import ensure_ssl_certificates
from database import init_db, get_db, User
from utils.response import unified_response  # 🌟 统一 JSON 响应函数
from middlewares.auth import redis_client  # 🌟 引入 Redis 客户端实例，保持原有功能连通
from jinja2 import Environment, FileSystemLoader

# 🌟 解决 Windows 平台高频弹出的 WinError 10054 异步连接断开警告
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

app = FastAPI(title="企业级标准 OAuth2.0 & License 双轨制融合鉴权平台", docs_url="/docs", redoc_url=None)

# ==================== 🎯 核心修复：注入并锚定 HTML 模板引擎 ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
template_dirs = [
    os.path.join(BASE_DIR, "admin_web"),
    os.path.join(BASE_DIR, "templates")
]
# 2. 手动创建一个 Jinja2 环境，绑定多路径加载器
jinja2_env = Environment(
    loader=FileSystemLoader(template_dirs),
    autoescape=True
)

# 3. 将手动配置好的环境传给 Jinja2Templates
templates = Jinja2Templates(env=jinja2_env)
# =========================================================================


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
            name="error.html",
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


# ==================== 🎨 Layui 管理端 Web 视图路由（全面升级安全拦截） ====================
@app.get("/admin/permissions", response_class=HTMLResponse, summary="【视图】进入权限节点管理页面")
def permissions_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)
):
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="permissions.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/admin/roles", response_class=HTMLResponse, summary="【视图】进入权限组管理页面")
def roles_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)
):
    user_logged_in = None
    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="roles.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/notices", response_class=HTMLResponse, summary="【视图】进入系统公告与消息中心")
def announcements_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)
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

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="notices.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/settings", response_class=HTMLResponse, summary="【视图】进入系统配置中心")
def settings_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)
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

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/callbacks", response_class=HTMLResponse, summary="【视图】进入回调地址管理中心")
def callbacks_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)
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

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="webhook.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/audit", response_class=HTMLResponse, summary="【视图】进入审计日志中心")
def audit_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)
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

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/sessions", response_class=HTMLResponse, summary="【视图】进入在线会话监控中心")
def sessions_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)
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

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="sessions.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/system/risk", response_class=HTMLResponse, summary="【视图】进入风险事件与安全中心")
def risk_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)
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

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="risk.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/admin/users", response_class=HTMLResponse, include_in_schema=False)
def users_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)
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

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="users.html",
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

    # 🔍 3. 顺手捞出完整的数据库用户对象（如果你的 groups.html 模板里需要渲染当前登录的用户名或头像）
    # user_obj = db.query(User).filter(User.username == user_logged_in).first()

    # 🎉 4. 完美通行：将上下文倾泻给 Jinja2 模板
    return templates.TemplateResponse(
        request=request,
        name="groups.html",
        context={
            "request": request,
            "username": user_logged_in  # 传递给前端页面，用来展示类似“欢迎您，admin”的字样
        }
    )


@app.get("/admin/apps", response_class=HTMLResponse, summary="【视图】进入独立应用管理大厅")
def admin_apps_page(
        request: Request,
        # 🎯 核心变轨：雷达全面锁定单轨核心 Cookie
        sso_session_id: str = Cookie(None)
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

    # 🎉 验证通过，将登录态上下文平滑递给 Jinja2 渲染
    return templates.TemplateResponse(
        request=request,
        name="apps.html",
        context={
            "request": request,
            "username": user_logged_in  # 塞给前端页面，方便大壳子右上角展示当前登录的管理员
        }
    )


@app.get("/admin/credentials", response_class=HTMLResponse, summary="【视图】进入凭证与激活码审计大厅")
def admin_credentials_page(
        request: Request,
        # 🎯 核心变轨：雷达全面锁定单轨核心 Cookie
        sso_session_id: str = Cookie(None)
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

    # 🎉 验证通过，平滑放行
    return templates.TemplateResponse(
        request=request,
        name="credentials.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/login", response_class=HTMLResponse, summary="【视图】进入中台统一认证登录终端")
def login_page(
        request: Request,
        # 🎯 核心变轨：雷达全面锁定单轨核心 Cookie
        sso_session_id: str = Cookie(None)
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
        name="login.html",
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
        name="register.html",
        context={"request": request}
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
        sso_session_id: str = Cookie(None)  # 🎯 锁定核心单轨 Cookie
):
    """
    🛡️ 兼容性重定向主页（函数名已修正：index_page_view）
    🔒 补齐漏洞：加入看门狗防线，严防匿名爬虫直接撞击 /index 白嫖视图
    """
    user_logged_in = None

    if sso_session_id and sso_session_id.startswith("sess_"):
        raw_user = redis_client.get(sso_session_id)
        if raw_user:
            user_logged_in = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

    # 🚨 漏洞堵死：没登录一律踢回登录墙
    if not user_logged_in:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    # 🎉 完美通行，携带当前在线用户名投喂给模板
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "username": user_logged_in
        }
    )


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page_view(
        request: Request,
        sso_session_id: str = Cookie(None)  # 🎯 锁定核心单轨 Cookie
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

    # 🎉 完美通行：渲染动态仪表盘
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
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
    from database import SessionLocal, User, Role, Permission
    from passlib.context import CryptContext

    db = SessionLocal()
    try:
        # 🎯 扩充权限网格：全面补齐看门狗（RBACChecker）所需的四大核心管理 Scope
        scopes_to_seed = {
            "read": "基础资源读取权限",
            "write": "业务数据写入与修改权限",

            # 🔒 核心追加：中台四大资产管理金刚锁
            "admin:read": "中台管理端-资产大盘全量读取只读权限",
            "admin:create": "中台管理端-开通工作室/创建独立应用权限",
            "admin:update": "中台管理端-一键启停熔断/更新资产配置权限",
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

        # 👤 普通注册合规用户组（维持原样：仅限 read 和 write，禁止染指管理端）
        user_role = db.query(Role).filter(Role.name == "standard_user").first()
        if not user_role:
            user_role = Role(name="standard_user", description="普通注册合规用户组")
            user_role.permissions = [seeded_permissions["read"], seeded_permissions["write"]]
            db.add(user_role)
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
