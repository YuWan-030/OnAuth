import os
import sys
import asyncio
import logging
import jwt

import uvicorn
from fastapi import FastAPI, Request, status, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from config import SECRET_KEY

# 🚀 引入解耦后的各个核心业务/管理模块路由
from routers import oauth, business, admin, auth_user
from utils.ssl_gen import ensure_ssl_certificates
from database import init_db, get_db, User
from utils.response import unified_response  # 🌟 统一 JSON 响应函数

# 🌟 解决 Windows 平台高频弹出的 WinError 10054 异步连接断开警告
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

app = FastAPI(title="企业级标准 OAuth2.0 & License 双轨制融合鉴权平台", docs_url="/docs", redoc_url=None)

# ==================== 🎯 核心修复：注入并锚定 HTML 模板引擎 ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "web"))
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


# ==================== 🛡️ 全局异常拦截硬核防线 ====================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """1. 拦截前端传参不合规错误"""
    errors = exc.errors()
    error_msg = f"参数校验失败: {errors[0]['loc'][-1]} 字段 - {errors[0]['msg']}" if errors else "请求参数格式破损"
    return unified_response(
        status_code=status.HTTP_400_BAD_REQUEST,
        status="fail",
        code=40001,
        message=error_msg
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """2. 拦截系统各路由模块中显式抛出的 raise HTTPException"""
    if exc.status_code == 404:
        return unified_response(
            status_code=404,
            status="fail",
            code=40400,
            message="您访问的中台核心路由不存在，请核对接口文档！"
        )
    internal_code = exc.status_code * 100
    return unified_response(
        status_code=exc.status_code,
        status="fail",
        code=internal_code,
        message=str(exc.detail)
    )


@app.exception_handler(Exception)
async def global_generic_exception_handler(request: Request, exc: Exception):
    """3. 终极兜底：拦截未知的、毁灭性的崩溃 500 错误"""
    logging.error(f"🚨 中台核心严重崩溃，真实现场: {str(exc)}", exc_info=True)
    return unified_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        status="fail",
        code=50000,
        message="中台系统执行遭遇阻断：Redis 服务可能未启动或数据库连接超时，请管理员速检查后台日志！"
    )


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

@app.get("/admin/groups", response_class=HTMLResponse, summary="【视图】进入顶级组织空间管理大厅")
def admin_groups_page(request: Request, auth_token: str = Cookie(None)):
    """
    🛡️ 视图级安全熔断
    🐛 幽灵修复二：切勿在浏览器页面重定向（GET 视图）时使用 HTTP_303_SEE_OTHER 状态码！
    根据标准，303 专门用于强制将 POST 请求转换为 GET 请求。
    如果用户直接访问 /admin/groups（本就是 GET），部分现代安全浏览器（如 Chrome 内核）
    在收到 303 重定向返回时，会为了安全起见拒绝自动附带当前站点的 HttpOnly Cookie。
    在此统一安全降维变轨为标准的浏览器临时性页面分流状态码：HTTP_302_FOUND。
    """
    if not verify_view_admin_session(auth_token):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="groups.html",
        context={"request": request}
    )


@app.get("/admin/apps", response_class=HTMLResponse, summary="【视图】进入独立应用管理大厅")
def admin_apps_page(request: Request, auth_token: str = Cookie(None)):
    if not verify_view_admin_session(auth_token):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="apps.html",
        context={"request": request}
    )


@app.get("/admin/credentials", response_class=HTMLResponse, summary="【视图】进入凭证与激活码审计大厅")
def admin_credentials_page(request: Request, auth_token: str = Cookie(None)):
    if not verify_view_admin_session(auth_token):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="credentials.html",
        context={"request": request}
    )


@app.get("/login", response_class=HTMLResponse, summary="【视图】进入中台统一认证登录终端")
def login_page(request: Request):
    """
    负责无条件渲染和托管统一登录面板
    """
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"request": request}
    )


# 🐛 幽灵修复三：你原本的 /register 视图函数命名与 /login 重名了（都叫 def login_page），
# Python 解释器在装载内存时，后定义的函数会无情覆盖掉先定义的同名函数，导致路由在特定环境下发生混淆崩溃。
# 现已将其精准重构解耦为 register_page
@app.get("/register", response_class=HTMLResponse, summary="【视图】进入中台统一认证注册终端")
def register_page(request: Request):
    """
    负责无条件渲染和托管统一注册面板
    """
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"request": request}
    )


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index_redirect(request: Request, auth_token: str = Cookie(None)):
    """
    根路由智能分流防御线
    """
    if not verify_view_admin_session(auth_token):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

@app.get("/index", response_class=HTMLResponse, include_in_schema=False)
def index_os_redirect(request: Request, auth_token: str = Cookie(None)):
    """
    兼容性重定向：部分用户习惯访问 /index 作为入口，智能分流防御线
    """
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request}
    )

@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def index_os_redirect(request: Request, auth_token: str = Cookie(None)):
    """
    主页大屏路由：提供中台核心资产与运营数据的全局概览，动态仪表盘
    """
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"request": request}
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