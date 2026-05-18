import datetime
import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Header, Form, Response, Cookie
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from passlib.context import CryptContext

# 🌟 引入数据库实体与核心依赖项
from database import get_db, User, Role
from utils.crypto import create_jwt_token
# 🌟 引入 Redis 客户端（保持原功能连通）
from middlewares.auth import redis_client
from config import SECRET_KEY, ALGORITHM

# 🎯 路由配置对齐：将前缀设为全局共用，内部支持平铺管理端与业务端
router = APIRouter(tags=["中台统一账户与动态会话鉴权中心"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Pydantic 输入模型验证 ---
class UserRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="用户名")
    password: str = Field(..., min_length=6, description="密码，至少6位")
    nickname: str = Field(None, description="昵称")


class UserLoginSchema(BaseModel):
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")


# --- 1. 用户注册接口 ---
@router.post("/auth/register", summary="用户注册")
def register_user(payload: UserRegisterSchema, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该用户名已被注册，请更换"
        )

    hashed_password = pwd_context.hash(payload.password)

    new_user = User(
        username=payload.username,
        password_hash=hashed_password,
        nickname=payload.nickname or payload.username,
        is_active=True
    )

    # 自动归入默认普通用户角色组
    default_role = db.query(Role).filter(Role.name == "standard_user").first()
    if default_role:
        new_user.roles.append(default_role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "status": "success",
        "message": "用户注册成功，并已自动划归至 [standard_user] 权限组",
        "user_id": new_user.id,
        "username": new_user.username,
        "assigned_role": default_role.name if default_role else "None"
    }


# --- 2. 管理中台核心：用户/管理员登录接口 (自动注入 HttpOnly Cookie) ---
@router.post("/admin/token", summary="【核心】管理员/用户登录并灌注会话Cookie")
@router.post("/auth/login", summary="【兼容】用户登录双轨制接口")
def login_user(payload: UserLoginSchema, response: Response, db: Session = Depends(get_db)):
    """
    🔒 核心变轨改造：
    当管理员或普通用户在前端 login.html 敲击登录时，本接口在核验无误后，
    会直接通过 HTTP 响应头强行向浏览器植入 HttpOnly 级别的 Cookie 会话令牌。
    """
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not pwd_context.verify(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="该账户已被冻结，请联系管理员"
        )

    # 设置会话有效期为 1 天
    expire_time = datetime.datetime.now() + datetime.timedelta(days=1)

    # 提取多维 RBAC 权限集合
    user_scopes = []
    for role in user.roles:
        if hasattr(role, 'permissions'):
            for perm in role.permissions:
                user_scopes.append(perm.name)

    final_scope_str = ",".join(set(user_scopes)) if user_scopes else "read"

    # 签发长效统一管理会话 JWT 令牌
    access_token = create_jwt_token(
        client_id=user.username,
        scope=final_scope_str,
        expire_at=expire_time,
        token_type="user_auth"
    )

    # 🚀 降维打击的核心：直接将 JWT 写入响应体的 Cookie 策略中，接轨统一安全防线
    response.set_cookie(
        key="auth_token",       # 必须与 main.py 视图层及 admin.py 数据层读取的 Cookie 键名完全一致
        value=access_token,     # 注入生成的加密明文令牌
        httponly=True,          # 🔒 杜绝前端任何恶意的 XSS 脚本通过 document.cookie 偷走令牌
        secure=True,            # 🔒 强制此 Cookie 仅在 HTTPS（本地配置的 SSL 证书）信道下传输
        samesite="lax",         # 🔒 防止跨站请求伪造（CSRF）钓鱼攻击
        max_age=86400           # 缓存存活时间：86400 秒 = 1天
    )

    # 同时返回传统 JSON，完美向下兼容 API 测试沙箱或客户端交互
    return {
        "status": "success",
        "message": "登录认证成功，安全信道已建立",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "nickname": user.nickname,
            "roles": [r.name for r in user.roles],
            "scopes": final_scope_str.split(",")
        }
    }


# ==================== 🛠️ 改造核心接口 1：用户退出登录 (Logout & 清除 Cookie) ====================
@router.post("/auth/logout", summary="用户退出登录")
@router.get("/admin/logout", summary="【管理端】快捷退出登录视图管线")
def logout_user(
        response: Response,
        authorization: str = Header(None, description="承载标准 Bearer Token 的请求头"),
        auth_token: str = Cookie(None, description="从 Cookie 缓存池中捕获的会话令牌"),
        sso_session_id: str = Form(None, description="可选：销毁单点登录会话状态")
):
    """
    业务逻辑：
    1. 动态双规合并：不论是从 Header 还是从浏览器 Cookie 传过来的 Token，通通就地拦截捕获。
    2. 将当前正在使用的令牌加入 Redis 黑名单熔断。
    3. 🚀 核心补置：下发擦除指令，强制让浏览器抹除本地的 auth_token Cookie。
    """
    token_to_revoke = None

    # 优先解析 Header 承载的 Token
    if authorization and authorization.startswith("Bearer "):
        token_to_revoke = authorization.split(" ")[1]
    # 缺省则捕获托管在 Cookie 里的身份 Token
    elif auth_token:
        token_to_revoke = auth_token

    if token_to_revoke:
        # 将令牌丢入 Redis 黑名单，阻断其余 API 链路（拉黑 24 小时）
        redis_client.setex(f"revoked_token:{token_to_revoke}", 86400, "1")

    # 如果传了网页端的 SSO 会话，一并从服务端粉碎
    if sso_session_id:
        redis_client.delete(sso_session_id)

    # 🚀 斩草除根：向响应头中下发 max_age=0，强制触发浏览器底层的 Cookie 物理粉碎机制
    response.delete_cookie(
        key="auth_token",
        secure=True,
        httponly=True,
        samesite="lax"
    )

    return {
        "status": "success",
        "message": "中台身份会话注销成功，浏览器托管的 Cookie 凭证已被全盘擦除熔断"
    }


# ==================== 🛠️ 改造核心接口 2：注销账户 (Delete Account) ====================
@router.delete("/auth/unregister", summary="合规性用户账户销户/注销")
def delete_account(
        response: Response,
        confirm_password: str = Form(..., description="高危操作：必须重新验证用户当前密码"),
        authorization: str = Header(None, description="当前登录用户的 Bearer 身份令牌"),
        auth_token: str = Cookie(None, description="浏览器托管的会话 Token"),
        db: Session = Depends(get_db)
):
    """
    业务逻辑：
    1. 兼顾 Cookie 会话与直连 Token 双轨验证，对销户行为进行密码二次高危审计。
    2. 物理抹除数据库用户实体，并同步粉碎浏览器 Cookie。
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    elif auth_token:
        token = auth_token

    if not token:
        raise HTTPException(status_code=401, detail="身份认证已失效，请重新登录后再执行高危操作")

    # 检查当前 Token 是否已经被拉黑
    if redis_client.exists(f"revoked_token:{token}"):
        raise HTTPException(status_code=401, detail="凭证已被吊销")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="非法或受损的身份凭证，拒绝高危执行")

    # 锁定数据库用户
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="目标账户不存在")

    # 严苛验证密码
    if not pwd_context.verify(confirm_password, user.password_hash):
        raise HTTPException(status_code=400, detail="安全审计失败：密码校验错误，拒绝销户请求")

    # 物理抹除
    db.delete(user)
    db.commit()

    # 将该用户的当前 Token 放入黑名单
    redis_client.setex(f"revoked_token:{token}", 86400, "1")

    # 🚀 同步下发擦除指令，强行清洗浏览器 Cookie
    response.delete_cookie(key="auth_token", secure=True, httponly=True, samesite="lax")

    return {
        "status": "success",
        "message": f"用户账户 [{username}] 已根据合规审计要求成功物理销户，相关核心数据及本地会话已被全面抹除。"
    }