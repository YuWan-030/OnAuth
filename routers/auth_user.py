import datetime
import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Header, Form, Response, Cookie
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import secrets

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


# --- 2. 管理中台核心：用户/管理员登录接口 (精简版单轨 Session 架构) ---
@router.post("/admin/token", summary="【核心】管理员/用户登录并灌注统一会话Cookie")
@router.post("/auth/login", summary="【兼容】用户登录标准接口")
def login_user(payload: UserLoginSchema, response: Response, db: Session = Depends(get_db)):
    """
    🔒 极简单轨 Session 架构：
    核验用户名密码成功后，向 Redis 灌入随机 Session 令牌。
    通过全局唯一的 sso_session_id Cookie 注入，配合响应体回传，
    让管理后台前端、Flet 客户端与 OAuth 授权大厅共享同一套生命周期。
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

    # 1. ⚡ 生成标准的分布式 Session ID（全局唯一标识）
    new_session_id = "sess_" + secrets.token_hex(12)

    # 2. 🗄️ 将状态托管至 Redis 中控（有效期 1 天 = 86400 秒）
    redis_client.setex(new_session_id, 86400, user.username)

    # 3. 🔑 穿透 RBAC 模型，提取真实的多维权限集合
    user_scopes = []
    for role in user.roles:
        if hasattr(role, 'permissions'):
            for perm in role.permissions:
                if perm.name:
                    user_scopes.append(perm.name)

    final_scopes_list = list(set(user_scopes)) if user_scopes else ["read"]

    # 4. 🚀 【大一统核心】向浏览器强推全网唯一的 sso_session_id Cookie
    # 路径设为 "/"，确保管理后台（/admin）与授权大厅（/oauth）在同一个浏览器下完美共享
    response.set_cookie(
        key="sso_session_id",
        value=new_session_id,
        httponly=True,  # 🔒 严格防范 XSS 脚本劫持
        path="/",  # 🌍 跨路由全域共享的生命线
        secure=False,  # 🎯 本地纯 HTTP 调试环境设为 False，避免现代浏览器内核将其拦截隐形
        samesite="lax"  # 🎯 设为 lax，保障 Flet 客户端拉起跨域重定向时可以安全携带
    )

    # 5. 🏁 【全量闭环】返回精简后的 JSON 响应体
    return {
        "status": "success",
        "message": "中台身份核验通过，单轨分布式 Session 会话已成功建立！",

        # 🛡️ 兼容垫片：依旧保持 access_token 字段的输出，
        # 这样即使管理后台前端的 Axios/Fetch 拦截器以前习惯了读 access_token，也完全不需要重构前端代码！
        "access_token": new_session_id,
        "token_type": "bearer",

        "sso_session_id": new_session_id,  # 明确返回单轨 ID
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
        redis_client.delete(target_session_id)

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