from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from database import get_db, User
from middlewares.auth import redis_client

class RBACChecker:
    """
    分布式全信道 RBAC 动态权限审查器（进化版：支持角色权限与用户独立权限合并）
    """

    def __init__(self, required_permission: str):
        # 🎯 初始化时传入所需的权限标识（如 "admin:read"）
        self.required_permission = required_permission

    def __call__(self, request: Request, db: Session = Depends(get_db)):
        # 1. 钥匙清洗（兼容 Cookie 与 Header）
        effective_session_id = request.cookies.get("sso_session_id")
        if not effective_session_id:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                effective_session_id = auth_header.split(" ")[1]

        if not effective_session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="身份凭证已缺失，请重新登录"
            )

        # 2. Redis 会话状态机校验
        if not effective_session_id.startswith("sess_"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="认证凭证不合法"
            )

        raw_user = redis_client.get(effective_session_id)
        if not raw_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="会话已过期，请重新登录"
            )

        username = raw_user.decode('utf-8') if isinstance(raw_user, bytes) else raw_user

        # 3. 锁定激活用户
        user = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="当前账户已被冻结或不存在"
            )

        # 4. 🚀 关键进化：聚合权限集 (角色权限 + 用户独立权限)
        user_permissions = set()

        # A. 提取角色继承的权限 (Role -> Permission)
        for role in user.roles:
            # 只有激活的角色才计入权限集
            if getattr(role, 'is_active', True) and hasattr(role, 'permissions'):
                for perm in role.permissions:
                    if perm.name:
                        user_permissions.add(perm.name)

        # B. 提取用户独立追加的权限 (User -> ExtraPermission)
        # 💡 这正是解决“权限同步”Bug 的核心逻辑，此权限不影响其它人
        if hasattr(user, 'extra_permissions'):
            for perm in user.extra_permissions:
                if perm.name:
                    user_permissions.add(perm.name)

        # 5. 🎯 硬核权限校验
        if self.required_permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"安全合规熔断：缺少必要权限 [{self.required_permission}]"
            )

        # 校验通过，返回 User 对象供路由使用
        return user