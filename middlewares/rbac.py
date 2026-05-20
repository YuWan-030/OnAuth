from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from database import get_db, User
from middlewares.auth import redis_client

class RBACChecker:
    """
    分布式全信道 RBAC 动态权限审查器
    """

    def __init__(self, *required_permissions: str):
        self.required_permissions = required_permissions

    def __call__(self, request: Request, db: Session = Depends(get_db)):
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

        raw_user_id = redis_client.get(effective_session_id)
        if not raw_user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="会话已过期，请重新登录"
            )

        user_id = int(raw_user_id.decode('utf-8') if isinstance(raw_user_id, bytes) else raw_user_id)

        # 3. 锁定激活用户
        user = db.query(User).filter(User.id ==user_id , User.is_active == True).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="当前账户已被冻结或不存在"
            )

        # 🌟 核心修复：遍历接口要求的 required_permissions，只要有任何一个存在于用户的 all_permissions 中，就放行
        has_permission = any(perm in user.all_permissions for perm in self.required_permissions)

        if not has_permission:
            perms_str = " 或 ".join([f"[{p}]" for p in self.required_permissions])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"安全合规熔断：缺少必要权限，必须具备 {perms_str} 之一"
            )

        # 校验通过，返回 User 对象供路由使用
        return user