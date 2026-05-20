from fastapi import APIRouter, Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from database import User, get_db
import jwt  # 需要安装 PyJWT
import config

router = APIRouter(tags=["用户信息统一管理接口"])

# 使用 FastAPI 自带的 Bearer 规范，它会自动帮你从 Header 中提取 "Bearer <token>"
security = HTTPBearer()

SECRET_KEY = config.SECRET_KEY
ALGORITHM = config.ALGORITHM


@router.get("/api/v1/user/get_info", summary="供其他系统调用的获取用户信息接口")
def get_user_info(
        credentials: HTTPAuthorizationCredentials = Security(security),
        db: Session = Depends(get_db)
):
    token = credentials.credentials

    # 1. 解密和校验 JWT (无需查库，速度极快)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效的Token声明")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="凭证已过期")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="凭证校验失败")

    # 2. 如果子系统需要最新的角色/权限信息，再通过 user_id 查一次库
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户不存在")

    return {
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": [role.name for role in user.roles]
    }