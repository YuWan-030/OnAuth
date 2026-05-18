import datetime
from fastapi import APIRouter, Query, Depends, HTTPException
from database import AppCredential
from middlewares.auth import verify_client_token

router = APIRouter(tags=["业务受保护接口"])


@router.get("/api/v1/inspect_license", summary="【核心受保护业务接口】校验客户端授权状态")
def inspect_license(app_id: int = Query(...), cred: AppCredential = Depends(verify_client_token)):
    if cred.app_id != app_id:
        raise HTTPException(status_code=403,
                            detail=f"密钥越权违规！当前激活码属于其他应用，无法用于当前程序！")

    now = datetime.datetime.now()
    remaining_days = max(0, (cred.expire_at - now).days) if cred.expire_at else 0
    return {
        "status": "active", "client_id": cred.client_id, "credential_name": cred.credential_name,
        "app_name": cred.app.app_name, "app_id": cred.app_id,
        "scopes": [s.strip() for s in cred.scope.split(",") if s.strip()],
        "expire_date": cred.expire_at.strftime("%Y-%m-%d %H:%M:%S") if cred.expire_at else "永久有效",
        "remaining_info": f"授权订阅状态正常，剩余生命周期: {remaining_days} 天。"
    }