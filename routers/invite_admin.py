from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import User
from middlewares.auth import redis_client
from middlewares.rbac import RBACChecker
from database import get_db
import routers.tenant_admin_invites as tenant_admin_invites
from routers.tenant_admin_invites import _issue_tenant_admin_invite_payload
from utils.role_constants import ROLE_SUPER_ADMIN

router = APIRouter(tags=["OnAuth 邀请码管理"])


@router.post("/auth/admin/tenant_admin/invite_code", summary="【超管】生成租户管理员邀请码")
def issue_tenant_admin_invite_code(
    db: Session = Depends(get_db),
    current_user: User = Depends(RBACChecker("admin:create")),
):
    tenant_admin_invites.redis_client = redis_client
    if ROLE_SUPER_ADMIN not in {role.name for role in (current_user.roles or [])}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅超级管理员可生成租户管理员邀请码")

    invite_code, payload = _issue_tenant_admin_invite_payload(current_user.username, db=db)
    if hasattr(db, "commit"):
        db.commit()
    invite_url = f"/tenant/register?invite_code={quote(invite_code, safe='')}"
    return {
        "status": "success",
        "message": "邀请码已生成",
        "data": {
            "invite_code": invite_code,
            "invite_url": invite_url,
            "issuer_username": payload["issuer_username"],
            "created_at": payload["created_at"],
            "expires_at": payload["expires_at"],
            "expires_in_seconds": 7 * 24 * 3600,
            "status": "active",
        },
    }

