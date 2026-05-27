from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, status

from database import User
from middlewares.rbac import RBACChecker
from routers.invite_helpers import _issue_tenant_admin_invite_payload
from utils.role_constants import ROLE_SUPER_ADMIN

router = APIRouter(tags=["OnAuth 邀请码管理"])


@router.post("/auth/admin/tenant_admin/invite_code", summary="【超管】生成租户管理员邀请码")
def issue_tenant_admin_invite_code(
    current_user: User = Depends(RBACChecker("admin:create")),
):
    if ROLE_SUPER_ADMIN not in {role.name for role in (current_user.roles or [])}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅超级管理员可生成租户管理员邀请码")

    invite_code, payload = _issue_tenant_admin_invite_payload(current_user.username)
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

