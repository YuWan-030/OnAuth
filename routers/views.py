from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from database import get_db
from middlewares.auth import redis_client
from template_env import templates
from utils.view_guard import (
    check_user_admin_privilege,
    _is_tenant_admin,
    _load_user_from_session,
    _tenant_access_snapshot,
)

router = APIRouter(tags=["Web Views"])
FAVICON_PATH = Path(__file__).resolve().parent.parent / "favicon.ico"


@router.get("/favicon.ico", include_in_schema=False)
def favicon_view():
    if FAVICON_PATH.exists():
        return FileResponse(path=FAVICON_PATH, media_type="image/x-icon")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="favicon.ico not found")


def _decode_session_username(sso_session_id: str | None) -> str | None:
    if not sso_session_id or not sso_session_id.startswith("sess_"):
        return None
    raw_user = redis_client.get(sso_session_id)
    if not raw_user:
        return None
    return raw_user.decode("utf-8") if isinstance(raw_user, bytes) else str(raw_user)


def _redirect_login_if_missing(username: str | None):
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return None


def _redirect_index_if_not_admin(username: str, db: Session):
    if not check_user_admin_privilege(username, db):
        print(f"⚠️ [风控警告] 普通用户 {username} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)
    return None


def _render_admin_template(request: Request, template_name: str, username: str):
    return templates.TemplateResponse(
        request=request,
        name=f"admin/{template_name}",
        context={"request": request, "username": username},
    )


@router.get("/admin/permissions", response_class=HTMLResponse, summary="【视图】进入权限节点管理页面")
def permissions_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "permissions.html", username)


@router.get("/admin/roles", response_class=HTMLResponse, summary="【视图】进入权限组管理页面")
def roles_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "roles.html", username)


@router.get("/system/notices", response_class=HTMLResponse, summary="【视图】进入系统公告与消息中心")
def announcements_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "notices.html", username)


@router.get("/system/settings", response_class=HTMLResponse, summary="【视图】进入系统配置中心")
def settings_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "settings.html", username)


@router.get("/system/callbacks", response_class=HTMLResponse, summary="【视图】进入回调地址管理中心")
def callbacks_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "webhook.html", username)


@router.get("/admin/{page_name}", response_class=HTMLResponse, include_in_schema=False)
def admin_page_view(
    request: Request,
    page_name: str,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response

    safe_name = page_name.strip().lstrip("/")
    if not safe_name.endswith(".html"):
        safe_name = f"{safe_name}.html"
    return templates.TemplateResponse(
        request=request,
        name=f"admin/{safe_name}",
        context={"request": request, "username": username},
    )


@router.get("/system/audit", response_class=HTMLResponse, summary="【视图】进入审计日志中心")
def audit_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "audit.html", username)


@router.get("/system/sessions", response_class=HTMLResponse, summary="【视图】进入在线会话监控中心")
def sessions_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "sessions.html", username)


@router.get("/system/risk", response_class=HTMLResponse, summary="【视图】进入风险事件与安全中心")
def risk_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "risk.html", username)


@router.get("/admin/users", response_class=HTMLResponse, include_in_schema=False)
def users_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "users.html", username)


@router.get("/admin/groups", response_class=HTMLResponse, summary="【视图】进入顶级组织空间管理大厅")
def admin_groups_page(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "groups.html", username)


@router.get("/admin/apps", response_class=HTMLResponse, summary="【视图】进入独立应用管理大厅")
def admin_apps_page(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "apps.html", username)


@router.get("/admin/credentials", response_class=HTMLResponse, summary="【视图】进入凭证与激活码审计大厅")
def admin_credentials_page(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "credentials.html", username)


@router.get("/admin/invite_codes", response_class=HTMLResponse, summary="【视图】进入租户管理员邀请码管理页面")
def admin_invite_codes_page(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    response = _redirect_login_if_missing(username)
    if response:
        return response
    response = _redirect_index_if_not_admin(username, db)
    if response:
        return response
    return _render_admin_template(request, "invite_codes.html", username)


@router.get("/login", response_class=HTMLResponse, summary="【视图】进入中台统一认证登录终端")
def login_page(
    request: Request,
    sso_session_id: str = Cookie(None),
):
    username = _decode_session_username(sso_session_id)
    if username:
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="admin/login.html", context={"request": request})


@router.get("/register", response_class=HTMLResponse, summary="【视图】进入中台统一认证注册终端")
def register_page(
    request: Request,
    sso_session_id: str = Cookie(None),
):
    username = _decode_session_username(sso_session_id)
    if username:
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="admin/register_user.html", context={"request": request})


@router.get("/tenant/register", response_class=HTMLResponse, summary="【视图】进入租户管理员注册终端")
def tenant_register_page(
    request: Request,
    sso_session_id: str = Cookie(None),
):
    username = _decode_session_username(sso_session_id)
    if username:
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="tenant/register.html", context={"request": request})


@router.get("/user", response_class=HTMLResponse, include_in_schema=False)
def user_root_view(
    request: Request,
    sso_session_id: str = Cookie(None),
):
    username = _decode_session_username(sso_session_id)
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/user/profile", status_code=status.HTTP_302_FOUND)


@router.get("/user/{page_name}", response_class=HTMLResponse, include_in_schema=False)
def user_page_view(
    request: Request,
    page_name: str,
    sso_session_id: str = Cookie(None),
):
    username = _decode_session_username(sso_session_id)
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    safe_name = page_name.strip().lstrip("/")
    if not safe_name.endswith(".html"):
        safe_name = f"{safe_name}.html"

    return templates.TemplateResponse(
        request=request,
        name=f"user/{safe_name}",
        context={"request": request, "username": username},
    )


@router.get("/tenant", response_class=HTMLResponse, include_in_schema=False)
def tenant_root_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    user_obj = _load_user_from_session(username, db)
    if not _is_tenant_admin(user_obj):
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    group, error_message = _tenant_access_snapshot(user_obj)
    if error_message:
        return RedirectResponse(url="/tenant/error", status_code=status.HTTP_302_FOUND)

    return RedirectResponse(url="/tenant/profile", status_code=status.HTTP_302_FOUND)


@router.get("/tenant/{page_name}", response_class=HTMLResponse, include_in_schema=False)
def tenant_page_view(
    request: Request,
    page_name: str,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    user_obj = _load_user_from_session(username, db)
    if not _is_tenant_admin(user_obj):
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    group, error_message = _tenant_access_snapshot(user_obj)
    safe_name = page_name.strip().lstrip("/")
    if not safe_name.endswith(".html"):
        safe_name = f"{safe_name}.html"

    if safe_name in ["apply.html", "error.html"]:
        return templates.TemplateResponse(
            request=request,
            name=f"tenant/{safe_name}",
            context={
                "request": request,
                "username": username,
                "group": group,
                "error_message": error_message or "",
            },
        )

    if error_message:
        return templates.TemplateResponse(
            request=request,
            name="tenant/error.html",
            context={
                "request": request,
                "username": username,
                "group": group,
                "error_message": error_message,
            },
        )

    return templates.TemplateResponse(
        request=request,
        name=f"tenant/{safe_name}",
        context={
            "request": request,
            "username": username,
            "group": group,
            "error_message": error_message or "",
        },
    )


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def root_intelligent_redirect(
    request: Request,
    sso_session_id: str = Cookie(None),
):
    username = _decode_session_username(sso_session_id)
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)


@router.get("/index", response_class=HTMLResponse, include_in_schema=False)
def index_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    is_admin = check_user_admin_privilege(username, db)
    if is_admin:
        target_template = "admin/index.html"
    else:
        user_obj = _load_user_from_session(username, db)
        if _is_tenant_admin(user_obj):
            target_template = "tenant/index.html"
        else:
            target_template = "user/index.html"

    return templates.TemplateResponse(
        request=request,
        name=target_template,
        context={"request": request, "username": username},
    )


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page_view(
    request: Request,
    sso_session_id: str = Cookie(None),
    db: Session = Depends(get_db),
):
    username = _decode_session_username(sso_session_id)
    if not username:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if not check_user_admin_privilege(username, db):
        print(f"⚠️ [风控警告] 普通用户 {username} 企图强撞管理空间，已安全降级至普通端！")
        return RedirectResponse(url="/index", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="admin/dashboard.html",
        context={"request": request, "username": username},
    )

