import datetime
import json
import os
import secrets
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Form, File, UploadFile, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db, DeveloperGroup, App, AppCredential, AppDevice, User, OperationLog
from middlewares.auth import redis_client
from middlewares.rbac import RBACChecker
from routers.webhook import dispatch_webhook_event
from schemas.admin_schema import CredentialStatusInput
from utils.crypto import generate_random_keys, hash_secret, create_jwt_token
from utils.app_logo import save_app_logo_upload, ensure_uploaded_logo_reference

router = APIRouter(prefix="/tenant", tags=["租户管理员空间管理"])

TENANT_MAX_APPS = max(1, int(os.getenv("TENANT_MAX_APPS", "50")))
TENANT_MAX_CREDENTIALS_PER_APP = max(1, int(os.getenv("TENANT_MAX_CREDENTIALS_PER_APP", "100")))


class TenantSpaceApplyInput(BaseModel):
    group_name: str = Field(..., min_length=1, max_length=64, description="租户空间名称")
    description: str | None = Field(None, description="租户空间说明")


class TenantSpaceToggleInput(BaseModel):
    is_active: bool = Field(..., description="是否启用租户空间")


class TenantAppUpdateInput(BaseModel):
    app_name: str = Field(..., min_length=1, max_length=64)


def _get_tenant_group(db: Session, current_user: User) -> Any:
    if not current_user.group_id:
        raise HTTPException(status_code=403, detail="当前账号未绑定租户空间")

    group = db.query(DeveloperGroup).filter(DeveloperGroup.id == current_user.group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="租户空间不存在")

    if group.status != "approved":
        raise HTTPException(status_code=403, detail="租户空间尚未通过审核")

    if not group.is_active:
        raise HTTPException(status_code=403, detail="租户空间已被冻结")

    if group.expire_at and group.expire_at < datetime.datetime.now():
        raise HTTPException(status_code=403, detail="租户空间已过期")

    return group


def _get_tenant_group_for_control(db: Session, current_user: User) -> Any:
    # 控制类动作必须尊重冻结状态，复用严格校验避免越权恢复
    return _get_tenant_group(db, current_user)


def _get_tenant_app(db: Session, group_id: int, app_id: int) -> Any:
    app = db.query(App).filter(App.id == app_id, App.group_id == group_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="应用不存在或不属于当前租户")
    return app


def _parse_redirect_uri_whitelist_input(raw_value: str | None) -> list[str]:
    if raw_value is None:
        return []

    normalized = raw_value.replace("\r\n", "\n").replace("\r", "\n").replace(",", "\n")
    values = [item.strip() for item in normalized.split("\n") if item.strip()]
    deduped: list[str] = []
    seen: set[str] = set()

    for uri in values:
        parsed = urlparse(uri)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise HTTPException(status_code=400, detail=f"redirect_uri 不合法: {uri}")
        if parsed.fragment:
            raise HTTPException(status_code=400, detail=f"redirect_uri 不允许包含 fragment: {uri}")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise HTTPException(status_code=400, detail=f"http redirect_uri 仅允许本地地址: {uri}")
        if uri not in seen:
            seen.add(uri)
            deduped.append(uri)

    return deduped


def _load_redirect_uri_whitelist(client_id: str) -> list[str]:
    redis_raw = redis_client.get(f"oauth:redirect_uris:{client_id}")
    if not redis_raw:
        return []

    if isinstance(redis_raw, bytes):
        redis_raw = redis_raw.decode("utf-8", errors="ignore")
    redis_value = str(redis_raw).strip()
    if not redis_value:
        return []

    try:
        parsed = json.loads(redis_value)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except Exception:
        pass

    return [item.strip() for item in redis_value.split(",") if item.strip()]


def _save_redirect_uri_whitelist(client_id: str, redirect_uris: list[str]) -> None:
    redis_key = f"oauth:redirect_uris:{client_id}"
    if redirect_uris:
        redis_client.set(redis_key, json.dumps(redirect_uris))
    else:
        redis_client.delete(redis_key)


@router.post("/space/toggle", summary="【租户管理员】启用/熔断自己的租户空间")
def toggle_tenant_space(
        payload: TenantSpaceToggleInput,
        current_user: User = Depends(RBACChecker("tenant:user:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group_for_control(db, current_user)
    if payload.is_active and not group.is_active:
        # 冻结后的恢复必须由超管审批链处理，租户管理员不可自行恢复
        raise HTTPException(status_code=403, detail="租户空间已被冻结，无法自行恢复，请联系超级管理员")
    group.is_active = payload.is_active
    db.commit()
    db.refresh(group)

    dispatch_webhook_event(
        event_type="tenant_space.toggle",
        payload={
            "group_id": group.id,
            "group_name": group.group_name,
            "is_active": group.is_active,
            "operator": current_user.username
        },
        db=db
    )

    return {
        "status": "success",
        "message": f"租户空间已{'启用' if group.is_active else '熔断'}",
        "data": {
            "group_id": group.id,
            "group_name": group.group_name,
            "is_active": group.is_active
        }
    }


@router.post("/space/apply", summary="【租户管理员】申请创建租户空间")
def apply_tenant_space(
        payload: TenantSpaceApplyInput,
        current_user: User = Depends(RBACChecker("tenant:user:create")),
        db: Session = Depends(get_db)
):
    if current_user.group_id:
        existing_group = db.query(DeveloperGroup).filter(DeveloperGroup.id == current_user.group_id).first()
        if existing_group and existing_group.status in ["pending", "approved"]:
            raise HTTPException(status_code=400, detail="当前账号已经拥有租户空间，请勿重复申请")

    group_name_exists = db.query(DeveloperGroup).filter(DeveloperGroup.group_name == payload.group_name).first()
    if group_name_exists:
        raise HTTPException(status_code=400, detail="该租户空间名称已被占用")

    group_code = None
    while not group_code:
        candidate = secrets.token_hex(4)
        exists = db.query(DeveloperGroup).filter(DeveloperGroup.group_code == candidate).first()
        if not exists:
            group_code = candidate

    new_group = DeveloperGroup(
        group_name=payload.group_name,
        description=payload.description or "",
        group_code=group_code or "",
        owner=current_user.username,
        owner_user_id=current_user.id,
        is_active=False,
        status="pending"
    )
    db.add(new_group)
    db.commit()
    db.refresh(new_group)

    current_user.group_id = new_group.id
    db.commit()

    dispatch_webhook_event(
        event_type="tenant_space.apply",
        payload={
            "group_id": new_group.id,
            "group_name": new_group.group_name,
            "group_code": new_group.group_code,
            "owner_user_id": current_user.id,
            "username": current_user.username
        },
        db=db
    )

    return {
        "status": "success",
        "message": "租户空间申请已提交，等待超级管理员审核",
        "data": {
            "group_id": new_group.id,
            "group_name": new_group.group_name,
            "group_code": new_group.group_code,
            "status": new_group.status
        }
    }


@router.get("/apps/list", summary="【租户管理员】拉取本租户应用列表")
def list_tenant_apps(
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("tenant:app:read")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    query = db.query(App).filter(App.group_id == group.id)
    total = query.count()
    apps = query.order_by(App.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return {
        "status": "success",
        "count": total,
        "data": [
            {
                "app_id": app.id,
                "app_name": app.app_name,
                "app_logo": app.app_logo or "",
                "is_active": app.is_active,
                "created_at": app.created_at.strftime("%Y-%m-%d %H:%M:%S") if app.created_at else "-"
            }
            for app in apps
        ]
    }


def _parse_date_range(value: str | None) -> tuple[datetime.datetime | None, datetime.datetime | None]:
    if not value:
        return None, None
    raw = value.strip()
    if " - " not in raw:
        return None, None
    start_str, end_str = [item.strip() for item in raw.split(" - ", 1)]

    def _parse_dt(text: str, is_end: bool) -> datetime.datetime | None:
        if not text:
            return None
        normalized = text.replace("/", "-")
        try:
            parsed = datetime.datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if len(normalized) == 10:
            if is_end:
                return parsed + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
            return parsed
        return parsed

    return _parse_dt(start_str, False), _parse_dt(end_str, True)


@router.get("/audit/logs", summary="【租户管理员】获取租户操作日志")
def list_tenant_operation_logs(
        page: int = Query(1, ge=1),
        limit: int = Query(15, ge=1, le=100),
        operator: str | None = Query(None),
        level: str | None = Query(None),
        date_range: str | None = Query(None),
        current_user: User = Depends(RBACChecker("tenant:app:read")),
        db: Session = Depends(get_db)
):
    query = db.query(OperationLog).filter(
        OperationLog.actor_role == "tenant_admin",
        OperationLog.group_id == current_user.group_id
    )

    if operator:
        query = query.filter(OperationLog.actor_username.contains(operator.strip()))
    if level:
        query = query.filter(OperationLog.level == level.strip().upper())

    start_dt, end_dt = _parse_date_range(date_range)
    if start_dt:
        query = query.filter(OperationLog.created_at >= start_dt)
    if end_dt:
        query = query.filter(OperationLog.created_at <= end_dt)

    total = query.count()
    rows = query.order_by(OperationLog.id.desc()).offset((page - 1) * limit).limit(limit).all()
    data = [
        {
            "id": item.id,
            "operator": item.actor_username,
            "action": item.action,
            "method": item.method,
            "path": item.path,
            "ip": item.ip,
            "level": item.level,
            "created_at": item.created_at.strftime("%Y-%m-%d %H:%M:%S") if item.created_at else "-",
            "payload": item.payload or ""
        }
        for item in rows
    ]
    return {
        "code": 200,
        "count": total,
        "data": data
    }


@router.post("/apps/logo/upload", summary="【租户管理员】安全上传应用图标")
def upload_tenant_app_logo(
        file: UploadFile = File(...),
        current_user: User = Depends(RBACChecker("tenant:app:create"))
):
    app_logo = save_app_logo_upload(file)
    return {
        "status": "success",
        "message": "图标上传成功",
        "data": {
            "app_logo": app_logo
        }
    }


@router.post("/apps", summary="【租户管理员】创建本租户应用")
def create_tenant_app(
        app_name: str = Form(..., min_length=1, max_length=64),
        app_logo: str | None = Form(None),
        current_user: User = Depends(RBACChecker("tenant:app:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    app_count = db.query(App).filter(App.group_id == group.id).count()
    if app_count >= TENANT_MAX_APPS:
        raise HTTPException(status_code=403, detail=f"当前租户应用数量已达上限（{TENANT_MAX_APPS}）")
    safe_logo = ensure_uploaded_logo_reference(app_logo) or ""

    new_app = App(
        group_id=group.id,
        app_name=app_name,
        app_logo=safe_logo,
        owner=current_user.username
    )
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    dispatch_webhook_event(
        event_type="tenant_app.create",
        payload={
            "group_id": group.id,
            "group_name": group.group_name,
            "app_id": new_app.id,
            "app_name": new_app.app_name,
            "owner": current_user.username
        },
        db=db
    )
    return {
        "status": "success",
        "message": "应用创建成功",
        "app_id": new_app.id,
        "app_name": new_app.app_name
    }


@router.put("/apps/{app_id}", summary="【租户管理员】修改应用名称")
def update_tenant_app(
        app_id: int,
        payload: TenantAppUpdateInput,
        current_user: User = Depends(RBACChecker("tenant:app:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    app = _get_tenant_app(db, group.id, app_id)

    app_name = payload.app_name.strip()
    duplicated = db.query(App).filter(App.group_id == group.id, App.app_name == app_name, App.id != app.id).first()
    if duplicated:
        raise HTTPException(status_code=400, detail="当前租户下已存在同名应用")

    app.app_name = app_name
    db.commit()
    return {"status": "success", "message": "应用名称更新成功", "app_id": app.id, "app_name": app.app_name}


@router.delete("/apps/{app_id}", summary="【租户管理员】删除应用")
def delete_tenant_app(
        app_id: int,
        current_user: User = Depends(RBACChecker("tenant:app:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    app = _get_tenant_app(db, group.id, app_id)
    app_name = app.app_name
    db.delete(app)
    db.commit()
    return {"status": "success", "message": f"应用 [{app_name}] 已删除"}


@router.get("/credentials/list", summary="【租户管理员】拉取本租户凭证列表")
def list_tenant_credentials(
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("tenant:credential:read")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    query = db.query(AppCredential).join(App, AppCredential.app_id == App.id) \
        .filter(App.group_id == group.id)
    total = query.count()
    credentials = query.order_by(AppCredential.id.desc()).offset((page - 1) * limit).limit(limit).all()

    return {
        "status": "success",
        "count": total,
        "data": [
            {
                "id": cred.id,
                "client_id": cred.client_id,
                "credential_name": cred.credential_name,
                "scope": cred.scope,
                "max_devices": cred.max_devices,
                "redirect_uris": _load_redirect_uri_whitelist(cred.client_id),
                "is_active": cred.is_active,
                "expire_at": cred.expire_at.strftime("%Y-%m-%d %H:%M:%S") if cred.expire_at else "永久有效",
                "app_id": int(cred.app.id) if cred.app else None,
                "app_name": cred.app.app_name if cred.app else "未知应用"
            }
            for cred in credentials
        ]
    }


@router.post("/apps/{app_id}/credentials", summary="【租户管理员】签发应用凭证")
def create_tenant_credential(
        app_id: int,
        credential_name: str = Form(..., min_length=1, max_length=64),
        scope: str = Form("read"),
        max_devices: int = Form(1, ge=1, le=1000),
        redirect_uris: str | None = Form(None),
        valid_days: int = Form(365, ge=1, le=3650),
        current_user: User = Depends(RBACChecker("tenant:credential:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    app = db.query(App).filter(App.id == app_id, App.group_id == group.id).first()
    if not app:
        raise HTTPException(status_code=404, detail="应用不存在或不属于当前租户")
    if not app.is_active:
        raise HTTPException(status_code=403, detail="当前应用已被停用，无法继续签发凭证")

    cred_count = db.query(AppCredential).filter(AppCredential.app_id == app.id).count()
    if cred_count >= TENANT_MAX_CREDENTIALS_PER_APP:
        raise HTTPException(status_code=403, detail=f"当前应用凭证数量已达上限（{TENANT_MAX_CREDENTIALS_PER_APP}）")

    client_id, client_secret = generate_random_keys()
    expire_time = datetime.datetime.now() + datetime.timedelta(days=valid_days)
    app_pk = int(getattr(app, "id"))
    uri_whitelist = _parse_redirect_uri_whitelist_input(redirect_uris)

    new_credential = AppCredential(
        app_id=app_pk,
        credential_name=credential_name,
        client_id=client_id,
        client_secret_hash=hash_secret(client_secret),
        scope=scope,
        max_devices=max_devices,
        expire_at=expire_time
    )
    db.add(new_credential)
    db.commit()
    _save_redirect_uri_whitelist(client_id, uri_whitelist)

    license_token = create_jwt_token(client_id=client_id, scope=scope, expire_at=expire_time, token_type="license")
    dispatch_webhook_event(
        event_type="tenant_credential.create",
        payload={
            "group_id": group.id,
            "group_name": group.group_name,
            "app_id": app_pk,
            "app_name": app.app_name,
            "credential_name": credential_name,
            "client_id": client_id,
            "scope": scope,
            "expire_at": expire_time.strftime("%Y-%m-%d %H:%M:%S")
        },
        db=db
    )
    return {
        "status": "success",
        "message": "凭证签发成功",
        "client_id": client_id,
        "client_secret": client_secret,
        "max_devices": max_devices,
        "redirect_uris": uri_whitelist,
        "expire_at": expire_time.strftime("%Y-%m-%d %H:%M:%S"),
        "license_key": license_token
    }


@router.post("/credentials/{client_id}/config", summary="【租户管理员】更新凭证配置(兼容旧前端)")
@router.put("/credentials/{client_id}/config", summary="【租户管理员】更新 scope/有效期/redirect_uri 白名单")
def update_tenant_credential_config(
        client_id: str,
        scope: str = Form(...),
        add_days: int = Form(..., ge=0, le=3650),
        max_devices: int = Form(1, ge=1, le=1000),
        redirect_uris: str | None = Form(None),
        current_user: User = Depends(RBACChecker("tenant:credential:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    credential = db.query(AppCredential).join(App, AppCredential.app_id == App.id).filter(
        AppCredential.client_id == client_id,
        App.group_id == group.id,
    ).first()
    if not credential:
        raise HTTPException(status_code=404, detail="凭证不存在或不属于当前租户")

    credential.scope = scope
    credential.max_devices = max_devices
    base_time = credential.expire_at if (
            credential.expire_at and credential.expire_at > datetime.datetime.now()) else datetime.datetime.now()
    credential.expire_at = base_time + datetime.timedelta(days=add_days)
    db.commit()

    if redirect_uris is not None:
        uri_whitelist = _parse_redirect_uri_whitelist_input(redirect_uris)
        _save_redirect_uri_whitelist(client_id, uri_whitelist)

    return {
        "status": "success",
        "message": "凭证配置已更新",
        "client_id": credential.client_id,
        "scope": credential.scope,
        "max_devices": credential.max_devices,
        "redirect_uris": _load_redirect_uri_whitelist(client_id),
        "expire_at": credential.expire_at.strftime("%Y-%m-%d %H:%M:%S") if credential.expire_at else "永久有效"
    }


@router.post("/credentials/{client_id}/revoke", summary="【租户管理员】吊销凭证")
def revoke_tenant_credential(
        client_id: str,
        current_user: User = Depends(RBACChecker("tenant:credential:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    credential = db.query(AppCredential).join(App, AppCredential.app_id == App.id).filter(
        AppCredential.client_id == client_id,
        App.group_id == group.id,
    ).first()
    if not credential:
        raise HTTPException(status_code=404, detail="凭证不存在或不属于当前租户")

    credential.is_active = False
    db.commit()
    return {"status": "success", "message": "凭证已吊销", "client_id": credential.client_id}


@router.post("/credentials/{client_id}/status", summary="【租户管理员】凭证启用/挂起(兼容旧前端)")
@router.put("/credentials/{client_id}/status", summary="【租户管理员】凭证启用/挂起")
def update_tenant_credential_status(
        client_id: str,
        payload: CredentialStatusInput,
        current_user: User = Depends(RBACChecker("tenant:credential:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    credential = db.query(AppCredential).join(App, AppCredential.app_id == App.id).filter(
        AppCredential.client_id == client_id,
        App.group_id == group.id,
    ).first()
    if not credential:
        raise HTTPException(status_code=404, detail="凭证不存在或不属于当前租户")

    credential.is_active = payload.is_active
    db.commit()
    return {
        "status": "success",
        "message": f"凭证已{'启用' if payload.is_active else '挂起'}",
        "client_id": credential.client_id,
        "is_active": credential.is_active,
    }


@router.delete("/credentials/{client_id}", summary="【租户管理员】删除凭证")
def delete_tenant_credential(
        client_id: str,
        current_user: User = Depends(RBACChecker("tenant:credential:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    credential = db.query(AppCredential).join(App, AppCredential.app_id == App.id).filter(
        AppCredential.client_id == client_id,
        App.group_id == group.id,
    ).first()
    if not credential:
        raise HTTPException(status_code=404, detail="凭证不存在或不属于当前租户")

    db.delete(credential)
    db.commit()
    _save_redirect_uri_whitelist(client_id, [])
    return {"status": "success", "message": "凭证已删除", "client_id": client_id}


@router.get("/apps/{app_id}/devices", summary="【租户管理员】查看应用设备列表")
def list_tenant_app_devices(
        app_id: int,
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("tenant:credential:read")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    app = _get_tenant_app(db, group.id, app_id)

    query = db.query(AppDevice).join(AppCredential, AppDevice.credential_id == AppCredential.id).filter(
        AppCredential.app_id == app.id
    )
    total = query.count()
    rows = query.order_by(AppDevice.id.desc()).offset((page - 1) * limit).limit(limit).all()

    return {
        "status": "success",
        "count": total,
        "data": [
            {
                "id": item.id,
                "device_id": item.device_id,
                "credential_id": item.credential_id,
                "is_revoked": item.is_revoked,
                "expires_at": item.expires_at.strftime("%Y-%m-%d %H:%M:%S") if item.expires_at else None,
                "last_seen_at": item.last_seen_at.strftime("%Y-%m-%d %H:%M:%S") if item.last_seen_at else None,
                "activated_at": item.activated_at.strftime("%Y-%m-%d %H:%M:%S") if item.activated_at else None,
            }
            for item in rows
        ]
    }


@router.post("/apps/{app_id}/devices/{device_id}/unbind", summary="【租户管理员】解绑应用设备")
def unbind_tenant_app_device(
        app_id: int,
        device_id: str,
        current_user: User = Depends(RBACChecker("tenant:credential:create")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    app = _get_tenant_app(db, group.id, app_id)

    target = db.query(AppDevice).join(AppCredential, AppDevice.credential_id == AppCredential.id).filter(
        AppCredential.app_id == app.id,
        AppDevice.device_id == device_id,
        AppDevice.is_revoked == False,
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="设备不存在或已解绑")

    target.is_revoked = True
    target.revoked_at = datetime.datetime.now()
    target.revoke_reason = "tenant_unbind"
    db.commit()
    return {"status": "success", "message": "设备已解绑", "device_id": device_id}


