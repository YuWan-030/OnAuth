import datetime
import secrets
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Form, File, UploadFile, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db, DeveloperGroup, App, AppCredential, User, OperationLog
from middlewares.rbac import RBACChecker
from routers.webhook import dispatch_webhook_event
from utils.crypto import generate_random_keys, hash_secret, create_jwt_token
from utils.app_logo import save_app_logo_upload, ensure_uploaded_logo_reference

router = APIRouter(prefix="/tenant", tags=["租户管理员空间管理"])


class TenantSpaceApplyInput(BaseModel):
    group_name: str = Field(..., min_length=1, max_length=64, description="租户空间名称")
    description: str | None = Field(None, description="租户空间说明")


class TenantSpaceToggleInput(BaseModel):
    is_active: bool = Field(..., description="是否启用租户空间")


def _get_tenant_group(db: Session, current_user: User) -> DeveloperGroup:
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

    return cast(DeveloperGroup, group)


def _get_tenant_group_for_control(db: Session, current_user: User) -> DeveloperGroup:
    if not current_user.group_id:
        raise HTTPException(status_code=403, detail="当前账号未绑定租户空间")

    group = db.query(DeveloperGroup).filter(DeveloperGroup.id == current_user.group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="租户空间不存在")

    if group.status != "approved":
        raise HTTPException(status_code=403, detail="租户空间尚未通过审核")

    if group.expire_at and group.expire_at < datetime.datetime.now():
        raise HTTPException(status_code=403, detail="租户空间已过期")

    return cast(DeveloperGroup, group)


@router.post("/space/toggle", summary="【租户管理员】启用/熔断自己的租户空间")
def toggle_tenant_space(
        payload: TenantSpaceToggleInput,
        current_user: User = Depends(RBACChecker("tenant:space:review")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group_for_control(db, current_user)
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
        current_user: User = Depends(RBACChecker("tenant:app:read")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    apps = db.query(App).filter(App.group_id == group.id).order_by(App.id.desc()).all()
    return {
        "status": "success",
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


@router.get("/credentials/list", summary="【租户管理员】拉取本租户凭证列表")
def list_tenant_credentials(
        current_user: User = Depends(RBACChecker("tenant:credential:read")),
        db: Session = Depends(get_db)
):
    group = _get_tenant_group(db, current_user)
    credentials = db.query(AppCredential).join(App, AppCredential.app_id == App.id) \
        .filter(App.group_id == group.id).order_by(AppCredential.id.desc()).all()

    return {
        "status": "success",
        "data": [
            {
                "id": cred.id,
                "client_id": cred.client_id,
                "credential_name": cred.credential_name,
                "scope": cred.scope,
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

    client_id, client_secret = generate_random_keys()
    expire_time = datetime.datetime.now() + datetime.timedelta(days=valid_days)

    new_credential = AppCredential(
        app_id=int(app.id),
        credential_name=credential_name,
        client_id=client_id,
        client_secret_hash=hash_secret(client_secret),
        scope=scope,
        expire_at=expire_time
    )
    db.add(new_credential)
    db.commit()

    license_token = create_jwt_token(client_id=client_id, scope=scope, expire_at=expire_time, token_type="license")
    dispatch_webhook_event(
        event_type="tenant_credential.create",
        payload={
            "group_id": group.id,
            "group_name": group.group_name,
            "app_id": int(app.id),
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
        "expire_at": expire_time.strftime("%Y-%m-%d %H:%M:%S"),
        "license_key": license_token
    }

