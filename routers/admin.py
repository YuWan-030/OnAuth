import datetime
import logging
from urllib.parse import urlparse

import psutil
import redis
from fastapi import APIRouter, Query, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from sqlalchemy.orm import Session

# 导入你的底层数据库实体与依赖
from database import get_db, App, AppCredential, DeveloperGroup, User, Role, Permission, OperationLog
from routers.webhook import dispatch_webhook_event
from schemas.PermissionUpdateSchema import UserPermissionUpdateSchema, UserRoleUpdateSchema
from utils.crypto import generate_random_keys, hash_secret, create_jwt_token
from utils.app_logo import save_app_logo_upload, ensure_uploaded_logo_reference
from sqlalchemy import func
from sqlalchemy import or_
from database import AppDevice
from middlewares.auth import redis_client
import json
import secrets
from middlewares.rbac import RBACChecker
from schemas.admin_schema import GroupCreateInput, GroupToggleInput, AppCreateInput, AppStatusInput, CredentialStatusInput
from schemas.admin_schema import UserCreateInput, UserNicknameUpdateInput,UserPasswordUpdateInput,UserToggleStatusInput
from schemas.admin_schema import TenantReviewInput, TenantSpaceAssignInput
from utils.role_constants import ROLE_SUPER_ADMIN, PRIVILEGED_ADMIN_ROLE_NAMES, ROLE_TENANT_ADMIN


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# 初始化全新架构的路由
router = APIRouter(prefix="/admin", tags=["OnAuth 核心管理中台管线"])



# ==================== 📦 Pydantic 交互数据流模型沙箱 ====================




def revoke_user_redis_sessions(user_id: int):
    """
    高性能熔断：通过反向索引 Set 集合，瞬间秒杀该用户的所有在线端
    """
    try:
        user_set_key = f"user:active_sessions:{user_id}"

        # 1. 一口气把该用户在所有设备（手机、网页等）上的 session_id 全部取出来
        active_sessions = redis_client.smembers(user_set_key)

        if active_sessions:
            # 2. 批量将这些会话全部从 Redis 里彻底抹去
            # *active_sessions 利用 Python 拆包特性，一次网络 I/O 就能批量删除
            redis_client.delete(*active_sessions)

        # 3. 顺便把这个索引 Key 自己也删掉
        redis_client.delete(user_set_key)
        print(f"[高性能熔断] 用户 [{user_id}] 的所有终端已成功强制下线")

    except Exception as e:
        print(f"[安全熔断失败] {str(e)}")

def _generate_group_code(db: Session) -> str:
    while True:
        candidate = secrets.token_hex(4)
        exists = db.query(DeveloperGroup).filter(DeveloperGroup.group_code == candidate).first()
        if not exists:
            return candidate

def _is_super_admin(user: User) -> bool:
    return any(role.name == ROLE_SUPER_ADMIN for role in user.roles)


def _resolve_group_owner_name(db: Session, group: DeveloperGroup) -> str:
    owner_name = (getattr(group, "owner", None) or "").strip()
    if owner_name:
        return owner_name

    owner_user_id = getattr(group, "owner_user_id", None)
    if not owner_user_id:
        return ""

    owner_user = db.query(User).filter(User.id == owner_user_id).first()
    return owner_user.username if owner_user else ""


class BatchUserStatusInput(BaseModel):
    user_ids: list[int] = Field(default_factory=list)
    is_active: bool


class BatchCredentialStatusInput(BaseModel):
    client_ids: list[str] = Field(default_factory=list)
    is_active: bool


def _require_super_admin(current_user: User):
    if not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="仅超级管理员可执行该操作")


def _clear_user_rbac_cache(user_id: int) -> None:
    user_set_key = f"user:active_sessions:{user_id}"
    session_ids = redis_client.smembers(user_set_key) or []
    for raw_session_id in session_ids:
        session_id = raw_session_id.decode("utf-8") if isinstance(raw_session_id, bytes) else str(raw_session_id)
        if session_id:
            redis_client.delete(f"rbac:perms:{session_id}")


def _ensure_tenant_admin_role_active(db: Session, user: User | None) -> bool:
    if not user:
        return False
    existing_role = None
    for role in (user.roles or []):
        if getattr(role, "name", None) == ROLE_TENANT_ADMIN:
            existing_role = role
            break
    if existing_role is not None:
        if hasattr(existing_role, "is_active") and existing_role.is_active is False:
            existing_role.is_active = True
            db.flush()
            return True
        return False

    role = db.query(Role).filter(Role.name == ROLE_TENANT_ADMIN).first()
    if not role:
        return False
    changed = False
    if not role.is_active:
        role.is_active = True
        changed = True
    if role not in (user.roles or []):
        user.roles.append(role)
        changed = True
    if changed:
        db.flush()
    return changed


def _parse_expire_at(expire_at_value: str | None) -> datetime.datetime | None:
    if not expire_at_value:
        return None

    normalized_value = expire_at_value.strip().replace("Z", "+00:00")
    try:
        return datetime.datetime.fromisoformat(normalized_value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="expire_at 必须是有效的 ISO 8601 时间字符串") from exc


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
            raise HTTPException(status_code=400, detail=f"http redirect_uri 仅允许本��地址: {uri}")
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


# ==================== 🏢 模块一：工作室组织空间资产管控 ====================

@router.get("/groups/list", summary="【管理端】拉取全量工作室组织资产")
def list_all_groups(
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    query = db.query(DeveloperGroup)
    total = query.count()
    groups = query.order_by(DeveloperGroup.id.desc()).offset((page - 1) * limit).limit(limit).all()
    result = []
    for g in groups:
        result.append({
            "id": g.id,
            "group_name": g.group_name,
            "group_code": g.group_code,
            "description": getattr(g, "description", "暂无说明") or "暂无说明",  # 🛡️ 安全防御容错，防止模型字段未迁移时报错
            "is_active": g.is_active,
            "status": getattr(g, "status", "pending"),
            "review_note": getattr(g, "review_note", None),
            "reviewed_at": g.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if getattr(g, "reviewed_at", None) else None,
            "expire_at": g.expire_at.strftime("%Y-%m-%d %H:%M:%S") if getattr(g, "expire_at", None) else None,
            "owner_user_id": g.owner_user_id,
            "owner": _resolve_group_owner_name(db, g)
        })
    return {"code": 200, "count": total, "data": result}


@router.post("/groups", summary="【管理端】新增工作室主体")
def create_group(
        payload: GroupCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    existing = db.query(DeveloperGroup).filter(DeveloperGroup.group_name == payload.group_name).first()
    if existing:
        raise HTTPException(status_code=400, detail="该工作室名称已被注册")

    if payload.group_code:
        code_exists = db.query(DeveloperGroup).filter(DeveloperGroup.group_code == payload.group_code).first()
        if code_exists:
            raise HTTPException(status_code=400, detail="该租户空间识别码已被占用")
        group_code = payload.group_code
    else:
        group_code = _generate_group_code(db)

    new_group = DeveloperGroup(
        group_name=payload.group_name,
        description=payload.description or "",
        group_code=group_code,
        owner=current_user.username,
        owner_user_id=current_user.id
    )
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return {
        "msg": "工作室主体开通成功",
        "group_id": new_group.id,
        "group_name": new_group.group_name,
        "group_code": new_group.group_code
    }


@router.post("/groups/{group_id}/toggle", summary="【管理端】工作室状态切换(兼容旧前端直发POST请求)")
@router.put("/groups/{group_id}/toggle", summary="【管理端】��键开关工作组/联动熔断/修改备注")
def toggle_group_status(
        group_id: int,
        payload: GroupToggleInput,
        current_user: User = Depends(RBACChecker("admin:update")),  # 🛡️ 细粒度审计
        db: Session = Depends(get_db)
):
    target = db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="组织不存在")

    # 1. 🔄 状态流同步（保留你原有的实时熔断开关功能）
    target.is_active = payload.is_active

    # 2. 📝 备注流同步：如果前端传了备注（哪怕是空字符串），都直接刷入数据库
    if payload.description is not None:
        target.description = payload.description

    db.commit()
    return {
        "msg": f"组织 [{target.group_name}] 配置资产已全盘同步更新成功！",
        "is_active": target.is_active,
        "description": target.description
    }


@router.delete("/groups/{group_id}", summary="【管理端】物理删除组织资产")
def delete_group(
        group_id: int,
        current_user: User = Depends(RBACChecker("admin:delete")),
        db: Session = Depends(get_db)
):
    target = db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="组织不存在")
    name = target.group_name
    db.delete(target)
    db.commit()
    return {"msg": f"工作组 [{name}] 及其旗下所有应用凭证已被全盘风暴级级联擦除"}


@router.get("/groups/reviews/pending", summary="【管理端】查看待审批的租户空间申请")
def list_pending_group_reviews(
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("tenant:space:review")),
        db: Session = Depends(get_db)
):
    _require_super_admin(current_user)
    query = db.query(DeveloperGroup).filter(DeveloperGroup.status == "pending")
    total = query.count()
    groups = query.order_by(DeveloperGroup.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return {
        "status": "success",
        "count": total,
        "data": [
            {
                "id": group.id,
                "group_name": group.group_name,
                "group_code": group.group_code,
                "description": group.description,
                "owner": group.owner,
                "owner_user_id": group.owner_user_id,
                "status": group.status,
                "review_note": group.review_note,
                "created_at": group.created_at.strftime("%Y-%m-%d %H:%M:%S") if group.created_at else None,
                "expire_at": group.expire_at.strftime("%Y-%m-%d %H:%M:%S") if group.expire_at else None
            }
            for group in groups
        ]
    }


@router.post("/groups/{group_id}/review", summary="【管理端】审批租户空间申请")
def review_group_space(
        group_id: int,
        payload: TenantReviewInput,
        current_user: User = Depends(RBACChecker("tenant:space:review")),
        db: Session = Depends(get_db)
):
    _require_super_admin(current_user)
    group = db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="租户空间不存在")

    action = payload.action.strip().lower()
    group.review_note = payload.review_note
    group.reviewed_at = datetime.datetime.now()

    owner_user = None
    ensure_role_changed = False
    if action == "approve":
        expire_at = _parse_expire_at(payload.expire_at)
        if not expire_at:
            raise HTTPException(status_code=400, detail="审批通过时必须提供 expire_at")
        group.status = "approved"
        group.is_active = True
        group.expire_at = expire_at
        owner_user = db.query(User).filter(User.id == group.owner_user_id).first() if group.owner_user_id else None
        ensure_role_changed = _ensure_tenant_admin_role_active(db, owner_user)
    elif action == "reject":
        group.status = "rejected"
        group.is_active = False
        group.expire_at = None
    else:
        raise HTTPException(status_code=400, detail="action 仅支持 approve 或 reject")

    db.commit()
    db.refresh(group)
    if owner_user and ensure_role_changed:
        _clear_user_rbac_cache(int(owner_user.id))
    dispatch_webhook_event(
        event_type="tenant_space.review",
        payload={
            "group_id": group.id,
            "group_name": group.group_name,
            "status": group.status,
            "review_note": group.review_note,
            "reviewed_at": group.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if group.reviewed_at else None,
            "expire_at": group.expire_at.strftime("%Y-%m-%d %H:%M:%S") if group.expire_at else None
        },
        db=db
    )
    return {
        "status": "success",
        "message": f"租户空间 [{group.group_name}] 已{ '通过' if action == 'approve' else '拒绝' }",
        "data": {
            "group_id": group.id,
            "status": group.status,
            "is_active": group.is_active,
            "expire_at": group.expire_at.strftime("%Y-%m-%d %H:%M:%S") if group.expire_at else None,
            "review_note": group.review_note,
            "reviewed_at": group.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if group.reviewed_at else None
        }
    }


@router.put("/groups/{group_id}/expire", summary="【管理端】更新租户空间到期时间")
def update_group_expire_at(
        group_id: int,
        expire_at: str = Query(..., description="ISO 8601 到期时间"),
        current_user: User = Depends(RBACChecker("tenant:space:review")),
        db: Session = Depends(get_db)
):
    _require_super_admin(current_user)
    group = db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="租户空间不存在")

    parsed_expire_at = _parse_expire_at(expire_at)
    if not parsed_expire_at:
        raise HTTPException(status_code=400, detail="expire_at 不能为空")

    group.expire_at = parsed_expire_at
    if group.status != "rejected":
        group.status = "approved"
        group.is_active = True
    group.reviewed_at = datetime.datetime.now()

    db.commit()
    db.refresh(group)
    return {
        "status": "success",
        "message": f"租户空间 [{group.group_name}] 到期时间已更新",
        "data": {
            "group_id": group.id,
            "expire_at": group.expire_at.strftime("%Y-%m-%d %H:%M:%S") if group.expire_at else None,
            "status": group.status,
            "is_active": group.is_active
        }
    }


@router.post("/groups/{group_id}/assign", summary="【管理端】分配租户空间给租户管理员")
def assign_group_to_tenant_admin(
        group_id: int,
        payload: TenantSpaceAssignInput,
        current_user: User = Depends(RBACChecker("tenant:space:review")),
        db: Session = Depends(get_db)
):
    _require_super_admin(current_user)
    group = db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="租户空间不存在")

    target_user = db.query(User).filter(User.id == payload.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="目标用户不存在")

    role_names = {role.name for role in target_user.roles}
    if ROLE_TENANT_ADMIN not in role_names and not role_names.intersection(PRIVILEGED_ADMIN_ROLE_NAMES):
        raise HTTPException(status_code=400, detail="目标用户不是租户管理员")

    ensure_role_changed = _ensure_tenant_admin_role_active(db, target_user)

    previous_owner_id = group.owner_user_id

    group.owner_user_id = target_user.id
    group.owner = target_user.username
    if payload.bind_user_group:
        target_user.group_id = group.id

    previous_owner = None
    if previous_owner_id and previous_owner_id != target_user.id:
        previous_owner = db.query(User).filter(User.id == previous_owner_id).first()
        if previous_owner and not _is_super_admin(previous_owner):
            previous_owner.group_id = None

    db.commit()
    db.refresh(group)
    db.refresh(target_user)
    if previous_owner:
        db.refresh(previous_owner)
    if ensure_role_changed:
        _clear_user_rbac_cache(int(target_user.id))

    dispatch_webhook_event(
        event_type="tenant_space.assign",
        payload={
            "group_id": group.id,
            "group_name": group.group_name,
            "user_id": target_user.id,
            "username": target_user.username,
            "bind_user_group": payload.bind_user_group
        },
        db=db
    )

    return {
        "status": "success",
        "message": f"租户空间 [{group.group_name}] 已分配给用户 [{target_user.username}]",
        "data": {
            "group_id": group.id,
            "owner_user_id": group.owner_user_id,
            "owner": group.owner,
            "user_group_id": target_user.group_id
        }
    }


# ==================== 📱 模块二：独立应用多租户产品生命周期 ====================

@router.get("/apps/flat_list", summary="【管理端】拉取平铺的应用资产大盘（含组织信息）")
def list_apps_flat(
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    query = db.query(App)
    total = query.count()
    apps = query.order_by(App.id.desc()).offset((page - 1) * limit).limit(limit).all()
    result = []
    for a in apps:
        result.append({
            "id": a.id,
            "group_id": a.group_id,
            "group_name": a.group.group_name if a.group else "未知组织",
            "app_name": a.app_name,
            "app_logo": a.app_logo or "",
            "owner": a.owner,
            "is_active": a.is_active,
            "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(a,
                                                                                'created_at') and a.created_at else "-"
        })
    return {"code": 200, "count": total, "data": result}


@router.post("/apps/logo/upload", summary="【管理端】安全上传应用图标")
def upload_app_logo(
        file: UploadFile = File(...),
        current_user: User = Depends(RBACChecker("admin:create"))
):
    app_logo = save_app_logo_upload(file)
    return {
        "status": "success",
        "message": "图标上传成功",
        "data": {
            "app_logo": app_logo
        }
    }


@router.post("/apps", summary="【管理端】在指定工作室下创建独立应用")
def create_app(
        payload: AppCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    group_exists = db.query(DeveloperGroup).filter(DeveloperGroup.id == payload.group_id).first()
    if not group_exists:
        raise HTTPException(status_code=404, detail="归属工作室主体不存在，无法创建应用")

    app_logo = ensure_uploaded_logo_reference(payload.app_logo) or ""

    new_app = App(
        group_id=payload.group_id,
        app_name=payload.app_name,
        app_logo=app_logo,
        owner=payload.owner or "admin"
    )
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    return {"msg": "应用创建成功", "app_id": new_app.id, "app_name": new_app.app_name}


@router.get("/dashboard/stats", summary="【管理端】首页核心大屏实时指标监控（Redis缓存版）")
def get_dashboard_stats(
        current_user: User = Depends(RBACChecker("admin:read")),  # 🛡️ 权限守卫
        db: Session = Depends(get_db)
):
    """
    🧠 工业级高并发降维打击改造：
    使用 Redis 作为前置大盘阻水坝，数据生命周期（TTL）设为 60 秒。
    1. 100个管理员同时看大盘，每分钟也只有 1 次撞击 MySQL。
    2. 穿透审计主题封禁，同时杜绝数据库全表扫描带来的锁表与崩溃风险。
    """
    CACHE_KEY = "onauth:dashboard:cache"
    CACHE_TTL = 60  # 🎯 缓存时效 60 秒（1分钟），兼顾大盘实时性与数据安全性

    # ==================== 🚪 拦截层：前置 Redis 缓存捞取 ====================
    try:
        cached_data = redis_client.get(CACHE_KEY)
        if cached_data:
            # 🎉 命中缓存！直接反序列化回传，不碰一下 MySQL
            return json.loads(cached_data)
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        # 容错：如果 Redis 偶发性断连，打印警告日志，降级穿透去查 MySQL，保障系统高可用
        logging.warning("⚠️ [大盘风控] Redis 读取失败，大盘临时降级穿透撞击数据库！")

    # ==================== 🚫 穿透层：缓存未命中，开始计算重度数据 ====================
    now_time = datetime.datetime.now()

    # 1. 用户与应用基础设施
    total_users = db.query(func.count(User.id)).scalar() or 0
    total_apps = db.query(func.count(App.id)).scalar() or 0

    # 2.【精准风控】多表穿透审计：计入主体/应用封禁旗下的影子凭证数
    frozen_credentials = db.query(func.count(AppCredential.id)) \
                             .join(App, AppCredential.app_id == App.id) \
                             .join(DeveloperGroup, App.group_id == DeveloperGroup.id) \
                             .filter(
        (AppCredential.is_active == False) |
        (AppCredential.expire_at < now_time) |
        (App.is_active == False) |
        (DeveloperGroup.is_active == False)
    ).scalar() or 0

    # 3. 在线活跃度双轨合流
    active_cutoff = now_time - datetime.timedelta(minutes=15)
    active_devices = db.query(func.count(AppDevice.id)).filter(
        AppDevice.last_seen_at >= active_cutoff,
        AppDevice.is_revoked == False,
        or_(AppDevice.expires_at == None, AppDevice.expires_at > now_time)
    ).scalar() or 0

    try:
        active_oauth_sessions = len(redis_client.keys("sess_*"))
    except Exception:
        active_oauth_sessions = 0

    # 4. 近 7 日双栖激活与授权爆发趋势
    seven_days_ago = now_time.date() - datetime.timedelta(days=6)

    raw_device_trend = db.query(
        func.date(AppDevice.activated_at).label("act_date"),
        func.count(AppDevice.id).label("day_count")
    ).filter(func.date(AppDevice.activated_at) >= seven_days_ago).group_by(func.date(AppDevice.activated_at)).all()
    device_trend_map = {str(row.act_date): row.day_count for row in raw_device_trend}

    raw_oauth_trend = db.query(
        func.date(AppCredential.created_at).label("auth_date"),
        func.count(AppCredential.id).label("day_count")
    ).filter(func.date(AppCredential.created_at) >= seven_days_ago).group_by(func.date(AppCredential.created_at)).all()
    oauth_trend_map = {str(row.auth_date): row.day_count for row in raw_oauth_trend}

    # 5. 补齐近 7 日多维时间轴
    mixed_trend = []
    for i in range(6, -1, -1):
        target_date = (now_time - datetime.timedelta(days=i)).date()
        date_str = target_date.strftime("%Y-%m-%d")
        display_str = target_date.strftime("%m-%d")

        mixed_trend.append({
            "date": display_str,
            "device_count": device_trend_map.get(date_str, 0),
            "oauth_count": oauth_trend_map.get(date_str, 0)
        })

    # 6. 服务器底层物理性能审计
    try:
        cpu_usage = psutil.cpu_percent(interval=0.1)
        virtual_mem = psutil.virtual_memory()
        memory_usage = virtual_mem.percent

        if cpu_usage > 85 or memory_usage > 90:
            health_status = "CRITICAL"
        elif cpu_usage > 70 or memory_usage > 75:
            health_status = "WARNING"
        else:
            health_status = "HEALTHY"
    except Exception:
        cpu_usage, memory_usage, health_status = 0, 0, "UNKNOWN"

    # ==================== 📦 组装全量倾泻响应体 ====================
    response_payload = {
        "status": "success",
        "data": {
            "refresh_time": now_time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_users": total_users,
            "total_apps": total_apps,
            "frozen_frequency": frozen_credentials,
            "active_devices": active_devices,
            "active_oauth_sessions": active_oauth_sessions,
            "mixed_trend": mixed_trend,
            "system_status": {
                "cpu": cpu_usage,
                "memory": memory_usage,
                "health": health_status
            }
        }
    }

    # ==================== 💾 注入层：将冷计算数据拍入 Redis 缓存 ====================
    try:
        # 使用 setex 原子操作：设置 Key、过期秒数、以及转为字符串的 JSON
        redis_client.setex(CACHE_KEY, CACHE_TTL, json.dumps(response_payload))
    except Exception as e:
        logging.error(f"❌ [大盘风控] 回写 Redis 缓存发生异常: {str(e)}")

    return response_payload

@router.get("/profile", summary="【全量用户】获取当前登录会话的真实账户名号")
def get_admin_profile(
    # 🎯 核心修正：降维到普通 "read" 权限，只要登录授信合规，即可读取自己的名字
    current_user: User = Depends(RBACChecker("read"))
):
    nickname = getattr(current_user, "nickname", None)
    return {
        "status": "success",
        "username": current_user.username,
        "nickname": nickname or "普通合规用户"
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


@router.get("/audit/logs", summary="【管理端】获取系统管理员操作日志")
def list_system_operation_logs(
        page: int = Query(1, ge=1),
        limit: int = Query(15, ge=1, le=100),
        operator: str | None = Query(None),
        level: str | None = Query(None),
        date_range: str | None = Query(None),
        scope: str | None = Query("system_admin"),
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    scope_value = (scope or "system_admin").strip().lower()
    if scope_value not in {"system_admin", "tenant_admin"}:
        scope_value = "system_admin"

    query = db.query(OperationLog).filter(OperationLog.actor_role == scope_value)

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


@router.put("/apps/{app_id}/status", summary="【��理端】一键启停/熔断独立应用")
def update_app_status(
        app_id: int,
        payload: AppStatusInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    target_app = db.query(App).filter(App.id == app_id).first()
    if not target_app:
        raise HTTPException(status_code=404, detail="未找到该应用")

    target_app.is_active = payload.is_active
    db.commit()
    return {"msg": f"应用 [{target_app.app_name}] 状态已修改为: {'启用' if payload.is_active else '禁用'}"}


@router.delete("/apps/{app_id}", summary="【管理端】彻底物理销毁应用资产")
def delete_app(
        app_id: int,
        current_user: User = Depends(RBACChecker("admin:delete")),
        db: Session = Depends(get_db)
):
    target_app = db.query(App).filter(App.id == app_id).first()
    if not target_app:
        raise HTTPException(status_code=404, detail="未找到该应用")
    app_name = target_app.app_name
    db.delete(target_app)
    db.commit()
    return {"msg": f"应用 [{app_name}] 及其名下所有授权凭证已被彻底物理清除"}


@router.get("/apps/{app_id}/devices", summary="【管理端】查看应用设备列表")
def list_admin_app_devices(
        app_id: int,
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    target_app = db.query(App).filter(App.id == app_id).first()
    if not target_app:
        raise HTTPException(status_code=404, detail="未找到该应用")

    query = db.query(AppDevice).join(AppCredential, AppDevice.credential_id == AppCredential.id).filter(
        AppCredential.app_id == target_app.id
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
                "credential_name": item.credential.credential_name if item.credential else "未知凭证",
                "client_id": item.credential.client_id if item.credential else "",
                "is_revoked": item.is_revoked,
                "revoked_at": item.revoked_at.strftime("%Y-%m-%d %H:%M:%S") if item.revoked_at else None,
                "revoke_reason": item.revoke_reason,
                "expires_at": item.expires_at.strftime("%Y-%m-%d %H:%M:%S") if item.expires_at else None,
                "last_seen_at": item.last_seen_at.strftime("%Y-%m-%d %H:%M:%S") if item.last_seen_at else None,
                "activated_at": item.activated_at.strftime("%Y-%m-%d %H:%M:%S") if item.activated_at else None,
            }
            for item in rows
        ]
    }


@router.post("/apps/{app_id}/devices/{device_id}/unbind", summary="【管理端】解绑应用设备")
def unbind_admin_app_device(
        app_id: int,
        device_id: str,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    target_app = db.query(App).filter(App.id == app_id).first()
    if not target_app:
        raise HTTPException(status_code=404, detail="未找到该应用")

    target = db.query(AppDevice).join(AppCredential, AppDevice.credential_id == AppCredential.id).filter(
        AppCredential.app_id == target_app.id,
        AppDevice.device_id == device_id,
        AppDevice.is_revoked == False,
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="设备不存在或已解绑")

    target.is_revoked = True
    target.revoked_at = datetime.datetime.now()
    target.revoke_reason = "admin_unbind"
    db.commit()
    return {"status": "success", "message": "设备已解绑", "device_id": device_id}


# ==================== 🔑 模块三：商业授权凭证与激活码下发 ====================

@router.get("/credentials/flat_list", summary="【管理端】拉取全量凭证激活码大盘")
def list_credentials_flat(
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    query = db.query(AppCredential)
    total = query.count()
    credentials = query.order_by(AppCredential.id.desc()).offset((page - 1) * limit).limit(limit).all()
    result = []
    for c in credentials:
        app_name = c.app.app_name if c.app else "未知应用"
        group_name = c.app.group.group_name if (c.app and c.app.group) else "未知组织"

        result.append({
            "id": c.id,
            "client_id": c.client_id,
            "credential_name": c.credential_name,
            "scope": c.scope,
            "max_devices": c.max_devices,
            "redirect_uris": _load_redirect_uri_whitelist(c.client_id),
            "is_active": c.is_active,
            "expire_at": c.expire_at.strftime("%Y-%m-%d %H:%M:%S") if c.expire_at else "永久有效",
            "app_name": app_name,
            "group_name": group_name
        })
    return {"code": 200, "count": total, "data": result}


@router.post("/apps/{app_id}/credentials", summary="【管理端】签发应用全新商业凭证并下发激活码")
def create_app_credential(
        app_id: int,
        credential_name: str = Query(...),
        scope: str = "read",
        max_devices: int = Query(1, ge=1, le=1000, description="当前最多允许几台设备"),
        redirect_uris: str | None = Query(None, description="redirect_uri 白名单，传空字符串可清空"),
        valid_days: int = Query(365),
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    target_app = db.query(App).filter(App.id == app_id).first()
    if not target_app:
        raise HTTPException(status_code=404, detail="应用不存在")

    client_id, client_secret = generate_random_keys()
    expire_time = datetime.datetime.now() + datetime.timedelta(days=valid_days)
    uri_whitelist = _parse_redirect_uri_whitelist_input(redirect_uris)

    new_credential = AppCredential(
        app_id=app_id,
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

    long_lived_token = create_jwt_token(client_id=client_id, scope=scope, expire_at=expire_time, token_type="license")
    return {
        "msg": "成功开通授权凭证并生成激活码！",
        "client_id": client_id,
        "client_secret": client_secret,
        "max_devices": max_devices,
        "redirect_uris": uri_whitelist,
        "expire_at": expire_time.strftime("%Y-%m-%d %H:%M:%S"),
        "license_key": long_lived_token
    }


@router.post("/credentials/{client_id}/status", summary="【管理端】凭证开关控制(兼容旧前端直发POST)")
@router.put("/credentials/{client_id}/status", summary="【管理端】同步启停/挂起商业凭证")
def update_credential_status(
        client_id: str,
        payload: CredentialStatusInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred:
        raise HTTPException(status_code=404, detail="凭证未找到")
    cred.is_active = payload.is_active
    db.commit()
    return {"msg": "凭证安全防御状态同步成功！"}


@router.post("/credentials/batch_status", summary="【管理端】批量启用/禁用凭证")
def batch_update_credential_status(
        payload: BatchCredentialStatusInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    client_ids = sorted({(cid or "").strip() for cid in payload.client_ids if (cid or "").strip()})
    if not client_ids:
        raise HTTPException(status_code=400, detail="至少需要一个有效 client_id")

    creds = db.query(AppCredential).filter(AppCredential.client_id.in_(client_ids)).all()
    if not creds:
        raise HTTPException(status_code=404, detail="未找到目��凭证")

    for cred in creds:
        cred.is_active = payload.is_active

    db.commit()
    return {
        "status": "success",
        "message": "批量凭证状态同步成功",
        "updated": len(creds)
    }


@router.post("/credentials/{client_id}/config", summary="【管理端】同步更新配置(兼容旧前端)")
@router.put("/credentials/{client_id}/config", summary="【管理端】配置裁剪与商业延期")
def update_credential_config(
        client_id: str,
        scope: str = Query(...),
        add_days: int = Query(...),
        max_devices: int = Query(1, ge=1, le=1000, description="当前最多允许几台设备"),
        redirect_uris: str | None = Query(None, description="redirect_uri 白名单，传空字符串可清空"),
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred:
        raise HTTPException(status_code=404, detail="凭证未找到")

    cred.scope = scope
    cred.max_devices = max_devices
    base_time = cred.expire_at if (
                cred.expire_at and cred.expire_at > datetime.datetime.now()) else datetime.datetime.now()
    cred.expire_at = base_time + datetime.timedelta(days=add_days)
    db.commit()
    if redirect_uris is not None:
        uri_whitelist = _parse_redirect_uri_whitelist_input(redirect_uris)
        _save_redirect_uri_whitelist(client_id, uri_whitelist)
    return {"msg": f"凭证 [{cred.credential_name}] 商业授权配置及延期调整成功！", "max_devices": cred.max_devices}


@router.delete("/credentials/{client_id}", summary="【管理端】物理吊销并剔除商业凭证")
def delete_credential(
        client_id: str,
        current_user: User = Depends(RBACChecker("admin:delete")),
        db: Session = Depends(get_db)
):
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred:
        raise HTTPException(status_code=404, detail="凭证不存在")
    db.delete(cred)
    db.commit()
    return {"msg": f"凭证 [{cred.credential_name}] 已被管理端物理强制全盘吊销抹除"}


# ==================== 📋 模块四：备用资产兼容查询管线 ====================

@router.get("/apps/list", summary="【管理端】拉取级联应用结构表")
def list_all_apps(
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    query = db.query(App)
    total = query.count()
    apps = query.order_by(App.id.desc()).offset((page - 1) * limit).limit(limit).all()
    result = []
    for a in apps:
        result.append({
            "app_id": a.id, "app_name": a.app_name, "is_active": a.is_active,
            "credentials": [{"credential_name": c.credential_name, "client_id": c.client_id, "scope": c.scope,
                             "is_active": c.is_active,
                             "expire_at": c.expire_at.strftime("%Y-%m-%d %H:%M:%S") if c.expire_at else "永久有效"} for
                            c in a.credentials]
        })
    return {"code": 200, "count": total, "data": result}

# --- 1. 用户列表分页穿透查询 ---
@router.get("/users/list", summary="【管理端】全量用户矩阵穿透审计")
def get_admin_users_list(
        page: int = Query(1, ge=1, description="当前页码"),
        limit: int = Query(10, ge=1, le=100, description="每页分页页长"),
        username: str = Query(None, description="模糊检索用户名"),
        is_active: str = Query(None, description="状态筛选"),
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    query = db.query(User)

    if username and username.strip():
        query = query.filter(User.username.like(f"%{username}%"))
    if is_active is not None and is_active.strip() != "":
        query = query.filter(User.is_active == (is_active.lower() == "true"))

    total = query.count()
    users = query.order_by(User.id.desc()).offset((page - 1) * limit).limit(limit).all()

    data_list = []
    for u in users:
        # 1. 提取角色名称
        roles_list = [r.name for r in u.roles]

        # 2. 🎯 聚合权限：角色权限 + 独立追加权限
        perms_list = set()

        # 从角色中聚合
        for r in u.roles:
            if hasattr(r, 'permissions'):
                for p in r.permissions:
                    if p.name:
                        perms_list.add(p.name)

        # 从独立权限中聚合 (这是你之前缺失的关键点)
        if hasattr(u, 'extra_permissions'):
            for p in u.extra_permissions:
                if p.name:
                    perms_list.add(p.name)

        data_list.append({
            "id": u.id,
            "username": u.username,
            "nickname": u.nickname or u.username,
            "is_active": u.is_active,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S") if u.created_at else "-",
            "roles": roles_list,
            "permissions": list(perms_list)  # 这里返回的是���并后的完整权限列表
        })

    return {"code": 0, "msg": "success", "count": total, "data": data_list}


# --- 2. 风控核心：用户一键封禁/解封并强制踢下线 ---
@router.post("/users/toggle_status", summary="【管理端】全网维度资产熔断与解冻")
def toggle_user_status(
        payload: UserToggleStatusInput,  # 🌟 由 Form 改为 Pydantic 接收
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    target_user = db.query(User).filter(User.id == payload.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="目标资产不存在")

    if target_user.username == "admin":
        raise HTTPException(status_code=400, detail="系统最高根权限超级管理员拒绝自我熔断")

    target_user.is_active = payload.is_active
    db.commit()

    if not payload.is_active:
        try:
            for key in redis_client.scan_iter("sess_*"):
                stored_user = redis_client.get(key)
                if stored_user and stored_user.decode("utf-8") == target_user.username:
                    redis_client.delete(key)
        except Exception:
            pass

    status_text = "激活受信" if payload.is_active else "风控隔离并强行全网��断下线"
    return {"status": "success", "message": f"用户 [{target_user.username}] 已成功切换为 {status_text} 状态"}


@router.post("/users/batch_toggle_status", summary="【管理端】批量启用/禁用用户")
def batch_toggle_user_status(
        payload: BatchUserStatusInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    target_ids = sorted({int(uid) for uid in payload.user_ids if int(uid) > 0})
    if not target_ids:
        raise HTTPException(status_code=400, detail="至少需要一个有效 user_id")

    users = db.query(User).filter(User.id.in_(target_ids)).all()
    if not users:
        raise HTTPException(status_code=404, detail="未找到目标用户")

    changed = 0
    skipped = 0
    for user_item in users:
        if user_item.username == "admin":
            skipped += 1
            continue
        user_item.is_active = payload.is_active
        changed += 1
        if not payload.is_active:
            revoke_user_redis_sessions(int(user_item.id))

    db.commit()
    return {
        "status": "success",
        "message": "批量状态切���完成",
        "updated": changed,
        "skipped": skipped
    }

# 权限修改接口，接收用户 ID 和新的权限列���以及是增还是删，更新数据库中的用户权限
@router.post("/users/update_permissions", summary="【管理端】更新用户独立权限")
def update_user_permissions(
        payload: UserPermissionUpdateSchema,
        # ���� 1. 修正 RBACChecker 传参，升级拦截权限为写权限
        current_user: User = Depends(RBACChecker("admin:write", "admin:update")),
        db: Session = Depends(get_db)
):
    # 🌟 2. 改用 Schema 获取 user_id
    target_user = db.query(User).filter(User.id == payload.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="目标用户不存在")

    # 🌟 3. 不再需要繁琐的字符串 split 过滤，直接用列表
    updated = False
    for perm_name in payload.permissions:
        perm = db.query(Permission).filter(Permission.name == perm_name).first()
        if not perm:
            continue

        if payload.action == "add":
            if perm not in target_user.extra_permissions:
                target_user.extra_permissions.append(perm)
                updated = True
        elif payload.action == "remove":
            if perm in target_user.extra_permissions:
                target_user.extra_permissions.remove(perm)
                updated = True
            else:
                return {
                    "status": "fail",
                    "message": f"权限 [{perm_name}] 属于角色赋予，无法从独立权限中移除。"
                }
        else:
            raise HTTPException(status_code=400, detail="无效的操作类型，必须为 add 或 remove")

    if updated:
        db.commit()
        # 🌟 4. 权限变更，立刻清理该用户的会话缓存，安全合规熔断
        revoke_user_redis_sessions(int(getattr(target_user, "id", 0)))

    return {"status": "success", "message": f"用户 [{target_user.username}] 的独立权限已更新。"}


@router.post("/users/update_roles", summary="【管理端】更新用户权限组")
def update_user_roles(
        payload: UserRoleUpdateSchema,
        # 🌟 1. 修正并收紧权限
        current_user: User = Depends(RBACChecker("admin:write", "admin:update")),
        db: Session = Depends(get_db)
):
    target_user = db.query(User).filter(User.id == payload.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="目标用户不存在")

    updated = False
    # 🌟 2. 干净的循环遍历
    for role_name in payload.roles:
        role = db.query(Role).filter(Role.name == role_name.strip()).first()
        if not role:
            continue

        if payload.action == "add":
            if role not in target_user.roles:
                target_user.roles.append(role)
                updated = True
        elif payload.action == "remove":
            if role in target_user.roles:
                target_user.roles.remove(role)
                updated = True
        else:
            raise HTTPException(status_code=400, detail="无效的操作类型，必须为 add 或 remove")

    if updated:
        try:
            db.commit()
            # 🌟 3. 角色变更意味着权限大洗牌，必须强刷缓存
            revoke_user_redis_sessions(int(getattr(target_user, "id", 0)))
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail="角色更新失���，数据库错误")

    return {
        "status": "success",
        "message": f"用户 [{target_user.username}] 的权限组已更新" if updated else "用户角色无需变更"
    }
# 强制修改用户密码接口，接收用户 ID 和新的密码，更新数据库中的用户密码
@router.post("/users/update_password", summary="【管理端】强制修改用户密码")
def update_user_password(
        payload: UserPasswordUpdateInput,  # 🌟 统一格式
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    target_user = db.query(User).filter(User.id == payload.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="目标用户不存在")

    target_user.password_hash = pwd_context.hash(payload.new_password)
    db.commit()

    try:
        redis_client.delete(f"user_session:{target_user.username}")
    except Exception:
        pass

    return {
        "status": "success",
        "message": f"管理员已强制重置用户 [{target_user.username}] 的密码。该用户可能需要重新登录。"
    }

# 强制删除用户接口，接收用户 ID，删除数据库中的用户
@router.delete("/users/{user_id}", summary="【管理端】物理删除用户")
def delete_user(
        user_id: int,
        current_user: User = Depends(RBACChecker("admin:delete")),  # 🛡️ 用户删除守卫
        db: Session = Depends(get_db)
):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="目标用户不存在")

    if target_user.username == "admin":
        raise HTTPException(status_code=400, detail="系统最高根权限超级管理员禁止被删除")

    db.delete(target_user)
    db.commit()
    dispatch_webhook_event(
        event_type="user.delete",
        payload={
            "user_id": target_user.id,
            "status": "terminated"
        },
        db=db
    )
    return {"status": "success", "message": f"用户 [{target_user.username}] 已被物理删除"}

# 强制创建用户接口，接收用户名、密码和权限组，创建新的用户
@router.post("/users/create", summary="【管理端】强制创建用户")
def create_user(
        payload: UserCreateInput,  # 🌟 全面拥抱 JSON
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="用户名已存在")

    # 🌟 前端可以直接传干净的数组，不需要再用传统的逗号切分字符串了
    user_roles = []
    for role_name in payload.roles:
        role = db.query(Role).filter(Role.name == role_name.strip()).first()
        if role:
            user_roles.append(role)

    new_user = User(
        username=payload.username,
        password_hash=pwd_context.hash(payload.password)
    )
    if hasattr(new_user, "roles"):
        new_user.roles = user_roles
    db.add(new_user)
    db.commit()
    dispatch_webhook_event(
        event_type="user.create",
        payload={
            "user_id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "created_at": str(new_user.created_at)
        },
        db=db
    )
    return {"status": "success", "message": f"用户 [{payload.username}] 已成功创建"}

# 强制修改用户昵称接口，接收用户 ID 和新的昵称，更新数据库中的用户昵称
@router.post("/users/update_nickname", summary="【管理端】强制修改用户昵称")
def update_user_nickname(
        payload: UserNicknameUpdateInput,  # 🌟 统一格式
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    target_user = db.query(User).filter(User.id == payload.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="目标用户不存在")

    target_user.nickname = payload.new_nickname
    db.commit()
    return {"status": "success", "message": f"用户 [{target_user.username}] 的昵称已成功更新"}


# ==================== 🏢 租户空间审批管理 ====================

@router.post("/system/bootstrap", summary="【管理端】���始化核心角色与权限种子")
def bootstrap_system_seed(
        current_user: User = Depends(RBACChecker("admin:create", "admin:update")),
        db: Session = Depends(get_db)
):
    if not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="仅超级管理员可执行初始化")

    seed_scopes = {
        "read": "全局可读权限",
        "write": "全局可写权限",
        "tenant:user:create": "租户管理端-邀请创建使用者账号",
        "tenant:app:read": "租户管理端-查看本租户应用列表",
        "tenant:app:create": "租户管理端-创建本租户应用",
        "tenant:credential:read": "租户管理端-查看本租户应用凭证",
        "tenant:credential:create": "租户管理端-签发本租户应用凭证",
        "tenant:space:review": "超级管理员-审批租户空间",
        "webhook:create": "Webhook-创建订阅端点",
        "webhook:update": "Webhook-更新订阅端点",
        "webhook:list": "Webhook-查看订阅端点",
        "webhook:delete": "Webhook-删除订阅端点",
        "webhook:logs": "Webhook-查看投递日志",
        "admin:read": "中台管理端-查看",
        "admin:create": "中台管理端-创建",
        "admin:update": "��台管理端-更新",
        "admin:delete": "中台管理端-删除",
    }

    created_permissions = 0
    for scope_name, desc in seed_scopes.items():
        exists = db.query(Permission).filter(Permission.name == scope_name).first()
        if not exists:
            db.add(Permission(name=scope_name, description=desc))
            created_permissions += 1
    db.commit()

    all_seed_permissions = db.query(Permission).filter(Permission.name.in_(list(seed_scopes.keys()))).all()
    by_name = {p.name: p for p in all_seed_permissions}

    def _ensure_role(role_name: str, role_desc: str, perm_names: list[str]) -> int:
        role = db.query(Role).filter(Role.name == role_name).first()
        created = 0
        if not role:
            role = Role(name=role_name, description=role_desc)
            db.add(role)
            db.flush()
            created = 1
        existing = {p.name for p in role.permissions}
        for perm_name in perm_names:
            perm_obj = by_name.get(perm_name)
            if perm_obj and perm_name not in existing:
                role.permissions.append(perm_obj)
        return created

    created_roles = 0
    created_roles += _ensure_role("super_admin", "系统最高权力控制组", list(seed_scopes.keys()))
    created_roles += _ensure_role("standard_user", "��通注册合规用户组", ["read", "write"])
    created_roles += _ensure_role(
        "tenant_admin",
        "租户空间管理员",
        [
            "read", "write", "tenant:user:create", "tenant:app:read", "tenant:app:create",
            "tenant:credential:read", "tenant:credential:create", "webhook:create", "webhook:update",
            "webhook:list", "webhook:delete", "webhook:logs"
        ],
    )

    db.commit()
    return {
        "status": "success",
        "message": "系统种子初始化完成",
        "created_permissions": created_permissions,
        "created_roles": created_roles,
    }

@router.get("/tenants/list", summary="【超管】租户空间列表与审批状态")
def list_tenants(
        page: int = Query(1, ge=1),
        limit: int = Query(20, ge=1, le=200),
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    if not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="仅允许超级管理员查看租户审批列表")

    query = db.query(DeveloperGroup)
    total = query.count()
    groups = query.order_by(DeveloperGroup.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return {
        "status": "success",
        "count": total,
        "data": [
            {
                "group_id": g.id,
                "group_name": g.group_name,
                "group_code": g.group_code,
                "status": g.status,
                "is_active": g.is_active,
                "review_note": g.review_note,
                "reviewed_at": g.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if g.reviewed_at else None,
                "expire_at": g.expire_at.strftime("%Y-%m-%d %H:%M:%S") if g.expire_at else None,
                "owner_user_id": g.owner_user_id,
                "owner": _resolve_group_owner_name(db, g)
            }
            for g in groups
        ]
    }


@router.post("/tenants/{group_id}/review", summary="【超管】审批租户空间")
def review_tenant(
        group_id: int,
        payload: TenantReviewInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    if not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="仅允许超级管理员审批租户空间")

    target = db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="租户空间不存在")

    action = (payload.action or "").lower().strip()
    now_time = datetime.datetime.now()

    owner_user = None
    ensure_role_changed = False
    if action == "approve":
        expire_at = _parse_expire_at(payload.expire_at)
        if not expire_at:
            raise HTTPException(status_code=400, detail="审批通过时必须提供 expire_at")
        target.status = "approved"
        target.is_active = True
        target.expire_at = expire_at
        owner_user = db.query(User).filter(User.id == target.owner_user_id).first() if target.owner_user_id else None
        ensure_role_changed = _ensure_tenant_admin_role_active(db, owner_user)
    elif action == "reject":
        target.status = "rejected"
        target.is_active = False
        target.expire_at = None
    else:
        raise HTTPException(status_code=400, detail="action 仅支持 approve 或 reject")

    db.commit()
    db.refresh(target)
    if owner_user and ensure_role_changed:
        _clear_user_rbac_cache(int(owner_user.id))
    return {
        "status": "success",
        "message": f"租户空间 [{target.group_name}] 审批已完成",
        "data": {
            "group_id": target.id,
            "status": target.status,
            "expire_at": target.expire_at.strftime("%Y-%m-%d %H:%M:%S") if target.expire_at else None
        }
    }
