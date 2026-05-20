import datetime

import psutil
import redis
from fastapi import APIRouter, Query, Depends, HTTPException, Form
from passlib.context import CryptContext
from sqlalchemy.orm import Session

# 导入你的底层数据库实体与依赖
from database import get_db, App, AppCredential, DeveloperGroup, User, Role, Permission
from schemas.PermissionUpdateSchema import UserPermissionUpdateSchema, UserRoleUpdateSchema
from utils.crypto import generate_random_keys, hash_secret, create_jwt_token
from sqlalchemy import func
from database import AppDevice
from database import App, DeveloperGroup
from middlewares.auth import redis_client
import json
from middlewares.rbac import RBACChecker
from schemas.admin_schema import GroupCreateInput, GroupToggleInput, AppCreateInput, AppStatusInput, CredentialStatusInput
from schemas.admin_schema import UserCreateInput, UserNicknameUpdateInput,UserPasswordUpdateInput,UserToggleStatusInput


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

# ==================== 🏢 模块一：工作室组织空间资产管控 ====================

@router.get("/groups/list", summary="【管理端】拉取全量工作室组织资产")
def list_all_groups(
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    groups = db.query(DeveloperGroup).order_by(DeveloperGroup.id.desc()).all()
    result = []
    for g in groups:
        result.append({
            "id": g.id,
            "group_name": g.group_name,
            "description": getattr(g, "description", "暂无说明") or "暂无说明",  # 🛡️ 安全防御容错，防止模型字段未迁移时报错
            "is_active": g.is_active
        })
    return result


@router.post("/groups", summary="【管理端】新增工作室主体")
def create_group(
        payload: GroupCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    existing = db.query(DeveloperGroup).filter(DeveloperGroup.group_name == payload.group_name).first()
    if existing:
        raise HTTPException(status_code=400, detail="该工作室名称已被注册")

    # 🎯 建立实例：根据你的数据库模型字段灵活适配描述
    insert_data = {"group_name": payload.group_name}
    if hasattr(DeveloperGroup, 'description'):
        insert_data["description"] = payload.description

    new_group = DeveloperGroup(
        group_name=payload.group_name,
        description=payload.description
    )
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return {"msg": "工作室主体开通成功", "group_id": new_group.id, "group_name": new_group.group_name}


@router.post("/groups/{group_id}/toggle", summary="【管理端】工作室状态切换(兼容旧前端直发POST请求)")
@router.put("/groups/{group_id}/toggle", summary="【管理端】一键开关工作组/联动熔断/修改备注")
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
    return {"msg": f"工作室 [{name}] 及其旗下所有应用凭证已被全盘风暴级级联擦除"}


# ==================== 📱 模块二：独立应用多租户产品生命周期 ====================

@router.get("/apps/flat_list", summary="【管理端】拉取平铺的应用资产大盘（含组织信息）")
def list_apps_flat(
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    apps = db.query(App).order_by(App.id.desc()).all()
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
    return result


@router.post("/apps", summary="【管理端】在指定工作室下创建独立应用")
def create_app(
        payload: AppCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    group_exists = db.query(DeveloperGroup).filter(DeveloperGroup.id == payload.group_id).first()
    if not group_exists:
        raise HTTPException(status_code=404, detail="归属工作室主体不存在，无法创建应用")

    new_app = App(
        group_id=payload.group_id,
        app_name=payload.app_name,
        app_logo=payload.app_logo,
        owner=payload.owner
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
        import logging
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
        AppDevice.last_seen_at >= active_cutoff
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
    return {
        "status": "success",
        "username": current_user.username,
        "nickname": current_user.nickname or "普通合规用户"
    }


@router.put("/apps/{app_id}/status", summary="【管理端】一键启停/熔断独立应用")
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


# ==================== 🔑 模块三：商业授权凭证与激活码下发 ====================

@router.get("/credentials/flat_list", summary="【管理端】拉取全量凭证激活码大盘")
def list_credentials_flat(
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    credentials = db.query(AppCredential).order_by(AppCredential.id.desc()).all()
    result = []
    for c in credentials:
        app_name = c.app.app_name if c.app else "未知应用"
        group_name = c.app.group.group_name if (c.app and c.app.group) else "未知组织"

        result.append({
            "id": c.id,
            "client_id": c.client_id,
            "credential_name": c.credential_name,
            "scope": c.scope,
            "is_active": c.is_active,
            "expire_at": c.expire_at.strftime("%Y-%m-%d %H:%M:%S") if c.expire_at else "永久有效",
            "app_name": app_name,
            "group_name": group_name
        })
    return result


@router.post("/apps/{app_id}/credentials", summary="【管理端】签发应用全新商业凭证并下发激活码")
def create_app_credential(
        app_id: int,
        credential_name: str = Query(...),
        scope: str = "read",
        valid_days: int = Query(365),
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    target_app = db.query(App).filter(App.id == app_id).first()
    if not target_app:
        raise HTTPException(status_code=404, detail="应用不存在")

    client_id, client_secret = generate_random_keys()
    expire_time = datetime.datetime.now() + datetime.timedelta(days=valid_days)

    new_credential = AppCredential(
        app_id=app_id,
        credential_name=credential_name,
        client_id=client_id,
        client_secret_hash=hash_secret(client_secret),
        scope=scope,
        expire_at=expire_time
    )
    db.add(new_credential)
    db.commit()

    long_lived_token = create_jwt_token(client_id=client_id, scope=scope, expire_at=expire_time, token_type="license")
    return {
        "msg": "成功开通授权凭证并生成激活码！",
        "client_id": client_id,
        "client_secret": client_secret,
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


@router.post("/credentials/{client_id}/config", summary="【管理端】同步更新配置(兼容旧前端)")
@router.put("/credentials/{client_id}/config", summary="【管理端】配置裁剪与商业延期")
def update_credential_config(
        client_id: str,
        scope: str = Query(...),
        add_days: int = Query(...),
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred:
        raise HTTPException(status_code=404, detail="凭证未找到")

    cred.scope = scope
    base_time = cred.expire_at if (
                cred.expire_at and cred.expire_at > datetime.datetime.now()) else datetime.datetime.now()
    cred.expire_at = base_time + datetime.timedelta(days=add_days)
    db.commit()
    return {"msg": f"凭证 [{cred.credential_name}] 商业授权配置及延期调整成功！"}


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
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    apps = db.query(App).all()
    result = []
    for a in apps:
        result.append({
            "app_id": a.id, "app_name": a.app_name, "is_active": a.is_active,
            "credentials": [{"credential_name": c.credential_name, "client_id": c.client_id, "scope": c.scope,
                             "is_active": c.is_active,
                             "expire_at": c.expire_at.strftime("%Y-%m-%d %H:%M:%S") if c.expire_at else "永久有效"} for
                            c in a.credentials]
        })
    return result

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
            "permissions": list(perms_list)  # 这里返回的是合并后的完整权限列表
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

    status_text = "激活受信" if payload.is_active else "风控隔离并强行全网切断下线"
    return {"status": "success", "message": f"用户 [{target_user.username}] 已成功切换为 {status_text} 状态"}

# 权限修改接口，接收用户 ID 和新的权限列表以及是增还是删，更新数据库中的用户权限
@router.post("/users/update_permissions", summary="【管理端】更新用户独立权限")
def update_user_permissions(
        payload: UserPermissionUpdateSchema,
        # 🌟 1. 修正 RBACChecker 传参，升级拦截权限为写权限
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
        revoke_user_redis_sessions(target_user.id)

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
        role = db.query(Role).filter(Role.name == role_name).first()
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
            revoke_user_redis_sessions(target_user.id)
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail="角色更新失败，数据库错误")

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

    if target_user.username == "admin":
        raise HTTPException(status_code=400, detail="系统最高根权限超级管理员密码禁止被修改")

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
        password_hash=pwd_context.hash(payload.password),
        roles=user_roles
    )
    db.add(new_user)
    db.commit()
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