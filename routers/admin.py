import datetime
import jwt
from typing import Optional
from fastapi import APIRouter, Query, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# 导入你的底层数据库实体与依赖
from database import get_db, App, AppCredential, DeveloperGroup, User, Role, Permission
from utils.crypto import generate_random_keys, hash_secret, create_jwt_token
from config import SECRET_KEY
from sqlalchemy import func
from database import AppDevice

# 初始化全新架构的路由
router = APIRouter(prefix="/admin", tags=["OnAuth 核心管理中台管线"])


# ==================== 🔐 核心：RBAC 动态多渠道权限看门狗 ====================

class RBACChecker:
    """
    分布式全信道 RBAC 动态权限审查器
    """

    def __init__(self, required_permission: str):
        # 🎯 实例化时传入该接口所需的细粒度权限标识，例如 "admin:read"
        self.required_permission = required_permission

    def __call__(self, request: Request, db: Session = Depends(get_db)):
        # 🚀 1. 多渠道提取令牌：优先从 Cookie 池子捞，捞不到再看请求头 Headers
        auth_token = request.cookies.get("auth_token") or request.cookies.get("token")
        if not auth_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                auth_token = auth_header.split(" ")[1]

        if not auth_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="身份凭证已缺失，请重新登录"
            )

        try:
            # 🚀 2. 强安全性 JWT 签名校验
            payload = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
            username: str = payload.get("sub") or payload.get("client_id") or payload.get("username")
            if username is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="非法令牌结构")

            # 🚀 3. 拦截第一层：锁定激活状态的用户主体
            user = db.query(User).filter(User.username == username, User.is_active == True).first()
            if user is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="当前管理员席位已被中台吊销")

            # 🚀 4. 🔓 提取该账号在 RBAC 权限组里绑定的所有独立 Permission.name
            user_permissions = set()
            for role in user.roles:
                for perm in role.permissions:
                    user_permissions.add(perm.name)

            # 🚀 5. 🎯 核心拦截第二层：高强度管理 Scope 硬核比对
            if self.required_permission not in user_permissions:
                print(
                    f"⚠️ [OnAuth 越权警报] 账户 [{username}] 企图非法操作需要 [{self.required_permission}] 的接口，已被安全隔离！")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"安全合规熔断：您所在的权限组缺少 [{self.required_permission}] 权限！"
                )

            return user

        except jwt.PyJWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="认证凭证已过期或被非法篡改")


# ==================== 📦 Pydantic 交互数据流模型沙箱 ====================

class AppCreateInput(BaseModel):
    group_id: int = Field(..., description="所属工作室ID")
    app_name: str = Field(..., min_length=1, max_length=64, description="应用名称")
    app_logo: Optional[str] = Field(None, description="应用 Logo URL")
    owner: Optional[str] = Field("admin", description="所有人")


class AppStatusInput(BaseModel):
    is_active: bool


class GroupCreateInput(BaseModel):
    group_name: str = Field(..., min_length=1, max_length=64)
    description: Optional[str] = None


class GroupToggleInput(BaseModel):
    is_active: bool
    description: Optional[str] = None


class CredentialStatusInput(BaseModel):
    is_active: bool


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


@router.get("/dashboard/stats", summary="【管理端】首页核心大屏实时指标监控")
def get_dashboard_stats(
        current_user: User = Depends(RBACChecker("admin:read")),  # 🛡️ 只读权限看门狗即可
        db: Session = Depends(get_db)
):
    # 🎯 1. 真实数据：实时计算用户总数
    total_users = db.query(func.count(User.id)).scalar() or 0

    # 🎯 2. 真实数据：实时计算到期熔断触发频次（已被锁定/禁用，或已过期的商业凭证总数）
    now_time = datetime.datetime.now()
    frozen_credentials = db.query(func.count(AppCredential.id)).filter(
        (AppCredential.is_active == False) | (AppCredential.expire_at < now_time)
    ).scalar() or 0

    # 🎯 3. 真实数据：实时计算在线/活跃设备总数（最近 15 分钟内有心跳活跃过的独立硬件指纹数）
    active_cutoff = now_time - datetime.timedelta(minutes=15)
    active_devices = db.query(func.count(AppDevice.id)).filter(
        AppDevice.last_seen_at >= active_cutoff
    ).scalar() or 0

    # 🎯 4. 🚀 【硬核改造】从数据库抽取 100% 真实边缘设备近 7 日授信通信激活趋势
    # 计算 6 天前的起始日期（连同今天刚好组成 7 天时间轴）
    seven_days_ago = now_time.date() - datetime.timedelta(days=6)

    # 使用 SQL 执行高效率的按天分组聚合并过滤历史流水
    raw_trend = db.query(
        func.date(AppDevice.activated_at).label("act_date"),
        func.count(AppDevice.id).label("day_count")
    ).filter(
        func.date(AppDevice.activated_at) >= seven_days_ago
    ).group_by(
        func.date(AppDevice.activated_at)
    ).all()

    # 将数据库查询回来的原始对象关系映射转化成瞬时检索字典 {"2026-05-18": 5, ...}
    trend_map = {str(row.act_date): row.day_count for row in raw_trend}

    # 完美补齐近 7 日时间轴：如果某天没有新设备激活，字典查不到就自动补 0，绝不断流
    device_trend = []
    for i in range(6, -1, -1):
        target_date = (now_time - datetime.timedelta(days=i)).date()
        date_str = target_date.strftime("%Y-%m-%d")  # 用于匹配数据库结果
        display_str = target_date.strftime("%m-%d")  # 用于回传前端 Layui 渲染

        device_trend.append({
            "date": display_str,
            "count": trend_map.get(date_str, 0)  # 🎯 查到即真实数量，查不到说明当天没有激活，安全补 0
        })

    return {
        "status": "success",
        "data": {
            "total_users": total_users,
            "frozen_frequency": frozen_credentials,
            "active_devices": active_devices,
            "device_trend": device_trend
        }
    }

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