from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db, Role, Permission
from middlewares.rbac import RBACChecker
from schemas.PermissionUpdateSchema import PermissionGroupUpdateSchema
from middlewares.auth import redis_client
router = APIRouter(tags=["【管理接口】权限类核心网关"])


# ============================ 权限组增删改查核心接口 ============================


@router.post("/api/v1/permission/group.update", summary="【核心管理接口】更新权限分组信息")
def update_permission_group(
        payload: PermissionGroupUpdateSchema,  # 1. 接收前端 JSON 传参
        db: Session = Depends(get_db),  # 2. 注入数据库连接
        current_user=Depends(RBACChecker("admin:write", "admin:update"))
):

    # 锁定目标角色（权限组）
    role = db.query(Role).filter(Role.id == payload.role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"更新失败：未找到 ID 为 [{payload.role_id}] 的权限分组"
        )

    # 如果要修改角色的唯一标识符（name），需要检查是否跟别的角色重名
    if payload.name and payload.name != role.name:
        existing_role = db.query(Role).filter(Role.name == payload.name).first()
        if existing_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"更新失败：权限组标识 [{payload.name}] 已被其他分组占用"
            )
        role.name = payload.name


    if payload.description is not None:
        role.description = payload.description

    if payload.is_active is not None:
        # 确保你的 Role 模型上有 is_active 字段
        if hasattr(role, 'is_active'):
            role.is_active = payload.is_active


    if payload.permission_ids is not None:
        # 去数据库里把前端传来的这批 ID 对应的 Permission 实体全部捞出来
        new_permissions = db.query(Permission).filter(Permission.id.in_(payload.permission_ids)).all()

        # 安全防御：防范前端传了不存在的恶意 ID
        if len(new_permissions) != len(set(payload.permission_ids)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="更新失败：传入的权限节点 ID 列表中包含不存在的无效节点"
            )

        role.permissions = new_permissions

    try:
        db.commit()
        db.refresh(role)  # 刷新对象获取最新状态
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据库写入异常，更新事务已回滚: {str(e)}"
        )

    return {
        "status": "success",
        "message": f"权限分组 [{role.name}] 信息及原子节点关联已成功同步更新！",
        "data": {
            "role_id": role.id,
            "name": role.name,
            "description": role.description,
            "current_nodes": [p.name for p in role.permissions]
        }
    }


@router.get("/api/v1/permission/group.list", summary="【核心管理接口】查询权限分组列表")
def list_permission_groups(
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("admin:read", "admin:list"))
):
    roles = db.query(Role).all()
    return {
        "status": "success",
        "data": [
            {
                "role_id": role.id,
                "name": role.name,
                "description": role.description,
                "is_active": getattr(role, 'is_active', None),
                "permissions": [p.name for p in role.permissions]
            }
            for role in roles
        ]
    }

@router.delete("/api/v1/permission/group.delete", summary="【核心管理接口】删除权限分组")
def delete_permission_group(
        role_id: int,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("admin:write", "admin:delete"))
):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"删除失败：未找到 ID 为 [{role_id}] 的权限分组"
        )

    try:
        db.delete(role)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据库删除异常，删除事务已回滚: {str(e)}"
        )

    return {
        "status": "success",
        "message": f"权限分组 [{role.name}] 已成功删除！"
    }


@router.post("/api/v1/permission/group.create", summary="【核心管理接口】创建权限分组")
def create_permission_group(
        payload: PermissionGroupUpdateSchema,  # 1. 接收前端 JSON 传参
        db: Session = Depends(get_db),  # 2. 注入数据库连接
        current_user=Depends(RBACChecker("admin:write", "admin:create"))
):
    if not payload.name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="创建失败：权限分组标识（name）不能为空"
        )

    existing_role = db.query(Role).filter(Role.name == payload.name).first()
    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"创建失败：权限分组标识 [{payload.name}] 已被其他分组占用"
        )

    new_role = Role(
        name=payload.name,
        description=payload.description,
        is_active=getattr(payload, 'is_active', True)
    )

    if payload.permission_ids:
        permissions = db.query(Permission).filter(Permission.id.in_(payload.permission_ids)).all()
        if len(permissions) != len(set(payload.permission_ids)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="创建失败：传入的权限节点 ID 列表中包含不存在的无效节点"
            )
        new_role.permissions = permissions

    try:
        db.add(new_role)
        db.commit()
        db.refresh(new_role)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据库写入异常，创建事务已回滚: {str(e)}"
        )

    return {
        "status": "success",
        "message": f"权限分组 [{new_role.name}] 已成功创建！",
        "data": {
            "role_id": new_role.id,
            "name": new_role.name,
            "description": new_role.description,
            "is_active": getattr(new_role, 'is_active', None),
            "permissions": [p.name for p in new_role.permissions]
        }
    }

@router.get("/api/v1/permission/group.get", summary="【核心管理接口】查询权限分组详情")
def get_permission_group_details(
        role_id: int,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("admin:read", "admin:get"))
):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"查询失败：未找到 ID 为 [{role_id}] 的权限分组"
        )

    return {
        "status": "success",
        "data": {
            "role_id": role.id,
            "name": role.name,
            "description": role.description,
            "is_active": getattr(role, 'is_active', None),
            "permissions": [p.name for p in role.permissions]
        }
    }

@router.get("/api/v1/permission/group.permissions", summary="【核心管理接口】查询权限分组的权限节点列表")
def list_permission_group_nodes(
        role_id: int,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("admin:read", "admin:list"))
):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"查询失败：未找到 ID 为 [{role_id}] 的权限分组"
        )

    return {
        "status": "success",
        "data": [
            {
                "permission_id": perm.id,
                "name": perm.name,
                "description": perm.description
            }
            for perm in role.permissions
        ]
    }

# ==================================== 权限节点增删查核心接口 ====================================

@router.get("/api/v1/permission/permission.get", summary="【核心管理接口】查询权限节点详情")
def get_permission_node_details(
        permission_id: int,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("admin:read", "admin:get"))
):
    perm = db.query(Permission).filter(Permission.id == permission_id).first()
    if not perm:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"查询失败：未找到 ID 为 [{permission_id}] 的权限节点"
        )

    return {
        "status": "success",
        "data": {
            "permission_id": perm.id,
            "name": perm.name,
            "description": perm.description
        }
    }

@router.get("/api/v1/permission/permission.create", summary="【核心管理接口】创建权限节点")
def create_permission_node(
        name: str,
        description: str = None,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("admin:write", "admin:create"))
):
    existing_perm = db.query(Permission).filter(Permission.name == name).first()
    if existing_perm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"创建失败：权限节点标识 [{name}] 已存在"
        )

    new_perm = Permission(name=name, description=description)
    try:
        db.add(new_perm)
        db.commit()
        db.refresh(new_perm)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据库写入异常，创建事务已回滚: {str(e)}"
        )

    return {
        "status": "success",
        "message": f"权限节点 [{new_perm.name}] 已成功创建！",
        "data": {
            "permission_id": new_perm.id,
            "name": new_perm.name,
            "description": new_perm.description
        }
    }

@router.delete("/api/v1/permission/permission.delete", summary="【核心管理接口】删除权限节点")
def delete_permission_node(
        permission_id: int,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("admin:write", "admin:delete"))
):
    perm = db.query(Permission).filter(Permission.id == permission_id).first()
    if not perm:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"删除失败：未找到 ID 为 [{permission_id}] 的权限节点"
        )

    try:
        db.delete(perm)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据库删除异常，删除事务已回滚: {str(e)}"
        )

    return {
        "status": "success",
        "message": f"权限节点 [{perm.name}] 已成功删除！"
    }


# ============================ 权限节点查询接口 ============================

@router.get("/api/v1/permission/node.list", summary="【核心管理接口】查询权限节点列表")
def list_permission_nodes(
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("admin:read", "admin:list"))
):
    permissions = db.query(Permission).all()
    return {
        "status": "success",
        "data": [
            {
                "permission_id": perm.id,
                "name": perm.name,
                "description": perm.description
            }
            for perm in permissions
        ]
    }

# ============================ 💡 抽取缓存安全熔断机制 ============================

def notify_all_sessions_dirty(user_id: int):
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