from pydantic import BaseModel, Field
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List
from sqlalchemy.orm import Session
from database import get_db, Role, Permission, User
from middlewares.rbac import RBACChecker

class UserPermissionUpdateSchema(BaseModel):
    user_id: int = Field(..., description="目标用户 ID")
    permissions: List[str] = Field(..., description="权限标识列表，例如 ['user:write', 'report:export']")
    action: str = Field(..., description="操作类型: add 或 remove")

class UserRoleUpdateSchema(BaseModel):
    user_id: int = Field(..., description="目标用户 ID")
    roles: List[str] = Field(..., description="角色标识列表，例如 ['admin', 'developer']")
    action: str = Field(..., description="操作类型: add 或 remove")

class PermissionCreateSchema(BaseModel):
    name: str = Field(..., max_length=64, description="权限节点唯一标识，如 'user:delete'")
    description: Optional[str] = Field(None, max_length=128, description="权限节点中文描述")

    class Config:
        json_schema_extra = {"example": {"name": "order:refund", "description": "订单退款放行权限"}}

class PermissionGroupUpdateSchema(BaseModel):
    role_id: int = Field(..., description="要修改的角色（权限组）ID")
    name: Optional[str] = Field(None, max_length=64, description="新的角色唯一标识，如 'app_developer'")
    description: Optional[str] = Field(None, max_length=128, description="新的角色描述")
    is_active: Optional[bool] = Field(None, description="是否启用该角色")

    # 🌟 核心：更新权限组时，通常需要同时调整它拥有的原子权限节点 ID 列表
    permission_ids: Optional[List[int]] = Field(None, description="全新的权限节点 ID 数组（覆盖式更新）")

    class Config:
        json_schema_extra = {
            "example": {
                "role_id": 2,
                "name": "app_developer_group",
                "description": "全新升级的普通开发者权限组",
                "is_active": True,
                "permission_ids": [1, 2, 4]  # 传入新的权限 ID 集合
            }
        }