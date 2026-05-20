
from typing import Optional
from pydantic import BaseModel, Field


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


class UserCreateInput(BaseModel):
    username: str = Field(..., min_length=1, max_length=32, description="用户名")
    password: str = Field(..., min_length=6, description="密码，至少6位")
    roles: list[str] = Field(..., description="权限组名称列表，例如 ['admin', 'test']")


class UserPasswordUpdateInput(BaseModel):
    user_id: int = Field(..., description="目标用户ID")
    new_password: str = Field(..., min_length=6, description="新密码，至少6位")


class UserNicknameUpdateInput(BaseModel):
    user_id: int = Field(..., description="目标用户ID")
    new_nickname: str = Field(..., min_length=1, description="新昵称")


class UserToggleStatusInput(BaseModel):
    user_id: int = Field(..., description="目标用户ID")
    is_active: bool = Field(..., description="是否激活")