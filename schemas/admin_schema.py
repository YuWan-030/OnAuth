from typing import Optional
from pydantic import BaseModel, Field


class AppCreateInput(BaseModel):
    group_id: int = Field(..., description="所属工作室ID")
    app_name: str = Field(..., min_length=1, max_length=64, description="应用名称")
    app_logo: Optional[str] = Field(None, description="应用 Logo 上传后返回的安全路径")
    owner: Optional[str] = Field("admin", description="所有人")


class AppStatusInput(BaseModel):
    is_active: bool


class GroupCreateInput(BaseModel):
    group_name: str = Field(..., min_length=1, max_length=64)
    description: Optional[str] = None
    group_code: Optional[str] = Field(None, min_length=4, max_length=32, description="租户空间唯一识别码")


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


class TenantReviewInput(BaseModel):
    action: str = Field(..., description="审批动作: approve 或 reject")
    expire_at: Optional[str] = Field(None, description="到期时间(ISO 8601)，approve 必填")
    review_note: Optional[str] = Field(None, description="审批备注")


class TenantSpaceAssignInput(BaseModel):
    user_id: int = Field(..., description="要接收空间的租户管理员用户ID")
    bind_user_group: bool = Field(True, description="是否同步把用户归属到该空间")


class RiskRuleCreateInput(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="规则名称")
    rule_type: str = Field("GENERIC", description="规则类型")
    target_key: Optional[str] = Field(None, description="规则目标")
    match_key: str = Field(..., min_length=1, description="匹配表达式")
    threshold_count: int = Field(1, ge=1, description="触发阈值次数")
    threshold_window: int = Field(60, ge=1, description="触发时间窗口(秒)")
    action: str = Field("BLOCK", description="处置动作 BLOCK/MFA/CAPTCHA")
    status: bool = Field(True, description="是否启用")


class RiskRuleUpdateInput(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    rule_type: Optional[str] = Field(None)
    target_key: Optional[str] = Field(None)
    match_key: Optional[str] = Field(None, min_length=1)
    threshold_count: Optional[int] = Field(None, ge=1)
    threshold_window: Optional[int] = Field(None, ge=1)
    action: Optional[str] = Field(None)
    status: Optional[bool] = Field(None)


class RiskRuleStatusInput(BaseModel):
    status: bool = Field(..., description="是否启用")


class RiskGlobalMeltInput(BaseModel):
    is_active: bool = Field(..., description="全局熔断是否启用")


class RiskEventCreateInput(BaseModel):
    rule_id: Optional[int] = Field(None, description="命中规则ID")
    action: str = Field("BLOCK", description="处置动作")
    latency_ms: int = Field(0, ge=0, description="处理耗时(毫秒)")
    ip: Optional[str] = Field(None, description="来源IP")
    path: Optional[str] = Field(None, description="请求路径")
    risk_level: Optional[str] = Field("medium", description="风险等级 low/medium/high")


class AnnouncementCreateInput(BaseModel):
    title: str = Field(..., min_length=1, max_length=255, description="公告标题")
    content: str = Field(..., min_length=1, description="公告内容")
    type: str = Field("notice", description="公告类型 notice/bulletin")
    is_pinned: bool = Field(False, description="是否置顶")
    status: str = Field("published", description="状态 published/draft")


class AnnouncementUpdateInput(BaseModel):
    id: int = Field(..., description="公告ID")
    title: str = Field(..., min_length=1, max_length=255, description="公告标题")
    content: str = Field(..., min_length=1, description="公告内容")
    type: str = Field("notice", description="公告类型 notice/bulletin")
    is_pinned: bool = Field(False, description="是否置顶")
    status: str = Field("published", description="状态 published/draft")


class SiteSettingUpdateInput(BaseModel):
    site_name: str = Field(..., min_length=1, max_length=128, description="站点名称")
    domain: str = Field(..., min_length=1, max_length=255, description="控制台域名")
    copyright: Optional[str] = Field(None, max_length=500, description="版权信息")

