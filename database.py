import datetime
import json
import os
from sqlalchemy import create_engine, Table, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey

import config

DATABASE_URL = config.DATABASE_URL


connect_args = {"check_same_thread": False}
# 使用 MySQL 时，connect_args 可以留空或删除，因为它们是 SQLite 特有的参数
# engine = create_engine(DATABASE_URL)
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
Base = declarative_base()

# ==================== 🔐 RBAC 多对多关联中间表 ====================

# 用户 与 角色（权限组）的多对多关联表
user_role_association = Table(
    "user_role_association",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
)

# 角色 与 权限节点 的多对多关联表
role_permission_association = Table(
    "role_permission_association",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)
)

# 用户 与 权限节点 的独立加权关联表（用于给用户单独赋予某权限，不通过角色）
user_permission_association = Table(
    "user_permission_association",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)
)


# ==================== 🏢 三层资产流体系模型 ====================

class WebhookConfig(Base):
    __tablename__ = "webhook_configs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    url = Column(String(500), nullable=False)
    secret = Column(String(255), nullable=True)
    events = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)

    # 🌟 必须添加这一行，并保存文件
    creator_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    created_at = Column(DateTime, default=datetime.datetime.now)

class WebhookLog(Base):
    __tablename__ = "webhook_logs"
    id = Column(Integer, primary_key=True, index=True)
    webhook_id = Column(Integer, ForeignKey("webhook_configs.id", ondelete="CASCADE"))
    event_type = Column(String(100))                             # 触发事件类型
    payload = Column(Text)                                       # 发送报文
    response_body = Column(Text)                                 # 响应内容
    status_code = Column(Integer)                                # HTTP 状态码
    is_success = Column(Boolean)                                 # 是否投递成功
    duration = Column(Integer)                                   # 耗时 (ms)
    creator_id = Column(Integer, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.now)

class DeveloperGroup(Base):
    """1. 【顶级容器】开发者组织/工作室表"""
    __tablename__ = "developer_groups"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    group_name = Column(String(64), nullable=False, unique=True, comment="工作室名称")
    group_code = Column(String(32), nullable=True, unique=True, index=True, comment="租户空间唯一识别码")
    description = Column(String(255), nullable=True)
    owner = Column(String(64), default="admin")
    owner_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(20), default="pending", index=True, comment="租户空间状态: pending/approved/rejected")
    review_note = Column(String(255), nullable=True, comment="审批备注")
    reviewed_at = Column(DateTime, nullable=True, comment="审批时间")
    expire_at = Column(DateTime, nullable=True, comment="空间到期时间")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now)

    apps = relationship("App", back_populates="group", cascade="all, delete-orphan")
    users = relationship("User", back_populates="group", foreign_keys="User.group_id")


class App(Base):
    """2. 【中层容器】独立应用主体表"""
    __tablename__ = "apps"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    group_id = Column(Integer, ForeignKey("developer_groups.id", ondelete="CASCADE"), nullable=False)
    app_name = Column(String(64), nullable=False)
    app_logo = Column(String(255), nullable=True)
    owner = Column(String(64), default="admin")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now)

    group = relationship("DeveloperGroup", back_populates="apps")
    credentials = relationship("AppCredential", back_populates="app", cascade="all, delete-orphan")


class AppCredential(Base):
    """3. 【底层容器】应用凭证/授权表"""
    __tablename__ = "app_credentials"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    app_id = Column(Integer, ForeignKey("apps.id", ondelete="CASCADE"), nullable=False)
    credential_name = Column(String(64), nullable=False)
    client_id = Column(String(64), unique=True, index=True, nullable=False)
    client_secret_hash = Column(String(128), nullable=False)
    scope = Column(String(255), default="read")
    is_active = Column(Boolean, default=True)
    max_devices = Column(Integer, default=1)
    redirect_uris_json = Column(Text, nullable=True, comment="redirect_uri 白名单 JSON 缓存")
    created_at = Column(DateTime, default=datetime.datetime.now)
    updated_at = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    expire_at = Column(DateTime, nullable=True)

    app = relationship("App", back_populates="credentials")
    devices = relationship("AppDevice", back_populates="credential", cascade="all, delete-orphan", lazy="selectin")


class AppDevice(Base):
    """4. 🔒 硬件设备指纹白名单表"""
    __tablename__ = "app_devices"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    credential_id = Column(Integer, ForeignKey("app_credentials.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(String(64), index=True, nullable=False)
    is_revoked = Column(Boolean, default=False, index=True)
    revoked_at = Column(DateTime, nullable=True)
    revoke_reason = Column(String(255), nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    activated_at = Column(DateTime, default=datetime.datetime.now)
    last_seen_at = Column(DateTime, default=datetime.datetime.now)

    credential = relationship("AppCredential", back_populates="devices")


class TenantAdminInviteRecord(Base):
    """租户管理员邀请码历史记录：Redis 仅保存当前有效邀请码，历史与审计落库。"""
    __tablename__ = "tenant_admin_invite_records"

    invite_code = Column(String(128), primary_key=True, index=True, comment="邀请码")
    issuer_username = Column(String(64), nullable=False, index=True, comment="发放人")
    created_at = Column(DateTime, default=datetime.datetime.now, nullable=False, index=True, comment="创建时间")
    expires_at = Column(DateTime, nullable=False, index=True, comment="过期时间")
    status = Column(String(16), default="active", nullable=False, index=True, comment="active/used/revoked/expired")
    used_at = Column(DateTime, nullable=True, index=True, comment="使用时间")
    used_by = Column(String(64), nullable=True, index=True, comment="使用人")
    revoked_at = Column(DateTime, nullable=True, index=True, comment="作废时间")
    revoked_by = Column(String(64), nullable=True, index=True, comment="作废人")
    updated_at = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now, index=True, comment="更新时间")


class OperationLog(Base):
    """操作日志：区分系统管理员与租户管理员"""
    __tablename__ = "operation_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    actor_id = Column(Integer, nullable=False, index=True)
    actor_username = Column(String(64), nullable=False, index=True)
    actor_role = Column(String(32), nullable=False, index=True)  # system_admin / tenant_admin
    group_id = Column(Integer, nullable=True, index=True)
    method = Column(String(10), nullable=False)
    path = Column(String(255), nullable=False)
    action = Column(String(255), nullable=False)
    level = Column(String(10), default="INFO")
    ip = Column(String(64), nullable=True)
    payload = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now, index=True)


# ==================== 🔐 RBAC 核心账号与分离权限体系 ====================

class Permission(Base):
    """权限原子节点：支持自关联树状结构，支持命名空间"""
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(64), unique=True, index=True, nullable=False, comment="权限标识，如 'user:create'")
    description = Column(String(128), nullable=True, comment="权限描述，如 '创建用户'")

    # 🌟 实现树状解耦：父权限ID (允许为空，为空代表顶级权限分类)
    parent_id = Column(Integer, ForeignKey("permissions.id", ondelete="SET NULL"), nullable=True)

    # 建立自关联关系，支持通过 permission.children 获取子权限列表
    parent = relationship("Permission", remote_side=[id], backref="children")


class Role(Base):
    """角色组：纯粹作为权限节点的载体"""
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True,comment="角色ID")
    name = Column(String(64), unique=True, index=True, nullable=False, comment="角色标识，如 'admin'")
    description = Column(String(128), nullable=True, comment="角色描述，如 '管理员角色，拥有所有权限'")
    is_active = Column(Boolean, default=True, comment="角色是否启用，False 代表冻结状态，不再授予权限")

    # 关联多个权限节点
    permissions = relationship("Permission", secondary=role_permission_association, lazy="selectin")


class User(Base):
    """用户表：彻底解耦角色与权限计算"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True, comment="用户ID")
    username = Column(String(64), unique=True, index=True, nullable=False, comment="登录用户名")
    nickname = Column(String(64), nullable=True, comment="用户昵称")
    password_hash = Column(String(128), nullable=False, comment="密码哈希值")
    email = Column(String(128), unique=True, index=True, nullable=True, comment="用户邮箱")
    group_id = Column(Integer, ForeignKey("developer_groups.id", ondelete="SET NULL"), nullable=True, index=True)

    is_active = Column(Boolean, default=True, comment="账户是否激活，False 代表被冻结")
    frozen_by_role = Column(String(32), nullable=True, index=True, comment="冻结来源：system_admin / tenant_admin")
    created_at = Column(DateTime, default=datetime.datetime.now, comment="账户创建时间")
    updated_at = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now, comment="账户更新时间")

    group = relationship("DeveloperGroup", back_populates="users", foreign_keys=[group_id])
    # 多对多关联：角色组
    roles = relationship("Role", secondary=user_role_association, lazy="selectin")
    # 多对多关联：额外独立赋权
    extra_permissions = relationship("Permission", secondary=user_permission_association, lazy="selectin")

    # 🌟 核心高光：动态合并计算出该用户的所有底层权限节点标识（去重）
    @property
    def all_permissions(self) -> set[str]:
        permissions_set = {
            perm.name
            for role in self.roles
            if getattr(role, "is_active", True)
            for perm in role.permissions
            if getattr(perm, "name", None)
        }
        permissions_set.update({
            perm.name
            for perm in self.extra_permissions
            if getattr(perm, "name", None)
        })
        return permissions_set


# ==================== 数据库初始化与获取连接 ====================

def init_db():
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    user_columns = {col["name"] for col in inspector.get_columns("users")}
    if "frozen_by_role" not in user_columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN frozen_by_role VARCHAR(32)"))

    credential_columns = {col["name"] for col in inspector.get_columns("app_credentials")}
    if "redirect_uris_json" not in credential_columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE app_credentials ADD COLUMN redirect_uris_json TEXT"))

    try:
        import redis as redis_lib

        redis_client = redis_lib.Redis(
            host=os.getenv("REDIS_HOST", "127.0.0.1"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            db=0,
            decode_responses=True,
            socket_connect_timeout=float(os.getenv("REDIS_CONNECT_TIMEOUT", "0.5")),
            socket_timeout=float(os.getenv("REDIS_SOCKET_TIMEOUT", "0.5")),
        )

        def _parse_cached_redirect_uris(raw_value: object) -> list[str]:
            if raw_value is None:
                return []
            text_value = str(raw_value or "").strip()
            if not text_value:
                return []
            try:
                parsed = json.loads(text_value)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            except Exception:
                pass
            return [item.strip() for item in text_value.split(",") if item.strip()]

        with SessionLocal() as db:
            credentials = db.query(AppCredential).filter(
                (AppCredential.redirect_uris_json.is_(None)) | (AppCredential.redirect_uris_json == "")
            ).all()
            dirty = False
            for credential in credentials:
                cached = _parse_cached_redirect_uris(redis_client.get(f"oauth:redirect_uris:{credential.client_id}"))
                if cached:
                    credential.redirect_uris_json = json.dumps(cached, ensure_ascii=False)
                    dirty = True
            if dirty:
                db.commit()
    except Exception:
        pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==================== 🧭 风控规则与事件流 ====================

class RiskRule(Base):
    __tablename__ = "risk_rules"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(128), nullable=False, index=True)
    rule_type = Column(String(64), default="GENERIC", index=True)
    target_key = Column(String(128), nullable=True)
    match_key = Column(Text, nullable=False)
    threshold_count = Column(Integer, default=1)
    threshold_window = Column(Integer, default=60)
    action = Column(String(16), default="BLOCK", index=True)
    status = Column(Boolean, default=True)
    creator_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.now)
    updated_at = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)

    events = relationship("RiskEvent", back_populates="rule", cascade="all, delete-orphan")


class RiskEvent(Base):
    __tablename__ = "risk_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("risk_rules.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(16), default="BLOCK", index=True)
    latency_ms = Column(Integer, default=0)
    ip = Column(String(64), nullable=True)
    path = Column(String(255), nullable=True)
    risk_level = Column(String(16), default="medium")
    created_at = Column(DateTime, default=datetime.datetime.now, index=True)

    rule = relationship("RiskRule", back_populates="events")


class RiskGlobalSetting(Base):
    __tablename__ = "risk_settings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    is_melt = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)


class SystemSiteSetting(Base):
    __tablename__ = "system_site_settings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    site_name = Column(String(128), default="OnAuth 云中台")
    domain = Column(String(255), default="https://localhost:8000")
    copyright = Column(String(500), nullable=True)
    updated_by = Column(String(64), nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)


class SystemAnnouncement(Base):
    __tablename__ = "system_announcements"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    type = Column(String(32), default="notice", index=True)
    is_pinned = Column(Boolean, default=False)
    status = Column(String(32), default="published", index=True)
    creator = Column(String(64), default="system")
    creator_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.now, index=True)
    updated_at = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)


init_db()

