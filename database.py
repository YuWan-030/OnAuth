from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime
from config import DATABASE_URL, DB_TYPE

connect_args = {"check_same_thread": False} if DB_TYPE == "sqlite" else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==================== 🔐 RBAC 权限体系多对多中间表 ====================

# 用户 与 角色（权限组）的多对多关联表
user_role_association = Table(
    "user_role_association",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
)

# 角色 与 权限（Scope）的多对多关联表
role_permission_association = Table(
    "role_permission_association",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)
)


# ==================== 🏢 核心高光追加：三层资产流体系模型 ====================

# 1. 【顶级容器】开发者组织/工作室表
class DeveloperGroup(Base):
    __tablename__ = "developer_groups"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    group_name = Column(String(64), nullable=False, unique=True, comment="工作室/组织主体名称，如 'A工作室'")
    description = Column(String(255), nullable=True, comment="运营说明/备注信息")
    owner = Column(String(64), default="admin", comment="该空间或组织的主所有人")
    is_active = Column(Boolean, default=True, comment="工作室空间状态（一键熔断该工作室旗下所有程序）")
    created_at = Column(DateTime, default=datetime.datetime.now)


    # 一个工作室可以开发经营多个独立应用/程序
    apps = relationship("App", back_populates="group", cascade="all, delete-orphan")


# 2. 【中层容器】独立应用主体表
class App(Base):
    __tablename__ = "apps"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    # 🌟 核心升级外键：外键关联到所属的工作室组织空间
    group_id = Column(Integer, ForeignKey("developer_groups.id", ondelete="CASCADE"), nullable=False,
                      comment="所属组织空间ID")

    app_name = Column(String(64), nullable=False, comment="应用独立名称，如 'A.1程序'")
    app_logo = Column(String(255), nullable=True, comment="应用图标URL（用于OAuth2授权界面渲染）")
    owner = Column(String(64), default="admin", comment="应用负责人")
    is_active = Column(Boolean, default=True, comment="应用整体状态")
    created_at = Column(DateTime, default=datetime.datetime.now)

    # 建立上层反向关联与下级凭证级联关联
    group = relationship("DeveloperGroup", back_populates="apps")
    credentials = relationship("AppCredential", back_populates="app", cascade="all, delete-orphan")


# 3. 【底层容器】应用凭证/授权表
class AppCredential(Base):
    __tablename__ = "app_credentials"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    app_id = Column(Integer, ForeignKey("apps.id", ondelete="CASCADE"), nullable=False, comment="所属应用ID")
    credential_name = Column(String(64), nullable=False, comment="凭证别名，如 'PC客户端生产环境', '测试环境沙箱'")

    client_id = Column(String(64), unique=True, index=True, nullable=False, comment="应用标识")
    client_secret_hash = Column(String(128), nullable=False, comment="哈希后的密钥")

    scope = Column(String(255), default="read", comment="该通道允许的最大权限范围，逗号隔开，如 'read,write'")
    is_active = Column(Boolean, default=True, comment="当前授权凭证是否启用")
    created_at = Column(DateTime, default=datetime.datetime.now)
    expire_at = Column(DateTime, nullable=True, comment="授权到期时间")

    max_devices = Column(Integer, default=1, comment="最大允许绑定设备数")

    app = relationship("App", back_populates="credentials")
    devices = relationship("AppDevice", back_populates="credential", cascade="all, delete-orphan")


# 4. 🔒 硬件设备指纹白名单表（维持原样）
class AppDevice(Base):
    __tablename__ = "app_devices"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    credential_id = Column(Integer, ForeignKey("app_credentials.id", ondelete="CASCADE"), nullable=False,
                           comment="关联的授权凭证ID")
    device_id = Column(String(64), index=True, nullable=False, comment="客户端硬件唯一指纹(SHA256)")
    activated_at = Column(DateTime, default=datetime.datetime.now, comment="首次设备激活绑定时间")
    last_seen_at = Column(DateTime, default=datetime.datetime.now, comment="该设备最后一次在线活跃时间")

    credential = relationship("AppCredential", back_populates="devices")


# ==================== 🔐 RBAC 核心账号权限体系（维持原样） ====================

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(64), unique=True, index=True, nullable=False, comment="权限Scope标识")
    description = Column(String(128), nullable=True, comment="权限说明")


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(64), unique=True, index=True, nullable=False, comment="角色全局唯一标识")
    description = Column(String(128), nullable=True, comment="角色组别说明")

    permissions = relationship("Permission", secondary=role_permission_association)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(64), unique=True, index=True, nullable=False, comment="全局唯一登录账号")
    password_hash = Column(String(128), nullable=False, comment="加盐哈希后的密码密文")
    nickname = Column(String(64), nullable=True, comment="用户昵称")
    is_active = Column(Boolean, default=True, comment="账户状态")
    created_at = Column(DateTime, default=datetime.datetime.now)

    roles = relationship("Role", secondary=user_role_association)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()