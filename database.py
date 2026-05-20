import datetime
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

import config

DATABASE_URL = config.DATABASE_URL
connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
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

class DeveloperGroup(Base):
    """1. 【顶级容器】开发者组织/工作室表"""
    __tablename__ = "developer_groups"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    group_name = Column(String(64), nullable=False, unique=True, comment="工作室名称")
    description = Column(String(255), nullable=True)
    owner = Column(String(64), default="admin")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now)

    apps = relationship("App", back_populates="group", cascade="all, delete-orphan")


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
    created_at = Column(DateTime, default=datetime.datetime.now)
    updated_at = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    expire_at = Column(DateTime, nullable=True)

    app = relationship("App", back_populates="credentials")
    devices = relationship("AppDevice", back_populates="credential", cascade="all, delete-orphan")


class AppDevice(Base):
    """4. 🔒 硬件设备指纹白名单表"""
    __tablename__ = "app_devices"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    credential_id = Column(Integer, ForeignKey("app_credentials.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(String(64), index=True, nullable=False)
    activated_at = Column(DateTime, default=datetime.datetime.now)
    last_seen_at = Column(DateTime, default=datetime.datetime.now)

    credential = relationship("AppCredential", back_populates="devices")


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
    permissions = relationship("Permission", secondary=role_permission_association)


class User(Base):
    """用户表：彻底解耦角色与权限计算"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True, comment="用户ID")
    username = Column(String(64), unique=True, index=True, nullable=False, comment="登录用户名")
    nickname = Column(String(64), nullable=True, comment="用户昵称")
    password_hash = Column(String(128), nullable=False, comment="密码哈希值")
    email = Column(String(128), nullable=True, comment="用户邮箱")

    is_active = Column(Boolean, default=True, comment="账户是否激活，False 代表被冻结")
    created_at = Column(DateTime, default=datetime.datetime.now, comment="账户创建时间")

    # 多对多关联：角色组
    roles = relationship("Role", secondary=user_role_association)
    # 多对多关联：额外独立赋权
    extra_permissions = relationship("Permission", secondary=user_permission_association)

    # 🌟 核心高光：动态合并计算出该用户的所有底层权限节点标识（去重）
    @property
    def all_permissions(self) -> set[str]:
        permissions_set = set()

        # 1. 提取角色组里的所有权限
        for role in self.roles:
            if getattr(role, 'is_active', True):
                for perm in role.permissions:
                    permissions_set.add(perm.name)

        # 2. 提取用户身上多带带赋予的独立权限
        for perm in self.extra_permissions:
            permissions_set.add(perm.name)

        return permissions_set


# ==================== 数据库初始化与获取连接 ====================

def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()