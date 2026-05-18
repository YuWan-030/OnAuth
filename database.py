from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime
from config import DATABASE_URL, DB_TYPE

connect_args = {"check_same_thread": False} if DB_TYPE == "sqlite" else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# 1. 应用主体表（支持管理多应用）
class App(Base):
    __tablename__ = "apps"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    app_name = Column(String(64), nullable=False, comment="应用名称")
    owner = Column(String(64), default="admin", comment="应用所有人")
    is_active = Column(Boolean, default=True, comment="应用整体状态")
    # 🌟 生产安全修正：在 SQLAlchemy 中默认时间请用 datetime.datetime.now，不要加括号，
    # 这样才能保证每次插入数据时动态获取当前时间，而不是服务启动的一瞬间锁死的时间。
    created_at = Column(DateTime, default=datetime.datetime.now)

    # 关联凭证表：一个应用对应多个凭证 (1 对 多)
    credentials = relationship("AppCredential", back_populates="app", cascade="all, delete-orphan")


# 2. 凭证/授权表（支持单应用多授权）
class AppCredential(Base):
    __tablename__ = "app_credentials"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    app_id = Column(Integer, ForeignKey("apps.id", ondelete="CASCADE"), nullable=False, comment="所属应用ID")
    credential_name = Column(String(64), nullable=False, comment="凭证别名，如'开发环境'、'线上生产'")

    client_id = Column(String(64), unique=True, index=True, nullable=False, comment="应用标识")
    client_secret_hash = Column(String(128), nullable=False, comment="哈希后的密钥")

    scope = Column(String(255), default="read", comment="该授权允许的权限范围，逗号隔开，如 'read,write'")
    is_active = Column(Boolean, default=True, comment="当前授权凭证是否启用")
    created_at = Column(DateTime, default=datetime.datetime.now)  # 🌟 修正同上

    # ======= 新增：该授权凭证/订阅的到期时间 =======
    expire_at = Column(DateTime, nullable=True, comment="授权到期时间，None表示永久有效")

    # 反向关联
    app = relationship("App", back_populates="credentials")


# ==================== 🔐 新增：用户账号体系表 ====================
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(64), unique=True, index=True, nullable=False, comment="全局唯一登录账号")
    password_hash = Column(String(128), nullable=False, comment="加盐哈希（bcrypt）后的密码密文")

    nickname = Column(String(64), nullable=True, comment="用户昵称")
    is_active = Column(Boolean, default=True, comment="账户状态：True正常，False封禁/熔断")
    created_at = Column(DateTime, default=datetime.datetime.now)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()