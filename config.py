# ================= 数据库配置开关 =================
# 可选值: "sqlite" 或 "mysql"
DB_TYPE = "sqlite"

# JWT 加密密钥
SECRET_KEY = "PLATFORM_INTERNAL_GLOBAL_SECRET_KEY"
ALGORITHM = "HS256"

# 根据选择组合连接字符串
if DB_TYPE == "sqlite":
    # SQLite 数据库文件将生成在当前目录下，名为 apps.db
    DATABASE_URL = "sqlite:///./apps.db"
elif DB_TYPE == "mysql":
    # MySQL 配置：用户名:密码@用户IP:端口/数据库名
    DB_USER = "root"
    DB_PASS = "123456"
    DB_HOST = "127.0.0.1"
    DB_PORT = "3306"
    DB_NAME = "auth_platform"
    DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
else:
    raise ValueError("不支持的数据库类型，请选择 'sqlite' 或 'mysql'")