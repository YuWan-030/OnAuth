# 🛡️ OnAuth 多租户统一身份认证与访问控制系统

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Uvicorn-222222?style=for-the-badge&logo=uvicorn&logoColor=white" alt="Uvicorn" />
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="Apache License 2.0" />
</p>

<p align="center">
  <b>🚀 高性能 · 异步驱动 · 颗粒度权限控制 · 专为现代云原生微服务打造的统一认证底座</b>
</p>

---

## 📢 法律与商业化声明

> ⚠️ **授权模式说明**  
> 本项目遵循 **Apache License 2.0** 协议开源。
>
> 您可以自由使用、修改和分发本项目，无需开源您的修改。但是，若需用于商用或闭源开发，请确保遵守 Apache License 2.0 要求，并保留原作者版权声明。

---

## 🎯 为什么选择 OnAuth？

在构建现代企业级架构时，重复开发身份认证和权限系统无异于重复发明轮子。OnAuth 旨在解决以下核心痛点：

*   **多应用孤岛**：告别每个子系统各自一套用户表的混乱局面，实现真正的 **单点登录 (SSO)**。
*   **权限黑盒**：传统硬编码权限难以维护。OnAuth 提供标准的 **RBAC (基于角色的访问控制)** 模型，权限精确到按钮级。
*   **安全隐患**：底层基于行业标准的 `Bcrypt` 加密算法与标准 `JWT` 令牌，天然防御重放攻击与明文泄露。
*   **零开销冷启动**：系统内置智能环境感知。检测到纯净数据库时，**秒级自动初始化**首个公网演示账号，拒绝繁琐的 SQL 导入。

---

## ✨ 核心特性矩阵 (Feature Matrix)

| 特性分类        | 功能要点                      | 技术实现 / 优势                                               |
|:------------|:--------------------------|:--------------------------------------------------------|
| ⚡ **极致性能**  | 纯异步高并发                    | 基于 FastAPI + Asyncio + Uvicorn 异步事件循环，基于异步事件循环，显著提升并发能力 |
| 🔒 **合规安全** | 行业级防护                     | `passlib` 驱动的 Bcrypt 强哈希（抗撞库）；自带 JWT 黑名单高频鉴权机制          |
| 🔌 **双轨鉴权** | 同时兼容 OAuth2 标准客户端与长期直连激活码 |   OAuth2 提供短期令牌 + 刷新机制，降低泄漏风险；License 用于高信任场景，减少网ⓝ... |
| 🌱 **智能运维** | 零配置启动                     | 控制台引导式环境自检，支持 `.env` 环境变量一键平滑切换开发/生产环境                  |

---

## 🏗️ 系统架构与认证时序 (Architecture)

### 1. 技术栈拓扑
```text
[ 客户端 (Web / App / 小程序) ]
             │  (HTTPS 安全加密传输)
             ▼
   [ Uvicorn ASGI 高性能服务器 ]
             │
   [ FastAPI 异步路由/安全拦截层 ] ◄──► [ Redis 令牌黑名单/频控 ]
             │
   [ SQLAlchemy Async ORM ]
             │
   [ 数据库 (MySQL / PostgreSQL / SQLite) ]
```
### 标准 OAuth 2.0 / JWT 认证时序
```text
用户                第三方客户端                OnAuth 授权后端
 │                      │                            │
 │                      │◄────── 1. 跳转授权页 ────────┤
 ├──── 2. 提交账号密码 ─►│                            │
 │                      ├────── 3. 发起授权请求 ──────►│
 │                      │                            ├─ 4. Bcrypt校验账号密码
 │                      │                            ├─ 5. 生成临时授权码 code
 │                      │◄───── 6. 回调带回 code ──────┤
 │                      │                            │
 │                      ├──── 7. code换取令牌 ────────►│
 │                      │                            ├─ 8. 校验授权码合法性
 │                      │                            ├─ 9. 签发 Access/Refresh 双Token
 │                      │◄──── 10. 返回令牌数据 ───────┤
 📦 本地/安全Cookie持久化存储Token
```
## 🛠️ 快速启动 (Quick Start)

### 1. 运行环境
* **Python**: 3.10 / 3.11 / 3.12+
* **支持系统**: Windows, Linux, macOS

### 2. 秒级部署流程

```bash
# 1. 克隆高能仓库
git clone [https://github.com/your-organization/OnAuth.git](https://github.com/your-organization/OnAuth.git)
cd OnAuth

# 2. 初始化虚拟隔离环境
python -m venv .venv

# 3. 激活虚拟环境
# Windows 环境:
.venv/Scripts/activate
# Linux / macOS 环境:
source .venv/Scripts/activate

# 4. 安装依赖（已做企业级生产环境版本锁定）
pip install -r requirements.txt
```
### ⚙️ 生产兼容性补丁说明：
> 为彻底解决旧版 `passlib` 无法读取新版 `bcrypt` 内部属性导致的 `AttributeError: module 'bcrypt' has no attribute '__about__'` 致命错误，本项目已在依赖中强制锁...
> ```bash
> pip install "bcrypt==4.0.1"
> ```
> **注意**：请勿使用 `bcrypt` 4.0.0 版本，因为它引入了不兼容的内部结构变更，导致 `passlib` 无法正常工作，从而引发认证系统崩溃。
> 
### 3. 环境配置
**请在项目根目录下创建一个名为 .env 的文件，并写入以下配置：**
```bash
# SERVER CONFIG
APP_ENV=development
APP_HOST=0.0.0.0
APP_PORT=8000

# SECURITY CONFIG
# ⚠️ 警告：由于 Bcrypt 底层算法限制，明文密码切勿超过 72 字节，否则初始化将报错
INITIAL_ADMIN_PASSWORD=SecurePassword123_PleaseChangeMe
JWT_SECRET_KEY=9a7b8c6d5e4f3g2h1i0j_your_super_secret_key

# DATABASE CONFIG
DATABASE_URL=sqlite+aiosqlite:///./onauth.db
```
### 4. 闪电启动
```bash
python main.py
```
**若为首次运行，系统将通过日志输出以下提示：**
```bash
🌱 检测到干净的数据库环境，正在为您初始化创建首个公网演示账号...
🚀 初始化用户成功！默认管理员配置已就绪。
INFO: Uvicorn running on [https://0.0.0.0:8000](https://0.0.0.0:8000) (Press CTRL+C to quit)
```
## 📖 交互式 API 开发者面板

服务运行后，开发者可以通过以下地址实时调试接口：

* **静态/交互式 Swagger 面板 (推荐)**: `https://127.0.0.1:8000/docs` —— 包含全量接口的 Request/Response 结构化示例。
* **ReDoc 深度文档**: `https://127.0.0.1:8000/redoc` —— 适合架构师审阅的结构化技术规格书。

---

## 🔒 生产环境加固规范 (Hardening)

1. **密码长度约束**：Bcrypt 算法原生限制明文长度为 **72 字节**。在前端表单或下游注册逻辑中，请务必增加 `len(password.encode('utf-8')) <= 72` 校验。
2. **密钥轮转**：生产环境（`APP_ENV=production`）下，必须定期更换 `JWT_SECRET_KEY`，且严禁使用默认初始密码。
3. **文档关闭**：在公网生产环境部署时，建议通过配置关闭 `/docs` 路由，防范接口暴露引起的嗅探。

---

## 🤝 参与贡献 (Contributing)

我们极度欢迎并渴望社区的优秀代码贡献！
s
```text
Fork 本仓库 ➔ 新建特性分支 (git checkout -b feature/AmazingFeature) ➔ 提交您的修改 ➔ 发起 Pull Request (PR)
```
## 📄 商业与开源许可证说明

* **开源版本**：本项目遵循 **Apache License 2.0** 开源协议，允许自由使用、修改及分发。 

---