# 🛡️ OnAuth 多租户统一身份认证与访问控制系统

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Uvicorn-222222?style=for-the-badge&logo=uvicorn&logoColor=white" alt="Uvicorn" />
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="Apache License 2.0" />
</p>

<p align="center"><b>企业级 OAuth2.0 + License 双轨鉴权 · RBAC · 多租户 · 风控 · 会话管理</b></p>

---

## 项目简介

OnAuth 是一个面向企业内网/中台/多租户场景的统一身份认证与访问控制系统，提供：

- OAuth 2.0 授权登录（`authorization_code + PKCE`、`client_credentials`、`refresh_token`）
- 基于 RBAC 的权限控制
- 多租户空间管理与成员管理
- Webhook 订阅与审计
- 风控规则引擎与全局熔断
- 普通用户会话管理
- 应用凭证与设备绑定控制
- 管理端 / 租户端 / 用户中心三套 Web 界面

---

## 当前完成度评价

**完成度：功能完备的 MVP / Beta 版本，约 80%~90%**

### 已完成的核心能力
- OAuth2 授权与令牌签发流程已打通
- PKCE 校验、刷新令牌、客户端凭证模式已支持
- RBAC 权限、租户空间、应用、凭证、会话、设备管理已形成闭环
- 风控规则引擎已可配置，并带有默认安全策略
- 管理端、租户端、用户端页面都已具备可用功能
- 已有 pytest 回归测试覆盖关键模块

### 还不算“生产级”的部分
- 配置仍有硬编码项，需要进一步改为环境变量化
- 仓库需要清理敏感文件后再公开
- README、部署脚本、演示截图还可继续增强
- 生产环境加固、监控、审计、备份策略仍可继续完善

**结论：可以上 GitHub，但建议作为“可运行的开源 MVP / Beta”发布，而不是直接宣称生产级成熟产品。**

---

## 核心特性

| 模块 | 能力 |
| --- | --- |
| 认证 | OAuth2 授权、PKCE、刷新令牌、客户端凭证 |
| 用户 | 登录、注册、资料管理、在线会话管理 |
| 租户 | 空间申请、审核、成员邀请、应用管理 |
| 应用 | 客户端管理、密钥、白名单、设备管理 |
| 风控 | 登录失败验证码、扫描器拦截、SQL 注入、XSS、敏感路径探测、全局熔断 |
| 安全 | Bcrypt 密码哈希、JWT、Redis 会话、设备绑定 |
| 运维 | 健康检查、审计日志、Webhook、Alembic 迁移 |

---

## 技术栈

- **后端**：FastAPI、Uvicorn、SQLAlchemy、Redis
- **认证**：OAuth 2.0、JWT、PKCE
- **数据库**：SQLite / MySQL（代码中当前默认使用 SQLite）
- **前端**：Layui + 原生 HTML / JS
- **测试**：pytest
- **迁移**：Alembic

---

## 项目结构

```text
OnAuth/
├─ app_factory.py          # FastAPI 应用装配
├─ bootstrap.py            # 启动初始化、默认角色/规则种子
├─ config.py               # 当前版本的基础配置
├─ database.py             # ORM 模型与数据库连接
├─ main.py                 # 启动入口
├─ routers/                # OAuth、管理端、租户端、用户端 API
├─ middlewares/            # RBAC、异常处理、操作日志
├─ utils/                  # 认证、安全、风控、验证码等工具
├─ admin_web/              # 管理端页面
├─ tenant_web/             # 租户端页面
├─ user_web/               # 用户中心页面
├─ templates/              # 通用模板
└─ tests/                  # pytest 回归测试
```

---

## 快速启动

### 1. 创建虚拟环境

```bash
python -m venv .venv
```

### 2. 激活虚拟环境

**Windows**

```powershell
.venv\Scripts\Activate.ps1
```

**Linux / macOS**

```bash
source .venv/bin/activate
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 启动服务

```bash
python main.py
```

启动后可访问：

- Swagger：`https://127.0.0.1:8000/docs`
- ReDoc：`https://127.0.0.1:8000/redoc`

> 首次启动时，系统会自动初始化数据库结构、默认角色、默认风控规则和演示账号。

---

## 配置说明

### 当前版本的配置方式

本项目目前仍以 `config.py` 为主进行基础配置，包括：

- 数据库类型
- JWT 密钥
- 数据库连接串

如果你准备部署到自己的环境，建议先检查并修改 `config.py`，避免直接使用仓库里的默认值。

### 建议的生产化方向

后续建议将以下内容改为环境变量：

- `SECRET_KEY`
- 数据库账号密码
- 生产环境域名
- 管理员初始密码
- 端口和协议配置

---

## 风控能力

当前风控系统支持基于表达式的动态规则配置，默认内置策略包括：

- 登录失败验证码
- 防扫描器
- 防恶意 UI / 自动化
- 防 SQL 注入
- 防 XSS 注入
- 高危路径探测

同时支持：

- 全局熔断
- 风控事件记录
- 规则启用 / 停用
- 管理端可视化维护

---

## 测试

```bash
pip install -r requirements-dev.txt
pytest -q
```

当前仓库已经包含关键回归测试，覆盖了：

- 密码哈希与令牌逻辑
- 风控表达式引擎
- OAuth 重定向 URI 匹配
- 用户会话管理
- 设备数量限制
- Windows 异步噪音过滤

---

## 公开到 GitHub 前的建议清单

如果你准备正式公开仓库，建议先做下面几件事：

- [ ] 移除或替换敏感文件：`.env`、`apps.db`、`local_server.crt`、`local_server.key`
- [ ] 添加或完善 `.gitignore`
- [ ] 将 `config.py` 中的硬编码密钥/密码改为环境变量
- [ ] 检查默认管理员密码是否需要改为首次启动随机生成
- [ ] 补充项目截图或页面预览
- [ ] 说明部署环境、数据库初始化和迁移方式
- [ ] 在 README 中明确“这是 MVP/Beta，不是生产级最终版”

---

## 许可证

本项目遵循 **Apache License 2.0**。

你可以自由使用、修改和分发本项目，但请保留原始版权与许可证声明。

---

## 结论

这个项目已经具备了很完整的业务闭环，**可以上传 GitHub**，并且很适合作为一个 **企业级统一认证平台的开源 MVP** 来展示。

不过，**在公开前最好先做一次仓库清理和配置脱敏**，否则会影响专业度，也可能带来安全风险。
