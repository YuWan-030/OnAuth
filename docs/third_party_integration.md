# 第三方接入教程（授权码模式 + 用户资料同步）

> 适用项目：OnAuth（基于 OAuth2 标准流）

本教程说明第三方系统如何通过**授权码模式（authorization_code）**接入 OnAuth，并使用返回的访问令牌获取用户资料，再在第三方系统内创建/更新用户。

---

## 0. 推荐流程（统一认证中心为主）

第三方网站不直接注册本地账号，注册与登录统一交由 OnAuth 完成：

1. 用户在第三方点击“登录/注册”。
2. 前端跳转到 OnAuth `/oauth/authorize` 授权入口或者`/register`。
3. 用户在 OnAuth 完成注册/登录并授权。
4. 第三方通过 `/oauth/token` 换取 `access_token`。
5. 使用 `/auth/me` 拉取用户资料，并在第三方系统内“创建/更新用户”。

该流程确保账号体系唯一，避免多套账号导致的权限割裂。

---

## 1. 前置准备（租户管理员侧）

### 1.1 创建应用

租户管理员在租户端创建应用：

- 接口：`POST /tenant/apps`
- 表单字段：`app_name`、`app_logo`（可选）

示例：

```bash
curl -X POST "https://<onauth-host>/tenant/apps" \
  -H "Authorization: Bearer <tenant_admin_sso_session_id>" \
  -F "app_name=ThirdPartyApp"
```

### 1.2 签发应用凭证

- 接口：`POST /tenant/apps/{app_id}/credentials`
- 表单字段：
  - `credential_name`
  - `scope`（默认 `read`）
  - `redirect_uris`（回调白名单，逗号或换行分隔）
  - `valid_days`（可选）

示例：

```bash
curl -X POST "https://<onauth-host>/tenant/apps/123/credentials" \
  -H "Authorization: Bearer <tenant_admin_sso_session_id>" \
  -F "credential_name=ThirdPartyCred" \
  -F "scope=read" \
  -F "redirect_uris=https://thirdparty.example.com/oauth/callback"
```

返回值中会包含：
- `client_id`
- `client_secret`

> 请安全保存 `client_secret`，不要在前端暴露。

### 1.3 更新/维护回调白名单

- 接口：`PUT /tenant/credentials/{client_id}/config`
- 表单字段：`redirect_uris`（逗号或换行分隔）

---

## 2. 授权码模式接入（推荐）

### 2.1 跳转授权入口（/oauth/authorize）

第三方系统将用户跳转到 OnAuth 授权地址：

```
GET /oauth/authorize
```

参数：
- `client_id`
- `response_type=code`
- `redirect_uri`（必须在白名单内）
- `scope`（建议 `read`）
- `state`（防 CSRF）
- `code_challenge` & `code_challenge_method=S256`（建议使用 PKCE）

示例：
```
https://<onauth-host>/oauth/authorize?client_id=xxx&response_type=code&redirect_uri=https%3A%2F%2Fthirdparty.example.com%2Foauth%2Fcallback&scope=read&state=RANDOMSTATE&code_challenge=...&code_challenge_method=S256
```

### 2.2 用户登录并授权

用户在 OnAuth 页面登录并完成授权，系统将重定向回 `redirect_uri`：

```
https://thirdparty.example.com/oauth/callback?code=code_xxx&state=RANDOMSTATE
```

### 2.3 换取访问令牌（/oauth/token）

- 接口：`POST /oauth/token`
- 表单字段：
  - `grant_type=authorization_code`
  - `client_id`
  - `client_secret`（如未使用 PKCE）
  - `code`
  - `code_verifier`（使用 PKCE 时必须）

示例（PKCE）：

```bash
curl -X POST "https://<onauth-host>/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=xxx" \
  -d "code=code_xxx" \
  -d "code_verifier=YOUR_VERIFIER"
```

返回示例：
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer",
  "expires_in": 86400,
  "scope": "read"
}
```

---

## 3. 获取用户资料（第三方系统调用）

使用 `access_token` 调用用户资料接口：

- 推荐接口：`GET /auth/me`
- 兼容接口：`GET /api/v1/user/get_info`
- Header：`Authorization: Bearer <access_token>`

示例：

```bash
curl "https://<onauth-host>/auth/me" \
  -H "Authorization: Bearer <access_token>"
```

返回示例：
```json
{
  "status": "success",
  "data": {
    "user_id": 101,
    "username": "alice",
    "nickname": "Alice",
    "email": "alice@example.com",
    "roles": ["tenant_admin"],
    "permissions": ["read", "write"],
    "group_id": 7,
    "group_name": "Tenant A",
    "group_code": "TENANT-A",
    "group_status": "approved",
    "group_is_active": true
  }
}
```

> 说明：`/api/v1/user/get_info` 也返回同构数据，可用兼容老系统。

---

## 4. 第三方系统内创建/更新用户

建议做“幂等 upsert”逻辑：

1. 用 `user_id` 作为 **OnAuth 外部唯一标识**（建议存为 `external_user_id`）。
2. 若本地不存在该 `external_user_id`：创建新用户。
3. 若已存在：更新 `username/nickname/email/roles/permissions/group` 等字段。

伪代码示例：

```text
if local_user.external_user_id == onauth.user_id:
    update local user
else:
    create local user with external_user_id = onauth.user_id
```

字段映射建议：
- `external_user_id` ← `data.user_id`
- `username` ← `data.username`
- `email` ← `data.email`
- `display_name` ← `data.nickname`
- `roles`/`permissions` ← `data.roles`/`data.permissions`
- `tenant_info` ← `data.group_*`

---

## 5. 第三方系统触发用户注册（可选）

如需由第三方系统主动在 OnAuth 创建账号，可调用注册接口：

### 5.1 普通用户注册

- 接口：`POST /auth/register`
- 请求体（JSON）：
  - `username`
  - `password`
  - `nickname`（可选）
  - `group_code`（租户空间识别码）

示例：

```bash
curl -X POST "https://<onauth-host>/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "third_user",
    "password": "StrongPass!123",
    "nickname": "Third User",
    "group_code": "TENANT-A"
  }'
```

---

## 6. 刷新令牌（refresh_token）

- 接口：`POST /oauth/token`
- 表单字段：
  - `grant_type=refresh_token`
  - `client_id`
  - `client_secret`
  - `refresh_token`

---

## 7. 服务器到服务器（client_credentials）

如果不需要用户身份，可使用：

- `POST /oauth/token` with `grant_type=client_credentials`

该模式**不绑定用户**，因此无法调用 `/api/v1/user/get_info` 或 `/auth/me`。

---

## 8. 常见错误排查

- `redirect_uri 不在白名单`：检查租户凭证配置。
- `缺少 read 权限`：确认 `tenant_admin` 角色启用且用户绑定角色，必要时清理 RBAC 缓存。
- `会话已过期`：刷新 access_token 或重新走授权流程。
