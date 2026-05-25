# OAuth 一键 PKCE 使用说明（client_tools/oauth_bootstrap.py）

本说明适用于 `client_tools/oauth_bootstrap.py`，用于一键完成 **OAuth 授权码 + PKCE** 流程，并获取 `access_token`。

> 该工具当前仅支持 PKCE 流程（授权码模式 + code_verifier）。

---

## 1. 前置条件

- 已创建应用并拿到 `client_id`（可选 `client_secret`）
- 已配置回调白名单（redirect_uri 必须在白名单内）
- 本地可监听回调端口（默认 `http://127.0.0.1:8765/callback`）

---

## 2. 安装依赖

```bash
pip install requests
```

---

## 3. 一键 PKCE 授权 + 换取令牌

示例脚本：

```python
from client_tools.oauth_bootstrap import one_click_oauth_authorize_and_exchange

result = one_click_oauth_authorize_and_exchange(
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    auth_base="https://127.0.0.1:8000",
    redirect_uri="http://127.0.0.1:8765/callback",
    scope="read",
    auto_open_browser=True,
    verify_ssl=False,
    compact=True,
)

print(result)
```

返回示例（`compact=True`）：

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer",
  "expires_in": 86400,
  "scope": "read",
  "code": "code_xxx",
  "state": "state_xxx",
  "code_verifier": "verifier_xxx"
}
```

---

## 4. 分步模式（可选）

### 4.1 生成授权链接（PKCE）

```python
from client_tools.oauth_bootstrap import one_click_oauth_start

launch = one_click_oauth_start(
    client_id="YOUR_CLIENT_ID",
    auth_base="https://127.0.0.1:8000",
    redirect_uri="http://127.0.0.1:8765/callback",
    scope="read",
    auto_open_browser=True,
    wait_callback=True,
)

print(launch)
```

### 4.2 使用授权码换取令牌

```python
from client_tools.oauth_bootstrap import exchange_authorization_code_for_token

token_response = exchange_authorization_code_for_token(
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    code="AUTH_CODE_FROM_CALLBACK",
    code_verifier="YOUR_CODE_VERIFIER",
    auth_base="https://127.0.0.1:8000",
    use_basic_auth=True,
    verify_ssl=False,
)

print(token_response)
```

---

## 5. 刷新令牌

```python
from client_tools.oauth_bootstrap import refresh_access_token

refresh_response = refresh_access_token(
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    refresh_token="YOUR_REFRESH_TOKEN",
    auth_base="https://127.0.0.1:8000",
    use_basic_auth=True,
    verify_ssl=False,
)

print(refresh_response)
```

---

## 6. 撤销令牌

```python
from client_tools.oauth_bootstrap import revoke_token

revoke_response = revoke_token(
    token="YOUR_ACCESS_TOKEN",
    auth_base="https://127.0.0.1:8000",
    token_type_hint="access_token",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    verify_ssl=False,
)

print(revoke_response)
```

---

## 7. 常见问题

- **回调失败**：检查 redirect_uri 是否在白名单内，并确保本地端口可监听。
- **证书错误**：服务器自签证书可设置 `verify_ssl=False`。
- **state 不匹配**：确保一次授权流程只使用一次回调。


