# client_tools OAuth One-Click

## Goal
Provide an importable helper that can start OAuth2 Authorization Code + PKCE flow by passing only `client_id`.

## Quick import
```python
from client_tools import one_click_oauth_start

ctx = one_click_oauth_start("your_client_id")
print(ctx["auth_url"])        # Authorization URL (already opened in browser by default)
print(ctx["code_verifier"])   # Keep this for token exchange
```

## One-click exchange token
```python
from client_tools import exchange_authorization_code_for_token

token = exchange_authorization_code_for_token(
    client_id="your_client_id",
    client_secret="your_client_secret",
    code="authorization_code_from_callback",
    code_verifier="code_verifier_from_one_click_oauth_start",
)
print(token["access_token"])
```

## Full one-shot flow (authorize + callback + token)
```python
from client_tools import one_click_oauth_authorize_and_exchange

result = one_click_oauth_authorize_and_exchange(
    client_id="your_client_id",
    client_secret="your_client_secret",
)

print(result["callback"]["code"])
print(result["token_response"]["access_token"])
```

Compact return mode:
```python
from client_tools import one_click_oauth_authorize_and_exchange

token = one_click_oauth_authorize_and_exchange(
    client_id="your_client_id",
    client_secret="your_client_secret",
    compact=True,
)
print(token["access_token"])
print(token["refresh_token"])
```

## Refresh and revoke helpers
```python
from client_tools import refresh_access_token, revoke_token

new_token = refresh_access_token(
    client_id="your_client_id",
    client_secret="your_client_secret",
    refresh_token="your_refresh_token",
)

revoke_token(new_token["access_token"], token_type_hint="access_token")
```

## Capture callback code automatically
```python
from client_tools import one_click_oauth_start

result = one_click_oauth_start(
    client_id="your_client_id",
    wait_callback=True,  # start local callback listener and wait
)

print(result["callback"]["code"])
print(result["callback"]["state_ok"])
```

Default callback URI is `http://127.0.0.1:8765/callback`.
If your OAuth app uses another callback, pass `redirect_uri=...`.

## CLI demo
```powershell
python -m client_tools.oauth_demo your_client_id --no-browser
python -m client_tools.oauth_demo your_client_id --wait-callback
python -m client_tools.oauth_demo your_client_id --exchange --client-secret your_secret --code your_code --code-verifier your_verifier
python -m client_tools.oauth_demo your_client_id --one-shot --client-secret your_secret
python -m client_tools.oauth_demo your_client_id --one-shot --client-secret your_secret --compact
python -m client_tools.oauth_demo your_client_id --refresh your_refresh_token --client-secret your_secret
python -m client_tools.oauth_demo your_client_id --revoke your_access_token --revoke-type access_token
```

## Token exchange notes
Use `code_verifier` returned by helper when calling `/oauth/token` with `grant_type=authorization_code`.

