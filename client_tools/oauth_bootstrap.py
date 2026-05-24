import base64
import hashlib
import secrets
import threading
import time
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs
import requests


DEFAULT_AUTH_BASE = "https://localhost:8000"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:8765/callback"


@dataclass
class OAuthLaunchContext:
    client_id: str
    auth_url: str
    state: str
    code_verifier: str
    code_challenge: str
    code_challenge_method: str
    redirect_uri: str


@dataclass
class OAuthCallbackResult:
    code: str | None
    state: str | None
    error: str | None
    raw_query: dict[str, list[str]]


def _urlsafe_b64_without_padding(raw_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")


def generate_pkce_verifier(length: int = 64) -> str:
    if length < 43 or length > 128:
        raise ValueError("PKCE code_verifier length must be in [43, 128]")
    raw = secrets.token_urlsafe(length)
    verifier = raw[:length]
    if len(verifier) < 43:
        verifier = (verifier + secrets.token_urlsafe(43))[:43]
    return verifier


def generate_pkce_challenge(code_verifier: str, method: str = "S256") -> str:
    normalized_method = (method or "S256").upper()
    if normalized_method not in {"S256", "PLAIN"}:
        raise ValueError("code_challenge_method must be 'S256' or 'plain'")
    if normalized_method == "PLAIN":
        return code_verifier
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return _urlsafe_b64_without_padding(digest)


def prepare_oauth_launch(
        client_id: str,
        auth_base: str = DEFAULT_AUTH_BASE,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
        scope: str = "read",
        state: str | None = None,
        code_challenge_method: str = "S256"
) -> OAuthLaunchContext:
    if not client_id or not client_id.strip():
        raise ValueError("client_id is required")

    clean_client_id = client_id.strip()
    clean_state = state.strip() if state else secrets.token_urlsafe(24)
    verifier = generate_pkce_verifier(64)
    challenge = generate_pkce_challenge(verifier, code_challenge_method)
    method = code_challenge_method.upper()

    params = {
        "client_id": clean_client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": clean_state,
        "code_challenge": challenge,
        "code_challenge_method": method,
    }
    auth_url = f"{auth_base.rstrip('/')}/oauth/authorize?{urlencode(params)}"

    return OAuthLaunchContext(
        client_id=clean_client_id,
        auth_url=auth_url,
        state=clean_state,
        code_verifier=verifier,
        code_challenge=challenge,
        code_challenge_method=method,
        redirect_uri=redirect_uri,
    )


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    callback_payload: dict[str, Any] = {}

    def do_GET(self):
        parsed = urlparse(self.path)
        query_dict = parse_qs(parsed.query)
        _OAuthCallbackHandler.callback_payload = {
            "path": parsed.path,
            "query": query_dict,
            "code": (query_dict.get("code") or [None])[0],
            "state": (query_dict.get("state") or [None])[0],
            "error": (query_dict.get("error") or [None])[0],
        }

        if _OAuthCallbackHandler.callback_payload["error"]:
            body = "OAuth callback received error. You can close this window."
            self.send_response(400)
        else:
            body = "OAuth callback received successfully. You can close this window."
            self.send_response(200)

        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format_str, *args):
        return


def wait_for_oauth_callback(redirect_uri: str, timeout_seconds: int = 180) -> OAuthCallbackResult:
    parsed = urlparse(redirect_uri)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("redirect_uri must be http or https")
    if not parsed.hostname or not parsed.port:
        raise ValueError("redirect_uri must include host and port for local callback capture")

    expected_path = parsed.path or "/"
    _OAuthCallbackHandler.callback_payload = {}

    httpd = HTTPServer((parsed.hostname, parsed.port), _OAuthCallbackHandler)
    httpd.timeout = 0.5

    done = {"value": False}

    def _run_once():
        while not done["value"]:
            httpd.handle_request()
            payload = _OAuthCallbackHandler.callback_payload
            if payload and payload.get("path") == expected_path:
                done["value"] = True

    thread = threading.Thread(target=_run_once, daemon=True)
    thread.start()

    start = time.time()
    while time.time() - start <= timeout_seconds:
        payload = _OAuthCallbackHandler.callback_payload
        if payload and payload.get("path") == expected_path:
            done["value"] = True
            break
        time.sleep(0.1)

    done["value"] = True
    try:
        httpd.server_close()
    except Exception:
        pass

    payload = _OAuthCallbackHandler.callback_payload or {}
    return OAuthCallbackResult(
        code=payload.get("code"),
        state=payload.get("state"),
        error=payload.get("error"),
        raw_query=payload.get("query", {}),
    )


def one_click_oauth_start(
        client_id: str,
        auth_base: str = DEFAULT_AUTH_BASE,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
        scope: str = "read",
        auto_open_browser: bool = True,
        wait_callback: bool = False,
        timeout_seconds: int = 180,
) -> dict[str, Any]:
    context = prepare_oauth_launch(
        client_id=client_id,
        auth_base=auth_base,
        redirect_uri=redirect_uri,
        scope=scope,
    )

    if auto_open_browser:
        webbrowser.open(context.auth_url)

    result: dict[str, Any] = {
        "client_id": context.client_id,
        "auth_url": context.auth_url,
        "state": context.state,
        "code_verifier": context.code_verifier,
        "code_challenge": context.code_challenge,
        "code_challenge_method": context.code_challenge_method,
        "redirect_uri": context.redirect_uri,
    }

    if wait_callback:
        callback = wait_for_oauth_callback(redirect_uri, timeout_seconds=timeout_seconds)
        result["callback"] = {
            "code": callback.code,
            "state": callback.state,
            "error": callback.error,
            "raw_query": callback.raw_query,
            "state_ok": callback.state == context.state if callback.state else False,
        }

    return result


def exchange_authorization_code_for_token(
        client_id: str,
        client_secret: str,
        code: str,
        code_verifier: str,
        auth_base: str = DEFAULT_AUTH_BASE,
        use_basic_auth: bool = True,
        timeout_seconds: int = 20,
        verify_ssl: bool = False,
) -> dict[str, Any]:
    if not client_id or not client_id.strip():
        raise ValueError("client_id is required")
    if not client_secret or not client_secret.strip():
        raise ValueError("client_secret is required")
    if not code or not code.strip():
        raise ValueError("authorization code is required")
    if not code_verifier or not code_verifier.strip():
        raise ValueError("code_verifier is required")

    token_url = f"{auth_base.rstrip('/')}/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "code": code.strip(),
        "code_verifier": code_verifier.strip(),
    }

    headers: dict[str, str] = {}
    if use_basic_auth:
        basic_raw = f"{client_id.strip()}:{client_secret.strip()}".encode("utf-8")
        basic_token = base64.b64encode(basic_raw).decode("utf-8")
        headers["Authorization"] = f"Basic {basic_token}"
    else:
        payload["client_id"] = client_id.strip()
        payload["client_secret"] = client_secret.strip()

    response = requests.post(token_url, data=payload, headers=headers, timeout=timeout_seconds, verify=verify_ssl)
    try:
        body = response.json()
    except Exception:
        body = {"raw": response.text}

    if response.status_code >= 400:
        raise RuntimeError(f"token exchange failed: http {response.status_code}, body={body}")

    return body


def refresh_access_token(
        client_id: str,
        client_secret: str,
        refresh_token: str,
        auth_base: str = DEFAULT_AUTH_BASE,
        use_basic_auth: bool = True,
        timeout_seconds: int = 20,
        verify_ssl: bool = False,
) -> dict[str, Any]:
    if not refresh_token or not refresh_token.strip():
        raise ValueError("refresh_token is required")

    token_url = f"{auth_base.rstrip('/')}/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token.strip(),
    }

    headers: dict[str, str] = {}
    if use_basic_auth:
        basic_raw = f"{client_id.strip()}:{client_secret.strip()}".encode("utf-8")
        headers["Authorization"] = f"Basic {base64.b64encode(basic_raw).decode('utf-8')}"
    else:
        payload["client_id"] = client_id.strip()
        payload["client_secret"] = client_secret.strip()

    response = requests.post(token_url, data=payload, headers=headers, timeout=timeout_seconds, verify=verify_ssl)
    try:
        body = response.json()
    except Exception:
        body = {"raw": response.text}
    if response.status_code >= 400:
        raise RuntimeError(f"refresh token failed: http {response.status_code}, body={body}")
    return body


def revoke_token(
        token: str,
        auth_base: str = DEFAULT_AUTH_BASE,
        token_type_hint: str = "access_token",
        client_id: str | None = None,
        client_secret: str | None = None,
        timeout_seconds: int = 20,
        verify_ssl: bool = False,
) -> dict[str, Any]:
    if not token or not token.strip():
        raise ValueError("token is required")

    revoke_url = f"{auth_base.rstrip('/')}/oauth/revoke"
    payload = {
        "token": token.strip(),
        "token_type_hint": token_type_hint,
    }
    headers: dict[str, str] = {}
    if client_id and client_secret:
        basic_raw = f"{client_id.strip()}:{client_secret.strip()}".encode("utf-8")
        headers["Authorization"] = f"Basic {base64.b64encode(basic_raw).decode('utf-8')}"
    response = requests.post(revoke_url, data=payload, headers=headers, timeout=timeout_seconds, verify=verify_ssl)
    try:
        body = response.json()
    except Exception:
        body = {"raw": response.text}
    if response.status_code >= 400:
        raise RuntimeError(f"revoke token failed: http {response.status_code}, body={body}")
    return body


def extract_token_fields(token_response: dict[str, Any]) -> dict[str, Any]:
    return {
        "access_token": token_response.get("access_token"),
        "refresh_token": token_response.get("refresh_token"),
        "token_type": token_response.get("token_type"),
        "expires_in": token_response.get("expires_in"),
        "scope": token_response.get("scope"),
    }


def one_click_oauth_authorize_and_exchange(
        client_id: str,
        client_secret: str,
        auth_base: str = DEFAULT_AUTH_BASE,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
        scope: str = "read",
        auto_open_browser: bool = True,
        timeout_seconds: int = 180,
        use_basic_auth: bool = True,
        verify_ssl: bool = False,
        compact: bool = False,
) -> dict[str, Any]:
    launch = one_click_oauth_start(
        client_id=client_id,
        auth_base=auth_base,
        redirect_uri=redirect_uri,
        scope=scope,
        auto_open_browser=auto_open_browser,
        wait_callback=True,
        timeout_seconds=timeout_seconds,
    )

    callback = launch.get("callback") or {}
    if callback.get("error"):
        raise RuntimeError(f"oauth callback returned error: {callback.get('error')}")
    if not callback.get("state_ok"):
        raise RuntimeError("oauth callback state mismatch")
    if not callback.get("code"):
        raise RuntimeError("oauth callback missing authorization code")

    token_result = exchange_authorization_code_for_token(
        client_id=client_id,
        client_secret=client_secret,
        code=str(callback["code"]),
        code_verifier=str(launch["code_verifier"]),
        auth_base=auth_base,
        use_basic_auth=use_basic_auth,
        timeout_seconds=min(timeout_seconds, 30),
        verify_ssl=verify_ssl,
    )

    launch["token_response"] = token_result
    launch["token"] = extract_token_fields(token_result)

    if compact:
        return {
            "access_token": launch["token"]["access_token"],
            "refresh_token": launch["token"]["refresh_token"],
            "token_type": launch["token"]["token_type"],
            "expires_in": launch["token"]["expires_in"],
            "scope": launch["token"]["scope"],
            "code": callback.get("code"),
            "state": launch.get("state"),
            "code_verifier": launch.get("code_verifier"),
        }

    return launch


