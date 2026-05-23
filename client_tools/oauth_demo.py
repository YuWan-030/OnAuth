import argparse
import json

from client_tools.oauth_bootstrap import (
    one_click_oauth_start,
    exchange_authorization_code_for_token,
    one_click_oauth_authorize_and_exchange,
    refresh_access_token,
    revoke_token,
)


def main():
    parser = argparse.ArgumentParser(description="One-click OAuth2 PKCE launcher")
    parser.add_argument("client_id", help="OAuth client_id")
    parser.add_argument("--client-secret", default="", help="OAuth client_secret (required for token exchange)")
    parser.add_argument("--code", default="", help="Authorization code for token exchange")
    parser.add_argument("--code-verifier", default="", help="PKCE code_verifier for token exchange")
    parser.add_argument("--auth-base", default="https://localhost:8000", help="OAuth server base URL")
    parser.add_argument("--redirect-uri", default="http://127.0.0.1:8765/callback", help="Redirect URI")
    parser.add_argument("--scope", default="read", help="Requested scope")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    parser.add_argument("--wait-callback", action="store_true", help="Wait for local callback and capture code")
    parser.add_argument("--exchange", action="store_true", help="Exchange code for token using --code and --code-verifier")
    parser.add_argument("--one-shot", action="store_true", help="Run full flow: open auth, wait callback, exchange token")
    parser.add_argument("--compact", action="store_true", help="Use compact output for --one-shot")
    parser.add_argument("--refresh", default="", help="Refresh token value for refresh flow")
    parser.add_argument("--revoke", default="", help="Token value for revoke flow")
    parser.add_argument("--revoke-type", default="access_token", help="token_type_hint for revoke")
    parser.add_argument("--no-basic-auth", action="store_true", help="Send client credentials in form body instead of Basic auth")
    parser.add_argument("--verify-ssl", action="store_true", help="Enable SSL certificate verification")
    parser.add_argument("--timeout", type=int, default=180, help="Callback wait timeout seconds")
    args = parser.parse_args()

    if args.refresh:
        result = refresh_access_token(
            client_id=args.client_id,
            client_secret=args.client_secret,
            refresh_token=args.refresh,
            auth_base=args.auth_base,
            use_basic_auth=not args.no_basic_auth,
            verify_ssl=args.verify_ssl,
        )
    elif args.revoke:
        result = revoke_token(
            token=args.revoke,
            auth_base=args.auth_base,
            token_type_hint=args.revoke_type,
            verify_ssl=args.verify_ssl,
        )
    elif args.one_shot:
        result = one_click_oauth_authorize_and_exchange(
            client_id=args.client_id,
            client_secret=args.client_secret,
            auth_base=args.auth_base,
            redirect_uri=args.redirect_uri,
            scope=args.scope,
            auto_open_browser=not args.no_browser,
            timeout_seconds=args.timeout,
            use_basic_auth=not args.no_basic_auth,
            verify_ssl=args.verify_ssl,
            compact=args.compact,
        )
    elif args.exchange:
        result = exchange_authorization_code_for_token(
            client_id=args.client_id,
            client_secret=args.client_secret,
            code=args.code,
            code_verifier=args.code_verifier,
            auth_base=args.auth_base,
            use_basic_auth=not args.no_basic_auth,
            verify_ssl=args.verify_ssl,
        )
    else:
        result = one_click_oauth_start(
            client_id=args.client_id,
            auth_base=args.auth_base,
            redirect_uri=args.redirect_uri,
            scope=args.scope,
            auto_open_browser=not args.no_browser,
            wait_callback=args.wait_callback,
            timeout_seconds=args.timeout,
        )

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

