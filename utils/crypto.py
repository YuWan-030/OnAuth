import hashlib
import secrets
import datetime
import jwt
from passlib.context import CryptContext
from config import SECRET_KEY, ALGORITHM

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
client_secret_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

LEGACY_SHA256_PREFIX = "sha256$"
BCRYPT_PREFIX = "bcrypt$"

def hash_secret(secret: str) -> str:
    hashed = client_secret_context.hash(secret)
    return f"{BCRYPT_PREFIX}{hashed}"


def verify_secret(secret: str, stored_hash: str | None) -> bool:
    if not secret or not stored_hash:
        return False

    raw_hash = str(stored_hash).strip()
    if raw_hash.startswith(BCRYPT_PREFIX):
        return client_secret_context.verify(secret, raw_hash[len(BCRYPT_PREFIX):])

    if raw_hash.startswith(LEGACY_SHA256_PREFIX):
        legacy_value = raw_hash[len(LEGACY_SHA256_PREFIX):]
    else:
        legacy_value = raw_hash
    return hashlib.sha256(secret.encode()).hexdigest() == legacy_value

def generate_random_keys():
    return "cli_" + secrets.token_hex(8), "sec_" + secrets.token_hex(16)

def create_jwt_token(client_id: str, scope: str, expire_at: datetime.datetime, token_type: str = "license"):
    exp_timestamp = int(expire_at.timestamp()) if expire_at else 2147483647
    to_encode = {
        "sub": client_id,
        "scope": scope,
        "exp": exp_timestamp,
        "token_type": token_type,
        "expire_date_str": expire_at.strftime("%Y-%m-%d %H:%M:%S") if expire_at else "永久有效",
        "iss": "auth_platform"
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(client_id: str, scope: str, expire_at: datetime.datetime):
    return create_jwt_token(client_id, scope, expire_at, token_type="access_token")


def create_refresh_token(client_id: str, scope: str, expire_at: datetime.datetime):
    return create_jwt_token(client_id, scope, expire_at, token_type="refresh_token")


def introspect_token(token: str, token_type: str | None = None) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return {"active": False}

    current_token_type = payload.get("token_type")
    if token_type and current_token_type != token_type:
        return {"active": False}

    return {
        "active": True,
        "sub": payload.get("sub"),
        "scope": payload.get("scope", ""),
        "exp": payload.get("exp"),
        "iss": payload.get("iss"),
        "token_type": current_token_type,
    }

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)