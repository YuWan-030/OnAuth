import hashlib
import secrets
import datetime
import jwt
from passlib.context import CryptContext
from config import SECRET_KEY, ALGORITHM

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()

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

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)