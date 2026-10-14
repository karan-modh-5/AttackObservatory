"""Password hashing (bcrypt), JWT HS256 tokens and ingest-key comparison."""

from __future__ import annotations

import bcrypt
import hmac
import jwt
from datetime import datetime, timedelta, timezone


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# The admin password comes from the environment; hash it once per process so
# each login does a single bcrypt check instead of a full hash + check round.
_ADMIN_HASH: dict[str, str] = {}


def admin_password_hash(admin_password: str) -> str:
    cached = _ADMIN_HASH.get(admin_password)
    if cached is None:
        cached = hash_password(admin_password)
        _ADMIN_HASH[admin_password] = cached
    return cached


def verify_admin_credentials(username: str, password: str, admin_user: str, admin_password: str) -> bool:
    user_ok = hmac.compare_digest(username.encode("utf-8"), admin_user.encode("utf-8"))
    pass_ok = verify_password(password, admin_password_hash(admin_password))
    return user_ok and pass_ok


def create_access_token(username: str, secret_key: str, expire_minutes: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


def decode_access_token(token: str, secret_key: str) -> str:
    """Return the subject or raise jwt.PyJWTError."""
    payload = jwt.decode(token, secret_key, algorithms=["HS256"])
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise jwt.InvalidTokenError("token has no subject")
    return subject


def ingest_key_matches(provided: str | None, expected: str) -> bool:
    if not provided:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
