import os
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiosqlite
from fastapi import Depends, HTTPException, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from .database import DATABASE_PATH

logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


class TokenData(BaseModel):
    sub: str
    role: str = "admin"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload["type"] = "access"
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload["type"] = "refresh"
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def verify_token(token: str, token_type: str = "access") -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != token_type:
            raise JWTError("Invalid token type")
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def verify_api_key(x_api_key: Optional[str] = Header(default=None)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key header")

    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, server_name, api_key_hash FROM server_api_keys WHERE is_active = 1"
        ) as cursor:
            rows = await cursor.fetchall()

    for row in rows:
        if verify_password(x_api_key, row["api_key_hash"]):
            async with aiosqlite.connect(DATABASE_PATH) as db:
                await db.execute(
                    "UPDATE server_api_keys SET last_seen = CURRENT_TIMESTAMP WHERE id = ?",
                    (row["id"],),
                )
                await db.commit()
            return row["server_name"]

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


async def jwt_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_token(credentials.credentials, token_type="access")


async def get_user(username: str) -> Optional[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def ensure_default_admin():
    """Create default admin user if no users exist."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            count = (await cursor.fetchone())[0]
        if count == 0:
            default_password = os.getenv("ADMIN_PASSWORD")
            if not default_password:
                default_password = secrets.token_urlsafe(16)
                logger.warning(
                    "ADMIN_PASSWORD not set — generated random password for admin: %s",
                    default_password,
                )
            hashed = hash_password(default_password)
            await db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hashed, "admin"),
            )
            await db.commit()
            logger.info("Created default admin user (username: admin)")
