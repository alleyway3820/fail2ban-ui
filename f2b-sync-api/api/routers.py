import asyncio
import ipaddress
import os
import re
import secrets
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from .auth import (
    verify_api_key,
    jwt_auth,
    verify_password,
    hash_password,
    create_access_token,
    create_refresh_token,
    verify_token,
    get_user,
)
from .database import DATABASE_PATH
from .geoip import async_lookup_country

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")

F2B_DB_PATH = os.getenv("DB_PATH", "/data/f2b.db")

# ── Rate limiting ──────────────────────────────────────────────────────────────

_rate_limit_lock = asyncio.Lock()
_rate_limit_data: dict[str, list[float]] = {}


async def _apply_rate_limit(key: str) -> None:
    now = time.time()
    async with _rate_limit_lock:
        timestamps = _rate_limit_data.get(key, [])
        timestamps = [t for t in timestamps if now - t < 60]
        if len(timestamps) >= 100:
            raise HTTPException(status_code=429, detail="Rate limit exceeded: 100 req/min")
        timestamps.append(now)
        _rate_limit_data[key] = timestamps


async def rate_limited_api_key(
    x_api_key: Optional[str] = Header(default=None),
    server_name: str = Depends(verify_api_key),
) -> str:
    await _apply_rate_limit(x_api_key or "")
    return server_name


def validate_ip(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip!r}")


# ── Pydantic models ────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ReportBanRequest(BaseModel):
    ip: str = Field(max_length=39)
    jail: str = Field(max_length=100)
    server_id: str = Field(max_length=100)
    hostname: Optional[str] = Field(default=None, max_length=255)
    failures: int = 0
    logs: Optional[str] = Field(default=None, max_length=10000)
    matches: Optional[str] = Field(default=None, max_length=10000)


class ReportUnbanRequest(BaseModel):
    ip: str = Field(max_length=39)
    jail: str = Field(max_length=100)
    server_id: str = Field(max_length=100)


class UnbanRequest(BaseModel):
    ip: str = Field(max_length=39)
    jail: str = Field(max_length=100)
    server_id: str = Field(max_length=100)


class GeoCountryRequest(BaseModel):
    country_code: str
    country_name: str
    enabled: bool = True


class AddServerRequest(BaseModel):
    server_name: str


class WhitelistRequest(BaseModel):
    ip: str = Field(max_length=39)
    reason: Optional[str] = Field(default=None, max_length=500)


# ── Auth endpoints ─────────────────────────────────────────────────────────────

@router.post("/login")
async def login(req: LoginRequest):
    user = await get_user(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    payload = {"sub": user["username"], "role": user["role"]}
    return {
        "access_token": create_access_token(payload),
        "refresh_token": create_refresh_token(payload),
        "token_type": "bearer",
    }


@router.post("/refresh")
async def refresh(req: RefreshRequest):
    payload = verify_token(req.refresh_token, token_type="refresh")
    new_payload = {"sub": payload["sub"], "role": payload.get("role", "admin")}
    return {
        "access_token": create_access_token(new_payload),
        "token_type": "bearer",
    }


# ── Server endpoints (API key auth) ───────────────────────────────────────────

@router.post("/report-ban")
async def report_ban(req: ReportBanRequest, server_name: str = Depends(rate_limited_api_key)):
    validate_ip(req.ip)
    country = await async_lookup_country(req.ip)
    globally_blocked = False
    whitelisted = False

    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row

        async with db.execute(
            "SELECT 1 FROM ip_whitelist WHERE ip_address = ?", (req.ip,)
        ) as cur:
            if await cur.fetchone():
                whitelisted = True

        # Always store ban report for audit trail, even if whitelisted
        await db.execute(
            """INSERT INTO ban_reports
               (ip_address, jail, server_id, hostname, failures, logs, matches, country_code)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (req.ip, req.jail, req.server_id, req.hostname, req.failures, req.logs, req.matches, country),
        )

        if not whitelisted and country:
            async with db.execute(
                "SELECT 1 FROM geo_blocked_countries WHERE country_code = ? AND enabled = 1", (country,)
            ) as cur:
                if await cur.fetchone():
                    await db.execute(
                        """INSERT OR REPLACE INTO global_blocklist
                           (ip_address, reason, country_code, source)
                           VALUES (?, ?, ?, 'geoip')""",
                        (req.ip, f"Geo-blocked country: {country}", country),
                    )
                    globally_blocked = True

        await db.execute(
            "UPDATE ban_reports SET globally_blocked = ? WHERE ip_address = ? AND server_id = ?",
            (1 if globally_blocked else 0, req.ip, req.server_id),
        )
        await db.commit()

    return {"blocked": not whitelisted, "country": country, "global_blocked": globally_blocked, "whitelisted": whitelisted}


@router.post("/report-unban")
async def report_unban(req: ReportUnbanRequest, server_name: str = Depends(rate_limited_api_key)):
    validate_ip(req.ip)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "DELETE FROM global_blocklist WHERE ip_address = ?",
            (req.ip,),
        )
        await db.commit()
    return {"status": "ok"}


@router.get("/blocklist")
async def get_blocklist(
    since: Optional[str] = Query(default=None),
    server_name: str = Depends(rate_limited_api_key),
):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        if since:
            async with db.execute(
                """SELECT ip_address, reason, source, banned_at
                   FROM global_blocklist WHERE banned_at > ?
                   ORDER BY banned_at DESC""",
                (since,),
            ) as cur:
                rows = await cur.fetchall()
        else:
            async with db.execute(
                "SELECT ip_address, reason, source, banned_at FROM global_blocklist ORDER BY banned_at DESC"
            ) as cur:
                rows = await cur.fetchall()

    ips = [
        {"ip": r["ip_address"], "reason": r["reason"], "source": r["source"], "banned_at": r["banned_at"]}
        for r in rows
    ]
    return {"ips": ips, "generated_at": datetime.now(timezone.utc).isoformat()}


@router.get("/stats")
async def get_stats(_server_name: str = Depends(rate_limited_api_key)):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM ban_reports") as cur:
            total_bans = (await cur.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM global_blocklist") as cur:
            active_bans = (await cur.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM server_api_keys WHERE is_active = 1") as cur:
            servers_count = (await cur.fetchone())[0]

    return {"total_bans": total_bans, "active_bans": active_bans, "servers_count": servers_count}


# ── Web UI endpoints (JWT auth) ────────────────────────────────────────────────

@router.get("/bans")
async def list_bans(
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    search: Optional[str] = Query(default=None, max_length=200),
    server_id: Optional[str] = Query(default=None, max_length=100),
    _user: dict = Depends(jwt_auth),
):
    results = []
    total = 0

    # Primary source: paginate ban_reports with proper limit/offset
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params: list = []
        if search:
            conditions.append("(ip_address LIKE ? OR jail LIKE ? OR hostname LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        if server_id:
            conditions.append("server_id = ?")
            params.append(server_id)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        async with db.execute(f"SELECT COUNT(*) FROM ban_reports {where}", params) as cur:
            total = (await cur.fetchone())[0]
        async with db.execute(
            f"""SELECT id, ip_address, jail, server_id, hostname, failures,
                       country_code, globally_blocked, reported_at as banned_at
                FROM ban_reports {where}
                ORDER BY reported_at DESC LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ) as cur:
            rows = await cur.fetchall()
        for r in rows:
            results.append({
                "id": r["id"],
                "ip": r["ip_address"],
                "jail": r["jail"],
                "server_id": r["server_id"],
                "hostname": r["hostname"],
                "failures": r["failures"],
                "country": r["country_code"],
                "globally_blocked": bool(r["globally_blocked"]),
                "banned_at": r["banned_at"],
                "source": "sync-api",
            })

    # Supplemental: recent fail2ban-ui entries (no pagination — always most recent 50)
    # Note: ban_events search only covers ip_address and jail (no hostname column)
    if os.path.exists(F2B_DB_PATH):
        try:
            async with aiosqlite.connect(F2B_DB_PATH) as f2b_db:
                f2b_db.row_factory = aiosqlite.Row
                conditions2 = []
                params2: list = []
                if search:
                    conditions2.append("(ip_address LIKE ? OR jail LIKE ?)")
                    params2.extend([f"%{search}%", f"%{search}%"])
                where2 = ("WHERE " + " AND ".join(conditions2)) if conditions2 else ""
                async with f2b_db.execute(
                    f"""SELECT id, ip_address, jail, banned_at
                        FROM ban_events {where2}
                        ORDER BY banned_at DESC LIMIT 50""",
                    params2,
                ) as cur:
                    f2b_rows = await cur.fetchall()
                for r in f2b_rows:
                    results.append({
                        "id": f"f2b-{r['id']}",
                        "ip": r["ip_address"],
                        "jail": r["jail"],
                        "server_id": None,
                        "hostname": None,
                        "failures": None,
                        "country": None,
                        "globally_blocked": False,
                        "banned_at": r["banned_at"],
                        "source": "fail2ban-ui",
                    })
        except Exception as e:
            logger.warning("Could not read fail2ban-ui ban_events: %s", e)

    results.sort(key=lambda x: x["banned_at"] or "", reverse=True)
    return {"bans": results, "total": total, "offset": offset}


@router.get("/bans/{ban_id}")
async def get_ban(ban_id: int, _user: dict = Depends(jwt_auth)):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM ban_reports WHERE id = ?", (ban_id,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Ban not found")
    return dict(row)


@router.post("/unban")
async def unban(req: UnbanRequest, _user: dict = Depends(jwt_auth)):
    validate_ip(req.ip)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "DELETE FROM global_blocklist WHERE ip_address = ?", (req.ip,)
        )
        await db.commit()
    return {"status": "ok", "ip": req.ip}


@router.get("/geo-countries")
async def list_geo_countries(_user: dict = Depends(jwt_auth)):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, country_code, country_name, enabled, created_at FROM geo_blocked_countries ORDER BY country_name"
        ) as cur:
            rows = await cur.fetchall()
    return {"countries": [dict(r) for r in rows]}


@router.post("/geo-countries", status_code=201)
async def add_geo_country(req: GeoCountryRequest, _user: dict = Depends(jwt_auth)):
    if not re.match(r'^[A-Z]{2}$', req.country_code.upper()):
        raise HTTPException(status_code=400, detail="country_code must be 2 uppercase letters (ISO 3166-1 alpha-2)")
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """INSERT INTO geo_blocked_countries (country_code, country_name, enabled)
               VALUES (?, ?, ?)
               ON CONFLICT(country_code) DO UPDATE SET country_name=excluded.country_name, enabled=excluded.enabled""",
            (req.country_code.upper(), req.country_name, 1 if req.enabled else 0),
        )
        await db.commit()
    return {"status": "ok", "country_code": req.country_code.upper()}


@router.delete("/geo-countries/{code}")
async def delete_geo_country(code: str, _user: dict = Depends(jwt_auth)):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "DELETE FROM geo_blocked_countries WHERE country_code = ?", (code.upper(),)
        )
        await db.commit()
    return {"status": "ok"}


@router.get("/servers")
async def list_servers(_user: dict = Depends(jwt_auth)):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, server_name, is_active, last_seen, created_at FROM server_api_keys ORDER BY created_at DESC"
        ) as cur:
            rows = await cur.fetchall()
    return {"servers": [dict(r) for r in rows]}


@router.post("/servers", status_code=201)
async def add_server(req: AddServerRequest, _user: dict = Depends(jwt_auth)):
    plaintext_key = secrets.token_hex(32)
    hashed = hash_password(plaintext_key)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cur = await db.execute(
            "INSERT INTO server_api_keys (server_name, api_key_hash) VALUES (?, ?)",
            (req.server_name, hashed),
        )
        server_id = cur.lastrowid
        await db.commit()
    return {"id": server_id, "server_name": req.server_name, "api_key": plaintext_key}


@router.delete("/servers/{server_id}")
async def delete_server(server_id: int, _user: dict = Depends(jwt_auth)):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE server_api_keys SET is_active = 0 WHERE id = ?", (server_id,)
        )
        await db.commit()
    return {"status": "ok"}


@router.get("/whitelist")
async def list_whitelist(_user: dict = Depends(jwt_auth)):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, ip_address, reason, created_at FROM ip_whitelist ORDER BY created_at DESC"
        ) as cur:
            rows = await cur.fetchall()
    return {"whitelist": [dict(r) for r in rows]}


@router.post("/whitelist", status_code=201)
async def add_whitelist(req: WhitelistRequest, _user: dict = Depends(jwt_auth)):
    validate_ip(req.ip)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO ip_whitelist (ip_address, reason) VALUES (?, ?)",
            (req.ip, req.reason),
        )
        await db.execute("DELETE FROM global_blocklist WHERE ip_address = ?", (req.ip,))
        await db.commit()
    return {"status": "ok", "ip": req.ip}


@router.delete("/whitelist/{ip}")
async def delete_whitelist(ip: str, _user: dict = Depends(jwt_auth)):
    validate_ip(ip)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("DELETE FROM ip_whitelist WHERE ip_address = ?", (ip,))
        await db.commit()
    return {"status": "ok"}
