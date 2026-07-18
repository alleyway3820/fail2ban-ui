import os
import aiosqlite

DATABASE_PATH = os.getenv("DATABASE_PATH", "/data/f2b-sync.db")

CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS geo_blocked_countries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country_code TEXT NOT NULL UNIQUE,
    country_name TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS global_blocklist (
    ip_address TEXT PRIMARY KEY,
    reason TEXT,
    country_code TEXT,
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    source TEXT DEFAULT 'manual'
);

CREATE TABLE IF NOT EXISTS server_api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT,
    bans_reported INTEGER DEFAULT 0,
    blocklist_pulled INTEGER DEFAULT 0,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ban_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    jail TEXT,
    server_id TEXT,
    hostname TEXT,
    failures INTEGER DEFAULT 0,
    logs TEXT,
    matches TEXT,
    country_code TEXT,
    globally_blocked INTEGER DEFAULT 0,
    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ip_whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    reason TEXT,
    expires_at TIMESTAMP,           -- NULL = permanent, set = auto-expire
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


async def init_db():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        for statement in CREATE_TABLES.strip().split(";"):
            stmt = statement.strip()
            if stmt:
                await db.execute(stmt)
        await db.commit()


async def get_db():
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        yield db
