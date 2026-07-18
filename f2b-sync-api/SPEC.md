# f2b-sync-api — Centralized fail2ban Sync Service

Companion API service for fail2ban-ui that adds:
- Global blocklist sync (servers pull curated blocklist)
- Geo-country blocking rules
- Server ban reporting
- Web UI login for managing geo-blocks and blocklist

## Architecture

Sits alongside fail2ban-ui in Docker Compose. Runs alongside fail2ban-ui with its own SQLite database. Reads fail2ban-ui's SQLite database read-only for ban_events/ban_reports cross-referencing.

Stack: Python FastAPI + SQLite + JWT auth

## Database Tables (in addition to fail2ban-ui's tables)

```sql
-- Geo-blocked countries
CREATE TABLE geo_blocked_countries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country_code TEXT NOT NULL UNIQUE,
    country_name TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Global blocklist cache (for quick agent sync)
CREATE TABLE global_blocklist (
    ip_address TEXT PRIMARY KEY,
    reason TEXT,
    country_code TEXT,
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    source TEXT DEFAULT 'manual' -- 'geoip', 'manual', 'recurring'
);

-- Server API keys
CREATE TABLE server_api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sync tracking per server
CREATE TABLE sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT,
    bans_reported INTEGER DEFAULT 0,
    blocklist_pulled INTEGER DEFAULT 0,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Web UI users
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## API Endpoints

### Server-to-Collector (API key auth in header)

| Method | Path | Purpose |
|--------|------|---------|
| POST | /api/v1/report-ban | Server reports a ban |
| POST | /api/v1/report-unban | Server reports an unban |
| GET | /api/v1/blocklist | Server pulls global blocklist |
| GET | /api/v1/blocklist?since=ISO8601 | Incremental pull |

### Web UI (JWT auth)

| Method | Path | Purpose |
|--------|------|---------|
| POST | /api/v1/login | Web UI login |
| GET | /api/v1/bans | List all bans with server/jail info |
| GET | /api/v1/bans/:id | Single ban detail |
| POST | /api/v1/unban | Unban an IP |
| GET | /api/v1/geo-countries | List geo-blocked countries |
| POST | /api/v1/geo-countries | Add/update geo-blocked country |
| DELETE | /api/v1/geo-countries/:code | Remove geo-blocked country |
| GET | /api/v1/servers | List registered servers |
| GET | /api/v1/stats | Dashboard stats |
| POST | /api/v1/whitelist | Add IP to whitelist |
| GET | /api/v1/whitelist | List whitelisted IPs |

## Geo-IP Integration

Use MaxMind GeoLite2 mmdb file. When a ban is reported:
1. Look up IP country
2. If country is in geo_blocked_countries (enabled=true), add IP to global_blocklist
3. Return whether this IP is now globally blocked

On startup + every hour, refresh the global_blocklist from:
- All active geo-blocked countries (resolve their known IP ranges OR add individual reported IPs)
- Manually added global blocks
- Recurring offender blocks from fail2ban-ui's permanent_blocks table

## Server Agent Scripts

### fail2ban Action (`agent/central-api.conf`)
Action config that fail2ban calls on ban/unban. POSTs to the sync API.

### Sync Script (`agent/sync.sh`)
Bash script that runs via cron every 5 minutes:
1. Pulls global blocklist from collector via GET /api/v1/blocklist
2. Adds new IPs to a dedicated fail2ban jail 'global-blocklist'
3. Reports any local bans since last run
4. Removes expired entries

## Auth

- Server-to-Collector: Pre-shared API key, passed as `X-API-Key` header
- Web UI: JWT tokens (access token 15min, refresh token 7 days)
- Password hashing: bcrypt
