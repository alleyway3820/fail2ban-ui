# f2b-sync-api — Centralized Fail2Ban Sync Companion

This companion service adds global blocklist sync, geo-IP blocking, and server management to fail2ban-ui.

## Stack

- **Python 3.11+ FastAPI** async service
- **SQLite** (separate DB from fail2ban-ui)
- **MaxMind GeoLite2** for IP geolocation
- **JWT + API key** auth (two tiers)

## Directory Layout

```
f2b-sync-api/
├── api/
│   ├── __init__.py
│   ├── auth.py          # JWT + API key auth
│   ├── background.py    # Hourly geo-blocklist refresh
│   ├── database.py      # SQLite schema + connection
│   ├── geoip.py         # MaxMind GeoLite2 lookup
│   └── routers.py       # All API endpoints
├── agent/
│   ├── central-api.conf          # fail2ban action config
│   ├── f2b-central.conf.example   # Config template for agents
│   ├── f2b-central-report.sh      # fail2ban ban/unban reporter
│   └── f2b-sync.sh               # 5-min cron sync script
├── web/
│   ├── static/
│   │   └── app.js       # Shared JS (JWT, API calls, toast)
│   └── templates/
│       ├── login.html            # JWT login page
│       ├── dashboard.html        # Ban list with search/pagination
│       ├── geo-countries.html    # Geo-block management
│       ├── servers.html          # Server API key management
│       └── whitelist.html        # IP whitelist management
├── main.py              # FastAPI app entry point
├── Dockerfile           # Multi-stage build
├── requirements.txt     # Python dependencies
└── SPEC.md              # Original spec
```

## API Endpoints

### Server-to-Collector (X-API-Key header)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/report-ban` | Server reports a new ban |
| POST | `/api/v1/report-unban` | Server reports an unban |
| GET | `/api/v1/blocklist` | Pull global blocklist (?since=ISO8601) |
| GET | `/api/v1/stats` | Get server stats |

### Web UI (Bearer JWT)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/login` | Login with username/password |
| POST | `/api/v1/refresh` | Refresh JWT token |
| GET | `/api/v1/bans` | List bans with search/pagination |
| GET | `/api/v1/bans/:id` | Single ban detail |
| POST | `/api/v1/unban` | Unban an IP |
| GET | `/api/v1/geo-countries` | List geo-blocked countries |
| POST | `/api/v1/geo-countries` | Add/update geo-blocked country |
| DELETE | `/api/v1/geo-countries/:code` | Remove geo-blocked country |
| GET | `/api/v1/servers` | List registered servers |
| POST | `/api/v1/servers` | Add server (returns API key once) |
| DELETE | `/api/v1/servers/:id` | Revoke server key |
| GET | `/api/v1/whitelist` | List whitelisted IPs |
| POST | `/api/v1/whitelist` | Add IP to whitelist |
| DELETE | `/api/v1/whitelist/:ip` | Remove whitelisted IP |

## Deployment

### Docker Compose (alongside fail2ban-ui)

```yaml
services:
  f2b-sync-api:
    build: ./f2b-sync-api
    container_name: f2b-sync-api
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - DATABASE_PATH=/data/f2b-sync.db
      - DB_PATH=/data/f2b.db
      - JWT_SECRET=your-secret-here
      - ADMIN_PASSWORD=your-admin-password
      - GEOIP_DB_PATH=/data/GeoLite2-Country.mmdb
    volumes:
      - shared-data:/data
    depends_on:
      - fail2ban-ui

volumes:
  shared-data:
```

### Per-Server Agent Setup

1. Copy `agent/f2b-central-report.sh` and `agent/f2b-sync.sh` to `/usr/local/bin/`
2. Copy `agent/f2b-central.conf.example` to `/etc/f2b-central.conf` and edit
3. Copy `agent/central-api.conf` to `/etc/fail2ban/action.d/`
4. Add to jail config: `action = central-api`
5. Add cron: `*/5 * * * * /usr/local/bin/f2b-sync.sh`
6. `systemctl restart fail2ban`

## Auth

- **Server API keys**: bcrypt-hashed, passed as `X-API-Key` header
- **Web UI**: JWT (15min access + 7d refresh), default admin/admin
- Rate limit: 100 req/min per API key

## Geo-IP

Requires MaxMind GeoLite2-Country.mmdb at the path specified by `GEOIP_DB_PATH`.
Free download from maxmind.com (requires free account registration).
