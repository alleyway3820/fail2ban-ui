# Fail2Ban Production Configuration Guide

**Stack:** FreeSWITCH/FusionPBX · CyberPanel/OpenLiteSpeed · Pure-FTPd · OpenSSH
**Integration:** All jails wired to f2b-sync-api `central-api` action

## Quick Reference — Recommended Thresholds

| Jail | maxretry | findtime | bantime | What it catches |
|------|----------|----------|---------|-----------------|
| sshd | 4 | 5m | 2h | SSH brute force |
| freeswitch-auth | 5 | 1m | 24h | SIP auth failures (REGISTER/INVITE) |
| freeswitch-dos | 30 | 30s | 72h | SIP flooding / scanning |
| wordpress-auth | 5 | 5m | 6h | wp-login brute force |
| wordpress-xmlrpc | 2 | 1m | 24h | XML-RPC attacks |
| ols-admin | 3 | 5m | 12h | LiteSpeed admin panel |
| ols-scan | 10 | 2m | 24h | 404 scanners, exploit probes |
| pure-ftpd | 4 | 5m | 6h | FTP auth failures |
| postfix-sasl | 5 | 5m | 6h | SMTP auth brute force |
| dovecot | 5 | 5m | 6h | IMAP/POP3 auth failures |
| recidive | 3 | 1d | 4w | Multi-jail repeat offenders |

## Filters Included

### FreeSWITCH (`filter.d/freeswitch.conf`)
- SIP auth failure (REGISTER) — the main one
- SIP auth failure (INVITE) — call scanning
- SIP auth challenge failures
- FreeSWITCH internal "Blocking IP" messages
- Too many registrations from IP

### FreeSWITCH DOS (`filter.d/freeswitch-dos.conf`)
- Separate jail for flood detection (30 hits in 30s = 72h ban)

### WordPress (`filter.d/wordpress-auth.conf`)
- POST to wp-login.php returning 200/302/403 (failed login)
- POST to xmlrpc.php returning 200/403/500
- GET wp-login.php?action=register

### OpenLiteSpeed Admin (`filter.d/openlitespeed-admin.conf`)
- Login failures on port 7080/7443
- Bad authentication attempts

### OLS Scanner (`filter.d/ols-scan.conf`)
- 404 storms on common exploit paths (.env, .git, phpmyadmin, etc.)
- Requests to wp-config.php, .htaccess, etc.

### Pure-FTPd (`filter.d/pure-ftpd-custom.conf`)
- Authentication failed messages
- Refused connections
- Max connections exceeded

## Additional Protections (Configured at iptables level, before fail2ban)

1. **GeoIP country blocking** — ipset with ipdeny.com data. Block CN, RU, NG, VN, PK, ID, BD, IR, KP. Weekly auto-updates. This alone eliminates 40-60% of attack traffic.

2. **iptables rate limiting** (hashlimit module):
   - SIP: max 10 UDP connections/sec per IP on port 5060
   - SSH: max 4 new connections/min per IP
   - HTTP/HTTPS: max 40 connections/min per IP
   
3. **Port scan detection** — iptables `recent` module drops IPs hitting 20+ unique ports in 60s

4. **OpenLiteSpeed native throttle** — Connection Throttle in WebAdmin (15-30 connections/IP)

## Deployment Priority

```
Day 1: GeoIP blocks → iptables rate limits → SSH jail → SIP jail
Day 2: WordPress jails → FTP jail → Recidive
Day 3: Validate with fail2ban-regex → fine-tune log paths
```

## Per-Server Setup (to wire into f2b-sync-api)

```bash
cp action.d/central-api.conf /etc/fail2ban/action.d/
cp agent/f2b-central-report.sh /usr/local/bin/
chmod +x /usr/local/bin/f2b-central-report.sh

# Create config
cat > /etc/f2b-central.conf <<EOF
COLLECTOR_URL=https://your-sync-api:8000
API_KEY=<generated-from-web-ui>
SERVER_ID=$(hostname -f)
EOF
chmod 600 /etc/f2b-central.conf
```

Each jail includes `action = central-api[server_id="$(hostname -f)"]` to sync bans to the central collector.
