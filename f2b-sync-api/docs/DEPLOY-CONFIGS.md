# Production Security Checklist — Deployment Configs

When ready to deploy, here are the configs for each item.

---

## 1. FreeSWITCH ESL Hardening

**File: `/etc/freeswitch/sip_profiles/event_socket.conf.xml`**
```xml
<configuration name="event_socket.conf" description="Socket Client">
  <settings>
    <param name="nat-map" value="false"/>
    <param name="listen-ip" value="127.0.0.1"/>
    <param name="listen-port" value="8021"/>
    <param name="password" value="CHANGE_THIS_TO_A_RANDOM_STRING"/>
    <param name="apply-inbound-acl" value="loopback.auto"/>
  </settings>
</configuration>
```
Then: `systemctl restart freeswitch` or `fsctl reload` via CLI.

Verify: `netstat -tlnp | grep 8021` → should show `127.0.0.1:8021`, not `0.0.0.0:8021`.

---

## 2. MySQL Bind Check

```bash
# Verify
netstat -tlnp | grep -E '3306|5432'

# Fix if bound to 0.0.0.0
sed -i 's/^bind-address\s*=\s*0.0.0.0/bind-address = 127.0.0.1/' /etc/mysql/my.cnf
systemctl restart mysql
```

---

## 3. CyberPanel Admin (port 7750)

Already changed from 8090 to 7750. Verify reachable only from management IPs:
```bash
iptables -A INPUT -p tcp --dport 7750 -s YOUR_MGMT_IP/32 -j ACCEPT
iptables -A INPUT -p tcp --dport 7750 -j DROP
```

---

## 4. Fail2ban Watchdog

**File: `/etc/cron.d/fail2ban-watchdog`**
```bash
*/5 * * * * root /usr/local/bin/f2b-watchdog.sh
```

**File: `/usr/local/bin/f2b-watchdog.sh`**
```bash
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/f2b-watchdog.log"
ALERT_EMAIL="${ALERT_EMAIL:-admin@yourdomain.com}"

if ! systemctl is-active fail2ban &>/dev/null; then
    systemctl restart fail2ban
    echo "$(date -Iseconds) fail2ban was down, restarted" >> "$LOG"
    echo "fail2ban was DOWN on $(hostname -f) at $(date) and has been restarted" \
        | mail -s "[CRITICAL] fail2ban restarted on $(hostname -s)" "$ALERT_EMAIL"
fi
```
```bash
chmod +x /usr/local/bin/f2b-watchdog.sh
```

---

## 5. SSH Port Change

**File: `/etc/ssh/sshd_config` — change these lines:**
```ini
Port 2222                              # was Port 22
PermitRootLogin prohibit-password      # key-only, no password
PasswordAuthentication no              # disable password auth
PubkeyAuthentication yes
AuthenticationMethods publickey
```

**Update firewall:**
```bash
# Allow new port
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
# Remove old SSH rule (if using -A with a stateful firewall, just ensure NEW on 2222)
```

**Then:**
```bash
systemctl restart sshd
# Keep current SSH session open while testing new port!
# Test from another terminal: ssh -p 2222 user@server
```

---

## 6. Spamhaus DROP Blocklist

**File: `/usr/local/bin/spamhaus-drop.sh`**
```bash
#!/usr/bin/env bash
set -euo pipefail
SETNAME="spamhaus-drop"
LOG="/var/log/spamhaus-drop.log"

log() { echo "$(date -Iseconds) $*" >> "$LOG"; }

log "Updating Spamhaus DROP list..."

# Create/reset ipset
if ipset list "$SETNAME" &>/dev/null; then
    ipset flush "$SETNAME"
else
    ipset create "$SETNAME" hash:net family inet hashsize 16384 maxelem 300000
    iptables -I INPUT 1 -m set --match-set "$SETNAME" src -j DROP 2>/dev/null || true
fi

# Download and load
curl -s https://www.spamhaus.org/drop/drop.txt | grep -v '^;' | awk '{print $1}' | \
while IFS= read -r cidr; do
    [[ -z "$cidr" ]] && continue
    ipset add "$SETNAME" "$cidr" 2>/dev/null || true
done

COUNT=$(ipset list "$SETNAME" | grep -c "/" || true)
log "Loaded $COUNT CIDR blocks"

# Also pull EDROP (hijacked IP space)
curl -s https://www.spamhaus.org/drop/edrop.txt | grep -v '^;' | awk '{print $1}' | \
while IFS= read -r cidr; do
    [[ -z "$cidr" ]] && continue
    ipset add "$SETNAME" "$cidr" 2>/dev/null || true
done

TOTAL=$(ipset list "$SETNAME" | grep -c "/" || true)
log "Complete: $TOTAL total CIDRs (DROP + EDROP)"
```
```bash
chmod +x /usr/local/bin/spamhaus-drop.sh
/usr/local/bin/spamhaus-drop.sh  # initial load
echo "0 6 * * * root /usr/local/bin/spamhaus-drop.sh" > /etc/cron.d/spamhaus-drop
```

---

## 7. Toll Fraud CDR Monitor

**File: `/usr/local/bin/freeswitch-cdr-monitor.sh`**
Located in `f2b-sync-api/agent/freeswitch-cdr-monitor.sh`
```bash
cp f2b-sync-api/agent/freeswitch-cdr-monitor.sh /usr/local/bin/
chmod +x /usr/local/bin/freeswitch-cdr-monitor.sh

# Set email recipient
echo 'ALERT_EMAIL=admin@yourdomain.com' >> /etc/f2b-central.conf

# Add to cron
echo "*/15 * * * * root /usr/local/bin/freeswitch-cdr-monitor.sh" > /etc/cron.d/f2b-cdr-monitor
```

Test: `ALERT_EMAIL=you@test.com /usr/local/bin/freeswitch-cdr-monitor.sh`

---

## 8. File Integrity Web Root Monitoring

**File: `/usr/local/bin/webroot-scan.sh`**
```bash
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/webroot-scan.log"
ALERT_EMAIL="${ALERT_EMAIL:-admin@yourdomain.com}"
STATE_FILE="/var/lib/webroot-scan/baseline"

mkdir -p "$(dirname "$STATE_FILE")"

# New PHP files in last 24h not owned by the site user
NEW_FILES=$(find /home/*/public_html -name "*.php" -ctime -1 -not -user root 2>/dev/null)

if [[ -n "$NEW_FILES" ]]; then
    echo "New PHP files detected on $(hostname -f):\n$NEW_FILES" \
        | mail -s "[FIM] New PHP files on $(hostname -s)" "$ALERT_EMAIL"
    echo "$(date -Iseconds) New PHP files found:\n$NEW_FILES" >> "$LOG"
fi
```
```bash
chmod +x /usr/local/bin/webroot-scan.sh
echo "0 6 * * * root /usr/local/bin/webroot-scan.sh" > /etc/cron.d/webroot-scan
```

---

## 9. TLS Reverse Proxy (for f2b-sync-api + fail2ban-ui)

**File: `/etc/nginx/sites-available/f2b-proxy`**
```nginx
server {
    listen 443 ssl;
    server_name f2b.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/f2b.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/f2b.yourdomain.com/privkey.pem;

    # fail2ban-ui
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # f2b-sync-api
    location /api/v1/ {
        proxy_pass http://127.0.0.1:8000/api/v1/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Require basic auth for sync API (on top of JWT)
    location /api/v1/ {
        auth_basic "f2b-sync-api";
        auth_basic_user_file /etc/nginx/.f2b-htpasswd;
        proxy_pass http://127.0.0.1:8000;
    }
}

server {
    listen 80;
    server_name f2b.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

```bash
# Get cert
apt install certbot python3-certbot-nginx
certbot --nginx -d f2b.yourdomain.com

# Create basic auth for sync API
htpasswd -c /etc/nginx/.f2b-htpasswd f2b-agent
```

---

## Deploy Order

When you're ready to deploy on each server:

```
Server A (FreeSWITCH box):
  1. ESL → 127.0.0.1 only
  2. MySQL bind check
  3. fail2ban watchdog
  4. SSH port change
  5. Spamhaus DROP
  6. CDR monitor

Server B (CyberPanel box):
  1. MySQL bind check
  2. fail2ban watchdog
  3. SSH port change
  4. Spamhaus DROP
  5. File integrity scan

Collector (f2b-sync-api host):
  1. TLS cert + nginx proxy
  2. Sync API basic auth
```
