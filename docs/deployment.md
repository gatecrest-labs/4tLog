# RHEL Bare-Metal Deployment

This covers running 4tlog directly on a RHEL/Rocky/AlmaLinux host with
Gunicorn behind Nginx, managed by systemd — the alternative to the Docker
path in `container.md`.

## 1. System packages

```bash
sudo dnf install -y python3.12 python3.12-venv nginx git
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## 2. Application user and directory

```bash
sudo useradd --system --home-dir /opt/4tlog --shell /sbin/nologin 4tlog
sudo mkdir -p /opt/4tlog
sudo chown 4tlog:4tlog /opt/4tlog
```

Clone the repo into `/opt/4tlog` as the `4tlog` user (or copy a release
tarball), then:

```bash
cd /opt/4tlog
sudo -u 4tlog uv sync --extra prod --no-dev
sudo -u 4tlog cp .env.example .env   # edit SECRET_KEY, etc.
sudo -u 4tlog cp users.example.json users.json
sudo -u 4tlog cp groups.example.json groups.json
sudo -u 4tlog uv run python manage_users.py secret     # paste into .env
sudo -u 4tlog uv run python manage_users.py add admin --role admin
```

## 3. TLS certificates

Terminate TLS at Nginx (recommended) rather than Gunicorn. Obtain a
certificate (e.g. via `certbot --nginx`) or place an internal CA-issued
cert/key at a path Nginx can read.

## 4. systemd unit

`/etc/systemd/system/4tlog.service`:

```ini
[Unit]
Description=4tlog Gunicorn service
After=network.target

[Service]
User=4tlog
Group=4tlog
WorkingDirectory=/opt/4tlog
Environment="PATH=/opt/4tlog/.venv/bin"
ExecStart=/opt/4tlog/.venv/bin/gunicorn \
    --workers 1 --threads 8 --worker-class gthread \
    --bind 127.0.0.1:8100 --timeout 120 \
    --access-logfile - --error-logfile - \
    wsgi:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 4tlog
sudo systemctl status 4tlog
```

**Note on `--workers 1 --threads 8` / `gthread`:** historically required
because every poller (`app/faz_health_cache.py`, etc.) ran its APScheduler
job and in-memory cache inside the Gunicorn process itself — per-process
state, not shared across pre-forked workers. Since the collector/web
process split (see readme.md's "Collector/web process split" and the
`4tlog-collector.service` unit below), this Gunicorn service starts no
scheduler at all by default (`RUN_SCHEDULERS` unset — its default is
"collector", not "inline") and reads poll results through each cache
module's SQLite read-through fallback instead, so that reason no longer
strictly applies. Left at 1 worker anyway as the conservative default;
raising it is a deliberate follow-up, not implied by this change. Get
concurrency from threads instead (`--worker-class gthread`, which lets a
background thread run within the same process — `sync` workers fork child
processes and don't share the parent's threads at all).

### Collector service

A second systemd unit runs `python -m app.collector` — the process that
now owns every poller (FAZ health, log stats, threat stats, host
metrics). It shares `/opt/4tlog` (and its SQLite files, at `DATA_DIR`,
default the repo root) with the Gunicorn service above; no bare-metal
`DATA_DIR` override is needed since both processes already share the same
filesystem (unlike the Docker Compose topology, which needs an explicit
shared volume — see `container.md`).

`/etc/systemd/system/4tlog-collector.service`:

```ini
[Unit]
Description=4tlog collector (poller) service
After=network.target

[Service]
User=4tlog
Group=4tlog
WorkingDirectory=/opt/4tlog
Environment="PATH=/opt/4tlog/.venv/bin"
ExecStart=/opt/4tlog/.venv/bin/python -m app.collector
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 4tlog-collector
sudo systemctl status 4tlog-collector
```

Do not set `RUN_SCHEDULERS=inline` on the Gunicorn service while also
running `4tlog-collector` — that starts every poller twice.

## 5. Nginx reverse proxy

`/etc/nginx/conf.d/4tlog.conf`:

```nginx
server {
    listen 443 ssl;
    server_name 4tlog.example.internal;

    ssl_certificate     /etc/pki/tls/certs/4tlog.crt;
    ssl_certificate_key /etc/pki/tls/private/4tlog.key;

    location / {
        proxy_pass http://127.0.0.1:8100;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

server {
    listen 80;
    server_name 4tlog.example.internal;
    return 301 https://$host$request_uri;
}
```

Set `TRUSTED_PROXY_COUNT=1` in `.env` so Flask trusts Nginx's
`X-Forwarded-*` headers for HSTS and client-IP-based rate limiting. Also set
`COOKIE_SECURE=true` explicitly in `.env`:

```bash
# .env
TRUSTED_PROXY_COUNT=1
COOKIE_SECURE=true
```

`COOKIE_SECURE=auto` only sets the cookie's `Secure` flag when local
`certs/cert.pem`/`certs/key.pem` files are present — but in this topology
TLS terminates at Nginx, so the Gunicorn/Flask process itself never sees a
cert on disk, and `auto` would silently leave session cookies insecure.

```bash
sudo systemctl enable --now nginx
sudo nginx -t && sudo systemctl reload nginx
```

## 6. Firewalld

```bash
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload
```

## 7. SELinux

If SELinux is enforcing and Nginx refuses to proxy to Gunicorn:

```bash
sudo setsebool -P httpd_can_network_connect 1
```

## 8. Verify

```bash
curl -sf https://4tlog.example.internal/login | grep -q Password && echo OK
```
