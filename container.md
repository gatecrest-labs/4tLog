# Docker Deployment

This covers running 4tlog as a container via Docker Compose — the
alternative to the RHEL bare-metal path in `docs/deployment.md`.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2 (the `docker compose` subcommand, not the standalone
  `docker-compose` binary)

## Quick sequence

```bash
cp .env.example .env
# Fill in SECRET_KEY — generate one with:
#   docker compose run --rm app uv run python manage_users.py secret
# and paste the result into .env.

cp users.example.json users.json
cp groups.example.json groups.json
cp faz_targets.example.json faz_targets.json

# TLS cert — see the TLS section below for a self-signed option
mkdir -p certs
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout certs/key.pem -out certs/cert.pem -subj "/CN=4tlog.local"

# Create the first admin account (users.json/groups.json are bind-mounted,
# so this writes to the host files):
docker compose run --rm app uv run python manage_users.py add admin --role admin

docker compose up -d
```

## TLS

An `nginx` service in front of `app` terminates TLS and proxies plain HTTP
to `app:8100` over the internal Docker network — `app` itself no longer
publishes a port to the host.

There's no `certs.example/` in this repo (certs aren't templatable the way
JSON config is) — place your real `certs/cert.pem`/`certs/key.pem`, or for
local/dev use, generate a self-signed pair:

```bash
mkdir -p certs
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=4tlog.local"
```

For production, replace `certs/cert.pem`/`certs/key.pem` with a real
certificate/key pair before `docker compose up`.

Set in `.env`:

```bash
COOKIE_SECURE=true
TRUSTED_PROXY_COUNT=1
```

`COOKIE_SECURE=auto` only detects local `certs/cert.pem`/`certs/key.pem`
from the `app` container's own filesystem — but in this topology TLS
terminates at `nginx`, so `app` never sees a cert on disk itself, and
`auto` would silently leave session cookies insecure. Same reasoning as
the RHEL/Nginx path in `docs/deployment.md` §5.

The app is reachable at `https://localhost:8300` (HTTP on `8301` redirects
to HTTPS).

## Collector/web process split

`docker compose up -d` now starts three services: `app` (Gunicorn, the web
UI and external API), `collector` (`python -m app.collector`, owns every
FAZ health/log stats/threat stats/host metrics poller), and `nginx`. Both
`app` and `collector` share a named volume (`4tlog-data`, mounted at
`/app/data`, set via `DATA_DIR=/app/data`) for the SQLite files
(`logstats.db`, `hostmetrics.db`, `collector_state.db`) — `collector`
writes each poll's latest result there, and `app` reads it through when
its own in-memory cache is empty (always, in this topology, since `app`
itself starts no scheduler). See readme.md's "Collector/web process
split" section for the read-through mechanics.

`collector` only bind-mounts `faz_targets.json` — it never touches
auth/session/API-token state, so `users.json`/`groups.json`/
`app_settings.json`/`api_tokens.json` stay `app`-only.

`docker compose logs -f collector` shows poll activity; `docker compose
restart collector` after editing `faz_targets.json` if you don't want to
wait for its next scheduled cycle.
