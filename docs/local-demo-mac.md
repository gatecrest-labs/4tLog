# Run the 4tlog demo on a Mac

This guide gets demo mode running on a Mac in a local container, so you can try a branch
(for example a pull request) before it is merged. Demo mode needs no FortiAnalyzer, no
`.env` and no local JSON files, and it never contacts a real network. See
[readme.md](../readme.md#demo-mode) for what the demo contains.

Two ways to run it:

- **[With Docker](#1-with-docker)**: the same image a real deployment uses, in one container.
  Recommended.
- **[Without Docker](#2-without-docker)**: straight from the checkout with `uv`, which is
  quickest when you are changing code.

## Prerequisites

- **A recent macOS** (one your Docker app supports), on Apple Silicon (M1 to M4) or Intel. Both work: the base image
  (`python:3.12-slim`) and every dependency have native arm64 builds, so no `--platform`
  flag or Rosetta is needed.
- **git**: run `git --version`. If macOS offers to install the Command Line Tools, accept.
- **For Docker**: [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/),
  or OrbStack. Either one provides `docker` and the `docker compose` command. Start it once
  and wait until it says it is running, then check:

  ```bash
  docker version
  docker compose version     # v2 or later
  ```

- **Without Docker**: [uv](https://docs.astral.sh/uv/), installed with `brew install uv` or
  uv's own installer. uv fetches a suitable Python (3.11 or later) by itself.

## Get the branch

New checkout:

```bash
git clone https://github.com/gatecrest-labs/4tLog.git
cd 4tLog
git switch claude/4tlog-demo-mode-gs73um
```

Existing checkout (commit or stash any local changes first):

```bash
cd 4tLog
git fetch origin
git switch claude/4tlog-demo-mode-gs73um
git pull
```

`git switch` creates the local branch from `origin/` automatically the first time. If
your git is older than 2.23, use `git checkout claude/4tlog-demo-mode-gs73um` instead.
Once the pull request is merged, use `main` in place of the branch name.

## 1. With Docker

### Build and start

From the checkout:

```bash
docker compose -f docker-compose.demo.yml up -d --build
docker compose -f docker-compose.demo.yml ps       # wait for "healthy"
```

The first build downloads the base image and the dependencies, so it takes a few
minutes. Later builds reuse the cache.

### Open it

Go to <http://localhost:8100> and sign in:

| User           | Password         | Sees                                       |
|----------------|------------------|--------------------------------------------|
| `demo-admin`   | `gatecrest-demo` | every tab, including Admin                 |
| `demo-analyst` | `gatecrest-demo` | Dashboard, SD-WAN and Log Search, Branches only |

It is plain `http://`. The browser may say "Not secure", which is expected for a local demo.
The port is bound to `127.0.0.1`, so other machines on your network cannot reach it.

Watch the logs with:

```bash
docker compose -f docker-compose.demo.yml logs -f
```

### Update to newer commits

When the branch gets new commits:

```bash
git pull
docker compose -f docker-compose.demo.yml up -d --build
```

`--build` rebuilds the image from your checkout, and `up -d` replaces the running container
with one from the new image. Your browser session ends, because the demo uses a new random
key each time it starts, so just sign in again. Demo data is generated rather than stored,
so nothing is lost.

If something looks stale, rebuild from scratch:

```bash
docker compose -f docker-compose.demo.yml build --no-cache
docker compose -f docker-compose.demo.yml up -d --force-recreate
```

### If you already run 4tlog in Docker

The demo is kept apart from a real 4tlog stack (`docker-compose.yml`), even in the same
checkout:

- **Image**: its image is tagged `4tlog:demo`, so building it never replaces the
  `4tlog:latest` image your real stack runs.
- **Compose project**: it has its own project name (`4tlog-demo`), so `up`, `down` and
  `--remove-orphans` on the demo never touch the real containers.
- **Data and port**: it shares no volumes or local files, and it uses port 8100, which the
  real stack doesn't publish (that stack is on 8300 and 8301).

Your real stack keeps running the code it was built from. Once this branch is merged and
you want the real stack on the new code, rebuild it the usual way, from `main`:

```bash
git switch main && git pull
docker compose up -d --build
```

### Stop and clean up

```bash
docker compose -f docker-compose.demo.yml stop      # pause it, start again with "start"
docker compose -f docker-compose.demo.yml down      # remove the container
docker image rm 4tlog:demo                          # remove the image too
```

`restart: unless-stopped` means a running demo comes back when Docker Desktop restarts.
Use `stop` or `down` when you are finished.

## 2. Without Docker

From the checkout:

```bash
uv sync
DEMO_MODE=true PORT=8100 uv run python wsgi.py
```

Open <http://localhost:8100> and sign in as above. Press Ctrl+C to stop it. After
`git pull`, run `uv sync` again and restart it.

Things to know when running without Docker:

- **Port**: avoid `PORT=5000` on a Mac, because macOS's AirPlay Receiver already listens
  there and you would get an "Address already in use" error or a blank 403 page. Port 8100
  or 5050 both work.
- **Firewall**: the dev server listens on all interfaces, so macOS may ask whether Python
  may accept incoming connections. Choose **Deny**, and `localhost` keeps working.
- **Local files**: demo mode ignores your own `users.json`, `faz_targets.json` and so on,
  and writes its SQLite files to `.demo-data/` in the checkout (git-ignored). Delete that
  folder to start fresh.
- **HTTPS**: if the checkout has `certs/cert.pem` and `certs/key.pem`, the dev server uses
  them, so open `https://localhost:8100` instead.

## Troubleshooting

- **`Cannot connect to the Docker daemon`**: Docker Desktop or OrbStack isn't running.
  Start it, wait until it says it is running, then retry.
- **`port is already allocated` / `Address already in use`**: something else has port 8100.
  Pick another port:
  `DEMO_PORT=8200 docker compose -f docker-compose.demo.yml up -d --build`
  and open <http://localhost:8200>. Use `lsof -nP -iTCP:8100 -sTCP:LISTEN` to see what holds
  the port.
- **`unknown shorthand flag: 'f'` or `docker-compose: command not found`**: you have the old
  standalone Compose. Use `docker compose` (with a space), which Docker Desktop includes.
- **The page doesn't load right after `up`**: the container needs a few seconds to start.
  Wait for `healthy` in `docker compose -f docker-compose.demo.yml ps`, or check
  `docker compose -f docker-compose.demo.yml logs`.
- **Signed out after an update or restart**: this is expected, because each start uses a
  new session key. Sign in again.
- **No demo banner, or a real login screen**: you are running the real app, not the demo.
  Check that you used `-f docker-compose.demo.yml` (or `DEMO_MODE=true` without Docker) and
  that the branch is checked out: `git branch --show-current`.
- **"changes are disabled" when saving in Admin**: this is by design. Demo mode refuses
  every write, while the API self-test still runs.
- **The build fails downloading packages**: this is usually a network or proxy problem on
  the Mac side. Retry, or check Docker Desktop's proxy settings.
- **Running out of disk**: remove old images with `docker image prune`, or remove the demo
  image as shown above.
