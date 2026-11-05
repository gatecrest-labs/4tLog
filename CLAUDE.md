# Contributor Notes

This file keeps a compact, public-facing orientation for contributors working in this
repository.

## What 4tlog Does

4tlog is a Flask application for interacting with FortiAnalyzer over its JSON-RPC API.
The main user-facing features are:

- Dashboard health cards backed by a background cache
- Log Search with FAZ-side filters and client-side export
- Admin pages for users, groups, targets, and logs

The Flask app is the primary interface. The Ansible playbook in `ansible/` remains as a
secondary CLI and reference path.

## Repository Layout

- `app/` contains the Flask app, route handlers, FAZ client, health cache, and static UI assets.
- `app/routes/` holds blueprint modules for auth, dashboard, admin, and log search.
- `tests/` contains the pytest suite.
- `ansible/` contains the legacy playbook and its documentation.
- `api-info/` contains FortiAnalyzer reference material used during development.
- `docs/` contains deployment guidance and contributor-facing design summaries.

## Runtime Data

Local runtime files are intentionally excluded from version control:

- `.env`
- `users.json`
- `groups.json`
- `faz_targets.json`
- `certs/`

Seed them from the corresponding example files before running the app.

## Development Commands

```bash
uv sync
uv run ruff check .
uv run pytest -q
uv run python wsgi.py
```

## FortiAnalyzer Version Compatibility

- `FAZClient.version` reports the appliance release; Admin -> API Self-Test (`app/faz_selftest.py`)
  runs the read-only calls the app depends on and shows which work on the connected
  FortiAnalyzer. Run it after a FortiAnalyzer upgrade or a token change.
- Fixtures: `scripts/record_faz_fixture.py` records a scrubbed capture into
  `tests/fixtures/faz_<version>/`; `tests/test_faz_replay_fixtures.py` replays every one. The
  repository is public, so read a capture before committing it.

## Contributor Expectations

- Keep changes focused and add tests for behavior changes.
- Do not commit secrets, local vault files, or live tokens.
- Prefer updating example files and docs when setup or operator workflows change.
- Preserve the cached Dashboard model so requests do not block on live FAZ polling.

For broader contributor context, see [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/superpowers/README.md](docs/superpowers/README.md).
