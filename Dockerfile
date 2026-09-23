FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock ./

RUN uv sync --extra prod --no-dev

ENV PATH="/app/.venv/bin:$PATH"

COPY wsgi.py manage_users.py ./
COPY app/ app/

RUN useradd --system --no-create-home --shell /sbin/nologin appuser \
    && mkdir -p /app/certs /app/data \
    && chown -R appuser:appuser /app

ENV HOME=/tmp
USER appuser

EXPOSE 8100

# --workers 1: historically required because the FAZ health poller
# (app/faz_health_cache.py) kept its scheduler and polled-status cache in
# this process's memory only, and a pre-forked Gunicorn worker would run
# its own independent scheduler/cache, doubling the FAZ/SNMP poll rate.
# Under the collector/web split (app/collector.py — see readme.md), this
# image's default entrypoint (this CMD) starts NO scheduler at all
# (RUN_SCHEDULERS defaults to "collector", not "inline"); a separate
# `app.collector` container/service owns every poller instead, so that
# reason no longer strictly applies. Left at 1 anyway as the conservative
# production default — raising it is a deliberate follow-up, not implied
# by this change. Concurrency comes from threads instead.
CMD ["gunicorn", \
     "--workers", "1", \
     "--threads", "8", \
     "--worker-class", "gthread", \
     "--bind", "0.0.0.0:8100", \
     "--timeout", "120", \
     "--worker-tmp-dir", "/dev/shm", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "wsgi:app"]
