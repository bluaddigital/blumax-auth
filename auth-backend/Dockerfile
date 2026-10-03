# ─── Stage 1: builder ───────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml ./

RUN uv venv .venv && \
    uv pip install --no-cache-dir -e ".[dev]" --python .venv/bin/python

# ─── Stage 2: runtime ───────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

COPY --from=builder /app/.venv /app/.venv

COPY app/ ./app/
COPY migrations/ ./migrations/
COPY scripts/ ./scripts/
COPY alembic.ini ./

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# appuser needs write access to create the dev-only generated signing key
# (app/core/keys.py::_load_or_create_dev_key, JWT_DEV_KEY_PATH) -- never
# needed in production, which requires JWT_PRIVATE_KEY to already be set
# and refuses to start without it (keys.py's own production guard). The
# directory must exist with correct ownership IN THE IMAGE before
# docker-compose.yml's named volume mounts over it (Phase 3C) -- an
# empty mount point Docker creates fresh at runtime defaults to root
# ownership, which a mere `chown -R /app` done before the directory
# exists cannot fix.
RUN mkdir -p /app/.dev-keys && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8040

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8040/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8040", "--workers", "1"]
