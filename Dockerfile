ARG PYTHON_VERSION=3.10
FROM python:${PYTHON_VERSION}-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.4 /uv /uvx /bin/

RUN useradd --create-home --uid 10001 app \
    && mkdir /app \
    && chown app:app /app

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=10 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001

COPY --chown=app:app pyproject.toml uv.lock README.md /app/

RUN uv sync --locked --extra dev

ENV PATH="/app/.venv/bin:$PATH"

COPY --chown=app:app guard/ /app/guard/
COPY --chown=app:app tests/ /app/tests/
COPY --chown=app:app examples/ /app/examples/
COPY --chown=app:app docs/ /app/docs/

RUN mkdir -p /app/data/ipinfo

# Probes the app service on port 8000. Any HTTP answer counts as alive; a refused connection or a timeout fails.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request, urllib.error\ntry:\n    urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3)\nexcept urllib.error.HTTPError:\n    pass"]
