ARG PYTHON_VERSION=3.10
FROM python:${PYTHON_VERSION}-slim

RUN apt-get update && apt-get install -y \
    libsodium23 \
    wget \
    build-essential \
    libffi-dev \
    curl

WORKDIR /app

ENV PIP_NO_CACHE_DIR=false \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=10 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install uv
RUN pip install uv

COPY pyproject.toml uv.lock README.md /app/

RUN uv sync --locked --extra dev

ENV PATH="/app/.venv/bin:$PATH"

COPY guard/ /app/guard/
COPY tests/ /app/tests/
COPY examples/ /app/examples/
COPY docs/ /app/docs/

RUN mkdir -p /app/data/ipinfo
