ARG PYTHON_VERSION=3.10
FROM python:${PYTHON_VERSION}-slim

RUN useradd --create-home --uid 10001 app \
    && mkdir /app \
    && chown app:app /app

WORKDIR /app

ENV PIP_NO_CACHE_DIR=false \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=10 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENV PATH="/app/.venv/bin:$PATH"

COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

USER 10001

COPY --chown=app:app . /app/

RUN mkdir -p /app/data/ipinfo

EXPOSE 8000

# Probes port 8000. Any HTTP answer counts as alive; a refused connection or a timeout fails.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request, urllib.error\ntry:\n    urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3)\nexcept urllib.error.HTTPError:\n    pass"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--reload"]
