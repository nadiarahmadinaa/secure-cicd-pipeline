# syntax=docker/dockerfile:1

# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.14-slim AS builder

WORKDIR /build

# Create a virtual environment — copied wholesale into the runtime stage,
# so packages are always on a known, explicit path regardless of which user runs them.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Stage 2: minimal runtime ──────────────────────────────────────────────────
FROM python:3.14-slim AS runtime

# Security: dedicated non-root user (UID 1001)
RUN groupadd -r appgroup && \
    useradd -r -g appgroup -u 1001 -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy the entire venv from the builder — no path ambiguity
COPY --from=builder /opt/venv /opt/venv

# Copy application source
COPY --chown=appuser:appgroup app.py .

RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

USER appuser

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" \
    || exit 1

# Gunicorn: after_request headers apply at the WSGI layer so Server override works.
# Werkzeug's dev server writes Server at the socket level, bypassing our hook.
ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--access-logfile", "-", "app:app"]
