# syntax=docker/dockerfile:1

# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install dependencies into user prefix so they can be copied cheaply
COPY requirements.txt .
RUN pip install --no-cache-dir --user --require-hashes -r requirements.txt 2>/dev/null || \
    pip install --no-cache-dir --user -r requirements.txt

# ── Stage 2: minimal runtime ──────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: create dedicated non-root user (UID 1001)
RUN groupadd -r appgroup && \
    useradd -r -g appgroup -u 1001 -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy pip-installed packages from builder stage
COPY --from=builder /root/.local /home/appuser/.local

# Copy application source (owned by appuser)
COPY --chown=appuser:appgroup app.py .

# Remove shell access helpers to reduce attack surface
RUN apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

USER appuser

ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" \
    || exit 1

ENTRYPOINT ["python", "app.py"]
