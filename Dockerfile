# =============================================================================
# RIG Security Scanner — Docker Image
# =============================================================================
# Base: Python 3.11 slim (Debian Bookworm)
#
# Build:  docker build -t rig-scanner .
# Run:    docker run --rm rig-scanner scan example.com
# Shell:  docker run --rm -it rig-scanner bash
# =============================================================================

FROM python:3.11-slim-bookworm AS builder

# Prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install build dependencies required by cryptography and other C-ext wheels
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        gcc \
        libssl-dev \
        libffi-dev \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# ── Install Python dependencies ─────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Final stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_USER=rig \
    APP_UID=1001

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Create non-root user
RUN addgroup --system --gid ${APP_UID} ${APP_USER} && \
    adduser --system --uid ${APP_UID} --gid ${APP_UID} --no-create-home ${APP_USER}

# Create application directory
WORKDIR /app

# Copy application source code
COPY src/ src/
COPY config/ config/

# Create reports and config volumes
RUN mkdir -p /app/reports /app/config && \
    chown -R ${APP_USER}:${APP_USER} /app

# Switch to non-root user
USER ${APP_USER}

# Default entrypoint
ENTRYPOINT ["python", "-m", "src.cli"]

# Default command (shows help)
CMD ["--help"]
