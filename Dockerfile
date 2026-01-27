# Chronix Dockerfile
#
# Multi-stage build for minimal production image

# Build stage
FROM python:3.12-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir .

# Production stage
FROM python:3.12-slim

# Security: Run as non-root user
RUN useradd --create-home --shell /bin/bash chronix

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=chronix:chronix src/ ./src/

# Create data directory
RUN mkdir -p /data && chown chronix:chronix /data

# Switch to non-root user
USER chronix

# Environment defaults
ENV CHRONIX_DB_PATH=/data/chronix.db
ENV CHRONIX_HOST=0.0.0.0
ENV CHRONIX_PORT=8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

EXPOSE 8000

# Run the application
CMD ["python", "-m", "chronix"]
