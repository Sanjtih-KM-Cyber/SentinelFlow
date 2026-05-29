# ─────────────────────────────────────────────────────────────────────────────
# SentinelFlow Dockerfile
# Multi-stage build: installs Go-based security tools + Python app
# ─────────────────────────────────────────────────────────────────────────────

# Stage 1: Build Go-based security tools
FROM golang:1.21-alpine AS tools-builder

RUN apk add --no-cache git ca-certificates

# Install ProjectDiscovery tools
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Python application
FROM python:3.11-slim

LABEL maintainer="SentinelFlow Security"
LABEL description="Automated External Attack Surface Management Pipeline"
LABEL version="1.0.0"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    libpcap-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Go tools from builder stage
COPY --from=tools-builder /go/bin/subfinder /usr/local/bin/
COPY --from=tools-builder /go/bin/httpx /usr/local/bin/
COPY --from=tools-builder /go/bin/naabu /usr/local/bin/
COPY --from=tools-builder /go/bin/nuclei /usr/local/bin/
COPY --from=tools-builder /go/bin/ffuf /usr/local/bin/

# Create non-root user for security
RUN useradd -m -u 1000 sentinelflow
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY --chown=sentinelflow:sentinelflow . .

# Initialize Nuclei templates (community templates)
RUN nuclei -update-templates -silent || true

# Create output and data directories
RUN mkdir -p /app/results /app/logs /app/data && \
    chown -R sentinelflow:sentinelflow /app/results /app/logs /app/data

# Switch to non-root user
USER sentinelflow

# Default environment
ENV PYTHONPATH=/app
ENV SF_DB_PATH=/app/data/sentinelflow.db

VOLUME ["/app/results", "/app/data", "/app/logs"]

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
