FROM python:3.11-slim

LABEL maintainer="SentinelFlow"
LABEL description="EASM & Continuous Security Monitoring Pipeline"

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl git ca-certificates unzip \
    libssl-dev libffi-dev \
    wordlists \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Go toolchain (for ProjectDiscovery tools) ─────────────────────────────────
ENV GO_VERSION=1.22.0
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# ── ProjectDiscovery tools ────────────────────────────────────────────────────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Nuclei template download ──────────────────────────────────────────────────
RUN nuclei -update-templates -silent || true

# ── Application code ──────────────────────────────────────────────────────────
COPY . .

# ── Data directories (mounted as volumes in docker-compose) ───────────────────
RUN mkdir -p /app/data /app/reports /app/logs

# ── Default command: run the pipeline ─────────────────────────────────────────
ENTRYPOINT ["python", "-m", "core.orchestrator"]
CMD ["--help"]
