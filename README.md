# 🛡 SentinelFlow

**Automated External Attack Surface Management (EASM) & Continuous Security Monitoring Pipeline**

> Gain full visibility into your digital footprint, identify misconfigurations in real time, and validate security controls against OWASP Top 10 benchmarks.

---

## ⚠️ Legal Notice

SentinelFlow is designed for **authorised security testing only**. Only scan domains and systems you own or have explicit written permission to test. Unauthorised scanning is illegal in most jurisdictions.

---

## Architecture

```
Seed Domain
    │
    ▼
┌─────────────────────────────────────────────────┐
│           Core Orchestrator (Python)             │
│                    + SQLite DB                   │
└───────┬──────────────┬──────────────┬────────────┘
        │              │              │
        ▼              ▼              ▼
  ┌──────────┐  ┌──────────────┐  ┌──────────┐
  │ Phase I  │  │   Phase II   │  │ Phase III│
  │Discovery │  │Config & SAST │  │   DAST   │
  │Subfinder │  │FFuf/JS/S3    │  │Nuclei/   │
  │httpx     │  │              │  │SQLmap/XSS│
  │naabu     │  │              │  │          │
  └──────────┘  └──────────────┘  └──────────┘
        │              │              │
        └──────────────┼──────────────┘
                       ▼
            ┌─────────────────────┐
            │  Vuln Assessment    │
            │  (dedup + scoring)  │
            └────────┬────────────┘
                     │
            ┌────────┴────────┐
            ▼                 ▼
    ┌──────────────┐  ┌──────────────┐
    │  Phase IV    │  │  Reporting   │
    │ Telegram Bot │  │  JSON + PDF  │
    └──────────────┘  └──────────────┘
```

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- A Telegram bot token (from [@BotFather](https://t.me/BotFather))
- Your Telegram chat ID (from [@userinfobot](https://t.me/userinfobot))

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in your Telegram tokens
nano .env
```

### 2. Build and start

```bash
# Build the image (downloads Go tools + nuclei templates — takes ~5 min first time)
docker-compose build

# Start lab targets (Juice Shop + DVWA) in the background
docker-compose up -d juice-shop dvwa

# Start the Telegram bot listener
docker-compose up -d telegram-bot
```

### 3. Run a scan

```bash
# Scan a domain
docker-compose run --rm scanner example.com

# Scan without Telegram notifications
docker-compose run --rm scanner example.com --no-notify

# Scan the local lab (Juice Shop)
docker-compose run --rm scanner juice-shop --no-notify
```

### 4. View results

```bash
# List all scans
python sf_cli.py scans

# View findings for scan #1
python sf_cli.py findings 1

# View assets for scan #1
python sf_cli.py assets 1

# Summary stats
python sf_cli.py summary 1

# Re-generate report
python sf_cli.py report 1
```

Reports are saved to `./reports/` as both `.json` and `.pdf`.

---

## Telegram Bot Commands

Once `telegram-bot` is running, message your bot:

| Command | Description |
|---------|-------------|
| `/scan example.com` | Trigger a full EASM scan |
| `/status` | Show last 5 scans |
| `/help` | Show available commands |

Critical and High findings are pushed as real-time alerts.

---

## Local Lab (Phase V)

The docker-compose file includes two pre-configured vulnerable targets for safe testing:

| Target | URL | Description |
|--------|-----|-------------|
| OWASP Juice Shop | http://localhost:3000 | Modern vulnerable web app |
| DVWA | http://localhost:8080 | Classic PHP/MySQL vuln app |

```bash
# Benchmark against both lab targets
python lab/run_lab.py

# Scan only Juice Shop
python lab/run_lab.py --target juice-shop
```

---

## Project Structure

```
sentinelflow/
├── core/
│   ├── orchestrator.py          # Central pipeline coordinator
│   └── database.py              # SQLite schema + helpers
├── phases/
│   ├── discovery/
│   │   ├── subdomain_enum.py    # Subfinder + DNS resolution
│   │   └── service_probe.py     # httpx + naabu port scan
│   ├── audit/
│   │   ├── endpoint_fuzz.py     # FFuf sensitive path discovery
│   │   ├── js_sast.py           # JavaScript secret scanning
│   │   └── cloud_exposure.py    # S3 bucket exposure check
│   ├── dast/
│   │   ├── input_validation.py  # SQLi + XSS parameter probing
│   │   └── nuclei_scan.py       # Nuclei CVE/template scanning
│   ├── alerting/
│   │   └── telegram_bot.py      # Async Telegram alert + bot
│   └── reporting/
│       └── report_generator.py  # JSON + PDF compliance reports
├── config/
│   └── settings.py              # Centralised configuration
├── lab/
│   └── run_lab.py               # Lab benchmark runner
├── sf_cli.py                    # CLI results viewer
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGRAM_BOT_TOKEN` | *required* | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | *required* | Target chat/group ID |
| `SHODAN_API_KEY` | optional | Improves subfinder coverage |
| `SECURITYTRAILS_API_KEY` | optional | Improves subfinder coverage |
| `SCAN_TIMEOUT_SEC` | 3600 | Max seconds per scan |
| `MAX_CONCURRENT_TASKS` | 5 | Parallel task limit |
| `ALERT_ON_SEVERITIES` | `critical,high` | Severities that trigger Telegram |
| `NUCLEI_SEVERITY_FILTER` | `critical,high,medium` | Nuclei severity filter |
| `S3_CHECK_ENABLED` | `true` | Enable S3 bucket exposure checks |

---

## Tool Installation (without Docker)

If running locally without Docker:

```bash
# Python dependencies
pip install -r requirements.txt

# Go tools (requires Go 1.21+)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest

# SQLmap
pip install sqlmap

# Nuclei templates
nuclei -update-templates

# Run
cp .env.example .env && nano .env
python -m core.orchestrator example.com
```

---

## Findings Severity Scale

| Severity | Score | Examples |
|----------|-------|---------|
| Critical | 10 | RCE, public S3 bucket, `.env` exposed, confirmed SQLi |
| High | 7 | XSS, hardcoded API keys, auth bypass, `.git` exposed |
| Medium | 4 | Swagger UI exposed, S3 exists (403), SSRF indicators |
| Low | 1 | Information disclosure, missing security headers |
| Info | 0 | Banner grabs, tech fingerprinting |
