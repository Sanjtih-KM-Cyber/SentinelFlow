# 🛡️ SentinelFlow — Automated EASM Pipeline

> **External Attack Surface Management** — Discover, audit, and monitor your entire digital footprint with a full security pipeline and real-time web dashboard.

---

## ⚠️ Legal Notice

**SentinelFlow is for authorized security testing ONLY.**
Only scan systems you own or have explicit written permission to test.
Unauthorized scanning is illegal under the CFAA and equivalent laws worldwide.

---

## 📸 Dashboard

Open `dashboard/index.html` in a browser for a preview in **demo mode** (no backend required).
For live data, start the Flask API:

```bash
python dashboard/app.py
# → http://localhost:5000
```

---

## 🚀 Quick Start

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install Go Security Tools (optional but recommended)

```bash
# ProjectDiscovery suite
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest

# Update Nuclei templates
nuclei -update-templates
```

> **Note:** All Go tools are optional. SentinelFlow has native Python fallbacks for every tool.

### 3. Configure API Keys (for better passive recon)

```bash
cp .env.example .env
# Edit .env with your API keys
```

### 4. Run a Scan

```bash
# Full pipeline (with authorization confirmation)
python main.py --domain example.com --authorized

# Discovery only (passive recon)
python main.py --domain example.com --phases discovery --authorized

# With Telegram alerts
python main.py --domain example.com \
  --telegram-token YOUR_TOKEN \
  --telegram-chat YOUR_CHAT_ID \
  --authorized
```

### 5. Launch Dashboard

```bash
python dashboard/app.py
# Open http://localhost:5000
```

---

## 🐳 Docker

```bash
# Build and run full stack (includes DVWA + Juice Shop test labs)
cd docker
docker-compose up -d

# Run a scan against the test lab
docker exec sentinelflow python main.py \
  --domain juiceshop \
  --authorized \
  --phases discovery,audit,dast,report
```

---

## 🏗️ Architecture

```
sentinelflow/
├── main.py                    # CLI entry point
├── dashboard/
│   ├── app.py                 # Flask REST API server
│   └── index.html             # Single-page web dashboard
├── core/
│   ├── config.py              # Configuration management
│   ├── database.py            # SQLite async data layer
│   ├── logger.py              # Structured colored logging
│   └── orchestrator.py        # Central pipeline coordinator
├── phases/
│   ├── discovery.py           # Phase I: Asset discovery
│   ├── auditor.py             # Phase II: Config & secret audit
│   ├── dast.py                # Phase III: Dynamic security testing
│   └── notifier.py            # Phase IV: Telegram alerts
├── reports/
│   └── generator.py           # JSON / HTML / PDF report generation
├── utils/
│   ├── http_client.py         # Shared aiohttp session factory
│   ├── rate_limiter.py        # Token bucket rate limiter
│   └── banner.py              # CLI banner
├── config/
│   ├── sentinelflow.yaml      # Main configuration file
│   └── wordlists/common.txt   # Fuzzing wordlist
├── docker/
│   ├── Dockerfile             # Multi-stage build (Go tools + Python)
│   └── docker-compose.yml     # Full stack with test labs
└── tests/
    └── test_sentinelflow.py   # Full test suite (pytest)
```

---

## 🔬 Pipeline Phases

### Phase I: Digital Asset Inventory (Discovery)
- **Passive Recon:** crt.sh, HackerTarget, AnubisDB, AlienVault OTX, URLScan.io
- **API Recon:** SecurityTrails, VirusTotal, Chaos (with API keys)
- **Tool Integration:** `subfinder` for comprehensive passive enum
- **Active DNS:** Concurrent A-record resolution (8.8.8.8, 1.1.1.1)
- **Service Probing:** `httpx` (or native aiohttp fallback) — title, server, tech stack, TLS, CDN, WAF
- **Port Scanning:** `naabu` (or native async TCP scanner)

### Phase II: Configuration & Secret Leakage Audit
- **Path Fuzzing:** 60+ sensitive paths (.env, .git, wp-config, backups, SSH keys…)
- **FFuf Integration:** Thorough directory enumeration via wordlist
- **JS SAST:** 15+ regex patterns for AWS keys, Stripe secrets, JWTs, private keys, passwords…
- **Cloud Exposure:** S3, GCS, Azure Blob public access checks

### Phase III: Dynamic Application Security Testing (DAST)
- **Security Headers:** HSTS, CSP, X-Frame-Options, CORS, Server disclosure
- **Endpoint Discovery:** Wayback Machine CDX API + page crawling + form extraction
- **SQLi Detection:** Error-based, non-destructive (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **XSS Detection:** Reflected XSS with 9 payload variants
- **Open Redirect:** Redirect parameter fuzzing
- **Nuclei:** CVE + misconfiguration template scanning

### Phase IV: Notifications
- Real-time Telegram alerts for Critical/High findings
- Scan start/complete summaries
- Interactive bot mode (`/scan`, `/status`, `/findings`)

### Phase V: Reports
- JSON (machine-readable, full detail)
- HTML (self-contained, shareable)
- PDF (via reportlab or weasyprint)
- OWASP Top 10 mapping
- PCI-DSS, ISO 27001, GDPR compliance assessment
- Risk score (0-100) and remediation timelines

---

## ⚙️ Configuration

Edit `config/sentinelflow.yaml`:

```yaml
scan:
  threads: 10
  rate_limit: 100
  ports: "80,443,8080,8443,..."
  severity: [critical, high, medium, low, info]
  alert_on: [critical, high]

notifications:
  telegram:
    token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
```

Or use environment variables:
```bash
export TELEGRAM_TOKEN=...
export SHODAN_API_KEY=...
export VIRUSTOTAL_API_KEY=...
```

---

## 🤖 Telegram Bot Mode

```bash
python main.py --bot-mode \
  --telegram-token YOUR_TOKEN \
  --telegram-chat YOUR_CHAT_ID
```

Bot commands:
- `/scan example.com` — trigger a scan
- `/status` — recent scan history
- `/findings 3` — findings for scan #3
- `/help` — command reference

---

## 🧪 Testing

```bash
# Run full test suite
pytest tests/ -v --asyncio-mode=auto

# With coverage
pytest tests/ -v --asyncio-mode=auto --cov=. --cov-report=html
```

---

## 📊 Dashboard API

| Endpoint | Description |
|---|---|
| `GET /api/stats` | Overall statistics |
| `GET /api/scans` | Scan history |
| `GET /api/scans/<id>` | Scan detail + findings |
| `GET /api/findings` | All findings (filterable) |
| `GET /api/assets/subdomains?domain=` | Subdomain inventory |
| `GET /api/assets/services?domain=` | Live services |
| `POST /api/scan/start` | Trigger new scan |
| `GET /api/domains` | All monitored domains |

---

## 🔧 CLI Reference

```
python main.py [OPTIONS]

Target:
  --domain DOMAIN           Root domain to scan
  --scope-file FILE         File with multiple domains
  --authorized              Confirm scan authorization (required)

Phases:
  --phases PHASES           Comma-separated: discovery,audit,dast,report
  --skip-phases PHASES      Phases to exclude
  --passive-only            No active probing

Output:
  --output DIR              Results directory (default: ./results)
  --format json|pdf|both    Report format
  --verbose                 Verbose logging

Notifications:
  --telegram-token TOKEN    Telegram bot token
  --telegram-chat CHAT_ID   Telegram chat ID

Bot Mode:
  --bot-mode               Start interactive Telegram bot

Config:
  --config FILE             YAML config file
  --db FILE                 SQLite database path
  --threads N               Concurrent threads (default: 10)
  --timeout N               Request timeout seconds (default: 30)
  --rate-limit N            Requests/second (default: 100)
```

---

## 📄 License

MIT License — See LICENSE file.

**Remember:** Always obtain explicit written authorization before scanning any system.
