import json, os, sys, threading, asyncio, re
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, abort
from flask_cors import CORS
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.database import Database
from core.logger import get_logger
logger = get_logger(__name__)
app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)
_db = None
_db_lock = threading.Lock()

def run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result(timeout=30)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)

def get_db():
    global _db
    with _db_lock:
        if _db is None:
            _db = Database(os.environ.get("SF_DB_PATH", "sentinelflow.db"))
            asyncio.run(_db.connect())
    return _db

@app.route("/")
def index():
    return send_from_directory(Path(__file__).parent, "index.html")

@app.route("/api/stats")
def api_stats():
    db = get_db()
    scans = run_async(db.get_recent_scans(limit=100)) or []
    total = critical = high = 0
    domains = set()
    for s in scans:
        domains.add(s["domain"])
        stats = json.loads(s.get("stats") or "{}")
        total += sum(stats.values())
        critical += stats.get("critical", 0)
        high += stats.get("high", 0)
    return jsonify({"total_scans": len(scans), "total_findings": total,
                    "critical_findings": critical, "high_findings": high,
                    "domains_monitored": len(domains),
                    "last_scan": scans[0]["started_at"] if scans else None})

@app.route("/api/scans")
def api_scans():
    db = get_db()
    limit = request.args.get("limit", 20, type=int)
    scans = run_async(db.get_recent_scans(limit=limit)) or []
    result = []
    for s in scans:
        stats = json.loads(s.get("stats") or "{}")
        result.append({"id": s["id"], "domain": s["domain"], "status": s["status"],
                       "phases": json.loads(s.get("phases") or "[]"),
                       "started_at": s["started_at"], "finished_at": s["finished_at"],
                       "stats": stats, "total_findings": sum(stats.values())})
    return jsonify(result)

@app.route("/api/scans/<int:scan_id>")
def api_scan_detail(scan_id):
    db = get_db()
    scan = run_async(db.get_scan(scan_id))
    if not scan:
        abort(404)
    findings = run_async(db.get_findings(scan_id=scan_id)) or []
    summary = run_async(db.get_findings_summary(scan_id)) or {}
    sd = dict(scan)
    sd["stats"] = json.loads(sd.get("stats") or "{}")
    sd["phases"] = json.loads(sd.get("phases") or "[]")
    return jsonify({"scan": sd, "findings": findings, "summary": summary})

@app.route("/api/findings")
def api_findings():
    db = get_db()
    findings = run_async(db.get_findings(
        scan_id=request.args.get("scan_id", type=int),
        severity=request.args.get("severity"),
        min_severity=request.args.get("min_severity"),
    )) or []
    return jsonify(findings[:request.args.get("limit", 500, type=int)])

@app.route("/api/findings/summary")
def api_findings_summary():
    db = get_db()
    scan_id = request.args.get("scan_id", type=int)
    if scan_id:
        return jsonify(run_async(db.get_findings_summary(scan_id)) or {})
    scans = run_async(db.get_recent_scans(limit=200)) or []
    summary = {}
    for s in scans:
        for sev, cnt in json.loads(s.get("stats") or "{}").items():
            summary[sev] = summary.get(sev, 0) + cnt
    return jsonify(summary)

@app.route("/api/assets/subdomains")
def api_subdomains():
    db = get_db()
    domain = request.args.get("domain")
    if not domain:
        return jsonify([])
    domain_id = run_async(db.upsert_domain(domain))
    return jsonify(run_async(db.get_subdomains(domain_id)) or [])

@app.route("/api/assets/services")
def api_services():
    db = get_db()
    domain = request.args.get("domain")
    domain_id = run_async(db.upsert_domain(domain)) if domain else None
    return jsonify(run_async(db.get_services(domain_id)) or [])

@app.route("/api/scan/start", methods=["POST"])
def api_start_scan():
    data = request.json or {}
    domain = re.sub(r'^https?://', '', data.get("domain", "").strip()).rstrip('/')
    phases = data.get("phases", ["discovery", "audit", "dast", "report"])
    if not domain or not re.match(r'^[a-zA-Z0-9\-\.\:]+$', domain):
        return jsonify({"error": "Invalid domain"}), 400
    if not data.get("authorized"):
        return jsonify({"error": "Authorization required"}), 403

    def run_scan():
        try:
            from core.orchestrator import SentinelOrchestrator
            from core.config import Config
            cfg = Config.__new__(Config)
            cfg.db_path = os.environ.get("SF_DB_PATH", "sentinelflow.db")
            cfg.output_dir = "./results"
            cfg.verbose = False
            cfg.threads = 25
            cfg.timeout = 30
            cfg.rate_limit = 200
            cfg.passive_only = False
            cfg.telegram_token = None
            cfg.telegram_chat = None
            cfg.subfinder_path = "subfinder"
            cfg.httpx_path = "httpx_nonexistent"
            cfg.naabu_path = "naabu"
            cfg.nuclei_path = "nuclei"
            cfg.ffuf_path = "ffuf"
            cfg.sqlmap_path = "sqlmap"
            cfg.shodan_api_key = None
            cfg.censys_api_id = None
            cfg.censys_api_secret = None
            cfg.virustotal_api_key = None
            cfg.securitytrails_api_key = None
            cfg.chaos_api_key = None
            cfg.ports = "80,443,8080,8443"
            cfg.wordlist_path = "config/wordlists/common.txt"
            cfg.nuclei_templates = ""
            cfg.severity_levels = ["critical", "high", "medium", "low", "info"]
            cfg.alert_on_severity = ["critical", "high"]
            cfg.cloud_providers = ["aws", "gcp", "azure"]
            cfg.excluded_subdomains = []
            cfg.excluded_ports = []
            cfg._yaml_config = {}

            async def _run():
                orch = SentinelOrchestrator(cfg)
                await orch.initialize()
                await orch.run_pipeline(domain=domain, phases=phases)
                await orch.shutdown()
            asyncio.run(_run())
        except Exception as e:
            logger.error(f"Scan error: {e}")

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"message": f"Scan started for {domain}", "domain": domain})

@app.route("/api/domains")
def api_domains():
    db = get_db()
    scans = run_async(db.get_recent_scans(limit=500)) or []
    domains = {}
    for s in scans:
        d = s["domain"]
        if d not in domains:
            domains[d] = {"domain": d, "last_scan": s["started_at"], "scan_count": 0, "total_findings": 0}
        domains[d]["scan_count"] += 1
        domains[d]["total_findings"] += sum(json.loads(s.get("stats") or "{}").values())
    return jsonify(list(domains.values()))

if __name__ == "__main__":
    print("\n  🛡️  SentinelFlow Dashboard\n  http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
