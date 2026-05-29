"""
SentinelFlow Test Suite
Unit and integration tests for core pipeline components.

Run with:
    pytest tests/ -v --asyncio-mode=auto
"""

import asyncio
import json
import os
import pytest
import pytest_asyncio
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def temp_db_path(tmp_path):
    return str(tmp_path / "test_sentinelflow.db")


@pytest.fixture
def mock_config(temp_db_path):
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from core.config import Config
    config = Config.__new__(Config)
    config.db_path = temp_db_path
    config.output_dir = "/tmp/sf_test_output"
    config.verbose = False
    config.threads = 5
    config.timeout = 10
    config.rate_limit = 50
    config.passive_only = False
    config.telegram_token = None
    config.telegram_chat = None
    config.subfinder_path = "subfinder"
    config.httpx_path = "httpx"
    config.naabu_path = "naabu"
    config.nuclei_path = "nuclei"
    config.ffuf_path = "ffuf"
    config.sqlmap_path = "sqlmap"
    config.shodan_api_key = None
    config.censys_api_id = None
    config.censys_api_secret = None
    config.virustotal_api_key = None
    config.securitytrails_api_key = None
    config.chaos_api_key = None
    config.ports = "80,443,8080"
    config.wordlist_path = "config/wordlists/common.txt"
    config.nuclei_templates = ""
    config.severity_levels = ["critical", "high", "medium", "low", "info"]
    config.alert_on_severity = ["critical", "high"]
    config.cloud_providers = ["aws", "gcp", "azure"]
    config.excluded_subdomains = []
    config.excluded_ports = []
    config._yaml_config = {}
    os.makedirs(config.output_dir, exist_ok=True)
    return config


@pytest_asyncio.fixture
async def db(mock_config):
    from core.database import Database
    database = Database(mock_config.db_path)
    await database.connect()
    yield database
    await database.close()


# ─── Database Tests ───────────────────────────────────────────────────────────

class TestDatabase:
    """Tests for the SQLite database layer."""

    @pytest.mark.asyncio
    async def test_upsert_domain(self, db):
        domain_id = await db.upsert_domain("example.com")
        assert domain_id is not None
        assert isinstance(domain_id, int)
        assert domain_id > 0

    @pytest.mark.asyncio
    async def test_upsert_domain_idempotent(self, db):
        id1 = await db.upsert_domain("example.com")
        id2 = await db.upsert_domain("example.com")
        assert id1 == id2

    @pytest.mark.asyncio
    async def test_upsert_subdomain_new(self, db):
        domain_id = await db.upsert_domain("example.com")
        sub_id, is_new = await db.upsert_subdomain(
            domain_id, "sub.example.com", "crtsh", "1.2.3.4"
        )
        assert sub_id is not None
        assert is_new is True

    @pytest.mark.asyncio
    async def test_upsert_subdomain_existing(self, db):
        domain_id = await db.upsert_domain("example.com")
        id1, is_new1 = await db.upsert_subdomain(domain_id, "sub.example.com", "crtsh")
        id2, is_new2 = await db.upsert_subdomain(domain_id, "sub.example.com", "hackertarget")
        assert id1 == id2
        assert is_new1 is True
        assert is_new2 is False

    @pytest.mark.asyncio
    async def test_get_subdomains(self, db):
        domain_id = await db.upsert_domain("example.com")
        await db.upsert_subdomain(domain_id, "a.example.com", "crtsh")
        await db.upsert_subdomain(domain_id, "b.example.com", "hackertarget")
        subs = await db.get_subdomains(domain_id)
        assert len(subs) == 2
        hostnames = [s["subdomain"] for s in subs]
        assert "a.example.com" in hostnames
        assert "b.example.com" in hostnames

    @pytest.mark.asyncio
    async def test_upsert_service(self, db):
        domain_id = await db.upsert_domain("example.com")
        sub_id, _ = await db.upsert_subdomain(domain_id, "www.example.com", "crtsh")
        svc_data = {
            "url": "https://www.example.com",
            "status_code": 200,
            "title": "Example Domain",
            "server": "nginx/1.18",
            "tech_stack": ["WordPress"],
            "tls_valid": True,
        }
        svc_id, is_new = await db.upsert_service(sub_id, svc_data)
        assert svc_id is not None
        assert is_new is True

    @pytest.mark.asyncio
    async def test_insert_finding(self, db):
        domain_id = await db.upsert_domain("example.com")
        scan_id = await db.create_scan("example.com", ["discovery", "audit"])
        finding_id = await db.insert_finding({
            "scan_id": scan_id,
            "service_id": None,
            "subdomain": "example.com",
            "url": "https://example.com/.env",
            "phase": "audit",
            "severity": "critical",
            "category": "exposed_file",
            "title": "Exposed .env File",
            "description": "The .env file is publicly accessible",
            "evidence": "DB_PASSWORD=secret123",
            "remediation": "Restrict access to .env files",
            "tool": "sentinelflow-fuzzer",
        })
        assert finding_id is not None

    @pytest.mark.asyncio
    async def test_get_findings_by_severity(self, db):
        domain_id = await db.upsert_domain("example.com")
        scan_id = await db.create_scan("example.com", ["dast"])

        for sev in ["critical", "high", "medium"]:
            await db.insert_finding({
                "scan_id": scan_id,
                "phase": "dast",
                "severity": sev,
                "title": f"Test {sev} finding",
                "tool": "test",
            })

        critical = await db.get_findings(scan_id=scan_id, severity="critical")
        assert len(critical) == 1
        assert critical[0]["severity"] == "critical"

        high_up = await db.get_findings(scan_id=scan_id, min_severity="high")
        assert len(high_up) == 2

    @pytest.mark.asyncio
    async def test_findings_summary(self, db):
        scan_id = await db.create_scan("example.com", ["dast"])
        severities = ["critical", "critical", "high", "medium", "low"]
        for sev in severities:
            await db.insert_finding({
                "scan_id": scan_id,
                "phase": "dast",
                "severity": sev,
                "title": f"Finding",
                "tool": "test",
            })
        summary = await db.get_findings_summary(scan_id)
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1

    @pytest.mark.asyncio
    async def test_mark_finding_alerted(self, db):
        scan_id = await db.create_scan("example.com", ["dast"])
        fid = await db.insert_finding({
            "scan_id": scan_id,
            "phase": "dast",
            "severity": "critical",
            "title": "Critical Finding",
            "tool": "test",
        })
        # Initially not alerted
        unalerted = await db.get_findings(scan_id=scan_id, alerted=False)
        assert any(f["id"] == fid for f in unalerted)

        await db.mark_finding_alerted(fid)

        # Now should be alerted
        alerted = await db.get_findings(scan_id=scan_id, alerted=True)
        assert any(f["id"] == fid for f in alerted)

    @pytest.mark.asyncio
    async def test_scan_lifecycle(self, db):
        scan_id = await db.create_scan("example.com", ["discovery", "audit", "dast"])
        assert scan_id is not None

        scan = await db.get_scan(scan_id)
        assert scan["status"] == "running"

        await db.complete_scan(scan_id, status="complete", stats={"critical": 1})
        scan = await db.get_scan(scan_id)
        assert scan["status"] == "complete"


# ─── Rate Limiter Tests ───────────────────────────────────────────────────────

class TestRateLimiter:
    """Tests for the token bucket rate limiter."""

    @pytest.mark.asyncio
    async def test_allows_requests_within_rate(self):
        from utils.rate_limiter import RateLimiter
        limiter = RateLimiter(rate=1000)  # High rate, should not block
        start = asyncio.get_event_loop().time()
        for _ in range(10):
            await limiter.acquire()
        elapsed = asyncio.get_event_loop().time() - start
        assert elapsed < 1.0  # Should complete quickly

    @pytest.mark.asyncio
    async def test_throttles_at_limit(self):
        from utils.rate_limiter import RateLimiter
        limiter = RateLimiter(rate=5, burst=5)
        # Drain burst
        for _ in range(5):
            await limiter.acquire()
        # Next should require waiting
        start = asyncio.get_event_loop().time()
        await limiter.acquire()
        elapsed = asyncio.get_event_loop().time() - start
        assert elapsed >= 0.1  # Should have waited for refill


# ─── Discovery Tests ──────────────────────────────────────────────────────────

class TestAssetDiscovery:
    """Tests for the asset discovery phase."""

    @pytest.mark.asyncio
    async def test_is_valid_subdomain(self, mock_config, db):
        from phases.discovery import AssetDiscovery
        discovery = AssetDiscovery(mock_config, db)

        assert discovery._is_valid_subdomain("sub.example.com", "example.com") is True
        assert discovery._is_valid_subdomain("example.com", "example.com") is True
        assert discovery._is_valid_subdomain("evil.com", "example.com") is False
        assert discovery._is_valid_subdomain("notexample.com", "example.com") is False
        assert discovery._is_valid_subdomain("*.example.com", "example.com") is False

    def test_extract_title(self, mock_config, db):
        from phases.discovery import AssetDiscovery
        discovery = AssetDiscovery(mock_config, db)

        html = "<html><head><title>Test Page</title></head></html>"
        assert discovery._extract_title(html) == "Test Page"

        no_title = "<html><body>No title</body></html>"
        assert discovery._extract_title(no_title) == ""

    def test_detect_technologies(self, mock_config, db):
        from phases.discovery import AssetDiscovery
        discovery = AssetDiscovery(mock_config, db)

        headers = {"X-Powered-By": "PHP/8.1"}
        body = "wp-content/themes/default wp-includes/js/jquery.js"
        tech = discovery._detect_technologies(headers, body)
        assert "PHP/8.1" in tech
        assert "WordPress" in tech

    def test_detect_cdn(self, mock_config, db):
        from phases.discovery import AssetDiscovery
        discovery = AssetDiscovery(mock_config, db)

        cf_headers = {"CF-Ray": "abc123-LAX"}
        assert discovery._detect_cdn(cf_headers) == "Cloudflare"

        no_cdn = {}
        assert discovery._detect_cdn(no_cdn) == ""


# ─── Auditor Tests ────────────────────────────────────────────────────────────

class TestConfigAuditor:
    """Tests for the configuration auditor."""

    def test_classify_path_severity(self, mock_config, db):
        from phases.auditor import ConfigAuditor
        auditor = ConfigAuditor(mock_config, db)

        # Critical
        assert auditor._classify_path_severity(".env", "DB_PASSWORD=secret") == "critical"
        assert auditor._classify_path_severity("id_rsa", "") == "critical"

        # High
        assert auditor._classify_path_severity(".git/config", "") == "high"
        assert auditor._classify_path_severity("wp-config.php", "") == "high"

        # Medium
        assert auditor._classify_path_severity("swagger.json", "") == "medium"

        # None (not interesting)
        assert auditor._classify_path_severity("random.txt", "") is None

    @pytest.mark.asyncio
    async def test_js_secret_patterns(self, mock_config, db):
        from phases.auditor import JS_SECRET_PATTERNS
        import re

        # Test AWS key pattern
        aws_pattern, _ = JS_SECRET_PATTERNS["aws_access_key"]
        test_content = 'var key = "AKIAIOSFODNN7EXAMPLE";'
        match = re.search(aws_pattern, test_content)
        assert match is not None

        # Test Stripe pattern
        stripe_pattern, _ = JS_SECRET_PATTERNS["stripe_secret"]
        stripe_content = 'stripe_key = "FAKE_STRIPE_TEST_KEY";'
        match = re.search(stripe_pattern, stripe_content)
        assert match is not None

        # Test Google API key pattern
        google_pattern, _ = JS_SECRET_PATTERNS["google_api_key"]
        google_content = 'apiKey: "AIzaSyB5pVGSxNh1234567890ABCDE"'
        match = re.search(google_pattern, google_content)
        assert match is not None


# ─── DAST Tests ───────────────────────────────────────────────────────────────

class TestDASTScanner:
    """Tests for the DAST scanner."""

    def test_detect_sqli_error_mysql(self, mock_config, db):
        from phases.dast import DASTScanner
        scanner = DASTScanner(mock_config, db)

        body = "You have an error in your SQL syntax; check the manual that corresponds to MySQL"
        db_type, sig = scanner._detect_sqli_error(body)
        assert db_type == "mysql"

    def test_detect_sqli_error_postgresql(self, mock_config, db):
        from phases.dast import DASTScanner
        scanner = DASTScanner(mock_config, db)

        body = "PostgreSQL ERROR: syntax error at or near"
        db_type, sig = scanner._detect_sqli_error(body)
        assert db_type == "postgresql"

    def test_detect_sqli_no_error(self, mock_config, db):
        from phases.dast import DASTScanner
        scanner = DASTScanner(mock_config, db)

        body = "Welcome to our website! Nothing suspicious here."
        db_type, sig = scanner._detect_sqli_error(body)
        assert db_type is None

    def test_rebuild_url(self, mock_config, db):
        from phases.dast import DASTScanner
        scanner = DASTScanner(mock_config, db)

        url = "https://example.com/search?q=hello&page=1"
        new_params = {"q": "test'", "page": "1"}
        rebuilt = scanner._rebuild_url(url, new_params)
        assert "q=test" in rebuilt
        assert "example.com/search" in rebuilt


# ─── Report Generator Tests ───────────────────────────────────────────────────

class TestReportGenerator:
    """Tests for the report generator."""

    def test_calculate_risk_score_zero(self, mock_config, db):
        from reports.generator import ReportGenerator
        gen = ReportGenerator(mock_config, db)
        assert gen._calculate_risk_score({}) == 0

    def test_calculate_risk_score_critical(self, mock_config, db):
        from reports.generator import ReportGenerator
        gen = ReportGenerator(mock_config, db)
        score = gen._calculate_risk_score({"critical": 3, "high": 2})
        assert score > 50
        assert score <= 100

    def test_risk_rating(self, mock_config, db):
        from reports.generator import ReportGenerator
        gen = ReportGenerator(mock_config, db)
        assert gen._risk_rating(90) == "CRITICAL"
        assert gen._risk_rating(65) == "HIGH"
        assert gen._risk_rating(45) == "MEDIUM"
        assert gen._risk_rating(25) == "LOW"
        assert gen._risk_rating(5) == "INFORMATIONAL"

    @pytest.mark.asyncio
    async def test_generate_json_report(self, mock_config, db):
        from reports.generator import ReportGenerator
        from pathlib import Path
        import tempfile

        gen = ReportGenerator(mock_config, db)

        report_data = {
            "metadata": {
                "report_title": "Test Report",
                "generated_at": "2024-01-01T00:00:00",
                "scan_id": 1,
                "domain": "example.com",
                "scan_started": None,
                "scan_finished": None,
                "phases_run": ["discovery"],
                "tool": "SentinelFlow v1.0",
                "classification": "CONFIDENTIAL",
            },
            "executive_summary": {
                "risk_score": 75,
                "risk_rating": "HIGH",
                "total_assets": 5,
                "live_services": 3,
                "total_findings": 2,
                "findings_by_severity": {"high": 2},
                "remediation_priority": [],
                "key_risks": [],
            },
            "asset_inventory": {"subdomains": [], "services": []},
            "findings": [],
            "owasp_coverage": {},
            "compliance": {},
            "recommendations": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            json_path = await gen._generate_json(report_data, output_dir)
            assert json_path.exists()

            with open(json_path) as f:
                loaded = json.load(f)
            assert loaded["metadata"]["domain"] == "example.com"
            assert loaded["executive_summary"]["risk_score"] == 75


# ─── Integration Test ─────────────────────────────────────────────────────────

class TestPipelineIntegration:
    """Integration test: run the full pipeline against localhost (mock responses)."""

    @pytest.mark.asyncio
    async def test_orchestrator_initializes(self, mock_config):
        from core.orchestrator import SentinelOrchestrator
        orch = SentinelOrchestrator(mock_config)
        await orch.initialize()
        assert orch.db is not None
        await orch.shutdown()

    @pytest.mark.asyncio
    async def test_pipeline_creates_scan_record(self, mock_config, db):
        """Test that a pipeline run creates a proper scan record."""
        from core.orchestrator import SentinelOrchestrator

        orch = SentinelOrchestrator(mock_config)
        await orch.initialize()

        # Mock all phases to avoid real network calls
        with patch.object(orch, '_run_discovery', new_callable=AsyncMock) as mock_disc, \
             patch.object(orch, '_run_audit', new_callable=AsyncMock) as mock_audit, \
             patch.object(orch, '_run_dast', new_callable=AsyncMock) as mock_dast, \
             patch.object(orch, '_run_reporting', new_callable=AsyncMock) as mock_report:

            mock_disc.return_value = {"subdomains": [], "services": []}
            mock_audit.return_value = {"total_findings": 0}
            mock_dast.return_value = {"total_findings": 0}
            mock_report.return_value = {"report_files": {}}

            results = await orch.run_pipeline(
                domain="test.example.com",
                phases=["discovery", "audit", "dast", "report"]
            )

        assert results["domain"] == "test.example.com"
        assert "scan_id" in results
        assert results["scan_id"] is not None

        # Verify scan record in DB
        scan = await orch.db.get_scan(results["scan_id"])
        assert scan is not None
        assert scan["domain"] == "test.example.com"
        assert scan["status"] == "complete"

        await orch.shutdown()
