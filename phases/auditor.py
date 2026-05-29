"""
SentinelFlow Phase II: Configuration & Secret Leakage Auditing
Detects exposed config files, hardcoded secrets in JS, and public cloud buckets.
"""

import asyncio
import re
import json
import shutil
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

import aiohttp

from core.config import Config
from core.database import Database
from core.logger import get_logger, log_finding
from utils.http_client import create_session
from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

# ─── Sensitive Path Wordlist ──────────────────────────────────────────────────

SENSITIVE_PATHS = [
    # Environment & config files
    ".env", ".env.local", ".env.production", ".env.backup", ".env.bak",
    ".env.old", ".env.dev", ".env.staging", ".env.test", ".env.example",
    "config.env", ".env2", "env.txt", ".environment",
    # Git exposure
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG", ".gitignore",
    ".git/logs/HEAD", ".git/refs/heads/master", ".git/refs/heads/main",
    ".git/packed-refs", ".git/index", ".git/FETCH_HEAD",
    # SVN/Mercurial
    ".svn/entries", ".svn/wc.db", ".hg/hgrc",
    # Server configs
    "config.php", "config.yml", "config.yaml", "config.json", "config.xml",
    "configuration.php", "settings.php", "wp-config.php", "database.yml",
    "application.properties", "application.yml", "appsettings.json",
    "web.config", "app.config", "local.xml", "local.yml",
    "database.php", "db.php", "connection.php",
    # AWS / Cloud
    "aws.json", "credentials", ".aws/credentials", "s3cfg",
    ".boto", "cloud.yaml", "gcloud.json",
    # SSH / Keys
    "id_rsa", "id_rsa.pub", ".ssh/id_rsa", "server.key", "private.key",
    "server.pem", "cert.pem", "key.pem", "ssl.key",
    # Backup files
    "backup.sql", "backup.zip", "dump.sql", "db.sql", "database.sql",
    "backup.tar.gz", "www.zip", "site.zip", "backup.bak",
    "data.sql", "users.sql", "admin.sql", "passwords.txt",
    "backup.tar", "site.tar.gz", "files.zip",
    # Docker
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    ".dockerenv", "docker-compose.override.yml",
    # Package managers / dependency files
    "package.json", "composer.json", "requirements.txt", "Gemfile",
    "yarn.lock", "package-lock.json", "composer.lock", "Pipfile",
    # Logs
    "debug.log", "error.log", "access.log", "laravel.log",
    "logs/debug.log", "storage/logs/laravel.log",
    "log.txt", "logs.txt", "application.log", "server.log",
    # Admin panels
    "admin/", "admin/login", "administrator/", "wp-admin/",
    "phpmyadmin/", "adminer.php", "cpanel/", "admin.php",
    "administrator/index.php", "manage/", "management/",
    # API docs
    "swagger.json", "swagger.yaml", "api-docs/", "openapi.json",
    "graphql", "graphiql", "api/swagger", "v1/swagger.json",
    # CI/CD
    ".travis.yml", ".github/workflows/", "Jenkinsfile",
    ".circleci/config.yml", "bitbucket-pipelines.yml", "gitlab-ci.yml",
    # Kubernetes / Terraform
    "kubernetes.yml", "k8s.yml", "deployment.yaml", "terraform.tfstate",
    "terraform.tfvars", ".terraform/",
    # Debug / info pages
    "phpinfo.php", "info.php", "test.php", "server-status", "server-info",
    "debug/", "trace/", "_debug/", "app_dev.php",
    # Spring Boot actuator
    "actuator/env", "actuator/health", "actuator/info",
    "actuator/mappings", "actuator/beans", "actuator",
    # WordPress
    "wp-config.php", "wp-config.php.bak", "wp-login.php",
    "wp-content/debug.log",
    # Misc
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    ".DS_Store", "thumbs.db", "desktop.ini",
    "readme.txt", "README.md", "CHANGELOG.md", "LICENSE",
    "test/", "tests/", "dev/", "staging/",
    "old/", "backup/", "bak/", "tmp/", "temp/",
]

# ─── JavaScript Secret Patterns ───────────────────────────────────────────────

JS_SECRET_PATTERNS = {
    "aws_access_key": (
        r"(?:AKIA|AIPA|AIDV|AROA|ASCA|ASIA)[A-Z0-9]{16}",
        "AWS Access Key ID"
    ),
    "aws_secret_key": (
        r"(?:aws[_\-\s]*secret|secret[_\-\s]*key|aws[_\-\s]*access)['\"\s]*[:=]['\"\s]*([A-Za-z0-9/+=]{40})",
        "AWS Secret Access Key"
    ),
    "google_api_key": (
        r"AIza[0-9A-Za-z\-_]{35}",
        "Google API Key"
    ),
    "stripe_secret": (
        r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
        "Stripe Secret Key"
    ),
    "stripe_publishable": (
        r"pk_(?:live|test)_[0-9a-zA-Z]{24,}",
        "Stripe Publishable Key"
    ),
    "github_token": (
        r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "GitHub Token"
    ),
    "slack_token": (
        r"xox[baprs]\-[0-9]{10,12}\-[0-9]{10,12}\-[a-zA-Z0-9]{24,32}",
        "Slack Token"
    ),
    "slack_webhook": (
        r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
        "Slack Webhook URL"
    ),
    "jwt_token": (
        r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+",
        "JWT Token"
    ),
    "private_key": (
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "Private Key"
    ),
    "password_literal": (
        r"(?:password|passwd|pwd|secret)['\"\s]*[:=]['\"\s]*(['\"][^'\"]{8,}['\"])",
        "Hardcoded Password"
    ),
    "api_key_generic": (
        r"(?:api[_\-]?key|apikey|api[_\-]?secret)['\"\s]*[:=]['\"\s]*['\"]([A-Za-z0-9\-_]{16,})['\"]",
        "Generic API Key"
    ),
    "sendgrid": (
        r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "SendGrid API Key"
    ),
    "twilio": (
        r"SK[a-z0-9]{32}",
        "Twilio API Key"
    ),
    "firebase": (
        r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
        "Firebase Server Key"
    ),
    "mailgun": (
        r"key-[0-9a-zA-Z]{32}",
        "Mailgun API Key"
    ),
    "internal_ip": (
        r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
        "Internal IP Address"
    ),
}

# ─── Cloud Bucket Patterns ────────────────────────────────────────────────────

S3_BUCKET_PATTERN = re.compile(
    r"([a-z0-9\-\.]{3,63})\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com",
    re.IGNORECASE
)
GCS_BUCKET_PATTERN = re.compile(
    r"(?:storage\.googleapis\.com/|([a-z0-9\-_]+)\.storage\.googleapis\.com)",
    re.IGNORECASE
)
AZURE_BLOB_PATTERN = re.compile(
    r"([a-z0-9]+)\.blob\.core\.windows\.net",
    re.IGNORECASE
)


class ConfigAuditor:
    """
    Audits web services for configuration leaks, exposed secrets, and cloud misconfigurations.
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
        logger.info(f"[Auditor] Starting configuration audit for {len(services)} services")

        results = {
            "exposed_files": [],
            "js_secrets": [],
            "cloud_exposure": [],
            "total_findings": 0,
        }

        # Run all audit tasks concurrently per service
        semaphore = asyncio.Semaphore(self.config.threads)

        async def audit_service(svc):
            async with semaphore:
                url = svc.get("url", "")
                svc_id = svc.get("id")
                if not url:
                    return

                # 1. Sensitive file/path fuzzing
                exposed = await self._fuzz_sensitive_paths(url, svc_id, scan_id)
                results["exposed_files"].extend(exposed)

                # 2. JS secret analysis
                secrets = await self._analyze_js_files(url, svc_id, scan_id)
                results["js_secrets"].extend(secrets)

                # 3. Cloud exposure from page content
                cloud = await self._check_cloud_references(url, domain_id, svc_id, scan_id)
                results["cloud_exposure"].extend(cloud)

        tasks = [audit_service(svc) for svc in services]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Run ffuf if available (more thorough fuzzing)
        if shutil.which(self.config.ffuf_path) and not self.config.passive_only:
            for svc in services[:20]:  # Cap ffuf targets
                await self._run_ffuf(svc.get("url", ""), svc.get("id"), scan_id)

        results["total_findings"] = (
            len(results["exposed_files"]) +
            len(results["js_secrets"]) +
            len(results["cloud_exposure"])
        )
        logger.info(f"[Auditor] Audit complete: {results['total_findings']} findings")
        return results

    # ─── Path Fuzzing ──────────────────────────────────────────────────────

    async def _fuzz_sensitive_paths(
        self, base_url: str, service_id: int, scan_id: int
    ) -> List[Dict]:
        """Check for exposed sensitive files and configuration paths."""
        findings = []
        semaphore = asyncio.Semaphore(20)

        async def check_path(path: str):
            async with semaphore:
                await self.rate_limiter.acquire()
                url = urljoin(base_url.rstrip("/") + "/", path)
                async with create_session(self.config) as session:
                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=False,
                            ssl=False,
                        ) as resp:
                            if resp.status in (200, 206):
                                body = await resp.text(errors="ignore")
                                content_len = len(body)

                                # Skip generic "not found" pages
                                if content_len < 20:
                                    return None

                                severity = self._classify_path_severity(path, body)
                                if not severity:
                                    return None

                                finding = {
                                    "scan_id": scan_id,
                                    "service_id": service_id,
                                    "url": url,
                                    "phase": "audit",
                                    "severity": severity,
                                    "category": "exposed_file",
                                    "title": f"Sensitive File Exposed: {path}",
                                    "description": (
                                        f"The file `{path}` is publicly accessible at `{url}`. "
                                        f"This may expose sensitive configuration, credentials, or source code."
                                    ),
                                    "evidence": body[:500],
                                    "remediation": (
                                        f"Restrict access to `{path}` via web server configuration. "
                                        "Ensure sensitive files are not in the web root."
                                    ),
                                    "tool": "sentinelflow-fuzzer",
                                }
                                await self.db.insert_finding(finding)
                                log_finding(logger, severity, finding["title"], {"url": url})
                                return finding
                    except Exception:
                        return None

        tasks = [check_path(p) for p in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings = [r for r in results if r and isinstance(r, dict)]
        return findings

    def _classify_path_severity(self, path: str, body: str) -> Optional[str]:
        """Determine severity - be aggressive, flag anything interesting."""
        path_lower = path.lower()
        body_lower = body.lower()

        critical_paths = [
            ".env", "id_rsa", "private.key", "credentials", "aws.json",
            ".aws/credentials", "passwords.txt", "terraform.tfstate",
            "terraform.tfvars", "wp-config.php", "database.sql", "dump.sql",
            "backup.sql", "users.sql"
        ]
        critical_content = [
            "password", "secret", "api_key", "apikey", "private_key",
            "access_key", "token", "passwd", "db_pass", "database_password",
            "aws_secret", "stripe", "twilio", "sendgrid"
        ]
        high_paths = [
            ".git/", "config.php", "database.yml", "application.yml",
            "appsettings.json", "web.config", "docker-compose",
            "server.key", "cert.pem", "key.pem", "backup.zip",
            "backup.tar", "site.zip", "actuator/env", "phpinfo",
            "server-status"
        ]
        medium_paths = [
            "config.yml", "config.json", "config.yaml", "swagger",
            "graphql", "openapi", "api-docs", "package.json",
            "composer.json", "requirements.txt", "Gemfile",
            "robots.txt", "readme", "changelog", "debug.log",
            "error.log", "access.log", "admin", "login", "manage",
            "actuator", "test.php", "info.php", ".travis", "jenkins",
            ".circleci", "gitlab-ci", "k8s.yml", "kubernetes"
        ]

        # Critical: secrets in content of critical files
        if any(kw in body_lower for kw in critical_content):
            return "critical"

        # Critical path
        if any(p in path_lower for p in critical_paths):
            return "critical"

        # High path
        if any(p in path_lower for p in high_paths):
            return "high"

        # Medium path
        if any(p in path_lower for p in medium_paths):
            return "medium"

        # Anything that returned 200 and has content is at least low
        if len(body) > 100:
            return "low"

        return None

    # ─── JS Secret Analysis ────────────────────────────────────────────────

    async def _analyze_js_files(
        self, base_url: str, service_id: int, scan_id: int
    ) -> List[Dict]:
        """Crawl JS files and scan for hardcoded secrets."""
        findings = []
        js_urls = await self._discover_js_urls(base_url)

        semaphore = asyncio.Semaphore(20)  # More concurrent JS scans

        async def scan_js(js_url: str):
            async with semaphore:
                await self.rate_limiter.acquire()
                async with create_session(self.config) as session:
                    try:
                        async with session.get(
                            js_url,
                            timeout=aiohttp.ClientTimeout(total=15),
                            ssl=False,
                        ) as resp:
                            if resp.status == 200:
                                content = await resp.text(errors="ignore")
                                return await self._scan_js_content(
                                    content, js_url, service_id, scan_id
                                )
                    except Exception:
                        return []
            return []

        tasks = [scan_js(u) for u in js_urls[:200]]  # Scan more JS files
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return findings

    async def _discover_js_urls(self, base_url: str) -> List[str]:
        """Extract JS file URLs from a page."""
        js_urls = []
        async with create_session(self.config) as session:
            try:
                async with session.get(
                    base_url,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        # Find all script src attributes
                        matches = re.findall(
                            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                            body, re.IGNORECASE
                        )
                        for m in matches:
                            full_url = m if m.startswith("http") else urljoin(base_url, m)
                            js_urls.append(full_url)

                        # Also look for inline script blocks
                        js_urls.append(base_url)  # Scan page itself

            except Exception as e:
                logger.debug(f"JS discovery error for {base_url}: {e}")

        return list(set(js_urls))

    async def _scan_js_content(
        self, content: str, js_url: str, service_id: int, scan_id: int
    ) -> List[Dict]:
        """Apply all regex patterns to JS content."""
        findings = []

        for secret_type, (pattern, description) in JS_SECRET_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                matched_value = match if isinstance(match, str) else match[0]
                # Truncate for storage
                truncated = matched_value[:80] + "..." if len(matched_value) > 80 else matched_value

                # Deduplicate
                secret_data = {
                    "service_id": service_id,
                    "js_url": js_url,
                    "secret_type": secret_type,
                    "pattern": pattern[:100],
                    "matched": truncated,
                }
                await self.db.insert_js_secret(secret_data)

                severity = "critical" if secret_type in (
                    "aws_access_key", "aws_secret_key", "private_key", "stripe_secret"
                ) else "high"

                finding = {
                    "scan_id": scan_id,
                    "service_id": service_id,
                    "url": js_url,
                    "phase": "audit",
                    "severity": severity,
                    "category": "secret_exposure",
                    "title": f"Hardcoded Secret: {description}",
                    "description": (
                        f"A {description} was found hardcoded in JavaScript at `{js_url}`. "
                        "Exposure of credentials in client-side code allows attackers to "
                        "directly access associated services."
                    ),
                    "evidence": f"Pattern: {secret_type}\nMatch: {truncated}",
                    "remediation": (
                        "Remove the credential from source code immediately. "
                        "Rotate the compromised credential. "
                        "Use environment variables and server-side secret management."
                    ),
                    "tool": "sentinelflow-sast",
                }
                await self.db.insert_finding(finding)
                log_finding(logger, severity, finding["title"], {"url": js_url, "type": secret_type})
                findings.append(finding)

        return findings

    # ─── Cloud Exposure ────────────────────────────────────────────────────

    async def _check_cloud_references(
        self, base_url: str, domain_id: int, service_id: int, scan_id: int
    ) -> List[Dict]:
        """Extract cloud storage references from page source and check their access."""
        findings = []

        async with create_session(self.config) as session:
            try:
                async with session.get(
                    base_url,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False,
                ) as resp:
                    body = await resp.text(errors="ignore")
            except Exception:
                return []

        # Extract bucket references
        buckets = []
        for match in S3_BUCKET_PATTERN.finditer(body):
            buckets.append(("aws", match.group(1), match.group(0)))
        for match in GCS_BUCKET_PATTERN.finditer(body):
            name = match.group(1) or "unknown"
            buckets.append(("gcp", name, match.group(0)))
        for match in AZURE_BLOB_PATTERN.finditer(body):
            buckets.append(("azure", match.group(1), match.group(0)))

        for provider, bucket_name, full_ref in buckets:
            exposure = await self._probe_cloud_bucket(provider, bucket_name)
            await self.db.upsert_cloud_exposure({
                "domain_id": domain_id,
                "bucket_name": bucket_name,
                "provider": provider,
                **exposure,
            })

            if exposure.get("is_public") or exposure.get("readable"):
                severity = "critical" if exposure.get("writable") else "high"
                finding = {
                    "scan_id": scan_id,
                    "service_id": service_id,
                    "url": base_url,
                    "phase": "audit",
                    "severity": severity,
                    "category": "cloud_misconfiguration",
                    "title": f"Public Cloud Storage: {bucket_name} ({provider.upper()})",
                    "description": (
                        f"The {provider.upper()} storage bucket `{bucket_name}` appears to be "
                        f"publicly {'readable and writable' if exposure.get('writable') else 'readable'}. "
                        "This can expose sensitive data or allow unauthorized file upload."
                    ),
                    "evidence": f"Bucket reference found at: {full_ref}",
                    "remediation": (
                        f"Set bucket ACL to private. Enable {provider.upper()} Block Public Access. "
                        "Audit bucket contents and remove sensitive files."
                    ),
                    "tool": "sentinelflow-cloud",
                }
                await self.db.insert_finding(finding)
                log_finding(logger, severity, finding["title"], {"bucket": bucket_name})
                findings.append(finding)

        return findings

    async def _probe_cloud_bucket(self, provider: str, bucket_name: str) -> Dict:
        """Probe a cloud storage bucket for public access."""
        result = {"is_public": False, "readable": False, "writable": False}

        if provider == "aws":
            url = f"https://{bucket_name}.s3.amazonaws.com/"
        elif provider == "gcp":
            url = f"https://storage.googleapis.com/{bucket_name}/"
        elif provider == "azure":
            url = f"https://{bucket_name}.blob.core.windows.net/?comp=list"
        else:
            return result

        async with create_session(self.config) as session:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        result["is_public"] = True
                        result["readable"] = True
                    elif resp.status == 403:
                        result["is_public"] = True  # Exists but access denied
            except Exception:
                pass

        return result

    # ─── FFuf Integration ──────────────────────────────────────────────────

    async def _run_ffuf(self, base_url: str, service_id: int, scan_id: int):
        """Run ffuf for thorough directory and file fuzzing."""
        if not base_url:
            return

        wordlist = self.config.wordlist_path
        if not shutil.which(self.config.ffuf_path):
            return

        try:
            cmd = [
                self.config.ffuf_path,
                "-u", f"{base_url.rstrip('/')}/FUZZ",
                "-w", wordlist,
                "-mc", "200,204,301,302,307,401,403",
                "-t", "50",
                "-timeout", "10",
                "-of", "json",
                "-o", "/tmp/ffuf_result.json",
                "-s",  # Silent
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)

            # Parse results
            import os
            if os.path.exists("/tmp/ffuf_result.json"):
                with open("/tmp/ffuf_result.json") as f:
                    data = json.load(f)
                for result in data.get("results", []):
                    url = result.get("url", "")
                    status = result.get("status", 0)
                    if status in (200, 204):
                        path = url.replace(base_url.rstrip("/") + "/", "")
                        severity = self._classify_path_severity(path, "")
                        if severity:
                            finding = {
                                "scan_id": scan_id,
                                "service_id": service_id,
                                "url": url,
                                "phase": "audit",
                                "severity": severity,
                                "category": "exposed_path",
                                "title": f"[ffuf] Exposed Path: {path}",
                                "description": f"Directory/file discovered via fuzzing: {url}",
                                "evidence": f"HTTP {status}",
                                "remediation": "Review and restrict access to this path.",
                                "tool": "ffuf",
                            }
                            await self.db.insert_finding(finding)
                os.remove("/tmp/ffuf_result.json")
        except Exception as e:
            logger.debug(f"ffuf error: {e}")
