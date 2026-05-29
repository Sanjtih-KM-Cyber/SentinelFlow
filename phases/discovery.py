"""
SentinelFlow Phase I: Digital Asset Inventory (Discovery)
Enumerates subdomains via passive APIs and active DNS, then probes for live services.
"""

import asyncio
import json
import re
import socket
import ssl
import subprocess
import shutil
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import dns.exception

from core.config import Config
from core.database import Database
from core.logger import get_logger
from utils.http_client import create_session
from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

# ─── Passive Recon Sources ────────────────────────────────────────────────────

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
ANUBIS_URL = "https://jonlu.ca/anubis/subdomains/{domain}"
ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
CHAOS_URL = "https://dns.projectdiscovery.io/dns/{domain}/subdomains"
SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"


class AssetDiscovery:
    """
    Discovers all internet-facing assets for a root domain.
    
    1. Passive subdomain enumeration (APIs, cert transparency)
    2. Active DNS resolution
    3. HTTP/HTTPS service probing (httpx)
    4. Port scanning (naabu)
    """

    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db
        self.rate_limiter = RateLimiter(config.rate_limit)

    async def run(self, domain: str, domain_id: int, scan_id: int) -> Dict[str, Any]:
        """Execute full discovery pipeline."""
        logger.info(f"[Discovery] Starting asset inventory for {domain}")
        # Handle direct IP/domain targets like 127.0.0.1:8080
        if ":" in domain or re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
            logger.info(f"[Discovery] Direct target mode for {domain}")

            host = domain.split(":")[0]

            svc = await self._probe_url(f"http://{domain}", host)

            services = []
            if svc:
                svc_id, _ = await self.db.upsert_service(None, svc)
                svc["id"] = svc_id
                services.append(svc)

            return {
                "subdomains": [],
                "services": services,
                "port_results": [],
            }

        # Step 1: Collect subdomains from all sources
        raw_subdomains = await self._enumerate_subdomains(domain)
        logger.info(f"[Discovery] Raw subdomains collected: {len(raw_subdomains)}")

        # Step 2: Active DNS resolution + dedup
        resolved = await self._resolve_subdomains(raw_subdomains, domain)
        logger.info(f"[Discovery] Resolved subdomains: {len(resolved)}")

        # Step 3: Persist to DB
        stored_subdomains = []
        for item in resolved:
            sub_id, is_new = await self.db.upsert_subdomain(
                domain_id=domain_id,
                subdomain=item["subdomain"],
                source=item["source"],
                resolved_ip=item.get("ip"),
            )
            item["id"] = sub_id
            item["is_new"] = is_new
            stored_subdomains.append(item)
            if is_new:
                logger.info(f"[Discovery] New subdomain: {item['subdomain']} → {item.get('ip', 'N/A')}")

        if self.config.passive_only:
            logger.info("[Discovery] Passive-only mode: skipping service probing")
            return {"subdomains": stored_subdomains, "services": []}

        # Step 4: Probe for live HTTP/HTTPS services
        live_services = await self._probe_services(stored_subdomains)
        logger.info(f"[Discovery] Live services: {len(live_services)}")

        # Step 5: Port scanning for non-standard ports
        port_results = await self._port_scan(resolved, domain)

        # Step 6: Persist services
        stored_services = []
        for svc in live_services:
            sub_match = next(
                (s for s in stored_subdomains if s["subdomain"] == svc.get("host")), None
            )
            sub_id = sub_match["id"] if sub_match else None
            svc_id, is_new = await self.db.upsert_service(sub_id, svc)
            svc["id"] = svc_id
            stored_services.append(svc)

        return {
            "subdomains": stored_subdomains,
            "services": stored_services,
            "port_results": port_results,
        }

    # ─── Subdomain Enumeration ─────────────────────────────────────────────

    async def _enumerate_subdomains(self, domain: str) -> Set[str]:
        """Gather subdomains from all passive sources + subfinder."""
        subdomains: Set[str] = set()

        sources = [
            self._crtsh(domain),
            self._hackertarget(domain),
            self._anubis(domain),
            self._alienvault(domain),
            self._urlscan(domain),
        ]

        # Add API-key sources if available
        if self.config.securitytrails_api_key:
            sources.append(self._securitytrails(domain))
        if self.config.virustotal_api_key:
            sources.append(self._virustotal(domain))
        if self.config.chaos_api_key:
            sources.append(self._chaos(domain))

        # Run all sources concurrently
        results = await asyncio.gather(*sources, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Source error (non-fatal): {result}")
                continue
            if isinstance(result, set):
                subdomains.update(result)

        # Run subfinder if available
        subfinder_subs = await self._run_subfinder(domain)
        subdomains.update(subfinder_subs)

        # Filter to only valid subdomains of target domain
        return {s.lower().strip() for s in subdomains
                if s and self._is_valid_subdomain(s, domain)}

    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Validate subdomain belongs to target domain."""
        subdomain = subdomain.strip().lower()
        domain = domain.lower()
        return (
            subdomain.endswith(f".{domain}") or subdomain == domain
        ) and bool(re.match(r'^[a-z0-9\-\.]+$', subdomain))

    async def _crtsh(self, domain: str) -> Set[str]:
        """Certificate Transparency search via crt.sh."""
        subdomains = set()
        url = CRTSH_URL.format(domain=domain)
        async with create_session(self.config) as session:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            names = entry.get("name_value", "")
                            for name in names.splitlines():
                                subdomains.add(name.lstrip("*."))
            except Exception as e:
                logger.debug(f"crt.sh error: {e}")
        logger.info(f"[crt.sh] Found {len(subdomains)} entries")
        return subdomains

    async def _hackertarget(self, domain: str) -> Set[str]:
        """HackerTarget free API for subdomain discovery."""
        subdomains = set()
        url = HACKERTARGET_URL.format(domain=domain)
        async with create_session(self.config) as session:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            parts = line.split(",")
                            if parts:
                                subdomains.add(parts[0].strip())
            except Exception as e:
                logger.debug(f"HackerTarget error: {e}")
        return subdomains

    async def _anubis(self, domain: str) -> Set[str]:
        """Anubis subdomain enumeration."""
        subdomains = set()
        url = ANUBIS_URL.format(domain=domain)
        async with create_session(self.config) as session:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if isinstance(data, list):
                            subdomains.update(data)
            except Exception as e:
                logger.debug(f"Anubis error: {e}")
        return subdomains

    async def _alienvault(self, domain: str) -> Set[str]:
        """AlienVault OTX passive DNS."""
        subdomains = set()
        url = ALIENVAULT_URL.format(domain=domain)
        async with create_session(self.config) as session:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data.get("passive_dns", []):
                            hostname = entry.get("hostname", "")
                            if hostname:
                                subdomains.add(hostname)
            except Exception as e:
                logger.debug(f"AlienVault error: {e}")
        return subdomains

    async def _urlscan(self, domain: str) -> Set[str]:
        """URLScan.io subdomain search."""
        subdomains = set()
        url = URLSCAN_URL.format(domain=domain)
        async with create_session(self.config) as session:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for result in data.get("results", []):
                            page = result.get("page", {})
                            hostname = page.get("domain", "")
                            if hostname:
                                subdomains.add(hostname)
            except Exception as e:
                logger.debug(f"URLScan error: {e}")
        return subdomains

    async def _securitytrails(self, domain: str) -> Set[str]:
        """SecurityTrails API (requires API key)."""
        subdomains = set()
        url = SECURITYTRAILS_URL.format(domain=domain)
        headers = {"apikey": self.config.securitytrails_api_key}
        async with create_session(self.config) as session:
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get("subdomains", []):
                            subdomains.add(f"{sub}.{domain}")
            except Exception as e:
                logger.debug(f"SecurityTrails error: {e}")
        return subdomains

    async def _virustotal(self, domain: str) -> Set[str]:
        """VirusTotal API v3 (requires API key)."""
        subdomains = set()
        url = VIRUSTOTAL_URL.format(domain=domain)
        headers = {"x-apikey": self.config.virustotal_api_key}
        async with create_session(self.config) as session:
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("data", []):
                            subdomains.add(item.get("id", ""))
            except Exception as e:
                logger.debug(f"VirusTotal error: {e}")
        return subdomains

    async def _chaos(self, domain: str) -> Set[str]:
        """ProjectDiscovery Chaos API (requires API key)."""
        subdomains = set()
        url = CHAOS_URL.format(domain=domain)
        headers = {"Authorization": self.config.chaos_api_key}
        async with create_session(self.config) as session:
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get("subdomains", []):
                            subdomains.add(f"{sub}.{domain}")
            except Exception as e:
                logger.debug(f"Chaos error: {e}")
        return subdomains

    async def _run_subfinder(self, domain: str) -> Set[str]:
        """Run subfinder tool if available."""
        subdomains = set()
        if not shutil.which(self.config.subfinder_path):
            logger.debug("subfinder not found in PATH, skipping")
            return subdomains

        try:
            cmd = [
                self.config.subfinder_path,
                "-d", domain,
                "-silent",
                "-all",
                "-o", "/dev/stdout",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            for line in stdout.decode().splitlines():
                line = line.strip()
                if line:
                    subdomains.add(line)
            logger.info(f"[subfinder] Found {len(subdomains)} subdomains")
        except asyncio.TimeoutError:
            logger.warning("subfinder timed out after 120s")
        except Exception as e:
            logger.debug(f"subfinder error: {e}")

        return subdomains

    # ─── DNS Resolution ────────────────────────────────────────────────────

    async def _resolve_subdomains(
        self, subdomains: Set[str], domain: str
    ) -> List[Dict]:
        """Resolve DNS for all discovered subdomains."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]

        semaphore = asyncio.Semaphore(50)
        resolved = []

        async def resolve_one(subdomain: str):
            async with semaphore:
                await self.rate_limiter.acquire()
                try:
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        None, lambda: resolver.resolve(subdomain, "A")
                    )
                    ips = [str(r) for r in answers]
                    return {
                        "subdomain": subdomain,
                        "ip": ips[0] if ips else None,
                        "all_ips": ips,
                        "source": "multi-source",
                        "resolved": True,
                    }
                except (dns.exception.DNSException, Exception):
                    return None

        tasks = [resolve_one(s) for s in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if r and isinstance(r, dict) and r.get("resolved"):
                resolved.append(r)

        return resolved

    # ─── Service Probing ───────────────────────────────────────────────────

    async def _probe_services(self, subdomains: List[Dict]) -> List[Dict]:
        """Probe subdomains for live HTTP/HTTPS services."""
        live = []
        semaphore = asyncio.Semaphore(self.config.threads)

        # Try httpx tool first
        # Native probing only - httpx tool disabled (wrong version in PATH)
        httpx_available = False

        # Fallback: native aiohttp probing
        async def probe_one(sub: Dict):
            async with semaphore:
                await self.rate_limiter.acquire()
                subdomain = sub["subdomain"]
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{subdomain}"
                    svc = await self._probe_url(url, subdomain)
                    if svc:
                        return svc
                return None

        tasks = [probe_one(s) for s in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if r and isinstance(r, dict):
                live.append(r)

        return live

    async def _probe_url(self, url: str, host: str) -> Optional[Dict]:
        """Probe a single URL and extract service metadata."""
        async with create_session(self.config) as session:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    body = await resp.text(errors="ignore")

                    # Extract metadata
                    title = self._extract_title(body)
                    server = resp.headers.get("Server", "")
                    tech_stack = self._detect_technologies(resp.headers, body)
                    cdn = self._detect_cdn(resp.headers)
                    waf = self._detect_waf(resp.headers)

                    # TLS info
                    tls_valid, tls_expiry = None, None
                    if url.startswith("https"):
                        tls_valid, tls_expiry = await self._check_tls(host)

                    return {
                        "url": str(resp.url),
                        "host": host,
                        "status_code": resp.status,
                        "title": title,
                        "server": server,
                        "tech_stack": tech_stack,
                        "cdn": cdn,
                        "waf": waf,
                        "tls_valid": tls_valid,
                        "tls_expiry": tls_expiry,
                        "content_length": len(body),
                    }
            except Exception:
                return None

    async def _run_httpx(self, subdomains: List[str]) -> List[Dict]:
        """Use httpx tool for bulk service detection."""
        services = []
        input_data = "\n".join(subdomains).encode()

        try:
            cmd = [
                self.config.httpx_path,
                "-silent",
                "-json",
                "-title",
                "-server",
                "-tech-detect",
                "-status-code",
                "-follow-redirects",
                "-timeout", str(self.config.timeout),
                "-threads", str(self.config.threads),
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=300
            )

            for line in stdout.decode().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    services.append({
                        "url": data.get("url", ""),
                        "host": data.get("host", ""),
                        "status_code": data.get("status-code"),
                        "title": data.get("title", ""),
                        "server": data.get("server", ""),
                        "tech_stack": data.get("technologies", []),
                        "cdn": data.get("cdn", ""),
                        "waf": "",
                        "tls_valid": data.get("tls", {}).get("valid"),
                        "tls_expiry": data.get("tls", {}).get("not_after"),
                    })
                except json.JSONDecodeError:
                    continue

            logger.info(f"[httpx] Probed {len(subdomains)} hosts → {len(services)} live")
        except Exception as e:
            logger.warning(f"httpx failed: {e}, falling back to native probing")

        return services

    # ─── Port Scanning ─────────────────────────────────────────────────────

    async def _port_scan(self, subdomains: List[Dict], domain: str) -> List[Dict]:
        """Use naabu for port scanning."""
        if not shutil.which(self.config.naabu_path):
            logger.debug("naabu not in PATH, performing native port check")
            return await self._native_port_scan(subdomains)

        hosts = [s["subdomain"] for s in subdomains]  # Scan ALL subdomains
        input_data = "\n".join(hosts).encode()
        results = []

        try:
            cmd = [
                self.config.naabu_path,
                "-p", self.config.ports,
                "-silent",
                "-json",
                "-rate", "100",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=300
            )
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            logger.info(f"[naabu] Port scan complete: {len(results)} open ports")
        except Exception as e:
            logger.warning(f"naabu error: {e}")

        return results

    async def _native_port_scan(self, subdomains: List[Dict]) -> List[Dict]:
        """Fallback native port scanner using asyncio."""
        ports = [int(p) for p in self.config.ports.split(",") if p.strip().isdigit()]
        results = []
        semaphore = asyncio.Semaphore(100)

        async def check_port(host: str, port: int):
            async with semaphore:
                try:
                    conn = asyncio.open_connection(host, port)
                    _, writer = await asyncio.wait_for(conn, timeout=3)
                    writer.close()
                    return {"host": host, "port": port, "state": "open"}
                except Exception:
                    return None

        tasks = [
            check_port(s["subdomain"], p)
            for s in subdomains
            for p in ports
        ]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        results = [r for r in scan_results if r and isinstance(r, dict)]
        logger.info(f"[native-scan] {len(results)} open ports found")
        return results

    # ─── Helpers ───────────────────────────────────────────────────────────

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:200] if match else ""

    def _detect_technologies(self, headers: dict, body: str) -> List[str]:
        tech = []
        header_map = {
            "X-Powered-By": lambda v: tech.append(v),
            "X-Generator": lambda v: tech.append(v),
            "X-Drupal-Cache": lambda _: tech.append("Drupal"),
            "X-WordPress": lambda _: tech.append("WordPress"),
        }
        for header, handler in header_map.items():
            val = headers.get(header)
            if val:
                handler(val)

        body_patterns = {
            "WordPress": r"wp-content|wp-includes",
            "Joomla": r"Joomla!|joomla",
            "Django": r"csrfmiddlewaretoken|django",
            "React": r"__REACT_DEVTOOLS|react\.development",
            "Angular": r"ng-version|angular",
            "Bootstrap": r"bootstrap\.min",
        }
        for name, pattern in body_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                tech.append(name)

        return list(set(tech))

    def _detect_cdn(self, headers: dict) -> str:
        cdn_headers = {
            "CF-Ray": "Cloudflare",
            "X-Fastly-Request-ID": "Fastly",
            "X-Amz-Cf-Id": "CloudFront",
            "X-Akamai-Request-ID": "Akamai",
        }
        for header, cdn_name in cdn_headers.items():
            if header in headers:
                return cdn_name
        return ""

    def _detect_waf(self, headers: dict) -> str:
        waf_indicators = {
            "X-Sucuri-ID": "Sucuri",
            "X-Protected-By": "Various",
            "Server": "",
        }
        server = headers.get("Server", "").lower()
        if "cloudflare" in server:
            return "Cloudflare"
        if "sucuri" in server:
            return "Sucuri"
        return ""

    async def _check_tls(self, hostname: str) -> tuple:
        """Check TLS certificate validity and expiry."""
        try:
            loop = asyncio.get_event_loop()
            ctx = ssl.create_default_context()

            def get_cert():
                with ctx.wrap_socket(
                    socket.socket(), server_hostname=hostname
                ) as ssock:
                    ssock.settimeout(10)
                    ssock.connect((hostname, 443))
                    cert = ssock.getpeercert()
                    return cert

            cert = await loop.run_in_executor(None, get_cert)
            expiry_str = cert.get("notAfter", "")
            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z") if expiry_str else None
            is_valid = expiry and expiry > datetime.now()
            return is_valid, expiry.isoformat() if expiry else None
        except Exception:
            return None, None
