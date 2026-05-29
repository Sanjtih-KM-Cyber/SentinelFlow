"""
Phase II — JavaScript Static Analysis (SAST)
Fetches client-side JS and scans for hardcoded credentials, API keys, secrets.
"""

import asyncio
import logging
import re
import urllib.request
from html.parser import HTMLParser
from typing import Optional

from core.database import insert_finding

log = logging.getLogger("audit.js_sast")

# Secret patterns — (pattern_name, regex, severity)
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS Access Key",        re.compile(r"AKIA[0-9A-Z]{16}"),                                          "critical"),
    ("AWS Secret Key",        re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),   "critical"),
    ("Generic API Key",       re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"), "high"),
    ("Bearer Token",          re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),                        "high"),
    ("JWT Token",             re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "high"),
    ("Slack Token",           re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}"),            "critical"),
    ("GitHub Token",          re.compile(r"gh[pousr]_[A-Za-z0-9_]{36}"),                                 "critical"),
    ("Stripe Key",            re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24}"),                             "critical"),
    ("Twilio Key",            re.compile(r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]"),                   "high"),
    ("Password in JS",        re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),   "high"),
    ("Private Key Header",    re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),           "critical"),
    ("Google API Key",        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                                    "high"),
    ("SendGrid Key",          re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),                 "critical"),
    ("Internal API Endpoint", re.compile(r"https?://(?:internal|intranet|api-internal|admin)[.\-][a-zA-Z0-9.\-]+"), "medium"),
    ("Hardcoded DB URL",      re.compile(r"(?i)(mysql|postgres|mongodb|redis)://[^'\"\s]{10,}"),         "critical"),
]

# Max JS file size to download (5 MB)
MAX_JS_SIZE = 5 * 1024 * 1024


async def run_js_sast(scan_id: int, assets: list) -> None:
    """Fetch JS from each live asset and scan for secrets."""
    tasks = [_analyze_host(scan_id, asset) for asset in assets]
    await asyncio.gather(*tasks, return_exceptions=True)


async def _analyze_host(scan_id: int, asset) -> None:
    fqdn = asset["fqdn"]
    asset_id = asset["id"]

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{fqdn}"
        js_urls = await _discover_js_urls(base_url)
        if not js_urls and scheme == "https":
            continue  # Try http fallback

        log.debug("  %s — scanning %d JS files", fqdn, len(js_urls))
        for js_url in js_urls[:20]:  # Cap at 20 files per host
            await _scan_js_file(scan_id, asset_id, js_url)
        break


async def _discover_js_urls(base_url: str) -> list[str]:
    """Fetch the root page and extract <script src> references."""
    loop = asyncio.get_event_loop()
    try:
        html = await loop.run_in_executor(None, _fetch_url, base_url, 512_000)
        if not html:
            return []
        parser = _ScriptTagParser(base_url)
        parser.feed(html)
        return parser.js_urls
    except Exception as exc:
        log.debug("Could not fetch %s: %s", base_url, exc)
        return []


async def _scan_js_file(scan_id: int, asset_id: int, js_url: str) -> None:
    """Download a JS file and run all secret patterns against it."""
    loop = asyncio.get_event_loop()
    try:
        content = await loop.run_in_executor(None, _fetch_url, js_url, MAX_JS_SIZE)
        if not content:
            return
    except Exception as exc:
        log.debug("Could not fetch JS %s: %s", js_url, exc)
        return

    for pattern_name, pattern, severity in SECRET_PATTERNS:
        matches = pattern.findall(content)
        for match in matches[:3]:  # Limit per-pattern matches
            snippet = match[:100] if isinstance(match, str) else str(match)[:100]
            finding_id = insert_finding(
                scan_id=scan_id,
                asset_id=asset_id,
                phase="audit",
                category="secret_exposure",
                title=f"Hardcoded secret detected: {pattern_name}",
                severity=severity,
                detail=f"Pattern '{pattern_name}' matched in {js_url}",
                evidence=f"{js_url} — snippet: {snippet}",
            )
            if finding_id:
                log.warning(
                    "  [%s] %s — %s in %s",
                    severity.upper(), pattern_name, snippet[:50], js_url,
                )


def _fetch_url(url: str, max_bytes: int) -> Optional[str]:
    """Synchronous HTTP fetch with size limit."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (SentinelFlow/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return resp.read(max_bytes).decode(errors="ignore")
    except Exception:
        return None


class _ScriptTagParser(HTMLParser):
    """HTML parser that extracts JS file URLs from <script src="...">."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self.js_urls: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        attrs_dict = dict(attrs)
        src = attrs_dict.get("src", "")
        if not src or not src.endswith(".js"):
            return
        if src.startswith("http"):
            self.js_urls.append(src)
        elif src.startswith("//"):
            self.js_urls.append("https:" + src)
        elif src.startswith("/"):
            self.js_urls.append(self.base_url + src)
        else:
            self.js_urls.append(self.base_url + "/" + src)
