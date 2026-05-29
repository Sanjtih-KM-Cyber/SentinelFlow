"""
Phase II — Cloud Exposure Check
Checks for publicly accessible S3 buckets and similar cloud storage misconfigurations.
"""

import asyncio
import logging
import urllib.request
import ssl
from typing import Optional

from core.database import insert_finding

log = logging.getLogger("audit.cloud_exposure")

# Common bucket naming patterns derived from a seed domain
# e.g. example.com → example, example-backup, example-dev, etc.
BUCKET_SUFFIXES = [
    "", "-backup", "-backups", "-dev", "-staging", "-prod", "-production",
    "-assets", "-static", "-media", "-uploads", "-files", "-data",
    "-logs", "-log", "-archive", "-releases", "-downloads", "-public",
    "-private", "-internal", "-admin", "-api", "-web", "-app",
    "-config", "-secrets", "-keys", "-credentials",
]

S3_REGION_ENDPOINTS = [
    "s3.amazonaws.com",
    "s3-us-east-1.amazonaws.com",
    "s3-eu-west-1.amazonaws.com",
    "s3-ap-southeast-1.amazonaws.com",
]


async def run_cloud_exposure(scan_id: int, seed: str) -> None:
    """Check S3 buckets derived from the seed domain name."""
    # Extract the base name from seed (strip TLD)
    parts = seed.split(".")
    base = parts[0] if len(parts) >= 2 else seed

    bucket_names = [f"{base}{suffix}" for suffix in BUCKET_SUFFIXES]
    # Also try the full domain with dots replaced
    bucket_names.append(seed.replace(".", "-"))
    bucket_names.append(seed.replace(".", ""))

    log.info("Checking %d candidate S3 bucket names for %s", len(bucket_names), seed)

    sem = asyncio.Semaphore(10)
    tasks = [_check_bucket(sem, scan_id, name) for name in bucket_names]
    await asyncio.gather(*tasks, return_exceptions=True)


async def _check_bucket(sem: asyncio.Semaphore, scan_id: int, bucket_name: str) -> None:
    async with sem:
        loop = asyncio.get_event_loop()
        for endpoint in S3_REGION_ENDPOINTS:
            url = f"https://{bucket_name}.{endpoint}/"
            status, body = await loop.run_in_executor(None, _probe_bucket, url)

            if status is None:
                continue  # Connection error — bucket likely doesn't exist

            if status == 200:
                # Publicly listable bucket — critical
                insert_finding(
                    scan_id=scan_id,
                    asset_id=None,
                    phase="audit",
                    category="cloud_exposure",
                    title=f"Public S3 bucket listable: {bucket_name}",
                    severity="critical",
                    detail="Bucket returns HTTP 200 with directory listing — all objects are publicly accessible.",
                    evidence=url,
                )
                log.warning("  [CRITICAL] Public S3 bucket: %s (%s)", bucket_name, url)
                break

            elif status == 403:
                # Bucket exists but access denied — still worth flagging
                insert_finding(
                    scan_id=scan_id,
                    asset_id=None,
                    phase="audit",
                    category="cloud_exposure",
                    title=f"S3 bucket exists (access denied): {bucket_name}",
                    severity="medium",
                    detail="Bucket exists and returns HTTP 403. Objects may be public even if listing is restricted.",
                    evidence=url,
                )
                log.info("  [MEDIUM] S3 bucket exists (403): %s", bucket_name)
                break

            # 404 = bucket does not exist, skip silently


def _probe_bucket(url: str) -> tuple[Optional[int], str]:
    """HTTP probe — returns (status_code, body_snippet) or (None, '')."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (SentinelFlow/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            body = resp.read(2048).decode(errors="ignore")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""
