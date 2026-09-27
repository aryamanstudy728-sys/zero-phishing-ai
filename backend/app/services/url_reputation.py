# URL reputation checking service

import httpx
import csv
import io
from typing import Optional
from dataclasses import dataclass
from app.config import get_settings

settings = get_settings()

# Cache for PhishTank data
_PHISHTANK_URLS: set[str] = set()
_PHISHTANK_LOADED = False


@dataclass
class URLReputationResult:
    url: str
    safe_browsing: dict  # threat types found
    phishtank: bool  # found in PhishTank
    anchor_mismatch: bool  # anchor text != href


async def check_safe_browsing(urls: list[str]) -> dict[str, list[str]]:
    """Check URLs against Google Safe Browsing API v4."""
    if not settings.safe_browsing_api_key or not urls:
        return {url: [] for url in urls}

    # Prepare request body
    threat_entries = [{"url": url} for url in urls]
    body = {
        "client": {
            "clientId": "zero-phishing-ai",
            "clientVersion": "0.1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries
        }
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.safe_browsing_api_key}",
                json=body
            )
            response.raise_for_status()
            data = response.json()

            # Parse results
            matches = data.get("matches", [])
            result = {url: [] for url in urls}
            for match in matches:
                url = match.get("threat", {}).get("url", "")
                threat_type = match.get("threatType", "")
                if url in result:
                    result[url].append(threat_type)
            return result
        except Exception:
            return {url: [] for url in urls}


async def load_phishtank_data() -> None:
    """Load PhishTank data from CSV."""
    global _PHISHTANK_URLS, _PHISHTANK_LOADED

    if _PHISHTANK_LOADED:
        return

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # Try API first if key available
            if settings.phishtank_api_key:
                response = await client.get(
                    f"https://data.phishtank.com/data/{settings.phishtank_api_key}/online-valid.json"
                )
                if response.status_code == 200:
                    data = response.json()
                    _PHISHTANK_URLS = {item["url"] for item in data if "url" in item}
                    _PHISHTANK_LOADED = True
                    return
        except Exception:
            pass

        # Fallback to CSV
        try:
            response = await client.get(settings.phishtank_data_url)
            if response.status_code == 200:
                content = response.text
                reader = csv.DictReader(io.StringIO(content))
                _PHISHTANK_URLS = {row["url"] for row in reader if "url" in row}
                _PHISHTANK_LOADED = True
        except Exception:
            _PHISHTANK_LOADED = True  # Don't retry on failure


def check_phishtank(url: str) -> bool:
    """Check if URL is in PhishTank database."""
    return url in _PHISHTANK_URLS


def check_anchor_mismatch(html: str, url: str) -> bool:
    """Check if anchor text differs significantly from href."""
    # This would be called with the full HTML and specific URL
    # For now, return False - implement in content analysis
    return False


async def analyze_urls(urls: list[str], html: Optional[str] = None) -> list[URLReputationResult]:
    """Analyze multiple URLs for reputation."""
    await load_phishtank_data()

    safe_browsing_results = await check_safe_browsing(urls)

    results = []
    for url in urls:
        sb_threats = safe_browsing_results.get(url, [])
        pt_found = check_phishtank(url)
        anchor_mismatch = False  # Would need HTML context

        results.append(URLReputationResult(
            url=url,
            safe_browsing={"threats": sb_threats} if sb_threats else {"threats": []},
            phishtank=pt_found,
            anchor_mismatch=anchor_mismatch,
        ))

    return results