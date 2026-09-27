# Domain reputation and analysis service

import whois
import json
import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
# python-levenshtein>=0.23 bundles rapidfuzz; the capital-L shim may not
# resolve on all platforms (especially Windows). Fall back to rapidfuzz.
try:
    from Levenshtein import distance as levenshtein_distance  # compat shim
except ImportError:
    from rapidfuzz.distance import Levenshtein as _Lev
    levenshtein_distance = _Lev.distance
from app.config import get_settings

settings = get_settings()

# Load brand list for homoglyph detection
_BRAND_LIST: list[str] = []


def load_brand_list() -> list[str]:
    global _BRAND_LIST
    if _BRAND_LIST:
        return _BRAND_LIST

    brand_file = Path(settings.brand_list_path)
    if brand_file.exists():
        with open(brand_file) as f:
            _BRAND_LIST = json.load(f)
    else:
        # Default top spoofed brands
        _BRAND_LIST = [
            "paypal", "amazon", "microsoft", "apple", "google", "facebook", "instagram",
            "linkedin", "twitter", "netflix", "spotify", "dropbox", "adobe", "salesforce",
            "chase", "bankofamerica", "wellsfargo", "citi", "capitalone", "amex",
            "dhl", "fedex", "ups", "usps", "walmart", "target", "costco", "ebay",
            "github", "gitlab", "bitbucket", "atlassian", "slack", "zoom", "teams",
            "office365", "outlook", "icloud", "yahoo", "aol", "protonmail",
            "coinbase", "binance", "kraken", "blockchain", "metamask", "ledger",
            "verizon", "att", "tmobile", "sprint", "comcast", "spectrum",
        ]
    return _BRAND_LIST


@dataclass
class DomainAnalysis:
    domain: str
    domain_age_days: Optional[int]
    is_new_domain: bool  # < 30 days
    homoglyph_match: Optional[str]  # matched brand if any
    homoglyph_distance: int
    registrar: Optional[str]
    registration_date: Optional[str]


def get_domain_age(domain: str) -> Optional[int]:
    """Get domain age in days using WHOIS."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            from datetime import datetime, timezone
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - creation_date).days
            return age
    except Exception:
        pass
    return None


def check_homoglyph(domain: str) -> tuple[Optional[str], int]:
    """Check if domain is a homoglyph of known brands."""
    brands = load_brand_list()
    domain_lower = domain.lower()

    # Extract just the domain name (no TLD)
    domain_name = domain_lower.split('.')[0]

    best_match = None
    best_distance = float('inf')

    for brand in brands:
        dist = levenshtein_distance(domain_name, brand)
        if dist < best_distance and dist <= 2:  # Allow up to 2 edits
            best_distance = dist
            best_match = brand

    if best_match and best_distance <= 2:
        return best_match, best_distance
    return None, int(best_distance) if best_distance != float('inf') else 999


def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address."""
    match = re.search(r'@([^>]+)', email)
    return match.group(1).lower() if match else ''


def analyze_domain(domain: str) -> DomainAnalysis:
    """Perform full domain analysis."""
    age_days = get_domain_age(domain)
    is_new = age_days is not None and age_days < 30
    homoglyph_match, homoglyph_dist = check_homoglyph(domain)

    registrar = None
    reg_date = None
    try:
        w = whois.whois(domain)
        registrar = w.registrar
        if w.creation_date:
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            reg_date = cd.isoformat() if cd else None
    except Exception:
        pass

    return DomainAnalysis(
        domain=domain,
        domain_age_days=age_days,
        is_new_domain=is_new,
        homoglyph_match=homoglyph_match,
        homoglyph_distance=homoglyph_dist,
        registrar=registrar,
        registration_date=reg_date,
    )