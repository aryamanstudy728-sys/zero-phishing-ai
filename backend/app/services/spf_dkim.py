# SPF/DKIM/DMARC verification service

import dns.resolver
import dns.exception
import re
from typing import Optional
from dataclasses import dataclass


@dataclass
class AuthResult:
    spf: str  # pass, fail, softfail, neutral, none, temperror, permerror
    dkim: str  # pass, fail, none
    dmarc: str  # pass, fail, none
    alignment: bool
    details: dict


def parse_authentication_results(headers_raw: str) -> dict:
    """Parse Authentication-Results header from email."""
    results = {}
    auth_results_match = re.search(
        r'Authentication-Results:\s*([^\r\n]+(?:\r?\n\s+[^\r\n]+)*)',
        headers_raw,
        re.IGNORECASE
    )
    if auth_results_match:
        auth_text = auth_results_match.group(1).replace('\r\n', ' ').replace('\n', ' ')
        # Parse key=value pairs
        for part in auth_text.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                results[key.strip().lower()] = value.strip()
    return results


def check_spf(domain: str, ip: Optional[str] = None) -> str:
    """Check SPF record for domain."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=spf1'):
                # In production, use proper SPF evaluation library
                # For now, return 'pass' if record exists
                return 'pass'
        return 'none'
    except dns.exception.DNSException:
        return 'none'


def check_dkim(domain: str, selector: str) -> str:
    """Check DKIM public key exists."""
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if 'v=DKIM1' in txt or 'p=' in txt:
                return 'pass'
        return 'fail'
    except dns.exception.DNSException:
        return 'none'


def check_dmarc(domain: str) -> str:
    """Check DMARC policy."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=DMARC1'):
                return 'pass'
        return 'none'
    except dns.exception.DNSException:
        return 'none'


def verify_alignment(headers_raw: str, from_domain: str) -> bool:
    """Check SPF/DKIM alignment with From domain."""
    # Extract domains from Authentication-Results
    spf_domain_match = re.search(r'spf=(\w+)\s+\([^)]*smtp\.mailfrom=([^;\)]+)', headers_raw)
    dkim_domain_match = re.search(r'dkim=(\w+)\s+\([^)]*header\.d=([^;\)]+)', headers_raw)

    spf_aligned = False
    dkim_aligned = False

    if spf_domain_match:
        spf_result, spf_domain = spf_domain_match.groups()
        spf_domain = spf_domain.strip().lower()
        from_domain_lower = from_domain.lower()
        spf_aligned = spf_result == 'pass' and (spf_domain == from_domain_lower or spf_domain.endswith('.' + from_domain_lower))

    if dkim_domain_match:
        dkim_result, dkim_domain = dkim_domain_match.groups()
        dkim_domain = dkim_domain.strip().lower()
        from_domain_lower = from_domain.lower()
        dkim_aligned = dkim_result == 'pass' and (dkim_domain == from_domain_lower or dkim_domain.endswith('.' + from_domain_lower))

    return spf_aligned or dkim_aligned


def extract_from_domain(headers_raw: str) -> Optional[str]:
    """Extract From domain from headers."""
    from_match = re.search(r'^From:\s*.*@([^\s>]+)', headers_raw, re.IGNORECASE | re.MULTILINE)
    if from_match:
        return from_match.group(1).lower()
    return None


def extract_sending_ip(headers_raw: str) -> Optional[str]:
    """Extract sending IP from Received headers."""
    # Look for first Received header (closest to us)
    received_match = re.search(r'Received:\s+from\s+[^\s]+\s+\([^)]*\[([\d.:]+)\]', headers_raw)
    if received_match:
        return received_match.group(1)
    return None


def verify_authenticity(headers_raw: str) -> AuthResult:
    """Main function to verify email authenticity."""
    from_domain = extract_from_domain(headers_raw)
    sending_ip = extract_sending_ip(headers_raw)

    # Parse existing Authentication-Results if present
    auth_results = parse_authentication_results(headers_raw)

    spf_result = auth_results.get('spf', 'none')
    dkim_result = auth_results.get('dkim', 'none')
    dmarc_result = auth_results.get('dmarc', 'none')

    # If not in headers, perform live checks (slower)
    if spf_result == 'none' and from_domain:
        spf_result = check_spf(from_domain, sending_ip)

    if dkim_result == 'none' and from_domain:
        # Need selector - try common ones
        for selector in ['default', 'google', 'selector1', 'selector2', 'k1', 'k2']:
            dkim_result = check_dkim(from_domain, selector)
            if dkim_result == 'pass':
                break

    if dmarc_result == 'none' and from_domain:
        dmarc_result = check_dmarc(from_domain)

    alignment = verify_alignment(headers_raw, from_domain) if from_domain else False

    return AuthResult(
        spf=spf_result,
        dkim=dkim_result,
        dmarc=dmarc_result,
        alignment=alignment,
        details={
            'from_domain': from_domain,
            'sending_ip': sending_ip,
            'auth_results_parsed': bool(auth_results),
        }
    )