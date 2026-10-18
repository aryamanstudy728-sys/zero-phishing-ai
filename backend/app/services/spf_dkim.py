# SPF/DKIM/DMARC verification service

import dns.resolver
import dns.exception
import re
from typing import Optional
from dataclasses import dataclass


@dataclass
class AuthResult:
    spf: str  # pass, fail, softfail, neutral, none, temperror, permerror, policy
    dkim: str  # pass, fail, none, permerror, ...
    dmarc: str  # pass, fail, none, policy, ...
    alignment: bool
    details: dict


def _topmost_auth_results_header(headers_raw: str) -> Optional[str]:
    """Return the topmost header starting exactly with "Authentication-Results:"
    at the start of a line (including folded continuation lines), or None.

    The anchor keeps "ARC-Authentication-Results" from matching, and only the
    first (topmost) occurrence is used: headers lower in the message can be
    added by the sender and cannot be trusted.
    """
    match = re.search(
        r'^Authentication-Results:[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*',
        headers_raw,
        re.IGNORECASE | re.MULTILINE,
    )
    return match.group(0) if match else None


def _unfold(header: str) -> str:
    """Join folded continuation lines (both \\r\\n and \\n) into a single line."""
    return re.sub(r'\r?\n[ \t]+', ' ', header)


def _normalize_result(value: str) -> str:
    """Lowercase first word of a result; map hardfail to fail."""
    value = value.strip()
    if not value:
        return 'none'
    word = value.split(None, 1)[0].lower()
    return 'fail' if word == 'hardfail' else word


def _domain_of(value: str) -> str:
    """Domain of an address or bare domain.

    Handles smtp.mailfrom with or without "@", and DKIM header.d/header.i
    values like "example.com", "@example.com" or "user@example.com"
    (strip a leading "@" and anything before "@").
    """
    value = value.strip().strip('"').lower()
    if '@' in value:
        value = value.split('@', 1)[1]
    return value.rstrip('.')


def _domains_aligned(a: str, b: str) -> bool:
    """Aligned means equal, or one is a subdomain of the other."""
    if not a or not b:
        return False
    return a == b or a.endswith('.' + b) or b.endswith('.' + a)


def _parse_trusted_results(headers_raw: str, provider: str = "gmail") -> Optional[dict]:
    """Parse the topmost Authentication-Results header if it is trusted for
    `provider`. Returns None when the header is missing or untrusted."""
    header = _topmost_auth_results_header(headers_raw)
    if header is None:
        return None

    text = _unfold(header)

    # The text before the first ';' is the authserv-id
    authserv_text, separator, results_text = text.partition(';')
    authserv_id = authserv_text.split(':', 1)[1].strip() if ':' in authserv_text else authserv_text.strip()

    if provider == "gmail":
        # Only the header added by Google's receiving server may be trusted.
        if authserv_id.lower() != "mx.google.com":
            return None
    else:
        # TODO: validate the authserv-id per provider (e.g. Outlook's receiving
        # servers) once known; for now accept the topmost header for others.
        pass

    spf: Optional[str] = None
    dmarc: Optional[str] = None
    dkim_results: list[str] = []

    if separator:
        for clause in results_text.split(';'):
            match = re.match(r'\s*(spf|dkim|dmarc)\s*=\s*(\S+)', clause, re.IGNORECASE)
            if not match:
                continue
            name = match.group(1).lower()
            value = _normalize_result(match.group(2))
            if name == 'spf':
                if spf is None:
                    spf = value
            elif name == 'dmarc':
                if dmarc is None:
                    dmarc = value
            elif name == 'dkim':
                dkim_results.append(value)

    # Several DKIM results: pass if any is pass, otherwise the first
    if 'pass' in dkim_results:
        dkim = 'pass'
    elif dkim_results:
        dkim = dkim_results[0]
    else:
        dkim = 'none'

    mailfrom_match = re.search(r'smtp\.mailfrom=([^\s;]+)', text, re.IGNORECASE)
    smtp_mailfrom = mailfrom_match.group(1) if mailfrom_match else None

    header_d = re.search(r'header\.d=([^\s;]+)', text, re.IGNORECASE)
    header_i = re.search(r'header\.i=([^\s;]+)', text, re.IGNORECASE)
    if header_d:
        dkim_domain = _domain_of(header_d.group(1))
    elif header_i:
        dkim_domain = _domain_of(header_i.group(1))
    else:
        dkim_domain = None

    return {
        'spf': spf if spf is not None else 'none',
        'dkim': dkim,
        'dmarc': dmarc if dmarc is not None else 'none',
        'smtp_mailfrom': smtp_mailfrom,
        'dkim_domain': dkim_domain,
    }


def _compute_alignment(parsed: dict, from_domain: Optional[str]) -> bool:
    """True if dmarc is pass; otherwise True if (spf is pass and the
    smtp.mailfrom domain aligns with the From domain) or (dkim is pass and
    the DKIM domain aligns)."""
    if parsed['dmarc'] == 'pass':
        return True
    if not from_domain:
        return False
    from_normalized = from_domain.strip().lower().rstrip('.')

    if parsed['spf'] == 'pass' and parsed['smtp_mailfrom']:
        if _domains_aligned(_domain_of(parsed['smtp_mailfrom']), from_normalized):
            return True

    if parsed['dkim'] == 'pass' and parsed['dkim_domain']:
        if _domains_aligned(parsed['dkim_domain'], from_normalized):
            return True

    return False


def parse_authentication_results(headers_raw: str, provider: str = "gmail") -> dict:
    """Parse the trusted topmost Authentication-Results header into normalized
    first-word results for spf/dkim/dmarc (lowercase). Returns {} when there
    is no trusted header."""
    parsed = _parse_trusted_results(headers_raw, provider)
    if parsed is None:
        return {}
    return {'spf': parsed['spf'], 'dkim': parsed['dkim'], 'dmarc': parsed['dmarc']}


# NOTE: The DNS helpers below are intentionally unused: existence of a DNS
# record is not a real SPF/DKIM/DMARC check. They are kept for reference.

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


def verify_alignment(headers_raw: str, from_domain: Optional[str], provider: str = "gmail") -> bool:
    """Check SPF/DKIM alignment with From domain using the trusted header."""
    parsed = _parse_trusted_results(headers_raw, provider)
    if parsed is None:
        return False
    return _compute_alignment(parsed, from_domain)


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


def verify_authenticity(headers_raw: str, provider: str = "gmail") -> AuthResult:
    """Main function to verify email authenticity.

    Only the topmost Authentication-Results header added by the receiving
    server is trusted. There is no DNS fallback: a missing or untrusted
    result is always 'none', never 'pass'.
    """
    from_domain = extract_from_domain(headers_raw)
    sending_ip = extract_sending_ip(headers_raw)

    parsed = _parse_trusted_results(headers_raw, provider)

    if parsed is None:
        # No trusted Authentication-Results header: nothing may be reported
        # as pass just because a DNS record exists.
        return AuthResult(
            spf='none',
            dkim='none',
            dmarc='none',
            alignment=False,
            details={
                'from_domain': from_domain,
                'sending_ip': sending_ip,
                'auth_results_parsed': False,
            },
        )

    return AuthResult(
        spf=parsed['spf'],
        dkim=parsed['dkim'],
        dmarc=parsed['dmarc'],
        alignment=_compute_alignment(parsed, from_domain),
        details={
            'from_domain': from_domain,
            'sending_ip': sending_ip,
            'auth_results_parsed': True,
        },
    )
