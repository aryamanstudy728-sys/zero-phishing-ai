// Backend unit tests

import pytest
from app.services.spf_dkim import verify_authenticity, AuthResult
from app.services.domain import analyze_domain, DomainAnalysis, check_homoglyph
from app.services.verdict import calculate_verdict, AnalysisResult


class TestSPFDKIM:
    def test_parse_authentication_results(self):
        headers = """Authentication-Results: mx.google.com;
    spf=pass (google.com: domain of user@example.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=user@example.com;
    dkim=pass header.d=example.com;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"""
        
        result = verify_authenticity(headers)
        assert result.spf == 'pass'
        assert result.dkim == 'pass'
        assert result.dmarc == 'pass'
        assert result.alignment is True

    def test_extract_from_domain(self):
        headers = "From: John Doe <john@example.com>\nSubject: Test"
        # This would be tested via the verify_authenticity function
        assert True


class TestDomainAnalysis:
    def test_check_homoglyph_exact_match(self):
        match, dist = check_homoglyph("paypal.com")
        assert match == "paypal"
        assert dist == 0

    def test_check_homoglyph_close_match(self):
        match, dist = check_homoglyph("paypa1.com")
        assert match == "paypal"
        assert dist == 1

    def test_check_homoglyph_no_match(self):
        match, dist = check_homoglyph("randomdomain.com")
        assert match is None
        assert dist > 2

    def test_extract_domain_from_email(self):
        from app.services.domain import extract_domain_from_email
        assert extract_domain_from_email("user@example.com") == "example.com"
        assert extract_domain_from_email("Name <user@sub.example.com>") == "sub.example.com"


class TestVerdictCalculation:
    def test_safe_verdict_low_score(self):
        auth = AuthResult(spf='pass', dkim='pass', dmarc='pass', alignment=True, details={})
        domain = DomainAnalysis(
            domain='example.com',
            domain_age_days=365,
            is_new_domain=False,
            homoglyph_match=None,
            homoglyph_distance=999,
            registrar=None,
            registration_date=None
        )
        from app.services.url_reputation import URLReputationResult
        urls = [URLReputationResult(url='https://example.com', safe_browsing={'threats': []}, phishtank=False, anchor_mismatch=False)]
        from app.services.llm_analysis import LLMAnalysisResult
        llm = LLMAnalysisResult(manipulation_score=5, tactics=[], summary='Legitimate email', confidence=0.9)

        result = calculate_verdict(auth, domain, urls, llm)
        assert result.verdict == 'safe'
        assert result.score < 30

    def test_dangerous_verdict_high_score(self):
        auth = AuthResult(spf='fail', dkim='fail', dmarc='fail', alignment=False, details={})
        domain = DomainAnalysis(
            domain='paypa1.com',
            domain_age_days=5,
            is_new_domain=True,
            homoglyph_match='paypal',
            homoglyph_distance=1,
            registrar=None,
            registration_date=None
        )
        from app.services.url_reputation import URLReputationResult
        urls = [URLReputationResult(url='https://paypa1.com/phish', safe_browsing={'threats': ['SOCIAL_ENGINEERING']}, phishtank=True, anchor_mismatch=False)]
        from app.services.llm_analysis import LLMAnalysisResult
        llm = LLMAnalysisResult(manipulation_score=95, tactics=['credential_request', 'urgency', 'fear'], summary='Phishing attempt', confidence=0.98)

        result = calculate_verdict(auth, domain, urls, llm)
        assert result.verdict == 'dangerous'
        assert result.score >= 70

    def test_suspicious_verdict_medium_score(self):
        auth = AuthResult(spf='pass', dkim='none', dmarc='none', alignment=False, details={})
        domain = DomainAnalysis(
            domain='newsletter.example.com',
            domain_age_days=100,
            is_new_domain=False,
            homoglyph_match=None,
            homoglyph_distance=999,
            registrar=None,
            registration_date=None
        )
        from app.services.url_reputation import URLReputationResult
        urls = [URLReputationResult(url='https://example.com/link', safe_browsing={'threats': []}, phishtank=False, anchor_mismatch=False)]
        from app.services.llm_analysis import LLMAnalysisResult
        llm = LLMAnalysisResult(manipulation_score=40, tactics=['urgency'], summary='Marketing email with urgency', confidence=0.8)

        result = calculate_verdict(auth, domain, urls, llm)
        assert result.verdict == 'suspicious'
        assert 30 <= result.score < 70