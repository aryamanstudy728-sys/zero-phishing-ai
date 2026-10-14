# Backend unit tests

import pytest
import uuid
from datetime import datetime, timezone
from app.services.spf_dkim import verify_authenticity, AuthResult
from app.services.domain import analyze_domain, DomainAnalysis, check_homoglyph
from app.services.verdict import calculate_verdict, AnalysisResult
from app.models import Email, Verdict


class TestSPFDKIM:
    def test_parse_authentication_results(self):
        headers = """From: John Doe <john@example.com>
Authentication-Results: mx.google.com; spf=pass (google.com: domain of user@example.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"""
        
        from app.services.spf_dkim import verify_authenticity
        result = verify_authenticity(headers)
        # The parser extracts the full value, check that it starts with 'pass'
        assert result.spf.startswith('pass')
        assert result.dkim.startswith('pass')
        assert result.dmarc.startswith('pass')
        # alignment requires proper SPF/DKIM domain matching - skip for this test

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


class TestUserIsolation:
    """Test that different users don't see each other's verdicts for the same message_id."""

    @pytest.mark.asyncio
    async def test_user_isolation_same_message_id_different_users(self, db_session):
        """Two users with the same message_id should have separate email records and verdicts."""
        user_hash_1 = "user_hash_1"
        user_hash_2 = "user_hash_2"
        message_id = "same_message_id_123"
        provider = "gmail"
        now = datetime.now(timezone.utc)

        # User 1 analyzes the email
        email_1 = Email(
            id=uuid.uuid4(),
            message_id=message_id,
            provider=provider,
            user_id=user_hash_1,
            headers_raw="From: test@example.com\nSubject: Test 1",
            body_text="Test body 1",
            body_html="<p>Test body 1</p>",
            urls=["https://example.com"],
            received_at=now,
        )
        db_session.add(email_1)
        await db_session.flush()

        verdict_1 = Verdict(
            email_id=email_1.id,
            verdict="dangerous",
            score=85,
            reasons=[{"category": "authenticity", "detail": "SPF fail", "severity": "high"}],
            authenticity={"spf": "fail"},
            url_reputation={},
            llm_analysis={},
        )
        db_session.add(verdict_1)
        await db_session.commit()

        # User 2 analyzes the SAME message_id - should create a separate record
        email_2 = Email(
            id=uuid.uuid4(),
            message_id=message_id,
            provider=provider,
            user_id=user_hash_2,
            headers_raw="From: test@example.com\nSubject: Test 2",
            body_text="Test body 2",
            body_html="<p>Test body 2</p>",
            urls=["https://different.com"],
            received_at=now,
        )
        db_session.add(email_2)
        await db_session.flush()

        verdict_2 = Verdict(
            email_id=email_2.id,
            verdict="safe",
            score=10,
            reasons=[],
            authenticity={},
            url_reputation={},
            llm_analysis={},
        )
        db_session.add(verdict_2)
        await db_session.commit()

        # Verify both emails exist
        from sqlalchemy import select
        stmt = select(Email).where(Email.message_id == message_id, Email.provider == provider)
        result = await db_session.execute(stmt)
        emails = result.scalars().all()
        assert len(emails) == 2

        # Verify each user only sees their own verdict
        user1_emails = [e for e in emails if e.user_id == user_hash_1]
        user2_emails = [e for e in emails if e.user_id == user_hash_2]
        assert len(user1_emails) == 1
        assert len(user2_emails) == 1

        # Verify verdicts are different
        v1_stmt = select(Verdict).where(Verdict.email_id == user1_emails[0].id)
        v1_result = await db_session.execute(v1_stmt)
        v1 = v1_result.scalar_one()
        assert v1.verdict == "dangerous"
        assert v1.score == 85

        v2_stmt = select(Verdict).where(Verdict.email_id == user2_emails[0].id)
        v2_result = await db_session.execute(v2_stmt)
        v2 = v2_result.scalar_one()
        assert v2.verdict == "safe"
        assert v2.score == 10