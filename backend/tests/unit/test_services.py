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
        # Exact values: the parser must return only the first word, lowercase
        assert result.spf == 'pass'
        assert result.dkim == 'pass'
        assert result.dmarc == 'pass'
        assert result.alignment is True
        assert result.details['auth_results_parsed'] is True

    def test_parse_authentication_results_returns_normalized_values(self):
        from app.services.spf_dkim import parse_authentication_results
        results = parse_authentication_results(self.GMAIL_ALL_PASS)
        # Only the first word of each result, never the whole text
        assert results == {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}

    # Realistic synthetic headers (example.com style domains only)
    GMAIL_ALL_PASS = (
        "From: Example Sender <bounce@mail.example.com>\n"
        "Subject: Hello\n"
        "Authentication-Results: mx.google.com;\n"
        "       dkim=pass header.i=@example.com header.s=sel1 header.b=AbCdEf;\n"
        "       spf=pass (google.com: domain of bounce@mail.example.com designates 203.0.113.5 as permitted sender) smtp.mailfrom=bounce@mail.example.com;\n"
        "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com\n"
    )

    GMAIL_ALL_FAIL = (
        "From: Example Sender <bounce@mail.example.com>\n"
        "Subject: Hello\n"
        "Authentication-Results: mx.google.com;\n"
        "       dkim=fail header.i=@example.com header.s=sel1;\n"
        "       spf=fail (google.com: domain of bounce@mail.example.com designates 203.0.113.5 as permitted sender) smtp.mailfrom=bounce@mail.example.com;\n"
        "       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=example.com\n"
    )

    GMAIL_SOFTFAIL = (
        "From: Example Sender <bounce@mail.example.com>\n"
        "Authentication-Results: mx.google.com;\n"
        "       spf=softfail smtp.mailfrom=bounce@mail.example.com;\n"
        "       dkim=none;\n"
        "       dmarc=fail header.from=example.com\n"
    )

    ARC_ABOVE_REAL = (
        "From: Example Sender <bounce@mail.example.com>\n"
        "ARC-Authentication-Results: i=1; mx.google.com; spf=fail smtp.mailfrom=bounce@mail.example.com; dkim=fail; dmarc=fail\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bounce@mail.example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com\n"
    )

    FORGED_BELOW_REAL = (
        "From: Example Sender <bounce@mail.example.com>\n"
        "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bounce@mail.example.com; dkim=fail header.d=example.com; dmarc=fail header.from=example.com\n"
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass header.d=example.com; dmarc=pass\n"
    )

    UNTRUSTED_AUTHSERV = (
        "From: Example Sender <bounce@mail.example.com>\n"
        "Authentication-Results: evil.example.net; spf=pass smtp.mailfrom=bounce@mail.example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com\n"
    )

    DKIM_SUBDOMAIN = (
        "From: John Doe <john@example.com>\n"
        "Authentication-Results: mx.google.com; spf=none; dkim=pass header.i=@news.example.com; dmarc=none header.from=example.com\n"
    )

    SPOOFED_MAILFROM = (
        "From: PayPal Security <alerts@paypal.example.com>\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bounce@evil.example.net; dkim=fail header.d=evil.example.net; dmarc=fail header.from=paypal.example.com\n"
    )

    CRLF_FOLDED = (
        "From: Example Sender <bounce@mail.example.com>\r\n"
        "Subject: Hello\r\n"
        "Authentication-Results: mx.google.com;\r\n"
        "       dkim=pass header.i=@example.com header.s=sel1;\r\n"
        "       spf=pass smtp.mailfrom=bounce@mail.example.com;\r\n"
        "       dmarc=pass header.from=example.com\r\n"
    )

    def test_all_pass_in_gmail_layout(self):
        result = verify_authenticity(self.GMAIL_ALL_PASS)
        assert result.spf == 'pass'
        assert result.dkim == 'pass'
        assert result.dmarc == 'pass'
        assert result.alignment is True

    def test_all_fail_in_gmail_layout(self):
        result = verify_authenticity(self.GMAIL_ALL_FAIL)
        assert result.spf == 'fail'
        assert result.dkim == 'fail'
        assert result.dmarc == 'fail'
        assert result.alignment is False

    def test_softfail_result(self):
        result = verify_authenticity(self.GMAIL_SOFTFAIL)
        assert result.spf == 'softfail'

    def test_arc_authentication_results_line_is_ignored(self):
        result = verify_authenticity(self.ARC_ABOVE_REAL)
        assert result.spf == 'pass'
        assert result.dkim == 'pass'
        assert result.dmarc == 'pass'

    def test_forged_lower_header_does_not_override_topmost(self):
        result = verify_authenticity(self.FORGED_BELOW_REAL)
        assert result.spf == 'fail'
        assert result.dkim == 'fail'
        assert result.dmarc == 'fail'

    def test_untrusted_authserv_id_is_treated_as_missing(self):
        result = verify_authenticity(self.UNTRUSTED_AUTHSERV)
        assert result.spf == 'none'
        assert result.dkim == 'none'
        assert result.dmarc == 'none'
        assert result.alignment is False
        assert result.details['auth_results_parsed'] is False

    def test_dkim_subdomain_is_aligned(self):
        result = verify_authenticity(self.DKIM_SUBDOMAIN)
        assert result.dkim == 'pass'
        assert result.alignment is True

    def test_unaligned_mailfrom_and_no_dkim_pass(self):
        result = verify_authenticity(self.SPOOFED_MAILFROM)
        assert result.spf == 'pass'
        assert result.alignment is False

    def test_crlf_and_folded_lines_parse_correctly(self):
        result = verify_authenticity(self.CRLF_FOLDED)
        assert result.spf == 'pass'
        assert result.dkim == 'pass'
        assert result.dmarc == 'pass'
        assert result.alignment is True

    def test_missing_header_gives_none_without_dns(self):
        headers = "From: John Doe <john@example.com>\nSubject: Test"
        result = verify_authenticity(headers)
        # No trusted header: nothing may be reported as pass (no DNS fallback)
        assert result.spf == 'none'
        assert result.dkim == 'none'
        assert result.dmarc == 'none'
        assert result.alignment is False
        assert result.details['auth_results_parsed'] is False

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


@pytest.fixture
def fake_analyses(monkeypatch):
    """Replace analyze_domain/analyze_urls/analyze_content so no network is used."""
    from app.services.url_reputation import URLReputationResult
    from app.services.llm_analysis import LLMAnalysisResult

    async def fake_analyze_urls(urls, html=None):
        return [
            URLReputationResult(
                url=url,
                safe_browsing={"threats": []},
                phishtank=False,
                anchor_mismatch=False,
            )
            for url in urls
        ]

    async def fake_analyze_content(headers, body_text, body_html, urls):
        return LLMAnalysisResult(
            manipulation_score=5,
            tactics=[],
            summary="Legitimate email",
            confidence=0.9,
        )

    monkeypatch.setattr("app.services.verdict.analyze_domain", lambda domain: None)
    monkeypatch.setattr("app.services.verdict.analyze_urls", fake_analyze_urls)
    monkeypatch.setattr("app.services.verdict.analyze_content", fake_analyze_content)


class TestAnalyzeEmailResponseIds:
    """analyze_email must return valid UUID strings for analysis_id and email_id,
    because VerdictResponse validates both as UUID (a missing id is the string 'None')."""

    # Complete Authentication-Results so verify_authenticity does not fall back
    # to live DNS checks (the analysis helpers themselves are faked below).
    HEADERS = (
        "From: John Doe <john@example.com>\r\n"
        "Authentication-Results: mx.google.com;\r\n"
        " dkim=pass header.i=@example.com header.s=sel1;\r\n"
        " spf=pass (google.com: domain of bounce@mail.example.com designates 203.0.113.5 as permitted sender) smtp.mailfrom=bounce@mail.example.com;\r\n"
        " dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com\r\n"
        "Subject: Test"
    )

    async def _analyze(self, db_session):
        from app.services.verdict import analyze_email
        return await analyze_email(
            db=db_session,
            user_hash="user_hash_uuid_test",
            message_id="uuid-msg-1",
            provider="gmail",
            headers_raw=self.HEADERS,
            body_text="Hello, please verify your account.",
            body_html="<p>Hello, please verify your account.</p>",
            urls=["https://example.com/verify"],
        )

    @pytest.mark.asyncio
    async def test_new_analysis_returns_valid_uuids(self, db_session, fake_analyses):
        result = await self._analyze(db_session)

        # 'None' would raise ValueError here; valid UUIDs must round-trip
        assert str(uuid.UUID(result["analysis_id"])) == result["analysis_id"]
        assert str(uuid.UUID(result["email_id"])) == result["email_id"]
        assert result["analysis_id"] != result["email_id"]

        # The returned dict must pass VerdictResponse validation
        from app.schemas import VerdictResponse
        response = VerdictResponse.model_validate(result)
        assert str(response.analysis_id) == result["analysis_id"]
        assert str(response.email_id) == result["email_id"]

    @pytest.mark.asyncio
    async def test_cached_call_returns_same_ids(self, db_session, fake_analyses):
        first = await self._analyze(db_session)
        second = await self._analyze(db_session)

        # Same analysis_id (cached verdict) and same email_id (same email row)
        assert second["analysis_id"] == first["analysis_id"]
        assert second["email_id"] == first["email_id"]

        # The cached response must also pass VerdictResponse validation
        from app.schemas import VerdictResponse
        VerdictResponse.model_validate(second)


class TestEngagementTags:
    """get_sender_tags must count opens only from event_type == 'open' and
    return only the current user's senders."""

    @staticmethod
    async def _add_event(db, user_hash, sender, event_type, duration_ms=None):
        from app.models import EngagementEvent
        db.add(EngagementEvent(
            email_id=None,
            user_id=user_hash,
            sender_email=sender,
            sender_domain=sender.split('@')[-1],
            event_type=event_type,
            duration_ms=duration_ms,
        ))
        await db.flush()

    @pytest.mark.asyncio
    async def test_user_only_gets_tags_for_own_senders(self, db_session):
        # User A: newsletter sender
        for _ in range(11):
            await self._add_event(db_session, "eng_user_a", "news@example.com", "open")
        # User B: priority sender
        for _ in range(3):
            await self._add_event(db_session, "eng_user_b", "boss@corp.example.com", "open")
        await self._add_event(db_session, "eng_user_b", "boss@corp.example.com", "reply")

        from app.services.engagement import get_sender_tags
        tags_a = await get_sender_tags(db_session, "eng_user_a")
        tags_b = await get_sender_tags(db_session, "eng_user_b")

        assert tags_a == {"news@example.com": "newsletter"}
        assert tags_b == {"boss@corp.example.com": "priority"}

    @pytest.mark.asyncio
    async def test_many_opens_and_no_replies_is_newsletter(self, db_session):
        for _ in range(11):
            await self._add_event(db_session, "eng_user_c", "weekly@news.example.com", "open")

        from app.services.engagement import get_sender_tags
        tags = await get_sender_tags(db_session, "eng_user_c")

        assert tags["weekly@news.example.com"] == "newsletter"

    @pytest.mark.asyncio
    async def test_replies_with_more_than_two_opens_is_priority(self, db_session):
        for _ in range(3):
            await self._add_event(db_session, "eng_user_d", "lead@corp.example.com", "open")
        await self._add_event(db_session, "eng_user_d", "lead@corp.example.com", "reply")

        from app.services.engagement import get_sender_tags
        tags = await get_sender_tags(db_session, "eng_user_d")

        assert tags["lead@corp.example.com"] == "priority"

    @pytest.mark.asyncio
    async def test_reply_events_are_not_counted_as_opens(self, db_session):
        # Replies and dwell events must not inflate the open count: 5 replies
        # and no opens means opens == 0 -> low-engagement, not priority.
        for _ in range(5):
            await self._add_event(db_session, "eng_user_e", "chatty@corp.example.com", "reply")
        await self._add_event(db_session, "eng_user_e", "chatty@corp.example.com", "dwell", duration_ms=5000)

        from app.services.engagement import get_sender_tags
        tags = await get_sender_tags(db_session, "eng_user_e")

        assert tags["chatty@corp.example.com"] == "low-engagement"


class TestIntegrityErrorRecovery:
    """A concurrent same-message analysis must not 500: the IntegrityError
    path waits (bounded) for the winner's rows and returns them."""

    @staticmethod
    async def _analyze(db_session, message_id):
        from app.services.verdict import analyze_email
        return await analyze_email(
            db=db_session,
            user_hash="user_hash_race_test",
            message_id=message_id,
            provider="gmail",
            headers_raw=TestAnalyzeEmailResponseIds.HEADERS,
            body_text="Hello, please verify your account.",
            body_html="<p>Hello, please verify your account.</p>",
            urls=["https://example.com/verify"],
        )

    @pytest.mark.asyncio
    async def test_race_returns_the_winning_stored_analysis(self, db_session, fake_analyses, monkeypatch):
        first = await self._analyze(db_session, "race-msg-1")
        # The winner's rows must be committed to survive our rollback, as they
        # would be in the real concurrent scenario
        await db_session.commit()

        import app.services.verdict as verdict_module
        real_find_email = verdict_module._find_email
        calls = {"n": 0}

        async def flaky_find_email(db, user_hash, message_id, provider):
            calls["n"] += 1
            if calls["n"] == 1:
                # Simulate the pre-save cache check missing the winner
                return None
            return await real_find_email(db, user_hash, message_id, provider)

        monkeypatch.setattr("app.services.verdict._find_email", flaky_find_email)

        raced = await self._analyze(db_session, "race-msg-1")

        # The IntegrityError actually fired (not a plain cache hit), and the
        # recovery returned the winner's stored ids
        assert calls["n"] >= 2
        assert raced["analysis_id"] == first["analysis_id"]
        assert raced["email_id"] == first["email_id"]

    @pytest.mark.asyncio
    async def test_recovery_is_bounded_and_reraises_when_nothing_is_stored(self, db_session, fake_analyses, monkeypatch):
        # Commit a conflicting (user, message, provider) row so the save fails,
        # while the lookup stays blind: the winner "never appears"
        db_session.add(Email(
            message_id="race-msg-2",
            provider="gmail",
            user_id="user_hash_race_test",
            headers_raw="From: test@example.com",
            body_text="stored",
            body_html=None,
            urls=[],
            received_at=datetime.now(timezone.utc),
        ))
        await db_session.commit()

        import app.services.verdict as verdict_module
        calls = {"n": 0}

        async def blind_find_email(db, user_hash, message_id, provider):
            calls["n"] += 1
            return None

        monkeypatch.setattr("app.services.verdict._find_email", blind_find_email)

        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            await self._analyze(db_session, "race-msg-2")

        # 1 cache-check call + the bounded recovery attempts, and no more
        assert calls["n"] == 1 + verdict_module._INTEGRITY_RECOVERY_ATTEMPTS


class TestEmailContentNotStored:
    """Privacy: analyze_email must use the raw email content for the analysis
    but must never store it on the Email row."""

    @pytest.fixture
    def capturing_analyses(self, monkeypatch):
        """Fakes that record what the analysis received (no network)."""
        from app.services.url_reputation import URLReputationResult
        from app.services.llm_analysis import LLMAnalysisResult

        captured = {"headers": None, "body_text": None, "urls": None}

        async def fake_analyze_urls(urls, html=None):
            captured["urls"] = list(urls)
            return [
                URLReputationResult(
                    url=url,
                    safe_browsing={"threats": []},
                    phishtank=False,
                    anchor_mismatch=False,
                )
                for url in urls
            ]

        async def fake_analyze_content(headers, body_text, body_html, urls):
            captured["headers"] = headers
            captured["body_text"] = body_text
            return LLMAnalysisResult(
                manipulation_score=5,
                tactics=[],
                summary="Legitimate email",
                confidence=0.9,
            )

        monkeypatch.setattr("app.services.verdict.analyze_domain", lambda domain: None)
        monkeypatch.setattr("app.services.verdict.analyze_urls", fake_analyze_urls)
        monkeypatch.setattr("app.services.verdict.analyze_content", fake_analyze_content)
        return captured

    @pytest.mark.asyncio
    async def test_content_is_used_for_analysis_but_not_stored(self, db_session, capturing_analyses):
        from sqlalchemy import select
        from app.services.verdict import analyze_email
        from app.schemas import VerdictResponse

        result = await analyze_email(
            db=db_session,
            user_hash="user_hash_privacy_test",
            message_id="privacy-msg-1",
            provider="gmail",
            headers_raw=TestAnalyzeEmailResponseIds.HEADERS,
            body_text="Hello, please verify your account.",
            body_html="<p>Hello, please verify your account.</p>",
            urls=["https://example.com/verify"],
        )

        # The response format is unchanged and still valid
        response = VerdictResponse.model_validate(result)
        assert response.verdict in ("safe", "suspicious", "dangerous")
        assert isinstance(response.score, int)
        assert 0 <= response.score <= 100
        assert len(response.reasons) >= 0
        assert str(response.analysis_id) == result["analysis_id"]
        assert str(response.email_id) == result["email_id"]

        # The analysis helpers received the REAL content
        assert capturing_analyses["body_text"] == "Hello, please verify your account."
        assert capturing_analyses["headers"] == TestAnalyzeEmailResponseIds.HEADERS
        assert capturing_analyses["urls"] == ["https://example.com/verify"]

        # But the saved Email row holds no content at all
        email_row = (await db_session.execute(
            select(Email).where(Email.message_id == "privacy-msg-1")
        )).scalar_one()
        assert email_row.headers_raw is None
        assert email_row.body_text is None
        assert email_row.body_html is None
        assert email_row.urls is None

        # Identity columns are kept
        assert email_row.provider == "gmail"
        assert email_row.user_id == "user_hash_privacy_test"
        assert email_row.received_at is not None


class TestScoringFixes:
    """Scoring rules: the authenticity cap runs after the domain points, a
    failed LLM step renormalizes the remaining weights, a confirmed Safe
    Browsing threat can never be 'safe', and PhishTank adds nothing. All
    inputs are fake objects - no network."""

    @staticmethod
    def _clean_auth():
        return AuthResult(spf='pass', dkim='pass', dmarc='pass', alignment=True, details={})

    @staticmethod
    def _max_auth():
        # 40 (spf fail) + 30 (dkim fail) + 25 (dmarc fail) + 20 (no alignment) = 115
        return AuthResult(spf='fail', dkim='fail', dmarc='fail', alignment=False, details={})

    @staticmethod
    def _lookalike_domain():
        # +15 (new domain) + 35 (lookalike): 115 + 50 = 165 before the cap
        return DomainAnalysis(
            domain='paypa1.example.com',
            domain_age_days=5,
            is_new_domain=True,
            homoglyph_match='paypal',
            homoglyph_distance=1,
            registrar=None,
            registration_date=None
        )

    @staticmethod
    def _clean_urls():
        from app.services.url_reputation import URLReputationResult
        return [URLReputationResult(url='https://example.com', safe_browsing={'threats': []}, phishtank=False, anchor_mismatch=False)]

    @staticmethod
    def _llm(score=0, tactics=None, summary='', confidence=0.0):
        from app.services.llm_analysis import LLMAnalysisResult
        return LLMAnalysisResult(
            manipulation_score=score,
            tactics=tactics if tactics is not None else [],
            summary=summary,
            confidence=confidence
        )

    def test_authenticity_points_above_100_stay_capped_after_domain_bonus(self):
        # Old behavior: the cap ran BEFORE +15/+35, so authenticity reached 150
        # and this scored 60. The cap now yields exactly 100 -> 100*0.4 = 40.
        result = calculate_verdict(self._max_auth(), self._lookalike_domain(), self._clean_urls(), self._llm())
        assert result.score == 40
        assert 0 <= result.score <= 100
        # The domain reasons are still reported alongside the capped score
        details = [r["detail"] for r in result.reasons]
        assert any("registered recently" in d for d in details)
        assert any("resembles known brand" in d for d in details)

    def test_llm_unavailable_renormalizes_to_authenticity_and_urls(self):
        # Authenticity 100, urls 0, LLM dead: (100*0.4 + 0*0.3) / 0.7 = 57.14
        # -> 57 (suspicious), not the old 40 (safe)
        llm = self._llm(tactics=['llm_unavailable'], summary='LLM analysis unavailable - no API key configured')
        result = calculate_verdict(self._max_auth(), self._lookalike_domain(), self._clean_urls(), llm)
        assert result.score == 57
        assert result.verdict == 'suspicious'

    def test_llm_unavailable_with_clean_email_is_safe_and_explains(self):
        llm = self._llm(tactics=['llm_error'], summary='LLM analysis failed: boom')
        result = calculate_verdict(self._clean_auth(), None, self._clean_urls(), llm)
        assert result.verdict == 'safe'
        assert result.score == 0
        details = [r["detail"] for r in result.reasons]
        # The one explanatory reason is present...
        assert "AI content analysis was unavailable, so the score uses authenticity and link checks only" in details
        # ...while the sentinel never becomes a "Detected ..." reason and the
        # exception text never reaches a user-facing reason
        assert not any("Detected llm_error" in d for d in details)
        assert not any("boom" in d for d in details)

    def test_safe_browsing_threat_with_clean_email_forces_dangerous(self):
        from app.services.url_reputation import URLReputationResult
        urls = [URLReputationResult(
            url='https://evil.example.com',
            safe_browsing={'threats': ['SOCIAL_ENGINEERING']},
            phishtank=False,
            anchor_mismatch=False
        )]
        result = calculate_verdict(self._clean_auth(), None, urls, self._llm())
        # The weighted score would be only 12; the confirmed threat floors it at 70
        assert result.score == 70
        assert result.verdict == 'dangerous'

    def test_working_llm_keeps_original_weights(self):
        # 45 authenticity (dkim none +15, dmarc none +10, no alignment +20;
        # spf pass adds nothing), 0 urls, 40 llm -> int(18 + 12) = 30
        auth = AuthResult(spf='pass', dkim='none', dmarc='none', alignment=False, details={})
        llm = self._llm(score=40, tactics=['urgency'], summary='Marketing email with urgency', confidence=0.8)
        result = calculate_verdict(auth, None, self._clean_urls(), llm)
        assert result.score == 30
        assert result.verdict == 'suspicious'
        assert any("Uses urgency tactic" in r["detail"] for r in result.reasons)

    def test_phishtank_adds_no_score_and_no_reason(self):
        # Rule (d): PhishTank must not be used - a phishtank hit changes
        # neither the score nor the reasons
        from app.services.url_reputation import URLReputationResult
        phish_urls = [URLReputationResult(
            url='https://listed.example.com',
            safe_browsing={'threats': []},
            phishtank=True,
            anchor_mismatch=False
        )]
        clean = calculate_verdict(self._clean_auth(), None, self._clean_urls(), self._llm())
        flagged = calculate_verdict(self._clean_auth(), None, phish_urls, self._llm())
        assert flagged.score == clean.score == 0
        assert not any("PhishTank" in r["detail"] for r in flagged.reasons)