# Verdict aggregation logic

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import Email, Verdict
from app.services.spf_dkim import verify_authenticity, AuthResult
from app.services.domain import analyze_domain, DomainAnalysis
from app.services.url_reputation import analyze_urls, URLReputationResult
from app.services.llm_analysis import analyze_content, LLMAnalysisResult
from app.config import get_settings

settings = get_settings()


@dataclass
class AnalysisResult:
    verdict: str  # safe, suspicious, dangerous
    score: int  # 0-100
    reasons: list[dict]
    authenticity: dict
    url_reputation: dict
    llm_analysis: dict


def calculate_verdict(
    auth: AuthResult,
    domain: Optional[DomainAnalysis],
    url_results: list[URLReputationResult],
    llm: LLMAnalysisResult,
) -> AnalysisResult:
    """Calculate final verdict from all analysis components."""
    reasons = []
    score = 0

    # Weights: Authenticity 40%, URL Reputation 30%, LLM 30%
    authenticity_score = 0
    url_score = 0
    llm_score = llm.manipulation_score

    # Authenticity scoring (0-100, higher = more suspicious)
    if auth.spf == 'fail':
        authenticity_score += 40
        reasons.append({
            "category": "authenticity",
            "detail": "SPF fail: sending IP not authorized for domain",
            "severity": "high"
        })
    elif auth.spf == 'softfail':
        authenticity_score += 20
        reasons.append({
            "category": "authenticity",
            "detail": "SPF softfail: sending IP may not be authorized",
            "severity": "medium"
        })
    elif auth.spf == 'none':
        authenticity_score += 10
        reasons.append({
            "category": "authenticity",
            "detail": "No SPF record found for sending domain",
            "severity": "low"
        })

    if auth.dkim == 'fail':
        authenticity_score += 30
        reasons.append({
            "category": "authenticity",
            "detail": "DKIM signature verification failed",
            "severity": "high"
        })
    elif auth.dkim == 'none':
        authenticity_score += 15
        reasons.append({
            "category": "authenticity",
            "detail": "No valid DKIM signature found",
            "severity": "medium"
        })

    if auth.dmarc == 'fail':
        authenticity_score += 25
        reasons.append({
            "category": "authenticity",
            "detail": "DMARC policy check failed",
            "severity": "high"
        })
    elif auth.dmarc == 'none':
        authenticity_score += 10
        reasons.append({
            "category": "authenticity",
            "detail": "No DMARC policy published",
            "severity": "low"
        })

    if not auth.alignment:
        authenticity_score += 20
        reasons.append({
            "category": "authenticity",
            "detail": "SPF/DKIM domain alignment failed with From address",
            "severity": "high"
        })

    authenticity_score = min(100, authenticity_score)

    # Domain scoring (only when domain lookup succeeded)
    if domain is not None:
        if domain.is_new_domain:
            authenticity_score += 15
            reasons.append({
                "category": "authenticity",
                "detail": f"Domain registered recently ({domain.domain_age_days} days ago)",
                "severity": "medium",
            })

        if domain.homoglyph_match:
            authenticity_score += 35
            reasons.append({
                "category": "authenticity",
                "detail": f"Domain resembles known brand '{domain.homoglyph_match}' (edit distance: {domain.homoglyph_distance})",
                "severity": "high",
            })

    # URL reputation scoring
    for url_result in url_results:
        if url_result.phishtank:
            url_score += 50
            reasons.append({
                "category": "url_reputation",
                "detail": f"URL found in PhishTank database: {url_result.url}",
                "severity": "critical"
            })

        if url_result.safe_browsing.get("threats"):
            threats = url_result.safe_browsing["threats"]
            url_score += 40
            reasons.append({
                "category": "url_reputation",
                "detail": f"Google Safe Browsing detects threats: {', '.join(threats)} for {url_result.url}",
                "severity": "critical"
            })

    url_score = min(100, url_score)

    # LLM scoring
    if llm.tactics:
        for tactic in llm.tactics:
            if tactic in ["credential_request", "payment_request"]:
                reasons.append({
                    "category": "content",
                    "detail": f"Requests sensitive action: {tactic.replace('_', ' ')}",
                    "severity": "critical"
                })
            elif tactic in ["urgency", "fear", "authority"]:
                reasons.append({
                    "category": "content",
                    "detail": f"Uses {tactic} tactic to pressure recipient",
                    "severity": "high"
                })
            else:
                reasons.append({
                    "category": "content",
                    "detail": f"Detected {tactic} tactic",
                    "severity": "medium"
                })

    # Add LLM summary as a reason
    if llm.summary:
        reasons.append({
            "category": "content",
            "detail": llm.summary,
            "severity": "medium" if llm.manipulation_score < 50 else "high"
        })

    # Calculate weighted score
    score = int(
        authenticity_score * 0.4 +
        url_score * 0.3 +
        llm_score * 0.3
    )
    score = max(0, min(100, score))

    # Determine verdict
    if score >= 70:
        verdict = "dangerous"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return AnalysisResult(
        verdict=verdict,
        score=score,
        reasons=reasons,
        authenticity={
            "spf": auth.spf,
            "dkim": auth.dkim,
            "dmarc": auth.dmarc,
            "alignment": auth.alignment,
            "details": auth.details,
            "domain": {
                "domain": domain.domain if domain else None,
                "age_days": domain.domain_age_days if domain else None,
                "is_new": domain.is_new_domain if domain else None,
                "homoglyph_match": domain.homoglyph_match if domain else None,
                "homoglyph_distance": domain.homoglyph_distance if domain else None,
            },
        },
        url_reputation={
            "urls": [
                {
                    "url": r.url,
                    "safe_browsing": r.safe_browsing,
                    "phishtank": r.phishtank,
                    "anchor_mismatch": r.anchor_mismatch,
                }
                for r in url_results
            ]
        },
        llm_analysis={
            "manipulation_score": llm.manipulation_score,
            "tactics": llm.tactics,
            "summary": llm.summary,
            "confidence": llm.confidence,
        }
    )


async def analyze_email(
    db: AsyncSession,
    user_hash: str,
    message_id: str,
    provider: str,
    headers_raw: str,
    body_text: str,
    body_html: str | None,
    urls: list[str]
) -> dict:
    """Main analysis function - runs all checks and returns verdict."""
    start_time = datetime.now(timezone.utc)

    # Check if already analyzed (user isolation)
    stmt = select(Email).where(
        Email.message_id == message_id,
        Email.provider == provider,
        Email.user_id == user_hash
    )
    result = await db.execute(stmt)
    email = result.scalar_one_or_none()

    if email:
        # Check for existing verdict
        verdict_stmt = select(Verdict).where(Verdict.email_id == email.id)
        verdict_result = await db.execute(verdict_stmt)
        existing_verdict = verdict_result.scalar_one_or_none()
        if existing_verdict:
            return {
                "verdict": existing_verdict.verdict,
                "score": existing_verdict.score,
                "reasons": existing_verdict.reasons,
                "analysis_id": str(existing_verdict.id),
            }

    # Run all analyses
    auth_result = verify_authenticity(headers_raw)
    from_domain = auth_result.details.get('from_domain', '')
    domain_result = analyze_domain(from_domain) if from_domain else None
    url_results = await analyze_urls(urls, body_html)
    llm_result = await analyze_content(headers_raw, body_text, body_html, urls)

    # Calculate verdict
    analysis = calculate_verdict(auth_result, domain_result, url_results, llm_result)

    # Save to database
    if not email:
        email = Email(
            message_id=message_id,
            provider=provider,
            user_id=user_hash,
            headers_raw=headers_raw,
            body_text=body_text,
            body_html=body_html,
            urls=urls,
            received_at=datetime.now(timezone.utc),
        )
        db.add(email)
        await db.flush()

    verdict = Verdict(
        email_id=email.id,
        verdict=analysis.verdict,
        score=analysis.score,
        reasons=analysis.reasons,
        authenticity=analysis.authenticity,
        url_reputation=analysis.url_reputation,
        llm_analysis=analysis.llm_analysis,
        analysis_duration_ms=int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000),
    )
    db.add(verdict)

    return {
        "verdict": analysis.verdict,
        "score": analysis.score,
        "reasons": analysis.reasons,
        "analysis_id": str(verdict.id),
    }