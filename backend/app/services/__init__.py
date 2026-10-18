# Services package

from app.services.spf_dkim import verify_authenticity, AuthResult
from app.services.domain import analyze_domain, DomainAnalysis
from app.services.url_reputation import analyze_urls, URLReputationResult
from app.services.llm_analysis import analyze_content, LLMAnalysisResult
from app.services.verdict import analyze_email, calculate_verdict, AnalysisResult
from app.services.feedback import submit_feedback
from app.services.engagement import record_engagement, get_sender_tags
from app.services.gmail import GmailClient
from app.services.graph import GraphClient

__all__ = [
    "verify_authenticity",
    "AuthResult",
    "analyze_domain",
    "DomainAnalysis",
    "analyze_urls",
    "URLReputationResult",
    "analyze_content",
    "LLMAnalysisResult",
    "analyze_email",
    "calculate_verdict",
    "AnalysisResult",
    "submit_feedback",
    "record_engagement",
    "get_sender_tags",
    "GmailClient",
    "GraphClient",
]