# LLM-based content analysis for social engineering detection
# NOTE: Requires google-generativeai==0.7.x (old SDK). If upgrading to the
# new google-genai SDK, replace genai.GenerativeModel / GenerationConfig
# with genai.Client() / types.GenerateContentConfig().

import google.generativeai as genai  # pip: google-generativeai>=0.7.0,<0.8.0
import json
import re
from typing import Optional
from dataclasses import dataclass
from app.config import get_settings

settings = get_settings()

# Configure Gemini
if settings.gemini_api_key:
    genai.configure(api_key=settings.gemini_api_key)

MODEL_NAME = settings.gemini_model


@dataclass
class LLMAnalysisResult:
    manipulation_score: int  # 0-100
    tactics: list[str]
    summary: str
    confidence: float  # 0-1


# Structured prompt for consistent analysis
ANALYSIS_PROMPT = """You are a cybersecurity expert analyzing emails for phishing and social engineering.
Analyze the email content and return a JSON object with:
- manipulation_score: integer 0-100 (how manipulative/deceptive the email is)
- tactics: array of strings (specific tactics detected)
- summary: 1-2 sentence plain English summary
- confidence: float 0-1 (your confidence in this assessment)

TACTICS TO DETECT:
- urgency: "act now", "immediate action required", "account will be closed", "limited time"
- fear: "security breach", "unauthorized access", "suspicious activity", "compromised"
- authority: "from CEO", "from IT department", "from security team", "official notice"
- scarcity: "limited offer", "last chance", "only X left", "expiring soon"
- curiosity: "you have a message", "important document", "see attachment"
- reward: "you won", "refund available", "prize", "gift card"
- credential_request: asks for password, login, verification, 2FA code, SSN
- payment_request: asks for payment, wire transfer, gift cards, crypto, bank details
- malware_indicator: unexpected attachment, enable macros, download file, run script

EMAIL TO ANALYZE:
Headers: {headers}
Body Text: {body_text}
Body HTML: {body_html}
Extracted URLs: {urls}

Return ONLY valid JSON. No markdown, no explanation.
"""

FEW_SHOT_EXAMPLES = [
    {
        "input": {
            "headers": "From: security@paypal.com\nSubject: Account Limited",
            "body_text": "Your PayPal account has been limited. Click here to verify: http://paypal-verify.com/login",
            "body_html": "<p>Your PayPal account has been limited. <a href='http://paypal-verify.com/login'>Click here to verify</a></p>",
            "urls": ["http://paypal-verify.com/login"]
        },
        "output": {
            "manipulation_score": 95,
            "tactics": ["fear", "authority", "credential_request", "urgency"],
            "summary": "Impersonates PayPal security team claiming account limitation to steal credentials via fake verification link.",
            "confidence": 0.98
        }
    },
    {
        "input": {
            "headers": "From: newsletter@company.com\nSubject: Weekly Update",
            "body_text": "Here's your weekly newsletter with company updates and upcoming events.",
            "body_html": "<p>Here's your weekly newsletter with company updates and upcoming events.</p>",
            "urls": ["https://company.com/newsletter"]
        },
        "output": {
            "manipulation_score": 5,
            "tactics": [],
            "summary": "Legitimate newsletter with no manipulative tactics detected.",
            "confidence": 0.95
        }
    },
    {
        "input": {
            "headers": "From: ceo@company.com\nSubject: URGENT: Wire Transfer Needed",
            "body_text": "I need you to process a wire transfer of $25,000 immediately. This is confidential. Reply with confirmation.",
            "body_html": "<p>I need you to process a wire transfer of $25,000 immediately. This is confidential. Reply with confirmation.</p>",
            "urls": []
        },
        "output": {
            "manipulation_score": 88,
            "tactics": ["authority", "urgency", "payment_request", "fear"],
            "summary": "CEO impersonation requesting urgent wire transfer - classic business email compromise (BEC) attempt.",
            "confidence": 0.92
        }
    }
]


def build_prompt(headers: str, body_text: str, body_html: Optional[str], urls: list[str]) -> str:
    """Build the analysis prompt with few-shot examples."""
    examples_text = ""
    for ex in FEW_SHOT_EXAMPLES:
        examples_text += f"Example:\nInput: {json.dumps(ex['input'])}\nOutput: {json.dumps(ex['output'])}\n\n"

    return f"""{ANALYSIS_PROMPT.format(
        headers=headers[:2000],
        body_text=body_text[:3000],
        body_html=body_html[:3000] if body_html else "N/A",
        urls=json.dumps(urls)
    )}

{examples_text}Now analyze the email above."""


async def analyze_content(
    headers: str,
    body_text: str,
    body_html: Optional[str],
    urls: list[str]
) -> LLMAnalysisResult:
    """Analyze email content using Gemini."""
    if not settings.gemini_api_key:
        return LLMAnalysisResult(
            manipulation_score=0,
            tactics=["llm_unavailable"],
            summary="LLM analysis unavailable - no API key configured",
            confidence=0.0
        )

    prompt = build_prompt(headers, body_text, body_html, urls)

    try:
        model = genai.GenerativeModel(MODEL_NAME)
        # response_mime_type requires google-generativeai>=0.3.0
        generation_config = genai.GenerationConfig(
            temperature=0.1,
            max_output_tokens=500,
            response_mime_type="application/json",
        )
        response = await model.generate_content_async(
            prompt,
            generation_config=generation_config,
        )

        raw = response.text
        # Strip accidental markdown fences the model may add despite the mime type
        json_match = re.search(r"\{.*\}", raw, re.DOTALL)
        result = json.loads(json_match.group(0) if json_match else raw)

        return LLMAnalysisResult(
            manipulation_score=max(0, min(100, int(result.get("manipulation_score", 0)))),
            tactics=result.get("tactics", []),
            summary=result.get("summary", ""),
            confidence=max(0.0, min(1.0, float(result.get("confidence", 0.5)))),
        )
    except Exception as e:
        return LLMAnalysisResult(
            manipulation_score=0,
            tactics=["llm_error"],
            summary=f"LLM analysis failed: {str(e)[:100]}",
            confidence=0.0,
        )