# Zero Phishing AI — Implementation Plan

**Status:** Ready for implementation
**Target:** Chrome Extension (MV3) + Python/FastAPI Backend on Cloud Run + PostgreSQL

## Architecture Decisions (Locked)

| Component | Choice |
|---|---|
| Backend | Python/FastAPI |
| Database | PostgreSQL |
| LLM | Google Gemini 1.5 Flash |
| Deployment | Google Cloud Run |
| Email Providers | Gmail + Outlook (parallel) |
| OAuth Flow | Client-side (Chrome Identity API + encrypted storage) |
| Data Retention | Full content for retraining |
| URL Reputation | Safe Browsing v4 + PhishTank |
| Feedback Loop | Local-only MVP |
| Observability | OpenTelemetry + Cloud Logging |
| CASA Timeline | Start prep in parallel with Phase 1 |

## 7-Phase Implementation Plan

- **Phase 0 (Week 1): Foundation** — monorepo setup, CI/CD, docker-compose, CASA prep, GCP secrets
- **Phase 1 (Week 2): Extension skeleton** — Manifest V3, Chrome Identity OAuth for Gmail/Outlook, encrypted token storage, email-open detection + badge injection for both providers, IndexedDB cache
- **Phase 2 (Week 2-3): Backend scaffold** — FastAPI + SQLAlchemy async, `/analyze` mock endpoint, extension↔backend wiring
- **Phase 3 (Week 3-4): Fast authenticity** — SPF/DKIM/DMARC parser, WHOIS domain age, homoglyph detection (top 500 brands), streaming partial verdicts
- **Phase 4 (Week 4-5): URL reputation + LLM** — Safe Browsing + PhishTank, Gemini 1.5 Flash for manipulation scoring, weighted verdict aggregation (40/30/30)
- **Phase 5 (Week 5-6): Outlook parity + engagement** — Graph API client, per-sender tracking (open/reply/dwell), priority/newsletter/low-engagement tags
- **Phase 6 (Week 6-7): Feedback + polish** — local "mark incorrect", loading states, rate limiting, accessibility, popup UI
- **Phase 7 (Week 7-8): Production** — Terraform (Cloud Run, Cloud SQL, Secret Manager), CI/CD, CASA submission, Chrome Web Store prep, load testing

## Key Data Models

- **Email**: `message_id`, `provider`, `headers_raw`, `body_text`, `body_html`, `urls`
- **Verdict**: `verdict`, `score`, `reasons[]`, `authenticity`, `url_reputation`, `llm_analysis`
- **EngagementEvent**: `sender`, `event_type`, `duration_ms`
- **UserFeedback**: `correction`, `note`

## API Contract

- `POST /api/v1/analyze` → `{verdict, score, reasons[], analysis_id}`
- `POST /api/v1/feedback` → `{email_id, correction}`
- `GET /api/v1/engagement/stats` → `{sender: tag}`

## Validation Targets

- ≥95% phishing recall, ≤5% false positive
- Fast checks <1s, full verdict <3-4s
- Manual QA checklist for both Gmail/Outlook

## Next Steps for Implementation Agent

1. Initialize repo with the structure above
2. Phase 0 tasks in parallel (dev tooling, CASA docs, GCP setup)
3. Phase 1 extension skeleton (critical path)
4. Phase 2 backend scaffold (parallel once detector works)
