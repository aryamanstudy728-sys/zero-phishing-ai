# Zero Phishing AI

A browser extension that analyzes emails in real-time for phishing and social engineering attempts, providing explainable verdicts (Safe/Suspicious/Dangerous) with detailed reasons.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Chrome Extension│────▶│  FastAPI Backend │────▶│  PostgreSQL DB  │
│  (Manifest V3)  │     │   (Cloud Run)    │     │   (Cloud SQL)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                        │
         │                       ▼                        │
         │              ┌──────────────────┐             │
         │              │  Analysis Engine │             │
         │              │  - SPF/DKIM/DMARC│             │
         │              │  - Domain Age    │             │
         │              │  - Homoglyph     │             │
         │              │  - URL Reputation│             │
         │              │  - LLM (Gemini)  │             │
         │              └──────────────────┘             │
         │                                              │
         └──────────────────────────────────────────────┘
                    Encrypted OAuth Tokens
```

## Features

- **Real-time analysis**: Triggers when user opens an email in Gmail or Outlook
- **Three-tier verdict**: Safe ✅ / Suspicious ⚠️ / Dangerous 🚫
- **Explainable AI**: "Why?" panel shows specific reasons for each verdict
- **Progressive loading**: Fast checks (SPF/DKIM) complete in <1s, LLM analysis follows
- **Local caching**: Previously analyzed emails show instant results
- **Engagement tracking**: Automatically categorizes senders (Priority/Newsletter/Low-Engagement)
- **User feedback**: "Mark as incorrect" stores corrections locally for future improvement
- **Privacy-first**: OAuth tokens stored encrypted in browser, full email content sent to backend only during analysis

## Tech Stack

| Component | Technology |
|-----------|------------|
| Extension | TypeScript, Manifest V3, Vite |
| Backend | Python 3.11, FastAPI, SQLAlchemy 2.0 |
| Database | PostgreSQL (asyncpg) |
| LLM | Google Gemini 1.5 Flash |
| URL Reputation | Google Safe Browsing v4, PhishTank |
| Deployment | Google Cloud Run, Cloud SQL, Secret Manager |
| Auth | Chrome Identity API (client-side OAuth) |

## Project Structure

```
zero-phishing-ai/
├── extension/                 # Chrome Extension (Manifest V3)
│   ├── src/
│   │   ├── background/        # Service worker (OAuth, messaging)
│   │   ├── content/
│   │   │   ├── gmail/         # Gmail-specific detection/extraction/injection
│   │   │   ├── outlook/       # Outlook-specific detection/extraction/injection
│   │   │   └── shared/        # Shared UI components
│   │   ├── popup/             # Extension popup UI
│   │   ├── utils/             # Crypto, cache, API client
│   │   └── styles/            # Injected CSS
│   └── package.json
├── backend/                   # FastAPI Backend
│   ├── app/
│   │   ├── api/               # API routes
│   │   ├── models/            # SQLAlchemy models
│   │   ├── schemas/           # Pydantic schemas
│   │   ├── services/          # Analysis services
│   │   ├── middleware/        # Logging, rate limiting
│   │   ├── config.py          # Settings
│   │   ├── database.py        # DB session management
│   │   └── main.py            # FastAPI app factory
│   ├── tests/
│   ├── alembic/               # DB migrations
│   ├── pyproject.toml
│   └── Dockerfile
├── infrastructure/
│   ├── docker-compose.yml     # Local development
│   └── terraform/             # GCP infrastructure (to be added)
└── docs/
```

## Quick Start

### Prerequisites

- Node.js 20+, pnpm 9+
- Python 3.11+, uv
- Docker & Docker Compose
- Google Cloud account (for production)

### Local Development

1. **Start infrastructure:**
   ```bash
   cd infrastructure
   docker-compose up -d
   ```

2. **Configure environment:**
   ```bash
   cd backend
   cp .env.example .env
   # Edit .env with your API keys
   ```

3. **Run database migrations:**
   ```bash
   cd backend
   uv run alembic upgrade head
   ```

4. **Start backend:**
   ```bash
   cd backend
   uv run uvicorn app.main:app --reload --port 8080
   ```

5. **Build extension:**
   ```bash
   cd extension
   pnpm install
   pnpm dev  # Watch mode
   # or
   pnpm build  # Production build
   ```

6. **Load extension in Chrome:**
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select `extension/dist`

### Configuration

Required API keys (add to `.env`):

| Key | Purpose | Get from |
|-----|---------|----------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Gmail OAuth | Google Cloud Console |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` | Outlook OAuth | Azure Portal |
| `SAFE_BROWSING_API_KEY` | URL reputation | Google Cloud Console |
| `PHISHTANK_API_KEY` | Phishing URL database | PhishTank |
| `GEMINI_API_KEY` | LLM analysis | Google AI Studio |

## Analysis Pipeline

1. **Sender Authenticity** (40% weight)
   - SPF/DKIM/DMARC verification from headers
   - Domain age via WHOIS (flags domains < 30 days)
   - Homoglyph detection against top 500 spoofed brands

2. **URL Reputation** (30% weight)
   - Google Safe Browsing API v4
   - PhishTank database
   - Anchor text vs href mismatch detection

3. **Content Analysis** (30% weight)
   - Gemini 1.5 Flash LLM analysis
   - Detects: urgency, fear, authority impersonation, credential/payment requests
   - Returns manipulation score (0-100), tactics, plain-language summary

4. **Verdict Aggregation**
   - Weighted score: `0.4*auth + 0.3*url + 0.3*llm`
   - Thresholds: Safe < 30, Suspicious 30-69, Dangerous ≥ 70

## Development Commands

```bash
# Root commands (from monorepo root)
pnpm dev          # Start backend dev server
pnpm build        # Build extension + backend
pnpm lint         # Lint all packages
pnpm typecheck    # TypeScript + mypy
pnpm test         # Run all tests
pnpm format       # Format with prettier
pnpm db:up        # Start Postgres + Redis
pnpm db:down      # Stop databases
```

## Testing

```bash
# Extension tests
cd extension && pnpm test

# Backend tests
cd backend && uv run pytest
```

## Production Deployment

1. **GCP Setup:**
   - Create GCP project
   - Enable APIs: Cloud Run, Cloud SQL, Secret Manager, Safe Browsing
   - Create Cloud SQL PostgreSQL instance
   - Store secrets in Secret Manager

2. **Infrastructure (Terraform):**
   ```bash
   cd infrastructure/terraform
   terraform init
   terraform apply
   ```

3. **Deploy Backend:**
   - Configure Cloud Build trigger on main branch
   - Or deploy manually: `gcloud run deploy --source .`

4. **Chrome Web Store:**
   - Build production extension: `pnpm build`
   - Zip `extension/dist` and upload to Chrome Web Store Developer Dashboard
   - Complete CASA security assessment for `gmail.readonly` scope

## CASA Compliance

Google requires CASA (Cloud Application Security Assessment) for apps requesting `gmail.readonly` scope with >100 users.

Key requirements:
- Data flow diagrams
- Threat model
- Security questionnaire
- Third-party penetration test (Tier 2)
- Annual recertification

Start documentation early (Phase 0) - process takes 6-12 weeks.

## Privacy & Security

- OAuth tokens encrypted with AES-GCM in `chrome.storage.local`
- No refresh tokens stored on backend
- Email content sent to backend only during active analysis
- User feedback stored locally only (MVP)
- Full content retention opt-in for model improvement (future)
- GDPR considerations: user data deletion endpoint planned

## License

MIT License - see LICENSE file for details.