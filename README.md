# Topcoder Enterprise Guardrails AI

An enterprise-grade guardrails solution that integrates with GitHub to enforce secure coding practices, enterprise standards, and compliance requirements for both AI-generated (Copilot) and human-written code before merge.

## Features

- **Secure Coding Guardrails** - Detect hardcoded secrets, SQL injection, command injection, path traversal, insecure deserialization
- **Enterprise Standards Enforcement** - Naming conventions, logging requirements, error handling patterns
- **AI-Assisted Code Review** - Deep analysis using Claude Haiku 4.5 for security, performance, and maintainability
- **License & IP Compliance** - Detect restricted licenses and potential IP risks
- **Copilot Awareness** - Detect and apply stricter rules to AI-generated code
- **Policy-Based Enforcement** - Advisory, Warning, and Blocking modes with override capability
- **Audit Logging** - Complete traceability with exportable logs

## Security Rules

### Built-in Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| SEC-001 | Hardcoded Secrets | Critical | Detects API keys, passwords, tokens in code |
| SEC-002 | SQL Injection | Critical | Detects vulnerable SQL query construction |
| SEC-003 | Command Injection | Critical | Detects shell command injection risks |
| SEC-004 | Path Traversal | High | Detects directory traversal vulnerabilities |
| SEC-005 | Insecure Deserialization | High | Detects unsafe deserialization patterns |

### Enterprise Standards Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| STD-001 | Naming Conventions | Medium | Enforces consistent naming patterns |
| STD-002 | Logging Requirements | Medium | Requires proper logging practices |
| STD-003 | Error Handling | High | Detects empty catch blocks and swallowed exceptions |

### Industry Compliance Rules

| Pack | Rules | Description |
|------|-------|-------------|
| Healthcare | HIPAA compliance | PHI handling, encryption requirements |
| Telecom | Network security | PII protection, call data security |
| Government | FedRAMP controls | Access control, audit logging |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEVELOPER WORKSTATION                        │
│  ┌──────────┐    ┌───────────────┐    ┌────────────────────┐   │
│  │ IDE +    │───▶│ Pre-commit    │───▶│ guardrails-cli     │   │
│  │ Copilot  │    │ Git Hook      │    │ (calls Backend API)│   │
│  └──────────┘    └───────────────┘    └────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         GITHUB                                   │
│  ┌──────────┐    ┌───────────────┐                              │
│  │ PR/Push  │───▶│ Webhook Event │─────────────────────────┐    │
│  └──────────┘    └───────────────┘                         │    │
└────────────────────────────────────────────────────────────│────┘
                                                             │
                              ┌──────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    NETLIFY (GitHub App)                          │
│  /.netlify/functions/webhook ──▶ Orchestrates scan              │
│                                  Posts PR comments               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RAILWAY (Python Backend)                      │
│  ┌────────────┐  ┌────────────┐  ┌─────────────────────────┐   │
│  │ FastAPI    │  │ Rule       │  │ AI Client               │   │
│  │ REST API   │  │ Engine     │  │ (Vercel AI Gateway)     │   │
│  └────────────┘  └────────────┘  └─────────────────────────┘   │
│        │                                    │                    │
│        ▼                                    ▼                    │
│  ┌────────────┐                   ┌─────────────────────────┐   │
│  │ PostgreSQL │                   │ Claude Haiku 4.5        │   │
│  │ (Audit)    │                   │ Security/Code Analysis  │   │
│  └────────────┘                   └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology | Deployment |
|-----------|------------|------------|
| Backend API | Python (FastAPI) | Railway |
| GitHub App | TypeScript | Netlify Functions |
| Pre-commit Hook | TypeScript CLI | npm package |
| AI/LLM | Claude Haiku 4.5 | Vercel AI Gateway |
| Database | PostgreSQL | Railway (addon) |

## Project Structure

```
├── guardrails-backend/          # Python FastAPI backend
│   ├── app/
│   │   ├── api/v1/              # API endpoints
│   │   ├── core/                # AI client, security
│   │   ├── models/              # SQLAlchemy models
│   │   ├── schemas/             # Pydantic schemas
│   │   └── services/            # Business logic
│   ├── requirements.txt
│   ├── Dockerfile
│   └── railway.toml
│
├── guardrails-github-app/       # TypeScript GitHub App
│   ├── netlify/functions/       # Netlify serverless functions
│   ├── src/
│   │   ├── handlers/            # Event handlers
│   │   ├── services/            # Backend client, formatters
│   │   └── types/               # TypeScript types
│   ├── package.json
│   └── netlify.toml
│
└── guardrails-cli/              # Pre-commit CLI (optional)
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL (or Railway PostgreSQL addon)
- Vercel AI Gateway API key
- GitHub App credentials

### 1. Deploy Backend (Railway)

```bash
cd guardrails-backend

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your configuration

# Run locally
uvicorn app.main:app --reload

# Deploy to Railway
railway up
```

### 2. Deploy GitHub App (Netlify)

```bash
cd guardrails-github-app

# Install dependencies
npm install

# Set environment variables
cp .env.example .env
# Edit .env with your configuration

# Build
npm run build

# Run locally
npm run dev

# Deploy to Netlify
netlify deploy --prod
```

### 3. Create GitHub App

1. Go to GitHub Settings > Developer Settings > GitHub Apps
2. Create a new GitHub App with these permissions:
   - **Repository permissions:**
     - Contents: Read
     - Pull requests: Read & Write
     - Commit statuses: Read & Write
     - Issues: Read & Write
   - **Subscribe to events:**
     - Pull request
     - Push
3. Generate a private key and save it
4. Note the App ID
5. Set webhook URL to your Netlify function: `https://your-app.netlify.app/.netlify/functions/webhook`
6. Set webhook secret and save it

### 4. Configure Environment Variables

**Railway (Backend):**
```
DATABASE_URL=postgresql://...
VERCEL_AI_GATEWAY_API_KEY=your-key
ANTHROPIC_BASE_URL=https://ai-gateway.vercel.sh
SECRET_KEY=your-secret-key
ALLOWED_ORIGINS=https://your-app.netlify.app
```

**Netlify (GitHub App):**
```
GITHUB_APP_ID=your-app-id
# Paste your GitHub App private key (PEM format, downloaded from GitHub App settings)
GITHUB_PRIVATE_KEY="<paste-your-github-app-private-key-here>"
GITHUB_WEBHOOK_SECRET=your-webhook-secret
BACKEND_API_URL=https://your-backend.railway.app
```

## Configuration

Create `.github/guardrails.yaml` in your repository:

```yaml
enforcement_mode: warning  # advisory | warning | blocking

override:
  enabled: true
  approvers: [security-team]

rule_packs:
  - default-security
  - enterprise-standards

security:
  block_threshold: high
  secrets: { enabled: true }
  sql_injection: { enabled: true }

standards:
  naming: { enabled: true }
  logging: { enabled: true, forbid_console_log: true }
  error_handling: { enabled: true, forbid_empty_catch: true }

license:
  allowed: [MIT, Apache-2.0, BSD-3-Clause]
  blocked: [GPL-3.0, AGPL-3.0]

copilot:
  strict_mode: true
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scan` | Full code scan |
| POST | `/api/v1/analyze` | AI-powered analysis |
| POST | `/api/v1/analyze/fix` | Get fix suggestions |
| POST | `/api/v1/license/check` | License compliance |
| GET | `/api/v1/rules` | List rules |
| POST | `/api/v1/rules` | Create custom rule |
| GET | `/api/v1/audit` | Query audit logs |
| GET | `/api/v1/audit/export` | Export logs |
| GET/PUT | `/api/v1/config/{org}/{repo}` | Repository config |

## PR Comment Example

When violations are detected, the GitHub App posts a detailed comment on the PR:

```markdown
## 🛡️ Guardrails Security & Compliance Report

**Scan ID:** `abc123`
**Scanned at:** 2024-01-15T10:30:00Z

---

### 📊 Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟧 High | 1 |
| 🟡 Medium | 3 |
| 🔵 Low | 0 |
| ℹ️ Info | 1 |

**Enforcement Action:** 🚫 Blocked (critical/high issues must be resolved)

---

### 🔴 Critical Issues

<details>
<summary><b>Hardcoded Secret Detected</b> - <code>src/config.ts:15</code></summary>

**Rule:** `SEC-001` | **CWE:** CWE-798

**Why this is an issue:**
Hardcoded credentials can be exposed through source control...

**Suggested Fix:**
Use environment variables or a secrets manager...

</details>

---

<sub>Powered by Topcoder Enterprise Guardrails AI</sub>
```

## Enforcement Modes

| Mode | Behavior |
|------|----------|
| **Advisory** | Informational comments only, no blocking |
| **Warning** | PR annotations and alerts, merge allowed |
| **Blocking** | Prevent merge for critical/high issues (override available) |

## Override Command

When blocking mode is enabled, approved users can override by commenting:

```
/guardrails override <justification>
```

## Rule Packs

| Pack | Description |
|------|-------------|
| `default-security` | Basic security rules (OWASP Top 10) |
| `enterprise-standards` | Coding standards (naming, logging, errors) |
| `healthcare` | HIPAA compliance rules |
| `telecom` | Telecom industry rules |
| `government` | FedRAMP compliance rules |

## Development

### Backend

```bash
cd guardrails-backend

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -r requirements.txt

# Run tests
pytest

# Run with hot reload
uvicorn app.main:app --reload
```

### GitHub App

```bash
cd guardrails-github-app

# Install dependencies
npm install

# Type check
npm run typecheck

# Run tests
npm test

# Run locally with Netlify CLI
npm run dev
```

## Testing

### Test Scan Endpoint

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "code": "const password = \"secret123\";",
    "file_path": "src/config.ts",
    "language": "typescript",
    "diff_only": false,
    "context": {
      "org": "test-org",
      "repo": "test-repo"
    },
    "options": {
      "enable_ai": true,
      "enforcement_mode": "warning"
    }
  }'
```

## Security

- **No Code Retention**: Code is processed in memory only
- **Encrypted Tokens**: All sensitive tokens encrypted at rest
- **Webhook Verification**: GitHub signatures validated
- **HTTPS Only**: All API communication over TLS

## License

This software is proprietary and confidential. Unauthorized copying, distribution, or use of this software is strictly prohibited. All rights reserved by irfanrosandi.
