# ScamGraph
ScamGraph helps people inspect suspicious messages and links. It extracts URLs,
email addresses, and domains, checks available threat intelligence, and connects
the evidence in an interactive graph. Each assessment explains its warning signs
and what remains unknown.

Built for Hack Atlantic 2026 with React, React Flow, Tailwind CSS, and FastAPI.

## Features

- Local checks for urgency, requests for credentials, and mismatched UNB domains.
- First-URL lookups with VirusTotal, URLhaus, and Google Safe Browsing.
- IPinfo network context and clickable evidence nodes.
- Optional Gemini explanations with a clearly labelled local fallback.
- Visible uncertainty: missing checks and zero scores never establish safety.

## Getting Started

### Windows

To start the frontend and backend on Windows, install Node.js 22.12+ (or 24) and uv, then run
this from the project folder in PowerShell:

```powershell
# Optional: create the provider configuration if you do not already have one.
if (-not (Test-Path backend/.env)) { Copy-Item backend/.env.example backend/.env }

powershell -NoProfile -ExecutionPolicy Bypass -File .\start-dev.ps1
```

The script creates the backend Python environment, installs backend dependencies,
and installs frontend dependencies on the first run. It opens a terminal for
each server. Once Vite is ready, visit http://localhost:5173. Stop both servers
with Ctrl+C in their terminals. Add `-Install` to the command to reinstall frontend
dependencies after they change. Backend dependencies are checked on every run.

The launcher uses backend port 8001 and sets the frontend API address to match.
API docs are at http://127.0.0.1:8001/docs. If that port is occupied, add
`-BackendPort 8002` to the launch command. Restart both servers when changing ports.

### macOS & Linux

Install Node.js 22.12+ (or 24) and uv (or python 3.12+), then run the backend and frontend in separate terminals:

```bash
# Terminal 1 — Backend
cd backend
uv venv && uv pip install -r requirements-dev.txt
[ ! -f .env ] && cp .env.example .env
.venv/bin/uvicorn main:app --reload --host 127.0.0.1 --port 8001

# Terminal 2 — Frontend
cd frontend
npm ci
VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev -- --port 5173
```

Open http://localhost:5173 in your browser. API docs are at http://127.0.0.1:8001/docs.

See the [backend guide](backend/README.md) and [frontend guide](frontend/README.md)
for further details.

## Optional provider keys

Put keys in `backend/.env`, using [backend/.env.example](backend/.env.example) as
the template. Restart the backend after changing them. Never put provider keys
in frontend variables or commit actual keys.

| Variable | Purpose |
| --- | --- |
| `VIRUSTOTAL_API_KEY` | Existing URL reports and vendor verdicts |
| `URLHAUS_AUTH_KEY` | Known malware URL listings |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google's unsafe URL lists |
| `IPINFO_TOKEN` | Country, ASN, and network owner context |
| `GEMINI_API_KEY` | Optional generated explanation |

All keys are optional. Without them, local checks and local explanations still
work, and provider nodes report that their checks were not configured.

## Demo walkthrough

1. Select **UNB Phish**, then **Analyze**. Inspect the local warning signs and
   click a URL or provider node to see its evidence.
2. Select **Official UNB** and analyze again. Explain that fewer warning signs do
   not establish safety, especially when provider checks are unavailable.
3. Select **Google Safe Browsing & VT Hit** with provider keys configured. Results
   depend on current records and availability; any explicit provider threat
   match sets a minimum HIGH verdict, with a reason shown alongside the score.
4. Click **Explain this in plain English**. Without Gemini, a labelled local
   explanation still describes the evidence and uncertainty.

Presets fill the input; they do not visit their links. Do not open suspicious
URLs during the demo. Absent records and provider rate limits remain visible
instead of being replaced with fabricated results.

## Scope and data handling

- Local English phrase checks cover the message. Provider lookups and organization
  comparison cover only the **first extracted URL**; additional URLs are skipped.
- Extraction supports explicit HTTP(S) links and common ASCII email addresses.
  Standalone domains and defanged links are not supported.
- Scores are evidence points, not probabilities. Explicit threat matches can
  raise the verdict above the score's usual band, with an explanation.
- IPinfo is context, not reputation. Domain age, IP reputation, and cross-message
  relationships are not implemented, so assessments remain partial or unavailable.
- Input is limited to 20,000 characters. No message database is used. Provider
  and successful explanation caches are bounded and held in memory.
- Reputation providers receive the selected URL; IP enrichment uses DNS and a
  public IP lookup. Clicking Explain sends the message and assessment to Gemini
  if its key is configured. Avoid including private or sensitive information.
- Public hosting still needs access controls, request-rate/body-size limits,
  shared provider quotas, and deployment-specific API/CORS configuration.

## Checks

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
cd ../frontend
npm test
npm run lint
npm run build
```

Backend tests use mocked responses and fake keys. Frontend tests cover pending
requests and resets without calling the backend or external APIs.
