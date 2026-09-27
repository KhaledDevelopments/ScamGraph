# ScamGraph backend

The FastAPI backend validates message text, extracts indicators, applies local
language/domain checks, and enriches the first URL through VirusTotal, URLhaus,
Google Safe Browsing, and IPinfo. Gemini optionally explains the recorded
assessment; a local evidence summary works without Gemini. Saving messages and
user accounts are not implemented.

## Local setup

Use Python 3.12 and uv. From the repository root in PowerShell:

```powershell
cd backend
uv venv --python 3.12
uv pip install --python .venv/Scripts/python.exe -r requirements-dev.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

For macOS/Linux:

```sh
cd backend
uv venv --python 3.12
uv pip install --python .venv/bin/python -r requirements-dev.txt
cp .env.example .env
.venv/bin/python -m uvicorn main:app --reload
```

The server runs at `http://127.0.0.1:8000`; interactive API docs are at
`http://127.0.0.1:8000/docs`. The Windows launcher `./start-dev.ps1 -Install`, run
from the repository root, uses port **8001** by default and configures the frontend
to match. See the [frontend setup](../frontend/README.md) for manual startup.

## Optional provider keys

Copy [`.env.example`](.env.example) to `backend/.env` and fill in the keys you want
to use. Do not overwrite an existing `.env` containing your keys. All five values
are optional; local extraction, warning signs, and fallback explanations work
with blank values.

| Variable | Enables |
| --- | --- |
| `VIRUSTOTAL_API_KEY` | Existing URL reports from VirusTotal. |
| `URLHAUS_AUTH_KEY` | Malware URL records from URLhaus. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing threat-list matching. |
| `IPINFO_TOKEN` | IPinfo Lite country and network context. |
| `GEMINI_API_KEY` | Gemini explanations when requested. |

Use a Google project key with the Safe Browsing API enabled for
`GOOGLE_SAFE_BROWSING_API_KEY`, and a Gemini API key for `GEMINI_API_KEY`. Configure
these separately even if you manage them through the same Google account.
URLhaus uses an abuse.ch Auth-Key; IPinfo uses a Lite API token.

The backend loads `.env` at startup independently of the terminal's working
directory. Existing environment variables take precedence. Restart the backend
after changing configuration. `.env` is ignored by Git; credentials remain on
the backend and must never be added to frontend environment variables.

## API and input validation

Send `POST /analyze` with `Content-Type: application/json`:

```json
{"content": "Contact support@example.com or visit https://example.com/login."}
```

The response echoes `content` and includes:

- `indicators`: extracted `urls`, `emails`, and `domains`.
- `threat_intelligence`: `virustotal`, `urlhaus`, `google_safe_browsing`, and
  `ipinfo` result lists, with provider status and available details.
- `assessment`: score, risk level, scope, local findings, and missing evidence.

Send `POST /explain` with the original `content` and the `assessment` and
`indicators` returned by `/analyze`. This endpoint explains the supplied
assessment; it does not rerun the checks. The response contains `explanation`,
`status: "ok"`, and `source: "gemini"` or `source: "fallback"`.

Both endpoints require `content` to be a string containing non-whitespace text
and at most **20,000 characters**. Invalid input returns HTTP 422 with a `detail`
list. Accepted content is preserved, including whitespace. The content limit
does not constitute a general HTTP body-size or request-rate limit.

The extractor handles explicit `http://` and `https://` URLs and common ASCII
email addresses. It lowercases domains, preserves subdomains, removes duplicates
in first-seen order, and trims common trailing prose punctuation. It does not
visit links. Bare domains, scheme-less `www.` links, defanged links such as
`hxxps://`, and unusual email formats are outside its current scope. IP-based URLs
are included in `urls`, but their IP addresses are not listed as domains.

Browser requests are allowed from `http://localhost:5173` and
`http://127.0.0.1:5173`. Update `allow_origins` in `main.py` when deploying the
frontend elsewhere. CORS does not provide authentication. The prototype has no
application-wide request limit; provider-specific limits below are per process.

## Provider behavior and privacy

Only the first unique extracted URL receives provider checks. Remaining URLs
have status `skipped`. The backend does not visit submitted URLs, download their
content, or submit them for a new VirusTotal scan.

- **VirusTotal** receives the selected URL encoded as its report identifier.
  Existing reports contain malicious, suspicious, harmless, and undetected
  vendor counts. HTTP 404 means no report, not a clean verdict. Requests time out
  after five seconds. The implementation permits four outbound requests per
  rolling minute and applies a cooldown after HTTP 429.
- **URLhaus** receives the selected URL for an existing malware-record lookup.
  A valid listing counts as malicious even when the recorded URL is offline.
  `no_results` means not listed, not safe. Requests time out after five seconds.
- **Google Safe Browsing** receives the selected URL through the v4
  `threatMatches:find` endpoint. Valid threat matches set `flagged: true` and list
  their threat types. An empty response object or empty `matches` list is a
  checked negative; malformed responses remain unknown. Requests time out after
  five seconds.
- **IPinfo** supplies country, ASN, network owner, and network domain for one
  public IP. For a domain, Cloudflare's public DNS-over-HTTPS resolver receives
  its hostname; the backend tries A records and then AAAA. IPinfo receives the
  selected public IP. Literal public IPs skip DNS, and private/local IPs are not
  sent to IPinfo. No DNS or IPinfo request is made without `IPINFO_TOKEN`.
  Each request has a five-second timeout; one lookup may require two DNS
  requests and one IPinfo request. This is network context, not IP reputation,
  and adds no risk points.

Successful reputation results and misses are cached for 15 minutes with a
128-entry limit per provider. IPinfo caches successful enrichment results with
the same lifetime and limit. HTTP 429 starts a cooldown of at least 60 seconds.
Missing keys, failures, rate limits, and skipped checks remain unknown rather
than fabricated negative findings. Common statuses are `ok`, `not_found`,
`not_configured`, `unavailable`, `rate_limited`, and `skipped`; IPinfo also uses
`non_public` and `unresolved`.

**Gemini receives the full message, assessment, and extracted indicators when
the user requests an explanation and `GEMINI_API_KEY` is configured.** The backend
currently uses `gemini-flash-lite-latest` with an eight-second timeout. Its prompt
asks for an evidence-grounded explanation that preserves uncertainty and the
first-URL scope. A generated explanation can still be mistaken; the structured
assessment remains the record of the checks.

Without a key, or after a failed/invalid Gemini response, a deterministic local
summary describes the recorded findings and missing checks. The response's
`source` distinguishes the two. Successful Gemini explanations are cached for
**900 seconds**, up to **128 entries**, keyed by the exact message, complete
assessment, indicators, and credential identity. Changed evidence invalidates a
previous explanation. Fallback text is not cached, allowing a recovered provider
to be retried on the next request.

All caches and cooldowns live in backend process memory and reset on restart.
Use one worker for this prototype; multiple workers would need shared limits
and caching. Provider-side quotas and data handling still apply to outbound
requests. Avoid using private messages or sensitive URL query parameters in a
demo intended for external services.

## Risk assessment

Local checks run without API keys. They flag English urgency/account threats
(+5), credential/sign-in requests (+10), and an explicit UNB mention paired with
a first URL outside `unb.ca` and its subdomains (+15). URLs and email addresses
are excluded from language matching; common negations are suppressed. These
phrase rules do not understand all context, and other organizations are not yet
checked. Findings appear in `assessment.heuristic_findings`.

Provider evidence contributes:

| Evidence | Points |
| --- | --- |
| VirusTotal malicious verdict or URLhaus malware listing | +35, once even when both match |
| At least three malicious VirusTotal verdicts | +20 |
| Google Safe Browsing threat match | +20 |

Each rule contributes at most once; the additive score is capped at 100. Ordinary
bands are LOW (0-24), SUSPICIOUS (25-49), HIGH (50-74), and CRITICAL (75-100).
**Any explicit VirusTotal, URLhaus, or Google Safe Browsing threat match sets a
minimum HIGH level.** The numeric score and breakdown remain additive; when this
changes the ordinary band, `risk_level_reason` and `assessment_note` explain why.
A Google-only match therefore displays **20/100, HIGH**, with its reason.

`assessment_status` is `unavailable`, `partial`, or `complete`. The frontend
displays unknown risk instead of a LOW/zero verdict when no assessment is
available. Missing checks add no points and remain `null` in `evidence`.
Domain age, suspicious-IP reputation, and malicious-relationship evidence have
no connected providers yet, so current live assessments remain partial or
unavailable. IPinfo does not populate suspicious-IP reputation. Client-supplied
evidence is ignored by `/analyze`; a zero score or checked negative does not
establish safety.

## Local checks

From `backend/` in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pytest
```

On macOS/Linux, replace `.\.venv\Scripts\python.exe` with `.venv/bin/python`.
Tests isolate credentials and use mocked HTTP responses. They cover input
validation, extraction, provider parsing and failures, caching, cooldowns,
scoring overrides, and explanation fallbacks. Passing these tests does not
verify live credentials, provider availability, or quota.
