# ScamGraph backend

The backend receives and validates user input, then extracts URLs, email
addresses, and domains. It retrieves an existing VirusTotal report for the
first extracted URL and scores the available evidence. Saving messages is not
implemented yet.

## Local setup (PowerShell)

From the repository root, using uv:

```powershell
cd backend
uv venv --python 3.12
uv pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

The development server runs at `http://127.0.0.1:8000`. Open
`http://127.0.0.1:8000/docs` to send requests using the interactive API docs.

## API keys

Store local provider keys in `backend/.env`. Create that file if needed and
set `VIRUSTOTAL_API_KEY` to your VirusTotal key. The `.env` is ignored by Git.
Each developer running the backend needs their own local `.env`. Use personal
API keys or share a permitted team key privately through a password manager.

The app loads this file at startup using `python-dotenv`, regardless of the
terminal's working directory. Existing environment variables take precedence
over values in the file. Restart the server after changing your keys.

The VirusTotal service reads `VIRUSTOTAL_API_KEY` from the environment.
Input extraction works without keys; in that case the provider result is
`not_configured`. The other provider integrations are not implemented yet.

## Receive a message

Send `POST /analyze` with `Content-Type: application/json` and this body:

```json
{"content": "Contact support@example.com or visit https://example.com/login."}
```

For example, without a VirusTotal key the response is HTTP 200. The extraction
and provider portion is shown below; the response also includes `assessment`
as described in the scoring section:

```json
{
  "message": "Content received",
  "content": "Contact support@example.com or visit https://example.com/login.",
  "indicators": {
    "emails": ["support@example.com"],
    "urls": ["https://example.com/login"],
    "domains": ["example.com"]
  },
  "threat_intelligence": {
    "virustotal": [
      {
        "provider": "virustotal",
        "indicator": "https://example.com/login",
        "status": "not_configured",
        "stats": null,
        "last_analysis_date": null
      }
    ]
  }
}
```

`content` must be a non-empty string containing at least one non-whitespace
character. Invalid input returns HTTP 422 with a `detail` list describing the
validation errors. Accepted content is returned unchanged, including whitespace.

`analyzer/extractor.py` scans the text locally; it does not visit links or resolve
domains. It handles explicit `http://` and `https://` links and common ASCII
email addresses. Domains come from URL hostnames and email addresses, with
subdomains preserved and domain names lowercased. Duplicates are removed in
first-seen order; URLs and email local parts retain their original case. IP-based
links are included in `urls`, but their IP addresses are not listed as domains.

This prototype skips unparseable URLs and strips common trailing prose
punctuation. It does not validate that a URL exists or is safe. Standalone
domains, `www.` links without a scheme, defanged links such as `hxxps://`, and
unusual email formats are outside its current scope. Trailing punctuation is
ambiguous in plain text; a URL intentionally ending in punctuation may be
trimmed. Empty matches produce empty lists, not a safe/unsafe verdict.

For browser requests, the backend allows the local Vite origins
`http://localhost:5173` and `http://127.0.0.1:5173`. Update `allow_origins` in
`main.py` when the frontend uses a different address. CORS controls browser
access; it is not authentication.

## VirusTotal reports

`providers/virustotal.py` calls the fixed VirusTotal API endpoint to retrieve an
existing report. It sends only the selected URL (encoded as an identifier), not
the full submitted message. It does not visit the suspicious URL or submit it
for a new scan. The API key stays in the backend request header.

Every result identifies the URL and provider, with one of these statuses:

| Status | Meaning |
| --- | --- |
| `ok` | Valid report; `stats` contains malicious, suspicious, harmless, and undetected counts. |
| `not_found` | VirusTotal has no report (HTTP 404). |
| `rate_limited` | The local rate budget or VirusTotal quota was reached. |
| `unavailable` | Timeout, network failure, invalid credentials, malformed report, or another provider error. |
| `not_configured` | The backend has no nonblank VirusTotal key. |
| `skipped` | This URL was not checked because only the first unique URL is checked per message. |

`last_analysis_date` is the report's Unix timestamp when provided. Failed and
skipped lookups have `stats: null`, not fabricated zero counts. Neither missing
evidence nor zero detections establishes that a URL is safe.

The HTTP timeout is five seconds, with no automatic retries or redirects.
Successful reports and 404 results are cached for 15 minutes (up to 128 entries).
The service permits four outbound requests per rolling minute across incoming
requests, and pauses uncached lookups for at least a minute after a provider 429.
Cached reports are still available during a cooldown.

These limits and the cache are in memory: use one backend worker for this
prototype. Restarting clears them; multiple workers or deployments would need
shared storage for limits. VirusTotal enforces the key's overall quotas,
including calls made by other apps. Its public API allows 4 requests/minute and
500/day and is restricted to noncommercial use. A daily quota error may continue
after the local cooldown expires.

References: [URL reports](https://docs.virustotal.com/reference/url-info),
[API limits](https://docs.virustotal.com/reference/public-vs-premium-api).

## Risk assessment

`services/analysis.py` connects extraction, provider lookup, and scoring. The
response preserves `indicators` and `threat_intelligence` and adds `assessment`:

- `risk_score`: evidence points from 0 to 100, not a probability.
- `risk_level`: LOW (0–24), SUSPICIOUS (25–49), HIGH (50–74), CRITICAL (75–100).
- `assessment_status`: unavailable, partial, or complete.
- `assessed_url` and `scope`: only the first extracted URL is assessed.
- `indicators`: scoring explanations, separate from top-level extracted indicators.
- `evidence`, `missing_evidence`, `score_breakdown`, and `assessment_note`:
  details of what was checked and what remains unknown.

VirusTotal contributes 35 points for at least one malicious verdict and 20 more
for at least three malicious verdicts. The other scoring rules are prepared but
their providers are not connected, so live assessments are currently partial
or unavailable. Missing checks remain `null`; client-supplied evidence is not
used. A zero score does not establish safety. The frontend hides the numeric
score and LOW label when the assessment is unavailable, and displays the scope
and missing evidence for partial results. Other URLs are explicitly skipped.

## Optional local checks

From `backend/`:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pytest
```

Tests use fake keys and mocked HTTP responses; they do not use your `.env` keys
or consume provider quota. They cover report parsing, API errors, timeouts,
caching, concurrent rate limiting, and the `/analyze` response.
