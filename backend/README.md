# ScamGraph backend

The backend receives and validates user input, then extracts URLs, email
addresses, and domains. Risk scoring, threat API calls, and saving messages
are not implemented yet.

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

## Receive a message

Send `POST /analyze` with `Content-Type: application/json` and this body:

```json
{"content": "Contact support@example.com or visit https://example.com/login."}
```

The response is HTTP 200:

```json
{
  "message": "Content received",
  "content": "Contact support@example.com or visit https://example.com/login.",
  "indicators": {
    "emails": ["support@example.com"],
    "urls": ["https://example.com/login"],
    "domains": ["example.com"]
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

## Optional local checks

From `backend/`:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pytest
```
