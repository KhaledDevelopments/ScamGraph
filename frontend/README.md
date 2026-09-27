# ScamGraph frontend

React, Vite, and React Flow provide the message input, evidence-based risk summary,
interactive graph, provider details, and optional plain-English explanation.
See the [project README](../README.md) for the demo and current limitations.

## Local setup

Use Node.js 22.12+ or Node.js 24 and npm. Start the
[backend](../backend/README.md) in another terminal, then run these commands from
the repository root in PowerShell:

```powershell
cd frontend
npm ci
Copy-Item .env.example .env
npm run dev -- --port 5173 --strictPort
```

On macOS/Linux, use `cp .env.example .env` in place of `Copy-Item`; the npm
commands are the same. Open `http://localhost:5173`.

The example environment file sets `VITE_API_BASE_URL=http://127.0.0.1:8000` for a
manually started backend. Without that variable, the application defaults to
`http://localhost:8000`. Restart Vite after changing `.env`.

Alternatively, run `./start-dev.ps1 -Install` from the repository root on Windows.
That launcher starts the backend on **8001** by default and sets the frontend's
API address to the same port automatically. Its `-BackendPort` option changes both.

Provider credentials belong in `backend/.env`. Never put secrets in a `VITE_`
variable: Vite embeds those values in the browser bundle.

## Using the interface

Paste a message or select a preset, then select **Analyze**. Input must contain
non-whitespace text and stay within 20,000 characters. The graph shows extracted
URLs, emails, domains, and provider evidence; select a node to inspect its details.
Local language checks cover the message, while provider checks cover only its
first extracted URL. Remaining URLs are marked as skipped.

Unavailable checks remain unknown. A low score is not a guarantee of safety.
Explicit threat matches receive at least a HIGH risk level, and the summary
explains when that level overrides the ordinary score band. Changing the input
or preset clears the previous results and cancels pending analysis/explanation
requests so late responses cannot appear under another message.

**Explain this in plain English** requests an explanation from the backend. When
Gemini is configured, this can send the full message, assessment, and extracted
indicators to Google. Otherwise, or if Gemini fails, the backend returns a local
evidence summary identified as a fallback in the interface.

## Checks and production build

From `frontend/`:

```powershell
npm test
npm run lint
npm run build
npm run preview
```

The tests exercise request cancellation, stale response handling, and input/error
validation without calling a live API. `npm run build` produces the static site
in `dist/`; `npm run preview` serves that build locally for inspection.

Set `VITE_API_BASE_URL` to the deployed API address **before building**. The backend
must separately allow the deployed frontend origin in its CORS configuration in
`backend/main.py`. The current allowlist includes only `http://localhost:5173`
and `http://127.0.0.1:5173`; the preview server's origin needs an explicit entry
if you want to call the API from it. Serve both frontend and API over HTTPS in a
hosted deployment. CORS is a browser access rule, not authentication; the current
prototype does not implement user accounts or application-wide rate limiting.
