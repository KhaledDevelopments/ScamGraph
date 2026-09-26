# ScamGraph backend

The backend currently receives and validates user input. It does not perform
scam analysis, call threat APIs, or save messages yet.

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
{"content": "Your account has been suspended..."}
```

The response is HTTP 200:

```json
{
  "message": "Content received",
  "content": "Your account has been suspended..."
}
```

`content` must be a non-empty string containing at least one non-whitespace
character. Invalid input returns HTTP 422 with a `detail` list describing the
validation errors. Accepted content is returned unchanged, including whitespace.

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
