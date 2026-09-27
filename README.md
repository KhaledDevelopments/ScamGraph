# ScamGraph
Hackathon-2026/27-Project

To start the frontend and backend on Windows, install Node.js and uv, then run
this from the project folder in PowerShell:

```powershell
If uv needs download: powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

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

See the [backend guide](backend/README.md) to run FastAPI locally and try
`POST /analyze`.
