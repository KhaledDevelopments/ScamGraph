# CI and deployment setup

GitHub Actions runs `.github/workflows/ci.yml` on pull requests, pushes to
`main`, and manual runs from the Actions tab. Python and React checks run
in parallel. Older runs for the same branch are cancelled.

The repository currently contains empty app folders. Until each app has a
dependency manifest, its checks are **skipped**, with a note in the run summary.
A green run at this stage does not mean an application was tested. Adding Python
or JavaScript/TypeScript source without its manifest fails the detection job.

## Proposal alignment

The [project proposal](ScamGraph_Hack_Atlantic_2026_Proposal_and_Plan.pdf)
specifies FastAPI, React + Vite, Tailwind CSS, React Flow, and SQLite initially
(page 6). The main API is `POST /analyze`, accepting a JSON `content` field
(page 8). VirusTotal is the first integration, followed by PhishTank and URLhaus.

This setup supplies development automation for that stack. It does not implement
the application; Phase 0 of the proposal calls for environment preparation before
the hackathon, subject to the competition's rules. Python 3.12 and Node.js 24
are CI defaults chosen here, not versions required by the proposal.

## FastAPI backend contract

- Runtime: Python 3.12 (change `python-version` in the workflow if needed).
- Add `backend/requirements.txt` with pinned dependencies, or a pip-installable
  `backend/pyproject.toml`. If both exist, CI installs `requirements.txt`.
- CI installs Ruff and pytest. Add `backend/requirements-dev.txt` to pin those
  tools and install test plugins or other development dependencies.
- Add tests discoverable by pytest, typically in `backend/tests/`.
- CI runs `python -m ruff check .`, `python -m ruff format --check .`, and
  `python -m pytest` from `backend/`. Missing tests fail the job.
- Configure Ruff/pytest in `backend/pyproject.toml` as needed. Tests should use
  test fixtures and mocks; no production credentials are supplied to CI.
- SQLite needs no separate database service in the workflow. Database tests
  should create an isolated temporary database and clean it up after each test.

## React / Vite frontend contract

- Runtime: Node.js 24, using npm.
- Commit both `frontend/package.json` and `frontend/package-lock.json`.
- Provide `lint`, `test:ci`, and `build` scripts in `package.json`. For Vitest,
  `test:ci` is usually `vitest run`; for Jest, `jest --ci`.
- CI runs `npm ci`, then each of these scripts. Missing scripts, failing tests,
  and dependency/lockfile mismatches fail the job.
- The Vite build must write to `frontend/dist/`. Successful builds
  are available as GitHub Actions artifacts for seven days.
- Browser configuration is public: never put server secrets in frontend build
  environment variables.

## Tests to add with the application

These are planned tests, not tests already implemented by this workflow:

- **Extraction and scoring:** exercise URL/domain/email extraction, heuristic
  evidence, and the agreed score calculation. Check that an unknown URL is not
  automatically classified as safe (proposal pages 4 and 9-10).
- **API contract:** test `POST /analyze` with valid, empty, and malformed input;
  verify the agreed response schema and evidence consumed by the graph.
- **Provider failures:** mock VirusTotal, PhishTank, and URLhaus responses,
  including timeouts, rate limits, and unavailable services. Assert that analysis
  continues using available evidence (page 12). PR checks should not depend on
  live provider uptime, quotas, or credentials.
- **Frontend behavior:** test content submission, loading/error states, risk
  display, graph nodes/edges, and opening evidence by selecting a node.
- **Integration checkpoint:** once the app exists, add a browser test covering
  paste -> Analyze -> score -> graph -> inspect evidence, using mocked provider
  responses. Separately verify at least one real threat API before the demo,
  as required by Phase 7; mocked CI tests do not prove a live integration works.

## Enable the workflow

1. Commit and push the workflow and application files to GitHub.
2. Open **Actions → CI** to inspect the first run.
3. In repository settings, create a ruleset for `main` requiring the
   **CI result** status check before merging (after that check has run once).

Dependabot proposes weekly updates for GitHub Actions. Repository settings
and branch rules have not been changed by this setup.

## Continuous deployment

Deployment is not enabled yet: the hosting provider, deployable applications,
and production configuration have not been selected. CI requires no deployment
secrets. The frontend artifact is a build output, not a live deployment.

Once hosting is chosen, add a deployment job that:

1. Runs only for a push to `main`, after both application check jobs succeed.
2. Uses a GitHub `production` environment with provider credentials stored as
   environment secrets (or uses the provider's supported OIDC authentication).
3. Deploys the exact tested commit/build, with deployment concurrency to prevent
   overlapping production releases.
4. Verifies the backend health endpoint and frontend URL, and reports failure.

The proposal does not select a hosting provider. To finish CD, decide:

- Where to host the FastAPI process and the Vite static build.
- The backend start command for the planned `backend/main.py`, and a health
  endpoint (the proposal specifies `/analyze`, but no health endpoint).
- The frontend's public API URL and the backend's allowed frontend origins.
- Which provider credentials the backend requires; keep threat-intelligence
  keys in backend runtime secrets.
- If SQLite data must survive deployments, its persistent storage location,
  backup approach, and any database initialization/migration command.

If using a host's automatic Git deployment, configure it to wait for CI before
releasing. Optional AI, OCR, history, and campaign detection do not require
additional CI services until those features are implemented.

References: [Python setup](https://github.com/actions/setup-python),
[Node setup](https://github.com/actions/setup-node), and
[build artifacts](https://github.com/actions/upload-artifact).
