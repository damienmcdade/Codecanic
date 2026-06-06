# Codecanic

Codecanic is an MVP for a free code operations platform that scans user repositories and infrastructure, generates prioritized reports, and lets users approve all repairs or selected repair segments. Codecanic is free for everyone and supported by sponsor ads.

## MVP Scope

- Connectors for GitHub, Vercel, Railway, Xcode projects, GitLab, and Bitbucket.
- Full infrastructure scan flow for repos, deployments, package managers, secrets, dependencies, and build settings.
- Reviewable findings report with severity, target, repair description, and approval controls.
- Selective repair approval for all findings or focused segments such as security and performance.
- Free for everyone with sponsor slots; every workspace gets the same priority scan and repair queue.
- PWA-ready web interface that can be wrapped for iOS and Android distribution.
- Deployable API endpoints for connector authorization handoff, scan reports, and repair queues.

## Product Architecture

The production version should separate the interface from trusted backend workers:

- Web app and mobile shell: dashboard, onboarding, connector authorization, reports, repair approvals.
- API service: users, organizations, connectors, audit logs, repair policies.
- Scan workers: repo checkout, dependency analysis, static checks, secret scanning, deployment checks, infrastructure inventory.
- Repair workers: deterministic autofixes, AI-assisted patches, validation reruns, pull request creation.
- Integrations: GitHub App, Vercel OAuth/API, Railway API, GitLab, Bitbucket, Xcode project import.

## Local Run

```bash
npm run dev
```

## Operating Endpoints

- `POST /api/auth/signup` creates a user, provisions a personal workspace, and sets a signed session cookie.
- `POST /api/auth/login` authenticates an existing user and returns their organizations.
- `POST /api/auth/logout` invalidates the active session.
- `GET /api/auth/me` returns the current user + memberships (incl. `emailVerified`), or `{ user: null }` for guests.
- `GET|POST /api/auth/verify-email?token=...` confirms an email (GET renders a page for the email link; POST is JSON).
- `POST /api/auth/resend-verification` re-issues a verification email for the signed-in user.
- `POST /api/auth/request-password-reset` sends a reset link (always a generic 200, to prevent account enumeration).
- `POST /api/auth/reset-password` consumes a reset token, sets a new password, and invalidates all existing sessions.
- `GET /api/orgs` lists organizations the signed-in user belongs to.
- `POST /api/orgs` creates a new organization owned by the signed-in user.
- `GET /api/connectors?name=GitHub` returns connector authorization status; when the matching client ID is set and the user is signed in, it returns a one-time signed OAuth URL.
- `GET /api/oauth/callback?provider=...&code=...&state=...` is the redirect target; it verifies the signed state, exchanges the code for an access token, and persists credentials scoped to the active organization.
- `GET /api/oauth/status` lists provider connections for the active organization.
- `GET /api/health` returns deployment identity for Vercel/Railway sync checks.
- `POST /api/scan` **enqueues** a scan job (`202` + `{ jobId, pollUrl }`); a background worker runs the real v1 scan engine against `sourceUrl` (an `https://github.com|gitlab.com|bitbucket.org/owner/repo` URL): it shallow-clones the repo (using the organization's connected provider token for private repos), then returns a prioritized report. Requires `Cookie: codecanic_session=...` and either an `X-Codecanic-Org` header or `?organization=` query. The endpoint validates the URL synchronously — unsupported hosts/malformed URLs return `400` up front (no job is queued, no fabricated findings). A private repo with no connected provider isn't rejected here; it **fails the job** with an access error visible via the poll URL (`GET /api/jobs/<id>` → `status: "failed"`), so the failure is honest rather than faked.
- `POST /api/repair` takes a `reportId` (from a prior scan) + approved `findingIds`. It runs **synchronous validation** (report/findings exist, repo is GitHub, token present — `404`/`400`/`422` as appropriate), then **enqueues** a repair job (`202` + `{ jobId, pollUrl }`). The worker clones the repo with the org's GitHub token, applies deterministic safe patches, commits, pushes a branch, and **opens a real pull request**. Findings that can't be auto-fixed safely are listed in the PR body as manual action items.
- `GET /api/jobs/<id>` returns a job's `status` (`queued`/`running`/`succeeded`/`failed`) and, when finished, its `result` (the scan report or repair outcome) or `error`. `GET /api/jobs` lists the org's recent jobs.
- `GET /api/suppressions` lists the org's suppressed finding fingerprints; `POST` suppresses a `fingerprint` (with optional `reason`); `DELETE` un-suppresses it. Suppressed findings are hidden from future scan reports.
- `GET /api/billing` returns the org's plan, entitlements, monthly scan usage/limit, and whether Stripe is configured. `POST /api/billing/checkout` starts a Stripe Checkout session for the Pro upgrade (or reports `configured:false`). `POST /api/billing/webhook` is the Stripe-signed endpoint that applies plan changes (with timestamp-tolerance replay protection).

### Repair engine (v1)

`api/_repair.js` turns approved findings into patches. Auto-fixed safely:

- **Vulnerable npm deps** — direct deps bumped to the OSV-reported fixed version in `package.json`; transitive deps pinned via `overrides` (the PR body notes that the lockfile must be refreshed with `npm install`).
- **TypeScript `strict`** — flipped to `true`.
- **Committed `.env`** — added to `.gitignore` and removed from the tree.
- **Missing CI** — a baseline GitHub Actions workflow is added.

Left as **manual action items** (never auto-edited): secrets in code, committed keys, `.npmrc` tokens, missing lockfile — because auto-editing these risks breakage or mishandling credentials.

Every dependency bump carries a **merge-confidence** signal classified by semver delta (🟢 patch / 🟡 minor / 🔴 major), surfaced in the PR body and as a 0–100 `confidenceScore` in the API response. Validation itself is delegated to the user's CI (the PR triggers it) — running the repo's code on Codecanic's servers would be unsafe. Patch planning/application + confidence scoring are proven by `npm run test:repair`.

### Scan engine (v1)

`api/_scanner.js` performs genuine analysis of the cloned tree:

- **Dependency SCA** — parses `package-lock.json` / `yarn.lock` / `package.json` (npm) and `requirements.txt` (PyPI), then queries [OSV.dev](https://osv.dev) for known vulnerabilities (real CVEs, severity, references).
- **SAST** — Semgrep-style real-vulnerability patterns for JS/TS + Python (eval/`new Function`, command injection via `exec()`, SQL string concat, weak hashes, `dangerouslySetInnerHTML`, `yaml.load` RCE, `pickle`, `subprocess(shell=True)`, `os.system`, TLS `verify=False`). Safe line-local fixes (md5→sha256, `yaml.load`→`safe_load`, `verify=False`→`True`) become auto-fix PRs; risky ones stay manual.
- **Supply-chain / malware signals** — typosquat detection (Damerau-Levenshtein vs a popular-package list, catching transpositions) and non-registry (git/http/file) dependency sources.
- **Secret scanning** — gitleaks-style regex + entropy over text files; matches are redacted and `.example`/`.sample` files ignored.
- **Repo hygiene** — committed `.env`/key files, `.npmrc` tokens, TypeScript `strict` off, missing lockfile, missing CI.
- **Noise control** — findings carry a stable fingerprint; orgs can suppress findings (`/api/suppressions`), hidden from future scans.

Bounded for safety: https-only SSRF-allowlisted hosts, shallow `--depth 1` clone with a timeout, file/size/finding caps, and the temp checkout is always deleted. Proven by `npm run test:scanner`.

Copy `.env.example` into your deployment environment and fill in the provider credentials owned by your company. Each OAuth-capable provider needs both `*_CLIENT_ID` and `*_CLIENT_SECRET`; sessions are signed with `CODECANIC_SESSION_SECRET`.

## Data layer

Codecanic uses **Postgres** via a small relational schema (`api/_db.js` + `api/_repo.js`): `users`, `organizations`, `memberships`, `sessions`, `connector_creds`, `reports` — with unique constraints, foreign keys, indexes, and `ON DELETE CASCADE`. All SQL lives in `api/_repo.js`; handlers call typed functions.

- **Production:** set `DATABASE_URL` to a managed Postgres (Railway Postgres / Neon / Supabase). The driver uses a connection pool and TLS, and `server.js` drains the pool on `SIGTERM`.
- **Local/dev/test:** with no `DATABASE_URL`, the app runs **embedded Postgres ([PGlite](https://pglite.dev), real Postgres in WASM)** persisted under `${CODECANIC_DATA_DIR}/pgdata` — the *same SQL* runs in both, so tests need no database server.

Durability across restarts, unique constraints, and cascading integrity are proven by `npm run test:db`.

## Access model & plans

- **GitHub App (preferred):** when `GITHUB_APP_ID` + `GITHUB_APP_PRIVATE_KEY` are set, orgs install a least-privilege GitHub App (per-repo, short-lived tokens) via `/api/oauth/github-app`; scans/repairs mint installation tokens. **Your code is never stored** — the temp clone is deleted after every scan. Falls back to OAuth when the App isn't configured.
- **Plans:** Codecanic stays **free + ad-supported** (Google AdSense). **Pro** is an optional paid upgrade (ad-free, unlimited scans) via Stripe — Free is capped at 50 scans/month. `/api/billing` reports plan/usage; `/api/billing/checkout` starts the upgrade (reports "not configured" without Stripe keys); `/api/billing/webhook` (Stripe-signed) flips the org plan.

## Authentication

- **Passwords** are hashed with scrypt at a raised cost (`N=65536, r=8, p=1`), with the parameters encoded in each stored hash. Legacy hashes still verify and are transparently re-hashed to the new cost on the next successful login.
- **Login throttling** is DB-backed (`login_attempts`): 5 failures per IP+email lock for 15 minutes. Unlike the previous in-memory counter, this survives restarts and works across replicas.
- **Email verification** — signups create a single-use, 24h token (only its SHA-256 is stored); scanning/repair are gated on a verified email. Enforced when an email provider is configured or `CODECANIC_REQUIRE_EMAIL_VERIFICATION=1`; otherwise signups are auto-verified.
- **Password reset** — single-use 1h token, generic responses (no account enumeration), and **all sessions are invalidated** on reset.
- **Email delivery** is pluggable (`api/_email.js`): Resend when `RESEND_API_KEY` is set, otherwise logged in dev. Tokens are returned in API responses **only** in non-production, so flows are testable without a provider.

Proven by `npm run test:auth` (hashing upgrade, DB lockout incl. restart-persistence, single-use token lifecycle) and the end-to-end `npm run e2e` (verification gate, lockout, full reset flow).

The web UI surfaces these: an **email-verification banner** with a resend button, a **"Forgot password?"** link, and a **`/reset-password`** page wired to the reset endpoint.

## Observability

- **Structured logging** (`api/_log.js`): one JSON object per request — method, pathname, status, duration, and a per-request id (also returned as the `X-Request-Id` header). The query string and request bodies are never logged, and secret-ish fields are redacted, so tokens/passwords can't leak into logs.
- **Error tracking** (`api/_observability.js`): set `SENTRY_DSN` to report exceptions (handler errors, unhandled rejections, uncaught exceptions) to Sentry; it's a safe no-op when unset. `server.js` flushes Sentry on shutdown.

Proven by `npm run test:obs` (log formatting, redaction, request-id shape, no-op capture).

## Background jobs

Scans and repairs run asynchronously so a long clone/scan/PR never blocks the request or hits a proxy timeout. `POST /api/scan` and `POST /api/repair` validate synchronously, then enqueue a row in the `jobs` table and return `202` + a `jobId`. An **in-process worker** (`api/_worker.js`, started by `server.js`) claims jobs with `SELECT … FOR UPDATE SKIP LOCKED` — so it's safe to run multiple replicas — executes the work (`api/_jobs.js`), and writes the result/error back. Jobs left `running` by a crashed worker are automatically re-queued. The web UI polls `/api/jobs/<id>` until the job finishes. Set `CODECANIC_DISABLE_WORKER=1` to run a dedicated worker process instead of the in-process one.

Proven by `npm run test:queue` (enqueue, claim-exactly-once, complete/fail, org scoping, stale requeue, executor error handling) and the e2e (real async scan → poll → report).

## Deployment Targets

- Vercel: static web deployment is ready through `vercel.json`.
- Railway: `railway.json` is included for hosting the current static MVP or future API/worker services.
- GitHub: initialize a repo and push once GitHub authentication is active.
- iOS/Android: Capacitor shells are integrated (`capacitor.config.json`, `android/`, `ios/`). They load the live `https://codecanic.app` site in a native WebView; build a signed Android AAB/APK with `npx cap sync android && (cd android && ./gradlew bundleRelease)`. See [MOBILE_DEPLOY.md](MOBILE_DEPLOY.md).

## Next Build Steps

1. ~~Add authentication and organization workspaces.~~ ✓ Session cookies + relational user/org/membership store.
2. ~~Implement real connector OAuth flows.~~ ✓ Signed-state authorization URL → `/api/oauth/callback` → provider-specific token exchange (GitHub, Vercel, GitLab, Bitbucket); per-org credentials persisted (encrypted at rest).
3. ~~Build a real scan engine.~~ ✓ v1 clones the repo and runs real dependency SCA (OSV.dev), secret scanning, and hygiene checks (`api/_scanner.js`).
4. ~~Make repair real.~~ ✓ v1 generates patches and opens a real GitHub pull request, with manual items in the PR body (`api/_repair.js`). Next: rerun validation/tests on the patched branch and add CI-based merge-confidence before proposing.
5. ~~Migrate the datastore to Postgres.~~ ✓ Relational schema with cascades + indexes; `pg` in prod, embedded PGlite locally (`api/_db.js`, `api/_repo.js`).
6. ~~Auth hardening.~~ ✓ Email verification, password reset, raised scrypt cost (with transparent upgrade), and DB-backed login lockout. Pluggable email via Resend (`api/_email.js`).
7. ~~Observability + frontend auth pages.~~ ✓ Structured JSON logging with request ids, Sentry error tracking (`api/_log.js`, `api/_observability.js`), and the verify-banner / forgot-password / reset-password UI.
8. ~~Async scan/repair job queues.~~ ✓ DB-backed queue + in-process worker (`api/_worker.js`, `api/_jobs.js`); endpoints return `202` + `jobId`, the UI polls `/api/jobs/<id>`.
9. ~~Add mobile packaging with Capacitor for iOS and Android.~~ ✓ Capacitor iOS + Android WebView shells point at `https://codecanic.app`; signed Android AAB/APK build documented in [MOBILE_DEPLOY.md](MOBILE_DEPLOY.md).
