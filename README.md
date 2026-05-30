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
- `GET /api/auth/me` returns the current user + memberships, or `{ user: null }` for guests.
- `GET /api/orgs` lists organizations the signed-in user belongs to.
- `POST /api/orgs` creates a new organization owned by the signed-in user.
- `GET /api/connectors?name=GitHub` returns connector authorization status; when the matching client ID is set and the user is signed in, it returns a one-time signed OAuth URL.
- `GET /api/oauth/callback?provider=...&code=...&state=...` is the redirect target; it verifies the signed state, exchanges the code for an access token, and persists credentials scoped to the active organization.
- `GET /api/oauth/status` lists provider connections for the active organization.
- `GET /api/health` returns deployment identity for Vercel/Railway sync checks.
- `POST /api/scan` runs the **real v1 scan engine** against `sourceUrl` (an `https://github.com|gitlab.com|bitbucket.org/owner/repo` URL): it shallow-clones the repo (using the organization's connected provider token for private repos), then returns a prioritized report. Requires `Cookie: codecanic_session=...` and either an `X-Codecanic-Org` header or `?organization=` query. Private repos with no connected provider return `422` (not fabricated findings); unsupported hosts/URLs return `400`.
- `POST /api/repair` takes a `reportId` (from a prior scan) + approved `findingIds`, and **opens a real GitHub pull request**: it clones the repo with the org's GitHub token, applies deterministic safe patches, commits, pushes a branch, and creates the PR. Findings that can't be auto-fixed safely are listed in the PR body as manual action items. Returns `422` (no fabricated PR) when GitHub isn't connected or the repo isn't on GitHub; `404` for an unknown report.

### Repair engine (v1)

`api/_repair.js` turns approved findings into patches. Auto-fixed safely:

- **Vulnerable npm deps** — direct deps bumped to the OSV-reported fixed version in `package.json`; transitive deps pinned via `overrides` (the PR body notes that the lockfile must be refreshed with `npm install`).
- **TypeScript `strict`** — flipped to `true`.
- **Committed `.env`** — added to `.gitignore` and removed from the tree.
- **Missing CI** — a baseline GitHub Actions workflow is added.

Left as **manual action items** (never auto-edited): secrets in code, committed keys, `.npmrc` tokens, missing lockfile — because auto-editing these risks breakage or mishandling credentials. Patch planning/application is proven by `npm run test:repair`.

### Scan engine (v1)

`api/_scanner.js` performs genuine analysis of the cloned tree:

- **Dependency SCA** — parses `package-lock.json` / `yarn.lock` / `package.json` (npm) and `requirements.txt` (PyPI), then queries [OSV.dev](https://osv.dev) for known vulnerabilities (real CVEs, severity, references).
- **Secret scanning** — gitleaks-style regex + entropy over text files (AWS keys, GitHub/GitLab tokens, Slack, Google, Stripe, private keys, JWTs, high-entropy assignments); matches are redacted in output and `.example`/`.sample` files are ignored.
- **Repo hygiene** — committed `.env`/key files, `.npmrc` auth tokens, TypeScript `strict` disabled, missing lockfile, missing CI pipeline.

Bounded for safety: https-only SSRF-allowlisted hosts, shallow `--depth 1` clone with a timeout, file/size/finding caps, and the temp checkout is always deleted. Proven by `npm run test:scanner`.

Copy `.env.example` into your deployment environment and fill in the provider credentials owned by your company. Each OAuth-capable provider needs both `*_CLIENT_ID` and `*_CLIENT_SECRET`; sessions are signed with `CODECANIC_SESSION_SECRET`.

## Deployment Targets

- Vercel: static web deployment is ready through `vercel.json`.
- Railway: `railway.json` is included for hosting the current static MVP or future API/worker services.
- GitHub: initialize a repo and push once GitHub authentication is active.
- iOS/Android: add Capacitor later to package this PWA shell for App Store and Google Play.

## Next Build Steps

1. ~~Add authentication and organization workspaces.~~ ✓ Session cookies + JSON-file user/org/membership store at `${CODECANIC_DATA_DIR}/codecanic.json`.
2. ~~Implement real connector OAuth flows.~~ ✓ Signed-state authorization URL → `/api/oauth/callback` → provider-specific token exchange (GitHub, Vercel, GitLab, Bitbucket); per-org credentials persisted.
3. ~~Build a real scan engine.~~ ✓ v1 clones the repo and runs real dependency SCA (OSV.dev), secret scanning, and hygiene checks (`api/_scanner.js`).
4. ~~Make repair real.~~ ✓ v1 generates patches and opens a real GitHub pull request, with manual items in the PR body (`api/_repair.js`). Next: rerun validation/tests on the patched branch and add CI-based merge-confidence before proposing.
5. Add async scan/repair job queues (scans/repairs are currently synchronous per request).
6. Migrate the JSON-file datastore to managed Postgres (durability + multi-replica safety).
5. Add mobile packaging with Capacitor for iOS and Android.
