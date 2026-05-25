# Codecanic

Codecanic is an MVP for a subscription code operations platform that scans user repositories and infrastructure, generates prioritized reports, and lets users approve all repairs or selected repair segments.

## MVP Scope

- Connectors for GitHub, Vercel, Railway, Xcode projects, GitLab, and Bitbucket.
- Full infrastructure scan flow for repos, deployments, package managers, secrets, dependencies, and build settings.
- Reviewable findings report with severity, target, repair description, and approval controls.
- Selective repair approval for all findings or focused segments such as security and performance.
- Tiered subscription model: Free, Basic, Pro, and Max with progressively faster scan and repair queues.
- PWA-ready web interface that can be wrapped for iOS and Android distribution.
- Deployable API endpoints for connector authorization handoff, scan reports, repair queues, and Stripe checkout sessions.

## Product Architecture

The production version should separate the interface from trusted backend workers:

- Web app and mobile shell: dashboard, onboarding, connector authorization, reports, billing, repair approvals.
- API service: users, organizations, subscriptions, connectors, audit logs, repair policies.
- Scan workers: repo checkout, dependency analysis, static checks, secret scanning, deployment checks, infrastructure inventory.
- Repair workers: deterministic autofixes, AI-assisted patches, validation reruns, pull request creation.
- Billing: Stripe subscriptions mapped to queue priority and worker concurrency.
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
- `POST /api/scan` creates a scan job for the active organization and returns a prioritized report. Requires `Cookie: codecanic_session=...` and either an `X-Codecanic-Org` header or `?organization=` query.
- `POST /api/repair` queues approved findings for patch generation and pull request preparation (auth-gated).
- `POST /api/checkout` creates a Stripe subscription checkout session for the active organization when Stripe environment variables are present.

Copy `.env.example` into your deployment environment and fill in the provider credentials owned by your company. Each OAuth-capable provider needs both `*_CLIENT_ID` and `*_CLIENT_SECRET`; sessions are signed with `CODECANIC_SESSION_SECRET`.

## Deployment Targets

- Vercel: static web deployment is ready through `vercel.json`.
- Railway: `railway.json` is included for hosting the current static MVP or future API/worker services.
- GitHub: initialize a repo and push once GitHub authentication is active.
- iOS/Android: add Capacitor later to package this PWA shell for App Store and Google Play.

## Next Build Steps

1. ~~Add authentication and organization workspaces.~~ ✓ Session cookies + JSON-file user/org/membership store at `${CODECANIC_DATA_DIR}/codecanic.json`.
2. Add Stripe checkout and subscription webhooks (checkout is wired; webhook + state sync still pending).
3. ~~Implement real connector OAuth flows.~~ ✓ Signed-state authorization URL → `/api/oauth/callback` → provider-specific token exchange (GitHub, Vercel, GitLab, Bitbucket); per-org credentials persisted.
4. Build backend scan and repair job queues (currently synchronous stubs).
5. Add pull request generation with approval/audit controls.
6. Add mobile packaging with Capacitor for iOS and Android.
