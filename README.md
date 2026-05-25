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

- `GET /api/connectors?name=GitHub` returns connector authorization status and an OAuth URL when the matching environment variable is configured.
- `POST /api/scan` creates a scan job and returns a prioritized report with findings and summary counts.
- `POST /api/repair` queues approved findings for patch generation and pull request preparation.
- `POST /api/checkout` creates a Stripe subscription checkout session when Stripe environment variables are present.

Copy `.env.example` into your deployment environment and fill in the provider credentials owned by your company.

## Deployment Targets

- Vercel: static web deployment is ready through `vercel.json`.
- Railway: `railway.json` is included for hosting the current static MVP or future API/worker services.
- GitHub: initialize a repo and push once GitHub authentication is active.
- iOS/Android: add Capacitor later to package this PWA shell for App Store and Google Play.

## Next Build Steps

1. Add authentication and organization workspaces.
2. Add Stripe checkout and subscription webhooks.
3. Implement real connector OAuth flows.
4. Build backend scan and repair job queues.
5. Add pull request generation with approval/audit controls.
6. Add mobile packaging with Capacitor for iOS and Android.
