# SHIFT Pre-Flight

Launch-readiness scanner for app developers. Audits an app's configuration and
store listing before submission and reports safety, legal, and store-listing
findings.

- Live: https://5b5170f25781d9d9dc.v2.appdeploy.ai/
- Platform: AppDeploy (`app_id: 5b5170f25781d9d9dc`)

## This repository is the source of truth

The app previously existed only as an AppDeploy snapshot. This repository now
holds that source, imported verbatim from applied version `1786457122129` (v7,
2026-08-11). Character counts were verified file-by-file against the remote
snapshot at import time.

From here on, edit the code **here**, then deploy. Do not edit the AppDeploy
snapshot directly — that is how the two drifted apart in the first place.

## Layout

The tree mirrors the AppDeploy snapshot exactly, so paths line up on deploy.

```
index.html                  scan form and landing page
src/main.ts                 all local (in-browser) scan rules + UI
src/styles.css              styles
backend/index.ts            wallet, credits, AI deep scan, Stripe checkout + webhook
public/privacy.html         privacy policy
public/terms.html           terms of use
tests/tests.txt             AppDeploy e2e test definitions
appdeploy.auth-login.json   hosted sign-in page config
package.json tsconfig.json vite.config.ts tailwind.config.js postcss.config.js
```

## Two scan modes

**Local Scan** is free, requires no account, and runs entirely in the browser.
Every rule lives in `src/main.ts` (`auditSafety`, `auditLegal`,
`auditMarketing`). Nothing is uploaded.

**AI Deep Scan** posts to `POST /api/deep-scan`, requires sign-in, and costs one
credit. New accounts get 3 free credits.

## Develop

```bash
npm install
npm run dev
```

Local Scan works fully offline in `npm run dev`. Deep Scan, wallet, and billing
need the deployed backend.

## Deploy

Deploys go through the AppDeploy MCP tools against `app_id 5b5170f25781d9d9dc`.
The working tree here is the local copy those tools upload from. Deploy from a
clean checkout so what ships matches what is committed.

Roll back with `apply_app_version`; `get_app_versions` lists them.

## Secrets

`STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` live in AppDeploy's secret store
and are read at runtime via `secrets.readSecret`. They are never committed here.
Billing degrades gracefully when they are absent: packs render, buy buttons
disable, and local scans keep working.

## Prior history

Before this import, the repository held an unrelated prototype — a "market
adaptive platform" concept that shared the SHIFT name but none of the code. It
is preserved at the tag `v0-market-adaptive-concept`:

```bash
git show v0-market-adaptive-concept:index.html
```
