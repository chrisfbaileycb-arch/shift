# SHIFT Pre-Flight

**SHIFT Pre-Flight** is a launch-readiness scanner for app developers. Paste an
`AndroidManifest.xml`, `Info.plist`, or `package.json` plus your store-listing
copy, and it runs an automated audit across the three areas that most often get
apps rejected, flagged, or sued:

1. **Safety audit (technical)** — hardcoded API keys and secrets (AWS, Google,
   Stripe, private keys, generic credentials), cleartext `http://` traffic,
   `debuggable`/`allowBackup` flags, disabled App Transport Security, outdated
   `targetSdkVersion`, sensitive-permission inventory, and dependency hygiene.
2. **Legal & compliance** — digital purchases mentioned without Play Billing /
   In-App Purchase, missing privacy policy, COPPA / Families-policy triggers,
   permissions your listing copy never justifies (data-minimization gaps), empty
   iOS usage descriptions, regulated-category flags, and missing accuracy
   disclaimers.
3. **Store listing / ASO** — Google Play's 30/80/4000-character limits, keyword
   stuffing, competitor-trademark mentions, banned superlative claims ("#1",
   "best"), promotional symbols in titles, and readability.

Each pillar gets a score out of 100 with severity-tagged findings, and the full
report can be downloaded as a standalone HTML file.

**Everything runs locally in your browser.** No backend, no account, no upload —
scan inputs never leave your device.

## Try it

Open `index.html` in any modern browser:

```bash
git clone https://github.com/chrisfbaileycb-arch/shift.git
cd shift
xdg-open index.html   # or just double-click index.html
```

Use the **Load Android sample** / **Load iOS sample** buttons to see the scanner
in action instantly.

## What's in the repo

| File | Purpose |
| --- | --- |
| `index.html` | The scanner app (UI + rule-based scan engine, self-contained) |
| `privacy.html` / `terms.html` | Privacy policy and terms — required for a store listing |
| `manifest.webmanifest` | PWA manifest (installable app, name, icons, theme) |
| `sw.js` | Service worker — offline support via cache-first app shell |
| `icons/` | 192/512 px and maskable launcher icons |

## Path to Google Play

The app is built as an installable PWA, which is the shortest route to the Play
Store for a web app. The steps:

1. **Host it over HTTPS** — GitHub Pages works out of the box for this repo
   (Settings → Pages → deploy from the `main` branch). The service worker and
   install prompt require HTTPS.
2. **Verify PWA installability** — open the hosted URL in Chrome, run a
   Lighthouse PWA audit, and confirm the install prompt appears.
3. **Package it as a Trusted Web Activity (TWA)** with
   [Bubblewrap](https://github.com/GoogleChromeLabs/bubblewrap):
   ```bash
   npm i -g @bubblewrap/cli
   bubblewrap init --manifest https://<your-host>/manifest.webmanifest
   bubblewrap build
   ```
   This produces a signed `.aab` Android app bundle.
4. **Set up Digital Asset Links** — Bubblewrap prints the `assetlinks.json` to
   host at `https://<your-host>/.well-known/assetlinks.json` so the TWA opens
   full-screen without browser chrome.
5. **Create the Play listing** — a one-time $25 Google Play developer account,
   then upload the `.aab`, fill in the Data safety form (this app collects **no
   data**, which makes that form trivial), and link the hosted `privacy.html` as
   the privacy policy URL.

The scanner can even audit its own listing copy before you submit it.

## Roadmap (from the product plan)

- **Credit wallet monetization** — bundle pricing ($5 / 5 scans, $9 / 10 scans)
  once a backend exists; local scanning stays free.
- **AI-assisted deep scan** — optional LLM-backed analysis of full repositories
  for issues rule-based scanning can't catch, returning structured JSON reports.
- **CI integration** — a GitHub Action that runs the scan on every push and
  fails the build when the safety score drops below a threshold.
- **Report history** — save past scans (locally at first) so builds can be
  compared over time.

## Disclaimer

Analysis is fully automated and rule-based; it may contain errors, false
positives, and false negatives. It is not certified legal advice, security
auditing, or a guarantee of store approval. Verify critical findings
independently before deployment.
