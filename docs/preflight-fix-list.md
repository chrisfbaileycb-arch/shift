# SHIFT Pre-Flight — fix list, verified against the code

The original fix list was written from the landing page and scan form alone,
with every uncertain item marked **[verify]**. Now that the source is in the
repository, every item has been checked against it.

Four of the nine were already built. Five are real. One of the five is a bug
that produces a false all-clear, which is the worst output this tool can give.

Verified against applied version `1786457122129` (v7).

---

## Already built — no work needed

### ~~1. Close the promise/capability gap~~

The list asked for an app-config input feeding deterministic checks. It exists.
`index.html` has the **App configuration** textarea (`#config`), and
`auditSafety` in `src/main.ts` already runs, with no model involved:

| Check | Location |
| --- | --- |
| AWS key `AKIA…` | `secretChecks[0]` |
| Google key `AIza…` | `secretChecks[1]` |
| Stripe live key `sk_live_…` | `secretChecks[2]` |
| `PRIVATE KEY` blocks | `secretChecks[3]` |
| generic `api_key`/`secret`/`token`/`password` assignment | `secretChecks[4]` |
| cleartext `http://` endpoints | `httpUrls` |
| `android:usesCleartextTraffic="true"` | inline |
| `NSAllowsArbitraryLoads` | inline |
| `android:debuggable="true"` | inline |
| `android:allowBackup="true"` | inline |
| `targetSdkVersion` below the Play floor | `tsdk` |
| 12 sensitive permissions | `DANGEROUS_PERMISSIONS` |
| wildcard dependency versions | `cfgType === 'node'` |
| `package.json` not marked private | `cfgType === 'node'` |

`detectConfigType` auto-detects AndroidManifest.xml, Info.plist, and
package.json.

Genuinely still missing from the original list, and worth adding:

- `eas.json` — no production profile, local version source, no autoIncrement
- placeholder app name or slug left from a scaffold template
- missing iOS bundle identifier / Android package name
- permission-bearing native modules present in dependencies but imported nowhere
  (needs a source file list, which the tool does not currently accept)

### ~~4. Make the free path work signed-out~~

Already correct. `runLocalScan()` is a plain form-submit handler. It calls no
API and touches no `auth` method. The only sign-in gates are `runDeepScan` and
the billing buttons, which is where they belong.

### ~~5. Make the samples sell~~

Already correct. `SAMPLE_ANDROID` is deliberately loaded with failures — a
hardcoded `AIza…` key, `debuggable="true"`, `usesCleartextTraffic="true"`, a
cleartext `http://` analytics endpoint, `targetSdkVersion 33`, three sensitive
permissions, a 53-character title with `#1` and `Best`, `scan scan scan your app
app app`, a `ChatGPT` trademark mention, and purchases with no billing
reference. A visitor who clicks it sees roughly a dozen findings including
several high-severity ones.

### ~~6. Price the credit~~

Already done. `loadBilling()` renders $1.50 / $5.00 / $9.00 with per-scan unit
pricing on the multi-credit packs.

Small remaining nit: the price lives in the billing card far down the page,
while the button that spends a credit says only "AI Deep Scan (1 credit)".
Putting "$1.50" next to that button closes the gap.

---

## Real — still to do

### 9. "Insufficient input" is missing, and it currently produces a false pass

**This is a bug, not a polish item.** `scoreOf` starts at 100 and only ever
subtracts, so a thin input has nothing to subtract. Paste a title and nothing
else — say `PhotoVault Pro`:

- `auditSafety` short-circuits on empty config, returns one `info` → **98**
- `auditLegal` finds nothing to check, falls to the `!out.length` branch and
  pushes a `pass` → **100**
- `auditMarketing` passes the title, pushes one `info` for the missing
  description → **98**

Result: **Safety 98 / Legal 100 / Marketing 98**, all three rendered green by
`scoreClass` (`>= 85` is `good`), with zero high- or warn-severity findings. The
user sees a clean bill of health for an app that was never examined.

Submitting the form completely empty is no better: **98 / 100 / 96**, still all
green. Both numbers were produced by running the real `auditSafety`,
`auditLegal`, `auditMarketing`, and `scoreOf` from `src/main.ts` against those
inputs, not estimated by reading.

`tests/tests.txt` Test 3 covers this path but only asserts that informational
findings render and nothing crashes — it never looks at the scores, so the
failure passes CI.

Fix: track coverage separately from score. When a pillar had no usable input,
return a distinct "not assessed" state rather than a number, render it neutral
rather than green, and say what to paste to get a real result.

### 7. Make output machine-readable

`downloadReport()` emits styled HTML and nothing else. There is no JSON, no
Markdown, and no copy button.

Findings already carry `category`, `severity`, `title`, and `detail` — the
structure is there, it just never leaves as data. Add "copy as Markdown" and
"copy as JSON" next to the existing download button.

Developers paste tool output straight into a coding agent. This is cheap and it
is the feature people tell each other about.

### 8. Date the rules — and they are already stale

The thresholds are scattered through the check functions as literals: `30`,
`80`, and `4000` inline in `auditMarketing`, the `TRADEMARKS` array inline,
`STOPWORDS` inline, and the Play floor buried in a sentence in `auditSafety`:

> `'…(API 35 as of Aug 2025, rising yearly)…'`

That string is now a year old and the comparison `v < 35` with it. The Play
floor moves annually. A scanner that confidently gives stale advice is worse
than no scanner, because the developer stops checking themselves.

Fix: pull every threshold into one `src/rules.ts` with a `RULES_UPDATED` date,
and render "rules current as of <date>" in the report.

### 2. Lead with the privacy guarantee

"Local Scan runs entirely in your browser — nothing is uploaded" is the
strongest thing on the page and it is currently mid-sentence inside
`.modes-note`, below the three pillars. Make it a badge above the fold.

For AI Deep Scan, the landing page says only "sends your text to our AI engine".
`public/privacy.html` is more forthcoming — it says the text goes to the backend
and an AI service, and that reports are retained in account history — but a
visitor deciding whether to paste a manifest never gets there. Surface the
retention answer at the point of decision and link the policy.

### 3. Soften the legal claim

`index.html` still reads "catching the mistakes that get apps rejected,
flagged, or **sued**." That is a legal-outcome promise from a tool that opens by
saying it is not legal advice.

Note that the disclaimers elsewhere are already strong — the results banner, the
micro-disclaimer under the form, and `public/terms.html` §2 and §3 all say the
right thing. It is only the marketing line that overreaches.

Change to "catches the configuration and listing problems that commonly cause
store rejections", and put a short "not legal advice" line next to the Legal &
Compliance pillar.

The same reasoning applies to the trademark and banned-claims checks: report the
pattern found and the rule it touches, never assert a legal conclusion. The
finding copy mostly does this already — `'Trademark infringement risk: mentions
…'` is a fair hedge.

---

## Suggested order

1. **#9** — it is a correctness bug that hands out false all-clears
2. **#8** — the Play floor is already a year stale and silently wrong
3. **#7** — highest value per hour of the remaining work
4. **#2 / #3** — copy changes, no logic
5. **#1 leftovers** — eas.json, placeholder slug, missing bundle id
