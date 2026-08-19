import './styles.css';
import { api, auth } from '@appdeploy/client';

type Severity = 'high' | 'warn' | 'info' | 'pass';
type Category = 'safety' | 'legal' | 'marketing';
interface Finding { category: Category; severity: Severity; title: string; detail: string; }
interface Scores { safety: number; legal: number; marketing: number; }
interface Report { appName: string; mode: 'local' | 'ai'; scores: Scores; findings: Finding[]; createdAt: number; }

const SEV_LABEL: Record<Severity, string> = { high: '⚠ High', warn: '⚠ Warning', info: 'ℹ Info', pass: '✅ Passed' };
const WEIGHT: Record<Severity, number> = { high: 15, warn: 7, info: 2, pass: 0 };
const CATS: Category[] = ['safety', 'legal', 'marketing'];
const CAT_LABEL: Record<Category, string> = { safety: 'Safety', legal: 'Legal', marketing: 'Marketing' };

const DANGEROUS_PERMISSIONS: Record<string, { label: string; justify: RegExp }> = {
  ACCESS_FINE_LOCATION: { label: 'precise location', justify: /location|map|nearby|navigat|gps|weather|deliver/i },
  ACCESS_BACKGROUND_LOCATION: { label: 'background location', justify: /background location|geofenc|track.*(route|run|ride)/i },
  READ_CONTACTS: { label: 'contacts', justify: /contact|invite friend|address book/i },
  RECORD_AUDIO: { label: 'microphone', justify: /voice|audio|record|microphone|dictat|karaoke|sing/i },
  CAMERA: { label: 'camera', justify: /camera|photo|video|scan|selfie|document|barcode|qr/i },
  READ_SMS: { label: 'SMS messages', justify: /sms|text message|otp|verification code/i },
  READ_CALL_LOG: { label: 'call log', justify: /call log|call history|caller/i },
  READ_PHONE_STATE: { label: 'phone state', justify: /caller id|phone call|dialer/i },
  MANAGE_EXTERNAL_STORAGE: { label: 'all-files storage access', justify: /file manager|file browser|backup tool/i },
  SYSTEM_ALERT_WINDOW: { label: 'draw over other apps', justify: /overlay|floating|bubble|screen filter/i },
  REQUEST_INSTALL_PACKAGES: { label: 'install other apps', justify: /app store|installer|launcher/i },
  QUERY_ALL_PACKAGES: { label: 'list installed apps', justify: /launcher|antivirus|device manage/i }
};

const TRADEMARKS = ['uber', 'airbnb', 'tiktok', 'instagram', 'facebook', 'whatsapp', 'snapchat', 'netflix', 'spotify', 'youtube', 'fortnite', 'minecraft', 'pokemon', 'chatgpt', 'photoshop', 'tinder', 'roblox', 'duolingo'];

const STOPWORDS = new Set('the a an and or but for nor with your you our their its this that these those from into onto over under about after before while when where what which who will shall can could would should may might must have has had was were are is be been being do does did not all any each more most other some such only own same so than too very just app apps get make also then them they there here how why out off'.split(' '));

function f(category: Category, severity: Severity, title: string, detail: string): Finding { return { category, severity, title, detail }; }

function detectConfigType(cfg: string): string {
  if (/<manifest[\s>]|android\.permission|AndroidManifest/i.test(cfg)) return 'android';
  if (/<plist|<key>|CFBundle|NS\w+UsageDescription/i.test(cfg)) return 'ios';
  if (/"dependencies"|"devDependencies"|"scripts"\s*:/.test(cfg)) return 'node';
  return cfg.trim() ? 'generic' : 'none';
}

function auditSafety(cfg: string, cfgType: string): Finding[] {
  const out: Finding[] = [];
  if (!cfg.trim()) {
    out.push(f('safety', 'info', 'No configuration provided', 'Paste your AndroidManifest.xml, Info.plist, or package.json for the technical safety audit. Only the listing copy was analyzed.'));
    return out;
  }
  const secretChecks: Array<[RegExp, string, string]> = [
    [/AKIA[0-9A-Z]{16}/, 'AWS access key ID detected', 'An AWS access key appears in your configuration. Shipping cloud credentials inside an app lets anyone extract and abuse them. Move keys server-side and rotate this credential immediately.'],
    [/AIza[0-9A-Za-z\-_]{35}/, 'Google API key detected', 'A Google API key is embedded in your configuration. If it must ship in-app, restrict it by package name and API scope; otherwise move it behind your own backend.'],
    [/sk_live_[0-9a-zA-Z]{10,}/, 'Stripe live secret key detected', 'A live Stripe secret key appears in your configuration. Remove it from the client immediately and rotate it; secret keys belong only on your server.'],
    [/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, 'Private key material detected', 'A private key block is embedded in your configuration. Never ship private keys in an app package.'],
    [/(api[_-]?key|secret|token|passwd|password|pwd)["']?\s*[:=]\s*["'][^"'\s]{8,}["']/i, 'Possible hardcoded credential', 'A value assigned to a key named like api_key, secret, token, or password was found. If real, move it to a server or secrets manager; bundled strings are trivially extracted from published apps.']
  ];
  for (const [re, title, detail] of secretChecks) if (re.test(cfg)) out.push(f('safety', 'high', title, detail));
  const httpUrls = cfg.match(/http:\/\/(?!schemas\.android\.com|www\.w3\.org|apple\.com\/DTDs|localhost|127\.0\.0\.1)[^\s"'<>]+/g) || [];
  if (httpUrls.length) out.push(f('safety', 'warn', 'Cleartext (http://) endpoint referenced', 'Found ' + httpUrls.length + ' non-HTTPS URL reference(s), e.g. ' + httpUrls[0].slice(0, 60) + '. Modern Android and iOS block cleartext traffic by default. Use https:// endpoints.'));
  if (/usesCleartextTraffic\s*=\s*["']true["']/i.test(cfg)) out.push(f('safety', 'warn', 'android:usesCleartextTraffic="true"', 'Your manifest globally re-enables unencrypted HTTP traffic. Scope legacy endpoints with a network security config instead.'));
  if (/NSAllowsArbitraryLoads[\s\S]{0,40}?<true\s*\/>/i.test(cfg)) out.push(f('safety', 'warn', 'App Transport Security disabled (NSAllowsArbitraryLoads)', 'Info.plist disables ATS entirely. App Review requires justification for this; prefer per-domain exceptions.'));
  if (/android:debuggable\s*=\s*["']true["']/i.test(cfg)) out.push(f('safety', 'high', 'android:debuggable="true" in manifest', 'Debuggable builds expose the app to runtime inspection and are rejected by Google Play. Remove the flag.'));
  if (/android:allowBackup\s*=\s*["']true["']/i.test(cfg)) out.push(f('safety', 'info', 'android:allowBackup="true"', 'Auto-backup will include app data in device backups. If you store tokens or sensitive data, exclude them with backup rules.'));
  const tsdk = cfg.match(/targetSdkVersion\s*[="' ]*(\d+)|android:targetSdkVersion\s*=\s*["'](\d+)["']/i);
  if (tsdk) {
    const v = parseInt(tsdk[1] || tsdk[2], 10);
    if (v < 35) out.push(f('safety', 'warn', 'targetSdkVersion ' + v + ' is below current Play requirements', 'Google Play requires new apps and updates to target a recent API level (API 35 as of Aug 2025, rising yearly). Raise targetSdkVersion and retest.'));
    else out.push(f('safety', 'pass', 'targetSdkVersion ' + v + ' meets current Play requirements', 'Target API level satisfies the current minimum for new submissions.'));
  }
  const perms = Object.keys(DANGEROUS_PERMISSIONS).filter(p => new RegExp('(android\\.permission\\.)?' + p).test(cfg));
  if (perms.length) out.push(f('safety', 'info', 'Sensitive permissions requested: ' + perms.join(', '), 'Each sensitive permission increases review scrutiny and install drop-off. Remove any your core features do not need.'));
  if (cfgType === 'node') {
    if (/:\s*["'](\*|latest)["']/.test(cfg)) out.push(f('safety', 'warn', 'Wildcard dependency versions', 'Unpinned dependencies make builds non-reproducible and can pull in breaking or compromised releases. Pin versions and commit a lockfile.'));
    if (!/"private"\s*:\s*true/.test(cfg) && /"name"\s*:/.test(cfg)) out.push(f('safety', 'info', 'package.json is not marked private', 'If this package is an app rather than a library, mark it "private": true to prevent accidental npm publication.'));
  }
  if (!out.some(x => x.severity === 'high' || x.severity === 'warn')) out.push(f('safety', 'pass', 'No high-risk technical issues detected', 'No hardcoded secrets, debug flags, or cleartext traffic found. Automated scanning is not exhaustive; run a full SAST tool before release.'));
  return out;
}

function auditLegal(cfg: string, marketing: string, allText: string): Finding[] {
  const out: Finding[] = [];
  const paymentMention = /subscription|premium|in.?app purchase|unlock|upgrade|credits?|coins|token pack|paywall|pro version|buy/i.test(marketing);
  const platformBilling = /play billing|com\.android\.vending\.BILLING|in.?app purchase|storekit|app store billing/i.test(allText);
  if (paymentMention && !platformBilling) out.push(f('legal', 'high', 'Digital purchases mentioned without platform billing reference', 'Your listing mentions purchases or unlocks, but nothing references Google Play Billing or Apple In-App Purchase. Store policy requires digital goods to use native platform billing; non-compliance means rejection or removal.'));
  else if (paymentMention && platformBilling) out.push(f('legal', 'pass', 'Purchases mentioned and platform billing referenced', 'Remember to declare in-app products in the store console and mark the listing as containing in-app purchases.'));
  if (marketing && !/privacy policy|privacy\.html|\/privacy/i.test(allText)) out.push(f('legal', 'high', 'No privacy policy referenced', 'Google Play requires every app to link a privacy policy and complete the Data safety form; Apple requires a policy URL and App Privacy labels. Publish a policy URL before submitting.'));
  else if (marketing) out.push(f('legal', 'pass', 'Privacy policy referenced', 'Make sure the linked policy URL is live, matches your actual data practices, and is entered in the store console.'));
  if (/\bkids?\b|\bchild(ren)?\b|toddler|preschool|for families|family friendly/i.test(marketing)) out.push(f('legal', 'warn', 'Child-directed language detected: COPPA / Families policies apply', 'Marketing that targets children triggers Play Families policy and COPPA / GDPR-K obligations: restricted ads, no behavioral tracking, verified parental consent. Confirm your target-audience declaration matches this copy.'));
  for (const [perm, meta] of Object.entries(DANGEROUS_PERMISSIONS)) {
    if (new RegExp('(android\\.permission\\.)?' + perm).test(cfg) && marketing && !meta.justify.test(marketing)) {
      out.push(f('legal', 'warn', 'Privacy compliance gap: ' + perm, 'Your app requests ' + meta.label + ' access, but the listing copy never explains a user-facing reason for it. Stores and privacy laws expect a declared purpose for every sensitive permission; reviewers reject apps whose permissions exceed their described features.'));
    }
  }
  for (const key of cfg.match(/NS\w+UsageDescription/g) || []) {
    if (new RegExp('<key>' + key + '</key>\\s*<string>\\s*</string>').test(cfg)) out.push(f('legal', 'warn', key + ' is empty', 'iOS shows this string in the permission prompt; App Review rejects empty or generic usage descriptions. Write a specific sentence explaining the need.'));
  }
  if (/medical|diagnos|health advice|symptom|treatment|therapy/i.test(marketing)) out.push(f('legal', 'info', 'Health / medical language detected', 'Health claims attract extra review and possibly medical-device regulation. Add a clear not-medical-advice disclaimer and avoid diagnostic claims unless certified.'));
  if (/invest|trading|loan|crypto|wallet|gambling|casino|betting/i.test(marketing)) out.push(f('legal', 'info', 'Financial / gambling language detected', 'Finance and real-money gaming categories require extra declarations, licenses, and country restrictions on both stores.'));
  if (marketing && /\bai\b|automated|analysis|recommend/i.test(marketing) && !/may (contain|include) (errors|mistakes)|verify|no (guarantee|warranty)|as.?is/i.test(allText)) out.push(f('legal', 'info', 'No accuracy / liability disclaimer found', 'Your copy describes automated or AI-driven functionality without a disclaimer. Add a short notice that results may contain errors and should be verified.'));
  if (!out.length) out.push(f('legal', 'pass', 'No legal red flags detected in the provided text', 'Automated review covers common store-policy pitfalls only. For binding compliance, consult qualified counsel.'));
  return out;
}

function auditMarketing(title: string, shortDesc: string, marketing: string): Finding[] {
  const out: Finding[] = [];
  if (title) {
    if (title.length > 30) out.push(f('marketing', 'warn', 'App title is ' + title.length + ' characters (limit: 30)', 'Google Play hard-limits titles to 30 characters; the App Store name field is also 30. Trim the title and move keywords into the short description.'));
    else out.push(f('marketing', 'pass', 'Title length OK (' + title.length + '/30)', 'Fits the 30-character limit.'));
    if (/!|[A-Z]{5,}|#1/.test(title)) out.push(f('marketing', 'warn', 'Promotional symbols / caps in title', 'Play metadata policy bans emoji, all-caps, exclamation marks, and rank claims like #1 in titles; a common rejection reason.'));
  } else out.push(f('marketing', 'info', 'No app title provided', 'Enter your store title to check length and policy compliance.'));
  if (shortDesc && shortDesc.length > 80) out.push(f('marketing', 'warn', 'Short description is ' + shortDesc.length + ' characters (limit: 80)', 'Google Play truncates short descriptions at 80 characters. Front-load the value proposition.'));
  if (marketing) {
    if (marketing.length > 4000) out.push(f('marketing', 'warn', 'Description is ' + marketing.length + ' characters (limit: 4000)', 'Google Play caps full descriptions at 4000 characters.'));
    if (marketing.length < 80) out.push(f('marketing', 'warn', 'Description is very short', 'Store search indexes your description. Under about 80 characters gives the algorithm almost nothing to rank; aim for 2-4 short paragraphs.'));
    const words = marketing.toLowerCase().match(/[a-z][a-z'-]{3,}/g) || [];
    const freq: Record<string, number> = {};
    for (const w of words) if (!STOPWORDS.has(w)) freq[w] = (freq[w] || 0) + 1;
    const stuffed = Object.entries(freq).filter(([, n]) => n >= 6 && n / words.length > 0.03);
    if (stuffed.length) out.push(f('marketing', 'warn', 'Possible keyword stuffing: ' + stuffed.map(([w, n]) => w + ' x' + n).join(', '), 'Repeating the same keyword violates Play metadata policy and reads badly. Use synonyms and natural sentences.'));
    const hits = TRADEMARKS.filter(t => new RegExp('\\b' + t + '\\b', 'i').test(marketing));
    if (hits.length) out.push(f('marketing', 'warn', 'Trademark infringement risk: mentions ' + hits.join(', '), 'Using competitor app names in public metadata can trigger metadata rejection or legal takedown demands under store IP policies. Describe the category instead.'));
    if (/\b(best|#1|number one|top rated|editor'?s choice|guaranteed)\b/i.test(marketing)) out.push(f('marketing', 'info', 'Unverifiable superlative claims', 'Stores restrict rank and performance claims unless substantiated. Rephrase around concrete benefits.'));
    const sentences = marketing.split(/[.!?]+\s/).filter(s => s.trim().length > 0);
    if (sentences.length && words.length / sentences.length > 30) out.push(f('marketing', 'info', 'Long average sentence length', 'Sentences average over 30 words. Store browsers skim; shorter lines convert better.'));
  } else out.push(f('marketing', 'info', 'No description provided', 'Paste your store listing copy to run the marketing audit.'));
  if (!out.some(x => x.severity !== 'pass')) out.push(f('marketing', 'pass', 'Listing metadata looks clean', 'No length, stuffing, trademark, or claim issues detected.'));
  return out;
}

function scoreOf(findings: Finding[], cat: Category): number {
  let s = 100;
  for (const x of findings) if (x.category === cat) s -= WEIGHT[x.severity];
  return Math.max(5, s);
}

const $ = <T extends HTMLElement>(sel: string): T => document.querySelector(sel) as T;
let lastReport: Report | null = null;
let activeTab: Category = 'safety';

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as Record<string, string>)[c]);
}

function scoreClass(v: number): string { return v >= 85 ? 'good' : v >= 60 ? 'mid' : 'bad'; }

function renderReport(report: Report): void {
  lastReport = report;
  activeTab = 'safety';
  $('#results-title').textContent = report.mode === 'ai' ? 'AI Deep Scan report' : 'Local scan report';
  $('#report-meta').textContent = 'Product audited: ' + (report.appName || 'Untitled app') + ' | Scan date: ' + new Date(report.createdAt).toLocaleString() + '.';
  $('#scores').innerHTML = CATS.map(cat => {
    const v = (report.scores as any)[cat] as number;
    const c = scoreClass(v);
    return '<div class="score-card"><h3>' + CAT_LABEL[cat] + ' score</h3><div class="score-value score-' + c + '">' + v + '<span class="of"> / 100</span></div><div class="score-bar"><span class="bar-' + c + '" style="width:' + v + '%"></span></div></div>';
  }).join('');
  const tabs = $('#tabs');
  tabs.innerHTML = CATS.map((cat, i) => {
    const issues = report.findings.filter(x => x.category === cat && x.severity !== 'pass').length;
    return '<button class="tab' + (i === 0 ? ' active' : '') + '" type="button" data-tab="' + cat + '">' + CAT_LABEL[cat] + ' findings<span class="count">' + issues + '</span></button>';
  }).join('');
  tabs.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeTab = (btn as HTMLElement).dataset.tab as Category;
      renderFindings();
    });
  });
  renderFindings();
  const results = $('#results');
  results.hidden = false;
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderFindings(): void {
  if (!lastReport) return;
  $('#findings-list').innerHTML = lastReport.findings.filter(x => x.category === activeTab).map(x =>
    '<li class="finding ' + x.severity + '"><span class="sev">' + SEV_LABEL[x.severity] + '</span><div><strong>' + escapeHtml(x.title) + '</strong>' + escapeHtml(x.detail) + '</div></li>'
  ).join('') || '<li class="finding info"><span class="sev">' + SEV_LABEL.info + '</span><div><strong>No findings in this category</strong></div></li>';
}

function collectInputs() {
  return {
    appName: ($('#app-title') as HTMLInputElement).value.trim(),
    shortDesc: ($('#short-desc') as HTMLInputElement).value.trim(),
    marketing: ($('#marketing') as HTMLTextAreaElement).value.trim(),
    config: ($('#config') as HTMLTextAreaElement).value
  };
}

function runLocalScan(): void {
  const { appName, shortDesc, marketing, config } = collectInputs();
  const allText = config + '\n' + marketing + '\n' + shortDesc;
  const findings = [
    ...auditSafety(config, detectConfigType(config)),
    ...auditLegal(config, marketing, allText),
    ...auditMarketing(appName, shortDesc, marketing)
  ];
  renderReport({
    appName,
    mode: 'local',
    scores: { safety: scoreOf(findings, 'safety'), legal: scoreOf(findings, 'legal'), marketing: scoreOf(findings, 'marketing') },
    findings,
    createdAt: Date.now()
  });
}

function apiErrorMessage(err: any, fallback: string): string {
  try {
    const parsed = JSON.parse(err?.responseText || '');
    if (typeof parsed?.error === 'string') return parsed.error;
    if (typeof parsed?.message === 'string') return parsed.message;
  } catch { /* not JSON */ }
  return typeof err?.message === 'string' && err.message ? err.message : fallback;
}

function toast(msg: string): void {
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  document.body.append(el);
  setTimeout(() => el.remove(), 6000);
}

let credits: number | null = null;

function setCredits(v: number | null): void {
  credits = v;
  const pill = $('#credits-pill');
  if (v === null) { pill.hidden = true; return; }
  pill.hidden = false;
  $('#credits-value').textContent = String(v);
}

async function refreshWallet(): Promise<void> {
  if (!auth.isSignedIn()) { setCredits(null); return; }
  try {
    const { data } = await api.get('/api/wallet');
    setCredits(Number(data?.credits) || 0);
    $('#wallet-status').textContent = 'You have ' + (Number(data?.credits) || 0) + ' AI scan credit(s).';
  } catch { setCredits(null); }
}

async function refreshAuthUI(): Promise<void> {
  const btn = $('#auth-btn');
  if (auth.isSignedIn()) {
    const user = await auth.getUser();
    btn.textContent = 'Sign out' + (user?.name ? ' (' + user.name.split(' ')[0] + ')' : '');
    await refreshWallet();
    await loadHistory();
  } else {
    btn.textContent = 'Sign in';
    setCredits(null);
    $('#history-card').hidden = true;
    $('#wallet-status').textContent = 'Sign in to see your wallet. New accounts start with 3 free AI scan credits.';
  }
}

async function ensureSignedIn(): Promise<boolean> {
  if (auth.isSignedIn()) return true;
  try {
    await auth.signIn();
    await refreshAuthUI();
    return true;
  } catch (err: any) {
    if (err?.code === 'popup_blocked') toast('Your browser blocked the sign-in popup. Please allow popups and try again.');
    else if (err?.code !== 'popup_closed') toast('Sign-in failed. Please try again.');
    return false;
  }
}

async function runDeepScan(): Promise<void> {
  const { appName, marketing, config } = collectInputs();
  if (!config.trim() && !marketing.trim()) { toast('Add app configuration or listing copy first.'); return; }
  if (!(await ensureSignedIn())) return;
  const btn = $('#deep-btn') as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = 'AI is analyzing your build…';
  try {
    const { data } = await api.post('/api/deep-scan', { appName, config, marketing });
    setCredits(Number(data?.credits) || 0);
    renderReport({ appName: data.report.appName, mode: 'ai', scores: data.report.scores, findings: data.report.findings, createdAt: data.report.createdAt });
    await loadHistory();
  } catch (err: any) {
    const msg = apiErrorMessage(err, 'The AI deep scan failed. Please try again.');
    toast(msg);
    if (err?.statusCode === 402 || /credit/i.test(msg)) $('#wallet-card').scrollIntoView({ behavior: 'smooth' });
  } finally {
    btn.disabled = false;
    btn.textContent = 'AI Deep Scan (1 credit)';
  }
}

async function loadBilling(): Promise<void> {
  try {
    const { data } = await api.get('/api/billing/status');
    const packsEl = $('#packs');
    const tags: Record<string, string> = { developer: 'Most popular', studio: 'Best value' };
    packsEl.innerHTML = (data?.packs || []).map((p: any) =>
      '<div class="pack">' + (tags[p.id] ? '<span class="tag">' + tags[p.id] + '</span>' : '<span class="tag">&nbsp;</span>') +
      '<span class="price">$' + (p.priceCents / 100).toFixed(2) + '</span>' +
      '<span class="desc">' + p.credits + ' AI scan credit' + (p.credits > 1 ? 's' : '') + (p.credits > 1 ? ' · $' + (p.priceCents / p.credits / 100).toFixed(2) + ' per scan' : '') + '</span>' +
      '<button type="button" data-pack="' + p.id + '"' + (data.enabled ? '' : ' disabled') + '>Buy</button></div>'
    ).join('');
    $('#billing-note').textContent = data?.enabled
      ? 'By purchasing, you agree that credits are non-refundable once used and buy automated, AI-driven guidance only. Pre-Flight does not provide certified legal counsel, formal security guarantees, or guaranteed app-store approval. Payments are processed securely by Stripe.'
      : 'Card payments are not enabled yet. Every new account still gets ' + (data?.freeCredits ?? 3) + ' free AI scan credits, and local scans are always free.';
    packsEl.querySelectorAll('button[data-pack]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!(await ensureSignedIn())) return;
        (btn as HTMLButtonElement).disabled = true;
        try {
          const { data: co } = await api.post('/api/billing/checkout', { pack: (btn as HTMLElement).dataset.pack });
          if (co?.url) window.location.href = co.url;
          else toast('Could not start checkout.');
        } catch (err: any) {
          toast(apiErrorMessage(err, 'Could not start checkout.'));
        } finally {
          (btn as HTMLButtonElement).disabled = false;
        }
      });
    });
  } catch {
    $('#billing-note').textContent = 'Billing status is unavailable right now. Local scans still work.';
  }
}

async function loadHistory(): Promise<void> {
  if (!auth.isSignedIn()) return;
  try {
    const { data } = await api.get('/api/reports');
    const reports = data?.reports || [];
    const card = $('#history-card');
    if (!reports.length) { card.hidden = true; return; }
    card.hidden = false;
    const list = $('#history-list');
    list.innerHTML = reports.map((r: any, i: number) =>
      '<li data-idx="' + i + '"><span>' + escapeHtml(r.appName || 'Untitled app') + ' · ' + new Date(r.createdAt).toLocaleDateString() + '</span><span class="h-scores">S ' + r.scores.safety + ' · L ' + r.scores.legal + ' · M ' + r.scores.marketing + '</span></li>'
    ).join('');
    list.querySelectorAll('li').forEach(li => {
      li.addEventListener('click', () => {
        const r = reports[Number((li as HTMLElement).dataset.idx)];
        if (r) renderReport({ appName: r.appName, mode: 'ai', scores: r.scores, findings: r.findings, createdAt: r.createdAt });
      });
    });
  } catch { /* history is non-critical */ }
}

function downloadReport(): void {
  if (!lastReport) return;
  const r = lastReport;
  const section = (cat: Category) => '<h2>' + CAT_LABEL[cat] + ' - ' + (r.scores as any)[cat] + '/100</h2><ul>' + r.findings.filter(x => x.category === cat).map(x => '<li><b>[' + SEV_LABEL[x.severity] + '] ' + escapeHtml(x.title) + '</b><br>' + escapeHtml(x.detail) + '</li>').join('') + '</ul>';
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SHIFT Pre-Flight Report - ' + escapeHtml(r.appName || 'Untitled app') + '</title><style>body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#1a1a24;line-height:1.6}.banner{background:#fff7e0;border:1px solid #e0c060;border-radius:8px;padding:12px 16px;font-size:.85rem}h2{margin-top:2em;border-bottom:1px solid #ddd;padding-bottom:4px}li{margin-bottom:.8em}</style></head><body><h1>SHIFT Pre-Flight - Automated Assessment</h1><p><b>Product audited:</b> ' + escapeHtml(r.appName || 'Untitled app') + '<br><b>Mode:</b> ' + (r.mode === 'ai' ? 'AI Deep Scan' : 'Local rule-based scan') + '<br><b>Scan date:</b> ' + new Date(r.createdAt).toLocaleString() + '</p><div class="banner"><b>Automated Pre-Flight Assessment Notice.</b> This document is automated analysis of provided configuration and marketing copy. It is not certified legal advice, official security auditing, or regulatory compliance verification. Independently test your code, verify current platform guidelines, and consult qualified legal counsel for binding compliance. SHIFT Pre-Flight accepts no liability for losses resulting from use of this data.</div>' + section('safety') + section('legal') + section('marketing') + '</body></html>';
  const blob = new Blob([html], { type: 'text/html' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'shift-preflight-report-' + (r.appName || 'app').toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40) + '.html';
  a.click();
  URL.revokeObjectURL(a.href);
}

const SAMPLE_ANDROID = {
  title: 'SHIFT Pre-Flight: The #1 Best App Launch Scanner Ever',
  short: 'Scan your app before launch',
  marketing: 'The best app scanner ever made! Better than ChatGPT! Scan scan scan your app app app before launch.\nUnlock premium credits to buy more scans and get the pro version upgrade today.\nTrack your location history and record voice notes with our smart assistant.',
  config: '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.shift">\n  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" />\n  <uses-permission android:name="android.permission.INTERNET" />\n  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />\n  <uses-permission android:name="android.permission.RECORD_AUDIO" />\n  <uses-permission android:name="android.permission.READ_CONTACTS" />\n  <application android:label="Shift" android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">\n    <meta-data android:name="com.example.API_KEY" android:value="AIzaSyD-EXAMPLEKEY1234567890abcdefghijk" />\n    <meta-data android:name="analytics" android:value="http://analytics.example.com/collect" />\n  </application>\n</manifest>'
};

const SAMPLE_IOS = {
  title: 'PhotoVault Pro',
  short: 'Private photo storage with smart albums',
  marketing: 'PhotoVault Pro keeps your photos organized in private, encrypted albums.\nUse your camera to capture and file documents instantly. Upgrade to a premium subscription for unlimited storage via In-App Purchase.\nWe respect your data - see our privacy policy at photovault.example/privacy. Results from smart album suggestions may contain errors; verify before deleting originals.',
  config: '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n  <key>CFBundleDisplayName</key><string>PhotoVault Pro</string>\n  <key>NSCameraUsageDescription</key><string>PhotoVault uses the camera to capture documents you choose to save.</string>\n  <key>NSPhotoLibraryUsageDescription</key><string></string>\n  <key>NSAppTransportSecurity</key>\n  <dict>\n    <key>NSAllowsArbitraryLoads</key><true/>\n  </dict>\n</dict>\n</plist>'
};

function loadSample(s: { title: string; short: string; marketing: string; config: string }): void {
  ($('#app-title') as HTMLInputElement).value = s.title;
  ($('#short-desc') as HTMLInputElement).value = s.short;
  ($('#marketing') as HTMLTextAreaElement).value = s.marketing;
  ($('#config') as HTMLTextAreaElement).value = s.config;
  ['#app-title', '#short-desc', '#marketing'].forEach(sel => $(sel).dispatchEvent(new Event('input')));
}

function bindCount(inputSel: string, countSel: string, limit: number): void {
  const input = $(inputSel) as HTMLInputElement | HTMLTextAreaElement;
  const count = $(countSel);
  const update = () => {
    count.textContent = input.value.length + ' / ' + limit;
    count.classList.toggle('over', input.value.length > limit);
  };
  input.addEventListener('input', update);
  update();
}

function init(): void {
  bindCount('#app-title', '#title-count', 30);
  bindCount('#short-desc', '#short-count', 80);
  bindCount('#marketing', '#desc-count', 4000);

  $('#scan-form').addEventListener('submit', e => { e.preventDefault(); runLocalScan(); });
  $('#deep-btn').addEventListener('click', () => { void runDeepScan(); });
  $('#sample-android').addEventListener('click', () => loadSample(SAMPLE_ANDROID));
  $('#sample-ios').addEventListener('click', () => loadSample(SAMPLE_IOS));
  $('#sample-clear').addEventListener('click', () => {
    loadSample({ title: '', short: '', marketing: '', config: '' });
    $('#results').hidden = true;
  });
  $('#download-report').addEventListener('click', downloadReport);
  $('#new-scan').addEventListener('click', () => {
    $('#results').hidden = true;
    $('#scan-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  $('#auth-btn').addEventListener('click', async () => {
    if (auth.isSignedIn()) { await auth.signOut(); await refreshAuthUI(); }
    else { await ensureSignedIn(); }
  });

  const billingParam = new URLSearchParams(window.location.search).get('billing');
  if (billingParam === 'success') {
    toast('Payment received. Your credits will appear within a moment.');
    window.history.replaceState({}, '', window.location.pathname);
    let attempts = 0;
    const poll = window.setInterval(() => {
      attempts += 1;
      void refreshWallet();
      if (attempts >= 5) window.clearInterval(poll);
    }, 3000);
  } else if (billingParam === 'cancelled') {
    toast('Checkout cancelled. No charge was made.');
    window.history.replaceState({}, '', window.location.pathname);
  }

  void refreshAuthUI();
  void loadBilling();
}

init();
