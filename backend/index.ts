import { router, json, error, requireAuth, secrets, db, ai } from '@appdeploy/sdk';

const FREE_CREDITS = 3;
const APP_ORIGIN = 'https://5b5170f25781d9d9dc.v2.appdeploy.ai';

const PACKS: Record<string, { credits: number; amount: number; label: string }> = {
  single: { credits: 1, amount: 150, label: 'SHIFT Pre-Flight - 1 AI scan credit' },
  developer: { credits: 5, amount: 500, label: 'SHIFT Pre-Flight - 5 AI scan credits' },
  studio: { credits: 10, amount: 900, label: 'SHIFT Pre-Flight - 10 AI scan credits' }
};

type Wallet = { id: string; userId: string; credits: number };

async function getWallet(userId: string): Promise<Wallet> {
  const { items } = await db.list<Wallet>('wallets', { filter: { userId } });
  if (items.length > 0) return { id: items[0].id, userId, credits: Number(items[0].credits) || 0 };
  const [id] = await db.add('wallets', [{ userId, credits: FREE_CREDITS }]);
  if (!id) throw new Error('Failed to create wallet');
  return { id, userId, credits: FREE_CREDITS };
}

const SCAN_SYSTEM = 'You are an automated software launch compliance inspector for SHIFT Pre-Flight. Analyze the app configuration and marketing metadata provided. Evaluate three pillars. safety: hardcoded secrets or API keys, insecure flags such as debuggable or cleartext traffic, risky permissions, outdated target SDK levels. legal: digital goods or purchases mentioned without Google Play Billing or Apple In-App Purchase (flag as high severity store-policy violation), missing privacy policy, high-privilege permissions with no user-facing justification in the marketing copy (flag as privacy compliance gap under CCPA and GDPR data minimization), COPPA exposure when copy targets children. marketing: store metadata limits (title 30 chars, short description 80, full description 4000 on Google Play), keyword stuffing, trademarked competitor names used in copy such as like Uber for food (flag as trademark infringement risk), unverifiable superlative claims. Score each pillar 0-100 where 100 is launch ready. Severity meanings: high = likely rejection or security incident, warn = fix before launch, info = advisory, pass = a check that succeeded. Reference the exact text you found. Do not invent findings. If input for a pillar is missing, score that pillar 70 and add an info finding saying the input was missing.';

const SCAN_SCHEMA = {
  type: 'object',
  properties: {
    scores: {
      type: 'object',
      properties: { safety: { type: 'number' }, legal: { type: 'number' }, marketing: { type: 'number' } },
      required: ['safety', 'legal', 'marketing']
    },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          category: { type: 'string', enum: ['safety', 'legal', 'marketing'] },
          severity: { type: 'string', enum: ['high', 'warn', 'info', 'pass'] },
          title: { type: 'string' },
          detail: { type: 'string' }
        },
        required: ['category', 'severity', 'title', 'detail']
      }
    }
  },
  required: ['scores', 'findings']
};

function clampScore(v: unknown): number {
  const n = Math.round(Number(v));
  if (!Number.isFinite(n)) return 70;
  return Math.max(0, Math.min(100, n));
}

function decodeRawBody(event: any): string {
  const g = globalThis as any;
  if (typeof event?.body !== 'string') return '';
  if (!event.isBase64Encoded) return event.body;
  const bin = g.atob(event.body);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function hmacHex(secret: string, payload: string): Promise<string> {
  const subtle = (globalThis as any).crypto.subtle;
  const enc = new TextEncoder();
  const key = await subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await subtle.sign('HMAC', key, enc.encode(payload));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export const handler = router({
  'GET /api/_healthcheck': [async () => json({ message: 'Success', product: 'SHIFT Pre-Flight' })],

  'GET /api/billing/status': [async () => {
    const names = await secrets.listSecretNames();
    return json({
      enabled: names.includes('STRIPE_SECRET_KEY'),
      webhookReady: names.includes('STRIPE_WEBHOOK_SECRET'),
      freeCredits: FREE_CREDITS,
      packs: Object.entries(PACKS).map(([id, p]) => ({ id, credits: p.credits, priceCents: p.amount, label: p.label }))
    });
  }],

  'GET /api/wallet': [requireAuth(), async (ctx) => {
    const wallet = await getWallet(ctx.user!.userId);
    return json({ credits: wallet.credits });
  }],

  'GET /api/reports': [requireAuth(), async (ctx) => {
    const { items } = await db.list('reports', { filter: { userId: ctx.user!.userId } });
    const reports = items
      .map((r: any) => ({ id: r.id, appName: r.appName, scores: r.scores, findings: r.findings, createdAt: r.createdAt }))
      .sort((a: any, b: any) => (b.createdAt || 0) - (a.createdAt || 0))
      .slice(0, 25);
    return json({ reports });
  }],

  'POST /api/deep-scan': [requireAuth(), async (ctx) => {
    const body = (ctx.body || {}) as { appName?: string; config?: string; marketing?: string };
    const config = typeof body.config === 'string' ? body.config.slice(0, 30000) : '';
    const marketing = typeof body.marketing === 'string' ? body.marketing.slice(0, 8000) : '';
    const appName = typeof body.appName === 'string' && body.appName.trim() ? body.appName.trim().slice(0, 100) : 'Untitled app';
    if (!config.trim() && !marketing.trim()) return error('Provide app configuration or marketing text to scan.', 400);

    const wallet = await getWallet(ctx.user!.userId);
    if (wallet.credits < 1) return error('Insufficient scan credits. Please top up your wallet.', 402);

    let scores: { safety: number; legal: number; marketing: number };
    let findings: Array<{ category: string; severity: string; title: string; detail: string }>;
    try {
      const result = await ai.generate({
        system: SCAN_SYSTEM,
        prompt: 'APP NAME: ' + appName + '\n\nCONFIGURATION:\n' + (config || '(not provided)') + '\n\nMARKETING COPY:\n' + (marketing || '(not provided)'),
        schema: SCAN_SCHEMA,
        maxTokens: 6000,
        temperature: 0.2,
        thinkingMode: 'FAST'
      });
      const parsed = JSON.parse(result.text);
      scores = {
        safety: clampScore(parsed?.scores?.safety),
        legal: clampScore(parsed?.scores?.legal),
        marketing: clampScore(parsed?.scores?.marketing)
      };
      findings = Array.isArray(parsed?.findings)
        ? parsed.findings
            .filter((x: any) => x && typeof x.title === 'string' && typeof x.detail === 'string')
            .map((x: any) => ({
              category: ['safety', 'legal', 'marketing'].includes(x.category) ? x.category : 'safety',
              severity: ['high', 'warn', 'info', 'pass'].includes(x.severity) ? x.severity : 'info',
              title: String(x.title).slice(0, 200),
              detail: String(x.detail).slice(0, 1200)
            }))
            .slice(0, 40)
        : [];
    } catch (err) {
      console.error('Deep scan AI call failed', err instanceof Error ? err.message : 'unknown');
      return error('The AI deep scan could not be completed. No credit was used. Please try again.', 502);
    }

    const [ok] = await db.update('wallets', [{ id: wallet.id, record: { userId: wallet.userId, credits: wallet.credits - 1 } }]);
    if (!ok) console.error('Credit deduction failed for wallet', wallet.id);
    const createdAt = Date.now();
    await db.add('reports', [{ userId: ctx.user!.userId, appName, scores, findings, createdAt }]);

    return json({ report: { appName, scores, findings, createdAt, mode: 'ai' }, credits: wallet.credits - 1 });
  }],

  'POST /api/billing/checkout': [requireAuth(), async (ctx) => {
    const pack = String((ctx.body as any)?.pack || '');
    const chosen = PACKS[pack];
    if (!chosen) return error('Unknown credit pack.', 400);
    const names = await secrets.listSecretNames();
    if (!names.includes('STRIPE_SECRET_KEY')) {
      return error('Payments are not enabled yet. Free scan credits still work.', 503);
    }
    const key = await secrets.readSecret('STRIPE_SECRET_KEY');
    const params = new URLSearchParams();
    params.set('mode', 'payment');
    params.set('success_url', APP_ORIGIN + '/?billing=success');
    params.set('cancel_url', APP_ORIGIN + '/?billing=cancelled');
    params.set('line_items[0][price_data][currency]', 'usd');
    params.set('line_items[0][price_data][product_data][name]', chosen.label);
    params.set('line_items[0][price_data][unit_amount]', String(chosen.amount));
    params.set('line_items[0][quantity]', '1');
    params.set('metadata[userId]', ctx.user!.userId);
    params.set('metadata[credits]', String(chosen.credits));
    params.set('metadata[pack]', pack);
    try {
      const resp = await fetch('https://api.stripe.com/v1/checkout/sessions', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString()
      });
      const session = (await resp.json()) as any;
      if (!resp.ok || !session?.url) {
        console.error('Stripe checkout creation failed', resp.status, session?.error?.type || 'unknown');
        return error('Could not start checkout. Please try again shortly.', 502);
      }
      return json({ url: session.url });
    } catch (err) {
      console.error('Stripe request error', err instanceof Error ? err.message : 'unknown');
      return error('Could not reach the payment service.', 502);
    }
  }],

  'POST /api/billing/webhook': [async (ctx) => {
    const names = await secrets.listSecretNames();
    if (!names.includes('STRIPE_WEBHOOK_SECRET')) return error('Webhook not configured.', 503);
    const whsec = await secrets.readSecret('STRIPE_WEBHOOK_SECRET');

    const raw = decodeRawBody(ctx.event);
    if (!raw) return error('Empty payload.', 400);
    const headers = (ctx.event?.headers || {}) as Record<string, string | undefined>;
    const sigHeader = headers['stripe-signature'] || headers['Stripe-Signature'] || '';
    let timestamp = '';
    const signatures: string[] = [];
    for (const part of sigHeader.split(',')) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      const k = part.slice(0, eq).trim();
      const v = part.slice(eq + 1).trim();
      if (k === 't') timestamp = v;
      if (k === 'v1') signatures.push(v);
    }
    if (!timestamp || signatures.length === 0) return error('Missing signature.', 400);

    const expected = await hmacHex(whsec, timestamp + '.' + raw);
    if (!signatures.some(sig => constantTimeEqual(sig, expected))) {
      console.error('Webhook signature verification failed');
      return error('Invalid signature.', 400);
    }

    let evt: any;
    try { evt = JSON.parse(raw); } catch { return error('Invalid JSON payload.', 400); }

    if (evt?.type === 'checkout.session.completed') {
      const session = evt.data?.object;
      const sessionId = typeof session?.id === 'string' ? session.id : '';
      const userId = typeof session?.metadata?.userId === 'string' ? session.metadata.userId : '';
      const credits = parseInt(session?.metadata?.credits, 10);
      if (sessionId && userId && Number.isFinite(credits) && credits > 0 && credits <= 100) {
        const { items: existing } = await db.list('transactions', { filter: { sessionId } });
        if (existing.length === 0) {
          await db.add('transactions', [{ sessionId, userId, credits, amountTotal: Number(session?.amount_total) || 0, status: 'completed', createdAt: Date.now() }]);
          const wallet = await getWallet(userId);
          const [ok] = await db.update('wallets', [{ id: wallet.id, record: { userId, credits: wallet.credits + credits } }]);
          if (!ok) console.error('Credit grant failed for wallet', wallet.id);
        }
      } else {
        console.error('Webhook session missing usable metadata');
      }
    }
    return json({ received: true });
  }]
});
