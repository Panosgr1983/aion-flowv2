/*
  ═══════════════════════════════════════════════════════════════════════════
  C3 FIX — gmail-sync/index.ts

  ΑΝΑΛΥΣΗ ΠΡΙΝ
  ─────────────
  • action='sync' (γραμμή 110): 🔴 ΜΗΔΕΝ AUTH
  • email_accounts select('*') χωρίς tenant filter → ΟΛΩΝ των tenants
  • contact_conversations/contact_messages insert χωρίς tenant_id
  • catch → String(err) → Stack trace στον client

  ΧΡΗΣΗ (μετρημένη):
  • Δεν βρέθηκε frontend caller για 'sync' — πιθανώς cron ή manual
  • Το 'auth' action δεν χρειάζεται auth (γεννά OAuth URL)
  • Το OAuth callback έχει ήδη getUser (γραμμή 72)

  ΑΠΟΦΑΣΗ
  ────────
  • sync → ΑΠΑΙΤΕΙ authenticated user με role owner/admin
  • tenant από profiles (server-side), ΟΧΙ από client
  • email_accounts: φίλτρο tenant_id
  • contact_conversations/contact_messages: tenant_id στα inserts
  • Safe errors, stack trace μόνο σε logs

  ΣΗΜΕΙΩΣΗ ΓΙΑ CRON
  ──────────────────
  Αν το sync καλείται από cron, χρειάζεται service key με ειδικό flag.
  Για τώρα: ΜΟΝΟ authenticated admin. Αν χρειαστεί cron, θα προστεθεί
  ξεχωριστό authenticated path.
  ═══════════════════════════════════════════════════════════════════════════
*/

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
};

const GOOGLE_CLIENT_ID = Deno.env.get('GOOGLE_CLIENT_ID') || '';
const GOOGLE_CLIENT_SECRET = Deno.env.get('GOOGLE_CLIENT_SECRET') || '';
const REDIRECT_URI = Deno.env.get('GOOGLE_REDIRECT_URI') ||
  `${Deno.env.get('SUPABASE_URL')}/functions/v1/gmail-sync`;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

// 🔴 Safe error — δεν εκθέτει stack trace
function safeError(status: number, code: string): Response {
  return json({ error: code }, status);
}

// HTML escape για plain-text body που μπορεί να έχει HTML
function escapeHtml(s: string): string {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 🔴 Ασφαλής sanitization: escape αντί strip
// Το escape είναι η μόνη εγγυημένα ασφαλής προσέγγιση —
// ακόμα κι αν μείνει μερικό tag, δεν εκτελείται ως HTML.
function sanitizeText(input: string): string {
  if (!input) return '';
  // 1) Αφαίρεση HTML tags με bounded loop
  let cleaned = input;
  for (let i = 0; i < 5; i++) {
    const next = cleaned.replace(/<[^>]*>/g, '');
    if (next === cleaned) break;
    cleaned = next;
  }
  // 2) Escape ΟΤΙΔΗΠΟΤΕ έχει απομείνει που μοιάζει με HTML
  return cleaned
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });

  const url = new URL(req.url);
  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
  const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const supabase = createClient(supabaseUrl, supabaseKey);

  const isGet = req.method === 'GET';

  // ─── OAuth callback (GET με ?code=) ───
  if (isGet && url.searchParams.get('code')) {
    try {
      const code = url.searchParams.get('code')!;

      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri: REDIRECT_URI,
          grant_type: 'authorization_code',
        }),
      });
      const tokens = await tokenRes.json();
      if (!tokens.access_token || !tokens.refresh_token) {
        return new Response('No refresh_token received. Try re-authorizing.', { status: 400 });
      }

      const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });
      const profile = await profileRes.json();
      if (!profile.email) {
        return new Response('Failed to retrieve email from Google', { status: 400 });
      }

      const email = profile.email;
      const jwt = req.headers.get('Authorization')?.replace('Bearer ', '') || '';
      const { data: { user } } = await supabase.auth.getUser(jwt);
      if (!user?.id) return new Response('Unauthorized', { status: 401 });

      // 🔴 Πάρε tenant από profiles
      const { data: profileRow } = await supabase
        .from('profiles')
        .select('tenant_id')
        .eq('id', user.id)
        .maybeSingle();

      if (!profileRow?.tenant_id) return new Response('No tenant', { status: 403 });

      await supabase.from('email_accounts').insert({
        email,
        provider: 'gmail',
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_expires_at: new Date(Date.now() + (tokens.expires_in || 3600) * 1000).toISOString(),
        sync_enabled: true,
        is_active: true,
        created_by: user.id,
        tenant_id: profileRow.tenant_id,   // 🔴 TENANT
      });

      return new Response(
        '<html><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#0f172a;color:#e2e8f0"><div style="text-align:center"><h2 style="color:#3b82f6">✅ Gmail Συνδεδεμένο</h2><p>Μπορείτε να κλείσετε αυτή τη σελίδα.</p></div></body></html>',
        { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...CORS_HEADERS } },
      );
    } catch (e) {
      console.error('[gmail-sync] OAuth callback error:', e instanceof Error ? e.stack : e);
      return new Response('Internal error', { status: 500 });
    }
  }

  // ─── POST actions ───
  if (req.method !== 'POST') return safeError(405, 'Method not allowed');

  let action = 'sync';
  try {
    const body = await req.json();
    action = body?.action || 'sync';
  } catch { /* default sync */ }

  // ─── Auth URL (δεν χρειάζεται auth — γεννά URL) ───
  if (action === 'auth') {
    if (!GOOGLE_CLIENT_ID) return safeError(400, 'Google OAuth not configured');
    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send');
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('prompt', 'consent');
    return json({ url: authUrl.toString() });
  }

  // ─── SYNC — 🔴 ΑΠΑΙΤΕΙ AUTH ───
  if (action === 'sync') {
    const authHeader = req.headers.get('Authorization') || '';
    const jwt = authHeader.replace(/^Bearer\s+/i, '');

    if (!jwt) return safeError(401, 'Unauthorized');

    // 1) Authenticated user
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const authClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: `Bearer ${jwt}` } },
    });

    const { data: { user }, error: authErr } = await authClient.auth.getUser(jwt);
    if (authErr || !user?.id) {
      console.error('[gmail-sync] sync auth failed:', authErr?.message);
      return safeError(401, 'Unauthorized');
    }

    // 2) Tenant + role από profiles (server-side)
    const { data: profile } = await supabase
      .from('profiles')
      .select('tenant_id, role')
      .eq('id', user.id)
      .maybeSingle();

    if (!profile?.tenant_id) return safeError(403, 'No tenant');

    // 3) Role check
    const allowedRoles = ['owner', 'admin'];
    if (!allowedRoles.includes(profile.role)) {
      return safeError(403, 'Insufficient role');
    }

    // 4) 🔴 TENANT-SCOPED query
    const { data: accounts } = await supabase
      .from('email_accounts')
      .select('*')
      .eq('tenant_id', profile.tenant_id)   // 🔴 ΚΡΙΣΙΜΟ
      .eq('is_active', true)
      .eq('sync_enabled', true);

    const results: { email: string; synced: number; error?: string }[] = [];

    for (const account of (accounts || [])) {
      try {
        let accessToken = account.access_token;

        if (account.token_expires_at && new Date(account.token_expires_at) < new Date()) {
          const refreshRes = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              refresh_token: account.refresh_token,
              client_id: GOOGLE_CLIENT_ID,
              client_secret: GOOGLE_CLIENT_SECRET,
              grant_type: 'refresh_token',
            }),
          });
          const newTokens = await refreshRes.json();
          accessToken = newTokens.access_token || accessToken;
          await supabase
            .from('email_accounts')
            .update({
              access_token: accessToken,
              token_expires_at: new Date(Date.now() + (newTokens.expires_in || 3600) * 1000).toISOString(),
            })
            .eq('id', account.id)
            .eq('tenant_id', profile.tenant_id);   // 🔴 tenant filter και στο update
        }

        const listRes = await fetch(
          `https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=20&q=is:unseen OR is:inbox after:${Math.floor(Date.now() / 1000 - 86400 * 7)}`,
          { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        const list = await listRes.json();
        const messages = list.messages || [];
        let synced = 0;

        for (const msg of messages) {
          const msgRes = await fetch(
            `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`,
            { headers: { Authorization: `Bearer ${accessToken}` } }
          );
          const full = await msgRes.json();
          const headers = full.payload?.headers || [];
          const from = headers.find((h: { name: string; value: string }) => h.name === 'From')?.value || '';
          const subject = headers.find((h: { name: string; value: string }) => h.name === 'Subject')?.value || '';

          const emailMatch = from.match(/<([^>]+)>/);
          const fromEmail = emailMatch ? emailMatch[1] : from;
          const fromName = from.replace(/<[^>]+>/, '').trim() || fromEmail;

          let body = '';
          const extract = (part: { mimeType?: string; body?: { data?: string }; parts?: unknown[] }) => {
            if (part.mimeType === 'text/plain' && part.body?.data) {
              body = atob(part.body.data.replace(/-/g, '+').replace(/_/g, '/'));
            }
            if (part.parts) (part.parts as { mimeType?: string; body?: { data?: string }; parts?: unknown[] }[]).forEach(extract);
          };
          if (full.payload) extract(full.payload);

          // 🔴 Sanitize: strip HTML tags με ασφαλή επαναληπτικό τρόπο
          body = sanitizeText(body);

          if (!body || !fromEmail) continue;

          // 5) 🔴 TENANT-SCOPED conversation lookup
          const { data: existing } = await supabase
            .from('contact_conversations')
            .select('id')
            .eq('tenant_id', profile.tenant_id)   // 🔴
            .ilike('email', fromEmail.toLowerCase())
            .eq('status', 'active')
            .limit(1);

          let convId: string;

          if (existing && existing.length > 0) {
            convId = existing[0].id;
          } else {
            convId = crypto.randomUUID();
            await supabase.from('contact_conversations').insert({
              id: convId,
              tenant_id: profile.tenant_id,      // 🔴
              email: fromEmail.toLowerCase(),
              name: fromName,
              status: 'active',
              last_message_at: new Date().toISOString(),
            });
          }

          await supabase.from('contact_messages').insert({
            tenant_id: profile.tenant_id,        // 🔴
            conversation_id: convId,
            name: fromName,
            email: fromEmail.toLowerCase(),
            subject,
            message: body,
            direction: 'incoming',
            status: 'new',
            attachments: [],
            last_message_at: new Date().toISOString(),
          });

          await fetch(
            `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}/modify`,
            {
              method: 'POST',
              headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ removeLabelIds: ['UNREAD'] }),
            }
          );
          synced++;
        }

        await supabase
          .from('email_accounts')
          .update({ last_sync_at: new Date().toISOString() })
          .eq('id', account.id)
          .eq('tenant_id', profile.tenant_id);

        results.push({ email: account.email, synced });
      } catch (err) {
        console.error('[gmail-sync] sync account error:', err instanceof Error ? err.stack : err);
        results.push({ email: account.email, synced: 0, error: 'Sync failed' });  // 🔴 safe
      }
    }

    return json({ ok: true, results });
  }

  return safeError(400, 'Unknown action');
});
