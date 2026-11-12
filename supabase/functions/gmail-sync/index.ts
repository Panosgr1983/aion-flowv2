/*
  ═══════════════════════════════════════════════════════════════════════════
  C3/C4 FIX v2 — gmail-sync/index.ts

  ΔΙΟΡΘΩΣΕΙΣ ΑΠΟ ΤΟΝ ΕΛΕΓΧΟ ΤΟΥ ΠΑΝΟΥ
  ─────────────────────────────────────
  #1 OAuth state flow:
     • Πριν: το callback περίμενε Authorization header → ΔΕΝ έρχεται
       σε browser redirect → ΣΠΑΣΜΕΝΟ
     • Τώρα: state token με {userId, tenantId}, αποθηκευμένο server-side
       → validate στο callback → κανένα header χρειάζεται

  #3 Shared rate limit:
     • Πριν: in-memory Map (κάθε instance ξεχωριστά)
     • Τώρα: PostgreSQL table `rate_limits` (shared σε όλα τα instances)

  #4 Exact email match:
     • Πριν: .ilike('email', target) — wildcards % _ ΔΟΥΛΕΥΟΥΝ
     • Τώρα: .eq() + validation ότι δεν υπάρχουν % ή _

  #5 Fail-closed:
     • Αν δεν υπάρχει state → 400, όχι fallback
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

function safeError(status: number, code: string): Response {
  return json({ error: code }, status);
}

// 🔴 #4: Exact email match — απαγόρευση wildcards
function isValidEmailExact(email: string): boolean {
  if (!email || typeof email !== 'string') return false;
  // Απόρριψη wildcards
  if (/[%_]/.test(email)) return false;
  // Αυστηρό email regex
  return /^[a-zA-Z0-9.!#$&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(email);
}

// 🔴 Sanitization: escape-only (CodeQL-safe)
function sanitizeText(input: string): string {
  if (!input) return '';
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 🔴 #3: Shared rate limit μέσω PostgreSQL
async function checkRateLimit(
  supabase: ReturnType<typeof createClient>,
  key: string,
  limit: number,
  windowSeconds: number
): Promise<boolean> {
  try {
    const { data, error } = await supabase.rpc('check_rate_limit', {
      p_key: key,
      p_limit: limit,
      p_window_seconds: windowSeconds,
    });
    if (error) {
      console.error('[rate-limit] RPC error:', error.message);
      // Fail-open για rate limit (να μη σπάσει η υπηρεσία)
      return true;
    }
    return data === true;
  } catch (e) {
    console.error('[rate-limit] exception:', e);
    return true;
  }
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });

  const url = new URL(req.url);
  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
  const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const supabase = createClient(supabaseUrl, supabaseKey);

  const isGet = req.method === 'GET';

  // ══════════════════════════════════════════════════════════════
  // #1 OAuth callback — μέσω state token, ΟΧΙ Authorization header
  // ══════════════════════════════════════════════════════════════
  if (isGet && url.searchParams.get('code')) {
    try {
      const code = url.searchParams.get('code')!;
      const state = url.searchParams.get('state');

      // 🔴 ΑΠΑΙΤΕΙΤΑΙ state — fail-closed
      if (!state) {
        console.error('[gmail-sync] OAuth callback χωρίς state');
        return new Response('Missing state parameter. Please restart the connection.', { status: 400 });
      }

      // Validate state
      const { data: stateRow, error: stateErr } = await supabase
        .from('oauth_states')
        .select('user_id, tenant_id, expires_at, used_at')
        .eq('state', state)
        .maybeSingle();

      if (stateErr || !stateRow) {
        console.error('[gmail-sync] Invalid state:', stateErr?.message);
        return new Response('Invalid or expired state. Please restart the connection.', { status: 400 });
      }
      if (stateRow.used_at) {
        return new Response('State already used.', { status: 400 });
      }
      if (new Date(stateRow.expires_at) < new Date()) {
        return new Response('State expired. Please restart the connection.', { status: 400 });
      }

      // Mark as used (one-time)
      await supabase
        .from('oauth_states')
        .update({ used_at: new Date().toISOString() })
        .eq('state', state);

      const userId = stateRow.user_id;
      const tenantId = stateRow.tenant_id;

      // Exchange code for tokens
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
      const gprofile = await profileRes.json();
      if (!gprofile.email) {
        return new Response('Failed to retrieve email from Google', { status: 400 });
      }

      // Verify role: μόνο owner/admin μπορούν να συνδέσουν Gmail
      const { data: userProfile } = await supabase
        .from('profiles')
        .select('role, is_super_admin')
        .eq('id', userId)
        .maybeSingle();

      if (!userProfile || (!userProfile.is_super_admin && !['owner', 'admin'].includes(userProfile.role))) {
        console.error('[gmail-sync] Insufficient role for Gmail connect:', userProfile?.role);
        return new Response('Insufficient permissions to connect Gmail.', { status: 403 });
      }

      // Insert email account
      await supabase.from('email_accounts').insert({
        email: gprofile.email,
        provider: 'gmail',
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_expires_at: new Date(Date.now() + (tokens.expires_in || 3600) * 1000).toISOString(),
        sync_enabled: true,
        is_active: true,
        created_by: userId,
        tenant_id: tenantId,
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

  // ══════════════════════════════════════════════════════════════
  // Auth URL — τώρα με state token
  // ══════════════════════════════════════════════════════════════
  if (action === 'auth') {
    if (!GOOGLE_CLIENT_ID) return safeError(400, 'Google OAuth not configured');

    // 🔴 Απαιτεί authenticated user
    const authHeader = req.headers.get('Authorization') || '';
    const jwt = authHeader.replace(/^Bearer\s+/i, '');
    if (!jwt) return safeError(401, 'Unauthorized');

    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const authClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: `Bearer ${jwt}` } },
    });
    const { data: { user } } = await authClient.auth.getUser(jwt);
    if (!user?.id) return safeError(401, 'Unauthorized');

    // Πάρε tenant
    const { data: profile } = await supabase
      .from('profiles')
      .select('tenant_id, role, is_super_admin')
      .eq('id', user.id)
      .maybeSingle();

    if (!profile?.tenant_id) return safeError(403, 'No tenant');
    if (!profile.is_super_admin && !['owner', 'admin'].includes(profile.role)) {
      return safeError(403, 'Insufficient role');
    }

    // Δημιουργία state
    const stateBytes = new Uint8Array(32);
    crypto.getRandomValues(stateBytes);
    const state = btoa(String.fromCharCode(...stateBytes))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    const { error: insErr } = await supabase.from('oauth_states').insert({
      state,
      user_id: user.id,
      tenant_id: profile.tenant_id,
      provider: 'gmail',
    });

    if (insErr) {
      console.error('[gmail-sync] state insert failed:', insErr.message);
      return safeError(500, 'Failed to create OAuth state');
    }

    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send');
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('prompt', 'consent');
    authUrl.searchParams.set('state', state);   // 🔴

    return json({ url: authUrl.toString() });
  }

  // ══════════════════════════════════════════════════════════════
  // SYNC — authenticated, tenant-scoped, rate-limited
  // ══════════════════════════════════════════════════════════════
  if (action === 'sync') {
    const authHeader = req.headers.get('Authorization') || '';
    const jwt = authHeader.replace(/^Bearer\s+/i, '');
    if (!jwt) return safeError(401, 'Unauthorized');

    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const authClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: `Bearer ${jwt}` } },
    });

    const { data: { user }, error: authErr } = await authClient.auth.getUser(jwt);
    if (authErr || !user?.id) {
      console.error('[gmail-sync] sync auth failed:', authErr?.message);
      return safeError(401, 'Unauthorized');
    }

    const { data: profile } = await supabase
      .from('profiles')
      .select('tenant_id, role, is_super_admin')
      .eq('id', user.id)
      .maybeSingle();

    if (!profile?.tenant_id) return safeError(403, 'No tenant');
    if (!profile.is_super_admin && !['owner', 'admin'].includes(profile.role)) {
      return safeError(403, 'Insufficient role');
    }

    // 🔴 #3: Shared rate limit (10 syncs/λεπτό ανά tenant)
    const rateOk = await checkRateLimit(supabase, `sync:${profile.tenant_id}`, 10, 60);
    if (!rateOk) return safeError(429, 'Too many sync requests');

    // 🔴 TENANT-SCOPED
    const { data: accounts } = await supabase
      .from('email_accounts')
      .select('*')
      .eq('tenant_id', profile.tenant_id)
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
            .eq('tenant_id', profile.tenant_id);
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
          const fromName = sanitizeText(from) || sanitizeText(fromEmail);

          // 🔴 #4: Validation από email
          if (!isValidEmailExact(fromEmail)) {
            console.warn('[gmail-sync] Skipping invalid sender email:', fromEmail.slice(0, 50));
            continue;
          }

          let body = '';
          const extract = (part: { mimeType?: string; body?: { data?: string }; parts?: unknown[] }) => {
            if (part.mimeType === 'text/plain' && part.body?.data) {
              body = atob(part.body.data.replace(/-/g, '+').replace(/_/g, '/'));
            }
            if (part.parts) (part.parts as { mimeType?: string; body?: { data?: string }; parts?: unknown[] }[]).forEach(extract);
          };
          if (full.payload) extract(full.payload);

          if (!body) continue;

          // 🔴 #4: Exact email match (eq, όχι ilike)
          const normalizedEmail = fromEmail.toLowerCase();

          const { data: existing } = await supabase
            .from('contact_conversations')
            .select('id')
            .eq('tenant_id', profile.tenant_id)
            .eq('email', normalizedEmail)   // 🔴 eq, ΟΧΙ ilike
            .eq('status', 'active')
            .limit(1);

          let convId: string;

          if (existing && existing.length > 0) {
            convId = existing[0].id;
          } else {
            convId = crypto.randomUUID();
            await supabase.from('contact_conversations').insert({
              id: convId,
              tenant_id: profile.tenant_id,
              email: normalizedEmail,
              name: sanitizeText(fromName),
              status: 'active',
              last_message_at: new Date().toISOString(),
            });
          }

          await supabase.from('contact_messages').insert({
            tenant_id: profile.tenant_id,
            conversation_id: convId,
            name: sanitizeText(fromName),
            email: normalizedEmail,
            subject: sanitizeText(subject),
            message: sanitizeText(body),
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
        results.push({ email: account.email, synced: 0, error: 'Sync failed' });
      }
    }

    return json({ ok: true, results });
  }

  return safeError(400, 'Unknown action');
});
