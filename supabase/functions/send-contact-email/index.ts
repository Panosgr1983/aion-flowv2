/*
  ═══════════════════════════════════════════════════════════════════════════
  C3/C4 FIX #2 — send-contact-email tenant resolution

  ΤΟ ΠΡΟΒΛΗΜΑ (εύρημα Πάνου)
  ──────────────────────────
  Πριν:
    const tenantId = Deno.env.get('TENANT_ID') || '00000000-...-001';

  Αυτό δουλεύει μόνο για single-tenant. Στο multi-tenant AION FLOW:
  • Όλα τα sites θα έστελναν σε ένα tenant
  • Ή θα χρειαζόταν ξεχωριστό edge function deployment ανά tenant

  Η ΛΥΣΗ
  ──────
  Tenant resolution από το Origin/Referer header:
    1. Πάρε Origin (ή Referer αν λείπει Origin)
    2. Extract domain
    3. `resolve_tenant_by_domain(domain)` → tenant_id
    4. Αν δεν βρεθεί → 400 (fail-closed, ΟΧΙ fallback)

  ΑΣΦΑΛΕΙΑ
  ────────
  • ΔΕΝ εμπιστευόμαστε client-supplied tenant_id
  • ΔΕΝ υπάρχει hardcoded fallback UUID
  • Αν το domain δεν έχει καταχωρηθεί → απόρριψη
  • Το frontend ΔΕΝ χρειάζεται να στείλει tenant — το domain αρκεί
  ═══════════════════════════════════════════════════════════════════════════
*/

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import nodemailer from 'npm:nodemailer@6';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

interface BasePayload {
  type: 'new' | 'reply' | 'forward';
  name?: string;
  email?: string;
  phone?: string;
  message?: string;
  subject?: string;
  to?: string;
  originalMessage?: string;
  attachments?: Array<{ name: string; contentType: string; data: string }>;
}

function safeError(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: code }), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

function validatePayload(p: unknown): { ok: true; data: BasePayload } | { ok: false; error: string } {
  if (!p || typeof p !== 'object') return { ok: false, error: 'Invalid payload' };
  const o = p as Record<string, unknown>;

  if (o.type !== 'new' && o.type !== 'reply' && o.type !== 'forward') return { ok: false, error: 'Invalid type' };
  if (!o.message || typeof o.message !== 'string' || !o.message.trim()) return { ok: false, error: 'Message required' };

  const email = o.email;
  if (email && typeof email === 'string' && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return { ok: false, error: 'Invalid email' };
  }
  if (String(o.message).length > 50000) return { ok: false, error: 'Message too long' };

  // 🔴 #4: Validation του `to` — απαγόρευση wildcards
  if (o.type === 'reply' || o.type === 'forward') {
    const to = String(o.to || '');
    if (!to) return { ok: false, error: 'Recipient required' };
    if (/[%_]/.test(to)) return { ok: false, error: 'Invalid recipient character' };
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) return { ok: false, error: 'Invalid recipient email' };
  }

  return { ok: true, data: o as unknown as BasePayload };
}

function escapeHtml(s: string): string {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 🔴 #2: Extract domain από Origin/Referer
function extractDomain(req: Request): string | null {
  const origin = req.headers.get('origin');
  const referer = req.headers.get('referer');

  const url = origin || referer;
  if (!url) return null;

  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

function clientIp(req: Request): string {
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') || 'unknown';
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });
  if (req.method !== 'POST') return safeError(405, 'Method not allowed');

  let payload: BasePayload;
  try {
    const raw = await req.json();
    const v = validatePayload(raw);
    if (!v.ok) return safeError(400, v.error);
    payload = v.data;
  } catch (e) {
    console.error('[send-contact-email] parse error:', e);
    return safeError(400, 'Invalid JSON');
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
  const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const supabase = createClient(supabaseUrl, supabaseKey);

  // ─── Auth για reply/forward ───
  const authHeader = req.headers.get('Authorization') || '';
  const jwt = authHeader.replace(/^Bearer\s+/i, '');

  let authedUser: { id: string } | null = null;
  let userTenant: string | null = null;

  if (payload.type === 'reply' || payload.type === 'forward') {
    if (!jwt) return safeError(401, 'Unauthorized');

    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const authClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: `Bearer ${jwt}` } },
    });

    const { data: { user }, error: authErr } = await authClient.auth.getUser(jwt);
    if (authErr || !user?.id) {
      console.error('[send-contact-email] auth failed:', authErr?.message);
      return safeError(401, 'Unauthorized');
    }
    authedUser = { id: user.id };

    const { data: profile } = await supabase
      .from('profiles')
      .select('tenant_id, role, is_super_admin')
      .eq('id', user.id)
      .maybeSingle();

    if (!profile?.tenant_id) return safeError(403, 'No tenant');
    if (!profile.is_super_admin && !['owner', 'admin', 'secretary'].includes(profile.role)) {
      return safeError(403, 'Insufficient role');
    }

    userTenant = profile.tenant_id;
  }

  // ─── 🔴 #2/#3: Tenant resolution + rate limit για public 'new' ───
  let tenantId: string | null = null;

  if (payload.type === 'new') {
    // Rate limit ΜΕ shared mechanism
    const ip = clientIp(req);
    const rl = await supabase.rpc('check_rate_limit', {
      p_key: `contact:${ip}`,
      p_limit: 5,
      p_window_seconds: 60,
    });
    if (rl.error) {
      console.error('[send-contact-email] rate limit RPC error:', rl.error.message);
      // fail-open: να μη σπάσει η φόρμα
    } else if (rl.data === false) {
      return safeError(429, 'Too many requests');
    }

    // 🔴 Tenant από domain
    const domain = extractDomain(req);
    if (!domain) {
      console.error('[send-contact-email] no Origin/Referer header');
      return safeError(400, 'Cannot determine site');
    }

    const r = await supabase.rpc('resolve_tenant_by_domain', { p_domain: domain });
    if (r.error) {
      console.error('[send-contact-email] domain resolve error:', r.error.message);
      return safeError(500, 'Internal error');
    }
    if (!r.data) {
      console.error('[send-contact-email] unknown domain:', domain);
      return safeError(403, 'Site not configured');
    }
    tenantId = r.data;
  } else {
    tenantId = userTenant;
  }

  if (!tenantId) return safeError(400, 'Cannot determine tenant');

  try {
    const { data: settings } = await supabase
      .from('site_settings')
      .select('key, value')
      .eq('tenant_id', tenantId)
      .in('key', [
        'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass',
        'smtp_from_email', 'smtp_from_name', 'contact_email', 'site_name',
      ]);

    const map: Record<string, string> = {};
    (settings || []).forEach((s: { key: string; value: unknown }) => {
      map[s.key] = typeof s.value === 'string' ? s.value : String(s.value || '');
    });

    const host = map['smtp_host'];
    const port = parseInt(map['smtp_port'] || '587', 10);
    const user = map['smtp_user'];
    const pass = map['smtp_pass'];
    const fromEmail = map['smtp_from_email'] || user;
    const fromName = map['smtp_from_name'] || map['site_name'] || '';
    const contactEmail = map['contact_email'];

    if (!host || !user || !pass) return safeError(503, 'Email service not configured');

    const transporter = nodemailer.createTransport({ host, port, secure: port === 465, auth: { user, pass } });

    let mailOptions: Record<string, unknown>;

    if (payload.type === 'reply') {
      const target = (payload.to || '').trim().toLowerCase();

      // 🔴 #4: Exact match (eq, ΟΧΙ ilike)
      const { data: contact } = await supabase
        .from('contact_messages')
        .select('id')
        .eq('tenant_id', tenantId)
        .eq('email', target)
        .limit(1)
        .maybeSingle();

      if (!contact) {
        const { data: conv } = await supabase
          .from('contact_conversations')
          .select('id')
          .eq('tenant_id', tenantId)
          .eq('email', target)
          .limit(1)
          .maybeSingle();

        if (!conv) {
          console.warn('[send-contact-email] reply blocked: unknown recipient', target);
          return safeError(403, 'Recipient not found in tenant');
        }
      }

      mailOptions = {
        from: `${fromName} <${fromEmail}>`,
        to: target,
        replyTo: payload.email || fromEmail,
        subject: payload.subject || 'Απάντηση',
        text: payload.message,
        attachments: (payload.attachments || []).map(a => ({
          filename: a.name, content: Buffer.from(a.data, 'base64'), contentType: a.contentType,
        })),
      };
    } else if (payload.type === 'forward') {
      const target = (payload.to || '').trim().toLowerCase();

      const { data: contact } = await supabase
        .from('contact_conversations')
        .select('id')
        .eq('tenant_id', tenantId)
        .eq('email', target)
        .limit(1)
        .maybeSingle();

      if (!contact) {
        const { data: msg } = await supabase
          .from('contact_messages')
          .select('id')
          .eq('tenant_id', tenantId)
          .eq('email', target)
          .limit(1)
          .maybeSingle();
        if (!msg) return safeError(403, 'Recipient not found in tenant');
      }

      mailOptions = {
        from: `${fromName} <${fromEmail}>`,
        to: target,
        replyTo: fromEmail,
        subject: payload.subject || 'Προώθηση',
        text: `${payload.message}\n\n--- Αρχικό μήνυμα ---\n${payload.originalMessage || ''}`,
        attachments: (payload.attachments || []).map(a => ({
          filename: a.name, content: Buffer.from(a.data, 'base64'), contentType: a.contentType,
        })),
      };
    } else {
      // type = 'new' — public form
      if (!contactEmail) return safeError(503, 'Contact email not configured');

      const safeName = escapeHtml(payload.name || 'Επισκέπτης');
      const safeEmail = escapeHtml(payload.email || '');
      const safePhone = escapeHtml(payload.phone || '');
      const safeMessage = escapeHtml(payload.message || '').replace(/\n/g, '<br>');

      mailOptions = {
        from: `${fromName} <${fromEmail}>`,
        to: contactEmail,   // 🔴 ΜΟΝΟ ο configured παραλήπτης
        replyTo: payload.email || fromEmail,
        subject: `Νέο μήνυμα από ${safeName}`,
        html: `
          <div style="font-family:sans-serif;max-width:600px">
            <h2>Νέο μήνυμα φόρμας επικοινωνίας</h2>
            <table style="border-collapse:collapse;width:100%">
              <tr><td style="padding:8px;background:#f3f4f6;font-weight:600">Όνομα</td><td style="padding:8px">${safeName}</td></tr>
              <tr><td style="padding:8px;background:#f3f4f6;font-weight:600">Email</td><td style="padding:8px">${safeEmail}</td></tr>
              ${safePhone ? `<tr><td style="padding:8px;background:#f3f4f6;font-weight:600">Τηλέφωνο</td><td style="padding:8px">${safePhone}</td></tr>` : ''}
            </table>
            <div style="margin-top:16px;padding:12px;background:#f9fafb;border-left:3px solid #2545F0">
              ${safeMessage}
            </div>
          </div>`,
      };
    }

    await transporter.sendMail(mailOptions);

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    });
  } catch (e) {
    console.error('[send-contact-email] fatal:', e instanceof Error ? e.stack : e);
    return safeError(500, 'Internal error');
  }
});
