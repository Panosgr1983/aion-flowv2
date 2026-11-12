/*
  ═══════════════════════════════════════════════════════════════════════════
  C4 FIX — send-contact-email/index.ts

  ΑΝΑΛΥΣΗ ΠΡΙΝ ΤΗ ΔΙΟΡΘΩΣΗ
  ─────────────────────────
  3 τύποι κλήσης:
    • type='reply'   → to: payload.to   ← 🔴 ΑΥΘΑΙΡΕΤΟΣ ΠΑΡΑΛΗΠΤΗΣ
    • type='forward' → to: payload.to   ← 🔴 ΑΥΘΑΙΡΕΤΟΣ ΠΑΡΑΛΗΠΤΗΣ
    • type='new'     → to: contact_email ← ✅ από settings

  Όλες καλούνται με ANON KEY από το frontend:
    headers: { Authorization: `Bearer ${ANON_KEY}` }

  Χρήση (μετρημένη):
    • ComposeWindow.tsx:132  → type='reply'
    • ThreadView.tsx:94      → type='forward'
    • dataHelpers.ts:710     → type='reply'
    • dataHelpers.ts:790     → type='new' (health check)

  ΑΠΟΦΑΣΗ
  ────────
  • type='reply' / 'forward' = CRM ADMIN λειτουργία
    → ΑΠΑΙΤΕΙ authenticated user με role owner/admin/secretary
    → Ο παραλήπτης πρέπει να είναι υπαρκτή επαφή του tenant

  • type='new' = δημόσια φόρμα επικοινωνίας
    → Παραμένει δημόσια
    → ΑΛΛΑ: rate limiting + lock στον configured contact_email
    → Χωρίς auth (γιατί είναι public form)

  ΑΣΦΑΛΕΙΑ
  ────────
  • Καμία service-role query χωρίς tenant filter
  • Stack traces μόνο σε server logs
  • Safe error messages στον client
  ═══════════════════════════════════════════════════════════════════════════
*/

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import nodemailer from 'npm:nodemailer@6';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

// ─── Types ───
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

// ─── Safe error helper (δεν εκθέτει stack trace) ───
function safeError(status: number, code: string): Response {
  return new Response(
    JSON.stringify({ error: code }),
    { status, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' } }
  );
}

// ─── Validation ───
function validatePayload(p: unknown): { ok: true; data: BasePayload } | { ok: false; error: string } {
  if (!p || typeof p !== 'object') return { ok: false, error: 'Invalid payload' };
  const o = p as Record<string, unknown>;

  const type = o.type;
  if (type !== 'new' && type !== 'reply' && type !== 'forward') {
    return { ok: false, error: 'Invalid type' };
  }

  if (!o.message || typeof o.message !== 'string' || !o.message.trim()) {
    return { ok: false, error: 'Message required' };
  }

  // Email format check
  const email = o.email;
  if (email && typeof email === 'string' && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return { ok: false, error: 'Invalid email' };
  }

  // Message length limit (anti-abuse)
  if (String(o.message).length > 50000) {
    return { ok: false, error: 'Message too long' };
  }

  return { ok: true, data: o as unknown as BasePayload };
}

// ─── HTML escape (αντί για regex strip) ───
function escapeHtml(s: string): string {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ─── Simple in-memory rate limiter ───
// Σημείωση: στα Supabase edge functions κάθε instance έχει δικό του memory.
// Επαρκές για basic protection. Για production-scale: Redis/Upstash.
const rateBuckets = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const b = rateBuckets.get(key);

  if (!b || now > b.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  if (b.count >= limit) return false;
  b.count++;
  return true;
}

function clientIp(req: Request): string {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    'unknown'
  );
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (req.method !== 'POST') {
    return safeError(405, 'Method not allowed');
  }

  // ─── Parse + validate ───
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

  // ─── Auth check για reply/forward ───
  const authHeader = req.headers.get('Authorization') || '';
  const jwt = authHeader.replace(/^Bearer\s+/i, '');

  let authedUser: { id: string } | null = null;
  let userTenant: string | null = null;
  let userRole: string | null = null;

  if (payload.type === 'reply' || payload.type === 'forward') {
    // 🔴 ADMIN-ONLY: απαιτείται authenticated user
    if (!jwt) return safeError(401, 'Unauthorized');

    const url = Deno.env.get('SUPABASE_URL')!;
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const authClient = createClient(url, anonKey, {
      global: { headers: { Authorization: `Bearer ${jwt}` } },
    });

    const { data: { user }, error: authErr } = await authClient.auth.getUser(jwt);
    if (authErr || !user?.id) {
      console.error('[send-contact-email] auth failed:', authErr?.message);
      return safeError(401, 'Unauthorized');
    }
    authedUser = { id: user.id };

    // Πάρε tenant + role από profiles (server-side, όχι client-supplied)
    const svc = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
    const { data: profile } = await svc
      .from('profiles')
      .select('tenant_id, role')
      .eq('id', user.id)
      .maybeSingle();

    if (!profile?.tenant_id) return safeError(403, 'No tenant');

    const allowedRoles = ['owner', 'admin', 'secretary'];
    if (!allowedRoles.includes(profile.role)) {
      return safeError(403, 'Insufficient role');
    }

    userTenant = profile.tenant_id;
    userRole = profile.role;
  }

  // ─── Rate limit για public 'new' ───
  if (payload.type === 'new') {
    const ip = clientIp(req);
    if (!checkRateLimit(`new:${ip}`, 5, 60_000)) {
      return safeError(429, 'Too many requests');
    }
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // 🔴 TENANT: για reply/forward από τον authenticated user
    //           για 'new' από env (public form, single-tenant default)
    const tenantId = userTenant || Deno.env.get('TENANT_ID') || '00000000-0000-0000-0000-000000000001';

    const { data: settings } = await supabase
      .from('site_settings')
      .select('key, value')
      .eq('tenant_id', tenantId)   // 🔴 πάντα φιλτραρισμένο
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

    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
    });

    let mailOptions: Record<string, unknown>;

    if (payload.type === 'reply') {
      // 🔴 Ο παραλήπτης πρέπει να είναι υπαρκτή επαφή του ΙΔΙΟΥ tenant
      const target = (payload.to || '').trim().toLowerCase();
      if (!target) return safeError(400, 'Recipient required');

      const { data: contact } = await supabase
        .from('contact_messages')
        .select('id')
        .eq('tenant_id', tenantId)                    // 🔴 tenant filter
        .ilike('email', target)
        .limit(1)
        .maybeSingle();

      if (!contact) {
        // Επίσης δέξου conversations
        const { data: conv } = await supabase
          .from('contact_conversations')
          .select('id')
          .eq('tenant_id', tenantId)
          .ilike('email', target)
          .limit(1)
          .maybeSingle();

        if (!conv) {
          console.warn('[send-contact-email] reply blocked: unknown recipient', target, 'tenant', tenantId);
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
      // Ίδιος περιορισμός με reply
      const target = (payload.to || '').trim().toLowerCase();
      if (!target) return safeError(400, 'Recipient required');

      const { data: contact } = await supabase
        .from('contact_conversations')
        .select('id')
        .eq('tenant_id', tenantId)
        .ilike('email', target)
        .limit(1)
        .maybeSingle();

      if (!contact) {
        const { data: msg } = await supabase
          .from('contact_messages')
          .select('id')
          .eq('tenant_id', tenantId)
          .ilike('email', target)
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
      // type === 'new' — PUBLIC CONTACT FORM
      if (!contactEmail) return safeError(503, 'Contact email not configured');

      const safeName = escapeHtml(payload.name || 'Επισκέπτης');
      const safeEmail = escapeHtml(payload.email || '');
      const safePhone = escapeHtml(payload.phone || '');
      const safeMessage = escapeHtml(payload.message || '').replace(/\n/g, '<br>');

      mailOptions = {
        from: `${fromName} <${fromEmail}>`,
        to: contactEmail,                 // 🔴 ΜΟΝΟ ο configured παραλήπτης
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

    return new Response(
      JSON.stringify({ ok: true }),
      { status: 200, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' } }
    );

  } catch (e) {
    // 🔴 Stack trace ΜΟΝΟ στο server log
    console.error('[send-contact-email] fatal:', e instanceof Error ? e.stack : e);
    return safeError(500, 'Internal error');
  }
});
