/*
  # 20261107000001_fix_tenant_isolation_gaps.sql

  🔴 ΔΙΟΡΘΩΣΗ ΚΕΝΟΥ ΑΣΦΑΛΕΙΑΣ — Απόφαση Πάνου 2026-11-07

  ## Πρόβλημα
  5 πίνακες του retreat module είχαν `tenant_id` αλλά ΔΕΝ είχαν
  Row Level Security ενεργό:
    - booking_submissions
    - experiences
    - faq_entries
    - retreat_events
    - workshops

  Αποτέλεσμα: οποιοσδήποτε authenticated χρήστης μπορούσε να διαβάσει
  και να γράψει δεδομένα ΟΛΩΝ των tenants.

  ## Διόρθωση
  - ENABLE ROW LEVEL SECURITY σε όλους
  - Policies: tenant isolation μέσω current_tenant_id() + is_super_admin()
  - Ξεχωριστή policy για booking_submissions: το κοινό (anon) μπορεί
    να ΥΠΟΒΑΛΛΕΙ αίτημα, αλλά ΟΧΙ να διαβάσει άλλων.

  ## Επαλήθευση μετά την εκτέλεση
    node ops/db-audit.mjs --strict
*/

-- ============================================================
-- 1. retreat_events — δημόσια ανάγνωση published, διαχείριση από tenant
-- ============================================================
ALTER TABLE public.retreat_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "retreat_events_tenant_select" ON public.retreat_events;
CREATE POLICY "retreat_events_tenant_select"
  ON public.retreat_events FOR SELECT TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "retreat_events_public_published" ON public.retreat_events;
CREATE POLICY "retreat_events_public_published"
  ON public.retreat_events FOR SELECT TO anon
  USING (status = 'published');

DROP POLICY IF EXISTS "retreat_events_tenant_insert" ON public.retreat_events;
CREATE POLICY "retreat_events_tenant_insert"
  ON public.retreat_events FOR INSERT TO authenticated
  WITH CHECK (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "retreat_events_tenant_update" ON public.retreat_events;
CREATE POLICY "retreat_events_tenant_update"
  ON public.retreat_events FOR UPDATE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin())
  WITH CHECK (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "retreat_events_tenant_delete" ON public.retreat_events;
CREATE POLICY "retreat_events_tenant_delete"
  ON public.retreat_events FOR DELETE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

-- ============================================================
-- 2. experiences
-- ============================================================
ALTER TABLE public.experiences ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "experiences_tenant_select" ON public.experiences;
CREATE POLICY "experiences_tenant_select"
  ON public.experiences FOR SELECT TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "experiences_public_published" ON public.experiences;
CREATE POLICY "experiences_public_published"
  ON public.experiences FOR SELECT TO anon
  USING (status = 'published');

DROP POLICY IF EXISTS "experiences_tenant_insert" ON public.experiences;
CREATE POLICY "experiences_tenant_insert"
  ON public.experiences FOR INSERT TO authenticated
  WITH CHECK (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "experiences_tenant_update" ON public.experiences;
CREATE POLICY "experiences_tenant_update"
  ON public.experiences FOR UPDATE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin())
  WITH CHECK (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "experiences_tenant_delete" ON public.experiences;
CREATE POLICY "experiences_tenant_delete"
  ON public.experiences FOR DELETE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

-- ============================================================
-- 3. workshops
-- ============================================================
ALTER TABLE public.workshops ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "workshops_tenant_select" ON public.workshops;
CREATE POLICY "workshops_tenant_select"
  ON public.workshops FOR SELECT TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "workshops_public_published" ON public.workshops;
CREATE POLICY "workshops_public_published"
  ON public.workshops FOR SELECT TO anon
  USING (status = 'published');

DROP POLICY IF EXISTS "workshops_tenant_insert" ON public.workshops;
CREATE POLICY "workshops_tenant_insert"
  ON public.workshops FOR INSERT TO authenticated
  WITH CHECK (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "workshops_tenant_update" ON public.workshops;
CREATE POLICY "workshops_tenant_update"
  ON public.workshops FOR UPDATE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin())
  WITH CHECK (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "workshops_tenant_delete" ON public.workshops;
CREATE POLICY "workshops_tenant_delete"
  ON public.workshops FOR DELETE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

-- ============================================================
-- 4. faq_entries
-- ============================================================
ALTER TABLE public.faq_entries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "faq_entries_tenant_select" ON public.faq_entries;
CREATE POLICY "faq_entries_tenant_select"
  ON public.faq_entries FOR SELECT TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "faq_entries_public_published" ON public.faq_entries;
CREATE POLICY "faq_entries_public_published"
  ON public.faq_entries FOR SELECT TO anon
  USING (status = 'published');

DROP POLICY IF EXISTS "faq_entries_tenant_insert" ON public.faq_entries;
CREATE POLICY "faq_entries_tenant_insert"
  ON public.faq_entries FOR INSERT TO authenticated
  WITH CHECK (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "faq_entries_tenant_update" ON public.faq_entries;
CREATE POLICY "faq_entries_tenant_update"
  ON public.faq_entries FOR UPDATE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin())
  WITH CHECK (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "faq_entries_tenant_delete" ON public.faq_entries;
CREATE POLICY "faq_entries_tenant_delete"
  ON public.faq_entries FOR DELETE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

-- ============================================================
-- 5. booking_submissions — ΕΙΔΙΚΗ ΠΕΡΙΠΤΩΣΗ
--    Το κοινό υποβάλλει αίτημα. ΔΕΝ διαβάζει αιτήματα άλλων.
-- ============================================================
ALTER TABLE public.booking_submissions ENABLE ROW LEVEL SECURITY;

-- Ανώνυμος χρήστης: ΜΟΝΟ insert (υποβολή φόρμας), ποτέ select
DROP POLICY IF EXISTS "booking_public_insert" ON public.booking_submissions;
CREATE POLICY "booking_public_insert"
  ON public.booking_submissions FOR INSERT TO anon
  WITH CHECK (true);

-- Authenticated: βλέπει μόνο τα δικά του
DROP POLICY IF EXISTS "booking_tenant_select" ON public.booking_submissions;
CREATE POLICY "booking_tenant_select"
  ON public.booking_submissions FOR SELECT TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "booking_tenant_update" ON public.booking_submissions;
CREATE POLICY "booking_tenant_update"
  ON public.booking_submissions FOR UPDATE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin())
  WITH CHECK (tenant_id = current_tenant_id() OR is_super_admin());

DROP POLICY IF EXISTS "booking_tenant_delete" ON public.booking_submissions;
CREATE POLICY "booking_tenant_delete"
  ON public.booking_submissions FOR DELETE TO authenticated
  USING (tenant_id = current_tenant_id() OR is_super_admin());

-- ============================================================
-- 6. Δικλείδα ασφαλείας: από εδώ και πέρα, ΚΑΘΕ νέος πίνακας με
--    tenant_id πρέπει να έχει RLS. Το παρακάτω view το επιτρέπει
--    να ελέγχεται αυτόματα.
-- ============================================================
CREATE OR REPLACE VIEW public.v_tenant_isolation_status AS
SELECT
  c.relname AS table_name,
  c.relrowsecurity AS rls_enabled,
  (SELECT count(*) FROM pg_policies p WHERE p.tablename = c.relname) AS policy_count,
  EXISTS (
    SELECT 1 FROM information_schema.columns col
    WHERE col.table_schema = 'public'
      AND col.table_name = c.relname
      AND col.column_name = 'tenant_id'
  ) AS has_tenant_id,
  CASE
    WHEN EXISTS (SELECT 1 FROM information_schema.columns col
                 WHERE col.table_schema='public' AND col.table_name=c.relname
                   AND col.column_name='tenant_id')
         AND NOT c.relrowsecurity THEN '🔴 ΚΕΝΟ'
    WHEN EXISTS (SELECT 1 FROM information_schema.columns col
                 WHERE col.table_schema='public' AND col.table_name=c.relname
                   AND col.column_name='tenant_id')
         AND c.relrowsecurity
         AND (SELECT count(*) FROM pg_policies p WHERE p.tablename=c.relname) = 0 THEN '🔴 RLS ΧΩΡΙΣ POLICY'
    ELSE 'OK'
  END AS status
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
ORDER BY status DESC, c.relname;

COMMENT ON VIEW public.v_tenant_isolation_status IS
  'Έλεγχος απομόνωσης tenant: κάθε πίνακας με tenant_id πρέπει να έχει RLS + policies.';
