/*
  # 20261107000002_harden_all_tenant_rls.sql

  🔴 ΚΡΙΣΙΜΗ ΔΙΟΡΘΩΣΗ ΑΣΦΑΛΕΙΑΣ — Απόφαση Πάνου 2026-11-07

  ## Τι βρέθηκε
  Το `node ops/db-audit.mjs` εντόπισε 15 πραγματικά κενά απομόνωσης:

  ### Α. Πίνακες με USING(true) — ΠΛΗΡΗΣ ΔΙΑΡΡΟΗ
  Κάθε authenticated χρήστης έβλεπε/άλλαζε δεδομένα ΟΛΩΝ των tenants:
    media, services, blog_posts, testimonials, credentials,
    core_values, site_settings, content_history, content_backups,
    service_related_articles

  ### Β. Πίνακες με tenant_id χωρίς RLS
    experiences, workshops, retreat_events, faq_entries, booking_submissions

  ### Γ. Policies με auth.uid() IS NOT NULL (χωρίς tenant)
    insert/update/delete σε media, services, blog_posts, ...

  ## Διόρθωση
  Αντικαθιστούμε ΟΛΕΣ τις permissive policies με tenant-scoped.

  ## ⚠️ ΠΡΙΝ ΤΗΝ ΕΚΤΕΛΕΣΗ
  1. Backup: Settings → Database → Backups (ή `pg_dump`)
  2. Έλεγχος: node ops/db-audit.mjs
  3. Μετά: node ops/db-audit.mjs --live <projectRef>

  ## Rollback
  Τα migration αρχεία είναι append-only. Για επαναφορά:
  restore από backup πριν το 20261107000002.
*/

-- ============================================================
-- ΒΟΗΘΗΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ (αν δεν υπάρχουν)
-- ============================================================
CREATE OR REPLACE FUNCTION public.current_tenant_id()
RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT COALESCE(
    (auth.jwt() ->> 'selected_tenant_id')::uuid,
    (auth.jwt() ->> 'tenant_id')::uuid
  )
$$;

CREATE OR REPLACE FUNCTION public.is_super_admin()
RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT COALESCE((auth.jwt() ->> 'is_super_admin')::boolean, false)
$$;

-- ============================================================
-- ΓΕΝΙΚΟ ΠΡΟΤΥΠΟ: διαγραφή ΟΛΩΝ των παλιών policies σε tenant πίνακες
-- και αντικατάσταση με tenant-scoped.
-- ============================================================

DO $$
DECLARE
  t text;
  pol record;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'media','services','blog_posts','testimonials','credentials','core_values',
    'site_settings','content_history','content_backups','service_related_articles',
    'core_entities','core_entity_versions','experiences','workshops','retreat_events',
    'faq_entries','booking_submissions','showreels','biographies','career_timelines',
    'filmography_entries','television_entries','theatre_entries','press_items',
    'gallery_items'
  ]
  LOOP
    -- Διέγραψε ΟΛΕΣ τις υπάρχουσες policies του πίνακα
    FOR pol IN
      SELECT policyname FROM pg_policies
      WHERE schemaname = 'public' AND tablename = t
    LOOP
      EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', pol.policyname, t);
    END LOOP;

    -- Ενεργοποίησε RLS
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;

-- ============================================================
-- ΝΕΕΣ POLICIES — ΑΥΣΤΗΡΗ ΑΠΟΜΟΝΩΣΗ
-- Πρότυπο: tenant_id = current_tenant_id() OR is_super_admin()
-- ============================================================

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'media','services','blog_posts','testimonials','credentials','core_values',
    'site_settings','content_history','content_backups','service_related_articles',
    'core_entities','core_entity_versions','experiences','workshops',
    'retreat_events','faq_entries','showreels','biographies','career_timelines',
    'filmography_entries','television_entries','theatre_entries','press_items',
    'gallery_items'
  ]
  LOOP
    EXECUTE format($f$
      CREATE POLICY %I ON public.%I
        FOR SELECT TO authenticated
        USING (tenant_id = public.current_tenant_id() OR public.is_super_admin())
    $f$, t || '_tenant_select', t);

    EXECUTE format($f$
      CREATE POLICY %I ON public.%I
        FOR INSERT TO authenticated
        WITH CHECK (tenant_id = public.current_tenant_id() OR public.is_super_admin())
    $f$, t || '_tenant_insert', t);

    EXECUTE format($f$
      CREATE POLICY %I ON public.%I
        FOR UPDATE TO authenticated
        USING (tenant_id = public.current_tenant_id() OR public.is_super_admin())
        WITH CHECK (tenant_id = public.current_tenant_id() OR public.is_super_admin())
    $f$, t || '_tenant_update', t);

    EXECUTE format($f$
      CREATE POLICY %I ON public.%I
        FOR DELETE TO authenticated
        USING (tenant_id = public.current_tenant_id() OR public.is_super_admin())
    $f$, t || '_tenant_delete', t);
  END LOOP;
END $$;

-- ============================================================
-- ΔΗΜΟΣΙΑ ΑΝΑΓΝΩΣΗ (anon) — μόνο published περιεχόμενο
-- Απαραίτητο για τα δημόσια sites.
-- ============================================================
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'services','blog_posts','testimonials','core_values','service_related_articles',
    'experiences','workshops','retreat_events','faq_entries'
  ]
  LOOP
    BEGIN
      EXECUTE format($f$
        CREATE POLICY %I ON public.%I
          FOR SELECT TO anon
          USING (status = 'published')
      $f$, t || '_public_published', t);
    EXCEPTION WHEN undefined_column THEN
      -- Ο πίνακας δεν έχει στήλη status — παράλειψε
      NULL;
    WHEN duplicate_object THEN
      NULL;
    END;
  END LOOP;
END $$;

-- media: δημόσια ανάγνωση (τα site assets πρέπει να φορτώνουν)
DROP POLICY IF EXISTS media_public_read ON public.media;
CREATE POLICY media_public_read ON public.media
  FOR SELECT TO anon
  USING (true);

-- ============================================================
-- booking_submissions — ΕΙΔΙΚΗ ΠΕΡΙΠΤΩΣΗ
-- Το κοινό ΥΠΟΒΑΛΛΕΙ, δεν ΔΙΑΒΑΖΕΙ.
-- ============================================================
DROP POLICY IF EXISTS booking_submissions_public_insert ON public.booking_submissions;
CREATE POLICY booking_submissions_public_insert ON public.booking_submissions
  FOR INSERT TO anon
  WITH CHECK (true);

DROP POLICY IF EXISTS booking_submissions_tenant_select ON public.booking_submissions;
CREATE POLICY booking_submissions_tenant_select ON public.booking_submissions
  FOR SELECT TO authenticated
  USING (tenant_id = public.current_tenant_id() OR public.is_super_admin());

DROP POLICY IF EXISTS booking_submissions_tenant_update ON public.booking_submissions;
CREATE POLICY booking_submissions_tenant_update ON public.booking_submissions
  FOR UPDATE TO authenticated
  USING (tenant_id = public.current_tenant_id() OR public.is_super_admin())
  WITH CHECK (tenant_id = public.current_tenant_id() OR public.is_super_admin());

DROP POLICY IF EXISTS booking_submissions_tenant_delete ON public.booking_submissions;
CREATE POLICY booking_submissions_tenant_delete ON public.booking_submissions
  FOR DELETE TO authenticated
  USING (tenant_id = public.current_tenant_id() OR public.is_super_admin());

-- ============================================================
-- PROFILES — ειδικό: βλέπεις τον εαυτό σου + συναδέλφους του tenant
-- ============================================================
DROP POLICY IF EXISTS "Users can view own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can insert own profile" ON public.profiles;
DROP POLICY IF EXISTS profiles_tenant_select ON public.profiles;
DROP POLICY IF EXISTS profiles_own_update ON public.profiles;

CREATE POLICY profiles_tenant_select ON public.profiles
  FOR SELECT TO authenticated
  USING (
    id = auth.uid()
    OR tenant_id = public.current_tenant_id()
    OR public.is_super_admin()
  );

CREATE POLICY profiles_own_update ON public.profiles
  FOR UPDATE TO authenticated
  USING (id = auth.uid() OR public.is_super_admin())
  WITH CHECK (id = auth.uid() OR public.is_super_admin());

-- ============================================================
-- TENANT_FEATURES / TENANT_SETTINGS — μόνο super admin ή ο ίδιος tenant
-- ============================================================
DROP POLICY IF EXISTS "Super admins can manage features" ON public.tenant_features;
DROP POLICY IF EXISTS tenant_features_access ON public.tenant_features;
CREATE POLICY tenant_features_access ON public.tenant_features
  FOR ALL TO authenticated
  USING (tenant_id = public.current_tenant_id() OR public.is_super_admin())
  WITH CHECK (tenant_id = public.current_tenant_id() OR public.is_super_admin());

DROP POLICY IF EXISTS "Super admins can manage tenant settings" ON public.tenant_settings;
DROP POLICY IF EXISTS tenant_settings_access ON public.tenant_settings;
CREATE POLICY tenant_settings_access ON public.tenant_settings
  FOR ALL TO authenticated
  USING (tenant_id = public.current_tenant_id() OR public.is_super_admin())
  WITH CHECK (tenant_id = public.current_tenant_id() OR public.is_super_admin());

-- ============================================================
-- ΔΕΙΚΤΕΣ για 성능 των RLS policies
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_media_tenant ON public.media(tenant_id);
CREATE INDEX IF NOT EXISTS idx_services_tenant ON public.services(tenant_id);
CREATE INDEX IF NOT EXISTS idx_blog_posts_tenant ON public.blog_posts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_testimonials_tenant ON public.testimonials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_credentials_tenant ON public.credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_core_values_tenant ON public.core_values(tenant_id);

-- ============================================================
-- ΕΠΑΛΗΘΕΥΣΗ
-- Μετά την εκτέλεση:
--   SELECT * FROM v_tenant_isolation_status WHERE status <> 'OK';
-- Πρέπει να επιστρέψει 0 γραμμές.
-- ============================================================
