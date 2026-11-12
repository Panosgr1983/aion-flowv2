import { useEffect, useMemo, useState } from 'react';
import { supabase } from '../../lib/supabase';
import { useTenant } from '../../lib/useTenant';
import {
  Search, Plus, RefreshCw, Edit2, Trash2, Eye, EyeOff,
  Check, X, Loader2, GraduationCap, AlertCircle
} from 'lucide-react';

/**
 * StudentsManager — Education vertical: Student Roster
 *
 * ENGINEERING READINESS GATE — Education UI
 *
 * Λειτουργίες:
 *   • Λίστα μαθητών με αναζήτηση και φίλτρα
 *   • Δημιουργία / επεξεργασία
 *   • Προβολή στοιχείων
 *   • Ενεργοποίηση / απενεργοποίηση
 *   • Διαγραφή (μόνο owner/admin)
 *
 * Role-based:
 *   owner/admin/secretary → βλέπουν όλους του tenant
 *   professional          → βλέπουν μόνο όσους δημιούργησαν
 *   viewer                → read-only, όλους του tenant
 *
 * Tenant isolation: η βάση το επιβάλλει (RLS). Το UI δεν το bypasses.
 */

interface Student {
  id: string;
  tenant_id: string;
  full_name: string;
  email: string | null;
  phone: string | null;
  grade: string | null;
  guardian_name: string | null;
  guardian_phone: string | null;
  notes: string | null;
  is_active: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

const EMPTY_FORM = {
  full_name: '',
  email: '',
  phone: '',
  grade: '',
  guardian_name: '',
  guardian_phone: '',
  notes: '',
};

export default function StudentsManager() {
  const { tenantId, isSuperAdmin } = useTenant();
  const [students, setStudents] = useState<Student[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState('');
  const [filterActive, setFilterActive] = useState<'all' | 'active' | 'inactive'>('all');
  const [filterGrade, setFilterGrade] = useState<string>('');

  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Student | null>(null);
  const [viewing, setViewing] = useState<Student | null>(null);
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [role, setRole] = useState<string | null>(null);

  // ── Φόρτωση role του τρέχοντος χρήστη ──
  useEffect(() => {
    (async () => {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) { setRole(null); return; }
      const { data } = await supabase
        .from('profiles')
        .select('role')
        .eq('id', user.id)
        .maybeSingle();
      setRole(data?.role ?? null);
    })();
  }, []);

  const canCreate = ['owner', 'admin', 'secretary', 'professional'].includes(role || '');
  const canEdit = ['owner', 'admin', 'secretary', 'professional'].includes(role || '');
  const canDelete = ['owner', 'admin'].includes(role || '') || isSuperAdmin;

  // ── Φόρτωση μαθητών ──
  const load = async () => {
    setLoading(true);
    setError(null);

    let q = supabase.from('education_students').select('*').order('full_name');
    if (filterActive === 'active') q = q.eq('is_active', true);
    if (filterActive === 'inactive') q = q.eq('is_active', false);

    const { data, error: err } = await q;
    if (err) {
      setError(err.message);
      setStudents([]);
    } else {
      setStudents(data || []);
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, [filterActive, tenantId]);

  // ── Client-side filter (search + grade) ──
  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return students.filter(s => {
      if (filterGrade && s.grade !== filterGrade) return false;
      if (!q) return true;
      return (
        s.full_name.toLowerCase().includes(q) ||
        (s.email || '').toLowerCase().includes(q) ||
        (s.phone || '').includes(q) ||
        (s.guardian_name || '').toLowerCase().includes(q)
      );
    });
  }, [students, search, filterGrade]);

  const grades = useMemo(() => {
    const set = new Set<string>();
    students.forEach(s => { if (s.grade) set.add(s.grade); });
    return [...set].sort();
  }, [students]);

  // ── Create / Update ──
  const submit = async () => {
    if (!form.full_name.trim()) {
      setError('Το ονοματεπώνυμο είναι υποχρεωτικό');
      return;
    }
    if (form.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(form.email)) {
      setError('Μη έγκυρη διεύθυνση email');
      return;
    }

    setSaving(true);
    setError(null);

    const { data: { user } } = await supabase.auth.getUser();

    if (editing) {
      const { error: err } = await supabase
        .from('education_students')
        .update({
          full_name: form.full_name.trim(),
          email: form.email.trim() || null,
          phone: form.phone.trim() || null,
          grade: form.grade.trim() || null,
          guardian_name: form.guardian_name.trim() || null,
          guardian_phone: form.guardian_phone.trim() || null,
          notes: form.notes.trim() || null,
        })
        .eq('id', editing.id);

      if (err) setError(err.message);
      else { setShowForm(false); setEditing(null); await load(); }
    } else {
      const { error: err } = await supabase
        .from('education_students')
        .insert({
          tenant_id: tenantId,
          full_name: form.full_name.trim(),
          email: form.email.trim() || null,
          phone: form.phone.trim() || null,
          grade: form.grade.trim() || null,
          guardian_name: form.guardian_name.trim() || null,
          guardian_phone: form.guardian_phone.trim() || null,
          notes: form.notes.trim() || null,
          created_by: user?.id || null,
        });

      if (err) setError(err.message);
      else { setShowForm(false); setForm({ ...EMPTY_FORM }); await load(); }
    }
    setSaving(false);
  };

  // ── Toggle active ──
  const toggleActive = async (s: Student) => {
    const { error: err } = await supabase
      .from('education_students')
      .update({ is_active: !s.is_active })
      .eq('id', s.id);
    if (err) setError(err.message);
    else await load();
  };

  // ── Delete ──
  const remove = async (s: Student) => {
    if (!confirm(`Διαγραφή μαθητή "${s.full_name}"; Η ενέργεια δεν αναιρείται.`)) return;
    const { error: err } = await supabase
      .from('education_students')
      .delete()
      .eq('id', s.id);
    if (err) setError(err.message);
    else await load();
  };

  const openCreate = () => {
    setEditing(null);
    setForm({ ...EMPTY_FORM });
    setShowForm(true);
    setError(null);
  };

  const openEdit = (s: Student) => {
    setEditing(s);
    setForm({
      full_name: s.full_name,
      email: s.email || '',
      phone: s.phone || '',
      grade: s.grade || '',
      guardian_name: s.guardian_name || '',
      guardian_phone: s.guardian_phone || '',
      notes: s.notes || '',
    });
    setShowForm(true);
    setError(null);
  };

  // ══════════════════════════════════════════════════════
  // RENDER
  // ══════════════════════════════════════════════════════
  return (
    <div className="space-y-5 animate-fade-in" data-testid="students-manager">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <GraduationCap size={20} className="text-blue-400" />
            Μαθητές
          </h2>
          <p className="text-sm text-gray-500">
            {visible.length} {visible.length === 1 ? 'μαθητής' : 'μαθητές'}
            {students.length !== visible.length && ` από ${students.length}`}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={load}
            className="btn-ghost p-2"
            title="Ανανέωση"
            data-testid="students-refresh"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
          {canCreate && (
            <button
              onClick={openCreate}
              className="btn-primary flex items-center gap-2 px-4 py-2 rounded-lg text-sm"
              data-testid="students-add"
            >
              <Plus size={14} /> Νέος μαθητής
            </button>
          )}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm" data-testid="students-error">
          <AlertCircle size={16} className="mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="flex-1 min-w-[200px] relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Αναζήτηση ονόματος, email, τηλεφώνου..."
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm"
            data-testid="students-search"
          />
        </div>
        <select
          value={filterActive}
          onChange={e => setFilterActive(e.target.value as any)}
          className="px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm"
          data-testid="students-filter-active"
        >
          <option value="all">Όλοι</option>
          <option value="active">Ενεργοί</option>
          <option value="inactive">Ανενεργοί</option>
        </select>
        <select
          value={filterGrade}
          onChange={e => setFilterGrade(e.target.value)}
          className="px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm"
          data-testid="students-filter-grade"
        >
          <option value="">Όλες οι τάξεις</option>
          {grades.map(g => <option key={g} value={g}>{g}</option>)}
        </select>
      </div>

      {/* Form */}
      {showForm && (
        <div className="card p-5 space-y-4" data-testid="students-form">
          <h3 className="font-semibold">{editing ? 'Επεξεργασία μαθητή' : 'Νέος μαθητής'}</h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Ονοματεπώνυμο *</label>
              <input
                type="text"
                value={form.full_name}
                onChange={e => setForm(f => ({ ...f, full_name: e.target.value }))}
                className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm"
                data-testid="form-full-name"
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Τάξη</label>
              <input
                type="text"
                value={form.grade}
                onChange={e => setForm(f => ({ ...f, grade: e.target.value }))}
                placeholder="π.χ. Γ Λυκείου"
                className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm"
                data-testid="form-grade"
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Email</label>
              <input
                type="email"
                value={form.email}
                onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
                className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm"
                data-testid="form-email"
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Τηλέφωνο</label>
              <input
                type="tel"
                value={form.phone}
                onChange={e => setForm(f => ({ ...f, phone: e.target.value }))}
                className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm"
                data-testid="form-phone"
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Κηδεμόνας</label>
              <input
                type="text"
                value={form.guardian_name}
                onChange={e => setForm(f => ({ ...f, guardian_name: e.target.value }))}
                className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm"
                data-testid="form-guardian"
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1 block">Τηλέφωνο κηδεμόνα</label>
              <input
                type="tel"
                value={form.guardian_phone}
                onChange={e => setForm(f => ({ ...f, guardian_phone: e.target.value }))}
                className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm"
                data-testid="form-guardian-phone"
              />
            </div>
          </div>

          <div>
            <label className="text-xs text-gray-500 mb-1 block">Σημειώσεις</label>
            <textarea
              value={form.notes}
              onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
              rows={2}
              className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-sm resize-none"
              data-testid="form-notes"
            />
          </div>

          <div className="flex gap-2">
            <button
              onClick={submit}
              disabled={saving}
              className="btn-primary flex items-center gap-2 px-4 py-2 rounded-lg text-sm disabled:opacity-50"
              data-testid="form-submit"
            >
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
              {editing ? 'Αποθήκευση' : 'Δημιουργία'}
            </button>
            <button
              onClick={() => { setShowForm(false); setEditing(null); setError(null); }}
              className="btn-ghost flex items-center gap-2 px-4 py-2 rounded-lg text-sm"
              data-testid="form-cancel"
            >
              <X size={14} /> Ακύρωση
            </button>
          </div>
        </div>
      )}

      {/* View details */}
      {viewing && (
        <div className="card p-5 space-y-3" data-testid="students-view">
          <div className="flex justify-between items-start">
            <h3 className="font-semibold">{viewing.full_name}</h3>
            <button onClick={() => setViewing(null)} className="btn-ghost p-1">
              <X size={16} />
            </button>
          </div>
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <dt className="text-gray-500">Τάξη</dt><dd>{viewing.grade || '—'}</dd>
            <dt className="text-gray-500">Email</dt><dd>{viewing.email || '—'}</dd>
            <dt className="text-gray-500">Τηλέφωνο</dt><dd>{viewing.phone || '—'}</dd>
            <dt className="text-gray-500">Κηδεμόνας</dt><dd>{viewing.guardian_name || '—'}</dd>
            <dt className="text-gray-500">Τηλ. κηδεμόνα</dt><dd>{viewing.guardian_phone || '—'}</dd>
            <dt className="text-gray-500">Κατάσταση</dt><dd>{viewing.is_active ? 'Ενεργός' : 'Ανενεργός'}</dd>
            <dt className="text-gray-500">Εγγραφή</dt><dd>{new Date(viewing.created_at).toLocaleDateString('el-GR')}</dd>
          </dl>
          {viewing.notes && (
            <div>
              <div className="text-gray-500 text-xs mb-1">Σημειώσεις</div>
              <p className="text-sm">{viewing.notes}</p>
            </div>
          )}
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-32">
            <Loader2 size={20} className="animate-spin text-blue-400" />
          </div>
        ) : visible.length === 0 ? (
          <div className="text-center py-12 text-gray-500" data-testid="students-empty">
            <GraduationCap size={32} className="mx-auto mb-2 opacity-30" />
            <p className="text-sm">
              {students.length === 0 ? 'Δεν υπάρχουν μαθητές ακόμα' : 'Κανένα αποτέλεσμα'}
            </p>
            {canCreate && students.length === 0 && (
              <button onClick={openCreate} className="btn-primary mt-3 px-4 py-2 rounded-lg text-sm">
                Πρόσθεσε τον πρώτο μαθητή
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                  <th className="text-left py-3 px-4">Ονοματεπώνυμο</th>
                  <th className="text-left py-3 px-4">Τάξη</th>
                  <th className="text-left py-3 px-4">Email</th>
                  <th className="text-left py-3 px-4">Τηλέφωνο</th>
                  <th className="text-left py-3 px-4">Κατάσταση</th>
                  <th className="text-right py-3 px-4">Ενέργειες</th>
                </tr>
              </thead>
              <tbody>
                {visible.map(s => (
                  <tr key={s.id} className="border-b border-gray-800/50 hover:bg-gray-800/20" data-testid={`student-row-${s.id}`}>
                    <td className="py-3 px-4 font-medium">{s.full_name}</td>
                    <td className="py-3 px-4 text-gray-400">{s.grade || '—'}</td>
                    <td className="py-3 px-4 text-gray-400">{s.email || '—'}</td>
                    <td className="py-3 px-4 text-gray-400">{s.phone || '—'}</td>
                    <td className="py-3 px-4">
                      <span className={`text-xs px-2 py-1 rounded ${s.is_active ? 'bg-green-500/10 text-green-400' : 'bg-gray-700/30 text-gray-500'}`}>
                        {s.is_active ? 'Ενεργός' : 'Ανενεργός'}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex justify-end gap-1">
                        <button onClick={() => setViewing(s)} className="p-1.5 rounded hover:bg-gray-700/50" title="Προβολή" data-testid={`student-view-${s.id}`}>
                          <Eye size={14} />
                        </button>
                        {canEdit && (
                          <button onClick={() => openEdit(s)} className="p-1.5 rounded hover:bg-gray-700/50" title="Επεξεργασία" data-testid={`student-edit-${s.id}`}>
                            <Edit2 size={14} />
                          </button>
                        )}
                        {canEdit && (
                          <button onClick={() => toggleActive(s)} className="p-1.5 rounded hover:bg-gray-700/50" title={s.is_active ? 'Απενεργοποίηση' : 'Ενεργοποίηση'} data-testid={`student-toggle-${s.id}`}>
                            {s.is_active ? <EyeOff size={14} /> : <Eye size={14} />}
                          </button>
                        )}
                        {canDelete && (
                          <button onClick={() => remove(s)} className="p-1.5 rounded hover:bg-red-500/20 text-red-400" title="Διαγραφή" data-testid={`student-delete-${s.id}`}>
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
