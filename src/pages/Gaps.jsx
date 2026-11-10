import { useId, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { GAP_KIND, plural } from '../lib.js'
import { GAP_STATES, gapDirty, gapPatch } from '../model.js'
import {
  Empty, ErrorState, Icon, Loading, RuleText, StatusChip, useAsync, usePageTitle, useSession,
} from '../components/ui.jsx'
import { GapStateChip, NoRunsCTA } from '../components/common.jsx'

const MAX_NOTES = 2000

async function load(signal) {
  const [body, runs, rules] = await Promise.all([
    api.gaps({ limit: 1000 }, signal), api.runs(signal), api.ruleCatalog().catch(() => new Map()),
  ])
  return { ...body, runs, rules }
}

function GapEditor({ gap, onSaved, onCancel }) {
  const [draft, setDraft] = useState({ status: gap.status, notes: gap.notes || '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const statusId = useId()
  const notesId = useId()
  const countId = useId()
  const dirty = gapDirty(gap, draft)
  async function save(e) {
    e.preventDefault()
    if (!dirty || busy) return
    setBusy(true)
    setError(null)
    try {
      const updated = await api.patchGap(gap.id, gapPatch(gap, draft))
      onSaved(updated)
    } catch (err) {
      setError(err.status === 403 ? 'Only an admin can edit gaps.' : err.message)
      setBusy(false)
    }
  }
  return (
    <form className="gap-edit" onSubmit={save} aria-label={`Edit the ${gap.technique_id} gap from run ${gap.run_id}`}>
      <div className="gap-edit-row">
        <span className="filter-field">
          <label htmlFor={statusId}>Status</label>
          <select id={statusId} value={draft.status} onChange={(e) => setDraft((d) => ({ ...d, status: e.target.value }))}>
            {Object.entries(GAP_STATES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </span>
      </div>
      <label className="field" htmlFor={notesId}>Analyst notes</label>
      <textarea id={notesId} rows={3} maxLength={MAX_NOTES} value={draft.notes} aria-describedby={countId}
        onChange={(e) => setDraft((d) => ({ ...d, notes: e.target.value }))} />
      <p id={countId} className="small muted">
        {draft.notes.length}/{MAX_NOTES} characters. Saving replaces the analyst notes; the notes PurpleBench wrote stay as they are.
      </p>
      {error && <div className="state error" role="alert">{error}</div>}
      <div className="actions">
        <button type="submit" className="btn primary small" aria-disabled={!dirty || busy}>
          {busy ? 'Saving…' : 'Save'}
        </button>
        <button type="button" className="btn ghost small" onClick={onCancel}>Cancel</button>
        {!dirty && <span className="small muted">No changes to save.</span>}
      </div>
    </form>
  )
}

function GapCard({ gap, rules, admin, onSaved }) {
  const [editing, setEditing] = useState(false)
  return (
    <li className={`card gap-card kind-${gap.kind}`}>
      <div className="gap-head">
        <StatusChip status={gap.kind} withHelp />
        <Link to={`/runs/${gap.run_id}?status=${gap.kind}`} className="gap-tech">
          <span className="mono tech-id">{gap.technique_id}</span> {gap.technique.name}
          <span className="sr-only"> (open the run {gap.run_id} results)</span>
        </Link>
        <GapStateChip gap={gap} />
        <span className="muted small gap-run">Found in run {gap.run_id}</span>
      </div>
      <dl className="gap-facts">
        <div>
          <dt>Found by PurpleBench</dt>
          <dd><RuleText text={gap.system_notes} rules={rules} />{!gap.system_notes && <span className="muted">—</span>}</dd>
        </div>
        {gap.telemetry_needed && <div><dt>Telemetry needed</dt><dd>{gap.telemetry_needed}</dd></div>}
        {gap.rule_idea && <div><dt>Rule idea</dt><dd>{gap.rule_idea}</dd></div>}
        {!editing && (
          <div>
            <dt>Analyst notes</dt>
            <dd>{gap.notes ? <RuleText text={gap.notes} rules={rules} /> : <span className="muted">None yet.</span>}</dd>
          </div>
        )}
      </dl>
      {admin && !editing && (
        <div className="actions tight">
          <button type="button" className="btn secondary small" onClick={() => setEditing(true)}>
            Edit status and notes<span className="sr-only"> for {gap.technique_id} in run {gap.run_id}</span>
          </button>
        </div>
      )}
      {admin && editing && (
        <GapEditor gap={gap} onCancel={() => setEditing(false)}
          onSaved={(g) => { onSaved(g); setEditing(false) }} />
      )}
    </li>
  )
}

export default function Gaps() {
  usePageTitle('Gaps')
  const session = useSession()
  const admin = session && !session.guest
  const [params, setParams] = useSearchParams()
  const { data, loading, error, reload, setData } = useAsync(load, [])
  const statusId = useId()
  const kindId = useId()
  const runId = useId()
  const status = GAP_STATES[params.get('status')] ? params.get('status') : ''
  const kind = GAP_KIND[params.get('kind')] ? params.get('kind') : ''
  const run = params.get('run') || ''
  function set(key, value) {
    setParams((p) => {
      const next = new URLSearchParams(p)
      if (value) next.set(key, value)
      else next.delete(key)
      return next
    }, { replace: true })
  }
  const all = data?.gaps || []
  const shown = all.filter((g) => (!status || g.status === status) && (!kind || g.kind === kind)
    && (!run || String(g.run_id) === run))
  const count = (k, v) => all.filter((g) => g[k] === v).length
  const [notice, setNotice] = useState('')
  const onSaved = (g) => {
    setData((d) => ({ ...d, gaps: d.gaps.map((x) => (x.id === g.id ? g : x)) }))
    setNotice(`Saved: the ${g.technique_id} gap from run ${g.run_id} is ${GAP_STATES[g.status]?.label.toLowerCase() || g.status}.`)
  }
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <p className="eyebrow">Gaps</p>
          <h1 tabIndex={-1}>Detection gaps</h1>
          <p className="lede">
            Every technique a run missed, could only partly detect, or could not match for lack of telemetry, with
            the telemetry and rule idea that would close it. A gap closes when a later run of the same campaign
            detects the technique.
          </p>
        </div>
      </header>
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.runs.length === 0 && <NoRunsCTA what="the gap list" />}
      {data && data.runs.length > 0 && (
        <>
          <ul className="count-chips wide" aria-label="Gaps by state">
            {Object.entries(GAP_STATES).map(([k, v]) => (
              <li key={k}><GapStateChip gap={{ status: k }} /> <strong>{count('status', k)}</strong><span className="sr-only"> {v.label.toLowerCase()}</span></li>
            ))}
          </ul>
          <section className="card flush" aria-labelledby="gaps-title">
            <div className="card-head padded">
              <h2 id="gaps-title">{plural(all.length, 'gap')}</h2>
              {!admin && <span className="muted small"><Icon name="lock" size={13} /> Read-only: an admin can set the status and add notes</span>}
            </div>
            <div className="filters" role="group" aria-label="Filter gaps">
              <span className="filter-field">
                <label htmlFor={statusId}>State</label>
                <select id={statusId} value={status} onChange={(e) => set('status', e.target.value)}>
                  <option value="">All states</option>
                  {Object.entries(GAP_STATES).map(([k, v]) => <option key={k} value={k}>{v.label} ({count('status', k)})</option>)}
                </select>
              </span>
              <span className="filter-field">
                <label htmlFor={kindId}>Kind</label>
                <select id={kindId} value={kind} onChange={(e) => set('kind', e.target.value)}>
                  <option value="">All kinds</option>
                  {Object.entries(GAP_KIND).map(([k, v]) => <option key={k} value={k}>{v} ({count('kind', k)})</option>)}
                </select>
              </span>
              <span className="filter-field">
                <label htmlFor={runId}>Run</label>
                <select id={runId} value={run} onChange={(e) => set('run', e.target.value)}>
                  <option value="">All runs</option>
                  {[...data.runs].reverse().map((r) => <option key={r.id} value={r.id}>Run {r.id} · {r.campaign_name}</option>)}
                </select>
              </span>
              {(status || kind || run) && (
                <button type="button" className="btn ghost small" onClick={() => setParams(new URLSearchParams(), { replace: true })}>Clear filters</button>
              )}
              <span className="filter-count" role="status">Showing {shown.length} of {plural(all.length, 'gap')}</span>
            </div>
            {admin && <p className="save-notice small" role="status">{notice}</p>}
          </section>
          {data.total > all.length && <p className="small muted" role="note">Showing the first {all.length} of {data.total} gaps.</p>}
          {shown.length === 0 ? <Empty>No gaps match these filters.</Empty> : (
            <ul className="gap-cards">
              {shown.map((g) => <GapCard key={g.id} gap={g} rules={data.rules} admin={admin} onSaved={onSaved} />)}
            </ul>
          )}
        </>
      )}
    </div>
  )
}
