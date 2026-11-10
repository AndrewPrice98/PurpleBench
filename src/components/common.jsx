import { useId, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { DEMO_WRITE_NOTICE, formatDate, showDemoWriteNotice } from '../lib.js'
import { GAP_STATES, uploadMessage, uploadProblem } from '../model.js'
import { Icon, Select, useSession } from './ui.jsx'

/** "Run 4 · Ransomware precursors · v4 · Nov 9, 2026" */
export function runOptionLabel(r) {
  return `Run ${r.id} · ${r.campaign_name} · rule set ${r.ruleset_version} · ${formatDate(r.started_at)}`
}

/** A labelled run picker (newest first). */
export function RunSelect({ runs, value, onChange, label = 'Run', extra = null }) {
  const id = useId()
  return (
    <span className="filter-field run-field">
      <label htmlFor={id}>{label}</label>
      <Select id={id} value={value ?? ''} onChange={(e) => onChange(e.target.value)}>
        {extra}
        {[...runs].reverse().map((r) => <option key={r.id} value={r.id}>{runOptionLabel(r)}</option>)}
      </Select>
    </span>
  )
}

/** A same-origin file download (the session cookie goes with it). */
export function DownloadLink({ href, children, className = 'btn secondary', fileName }) {
  return (
    <a className={className} href={href} download={fileName || ''}>
      <Icon name="download" /> {children}
    </a>
  )
}

/** Command text shown as text, with a copy button that announces the result. */
export function CopyBlock({ label, text }) {
  const [state, setState] = useState('')
  const preRef = useRef(null)
  const labelId = useId()
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setState('Copied to the clipboard.')
    } catch {
      // No clipboard permission: select the text so Ctrl+C works.
      const range = document.createRange()
      range.selectNodeContents(preRef.current)
      const sel = window.getSelection()
      sel.removeAllRanges()
      sel.addRange(range)
      setState('Selected: press Ctrl+C to copy.')
    }
  }
  return (
    <div className="copy-block">
      <div className="copy-head">
        <span id={labelId} className="copy-label">{label}</span>
        <button type="button" className="btn ghost small" onClick={copy}>
          <Icon name="copy" size={14} /> Copy<span className="sr-only"> {label}</span>
        </button>
      </div>
      <pre ref={preRef} tabIndex={0} aria-labelledby={labelId}><code>{text}</code></pre>
      <p className="copy-status small muted" role="status">{state}</p>
    </div>
  )
}

export function GapStateChip({ gap }) {
  const st = GAP_STATES[gap.status] || GAP_STATES.open
  return (
    <span className={`status s-${gap.status}`} title={st.help}>
      {st.label}{gap.status === 'closed' && gap.closed_in_run ? ` in run ${gap.closed_in_run}` : ''}
    </span>
  )
}

/** Admin-only lab run upload (POST /api/runs). Opens the run when it has been imported. */
export function UploadRun({ compact = false }) {
  const session = useSession()
  const navigate = useNavigate()
  const inputId = useId()
  const helpId = useId()
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  if (!session || session.guest) return null
  const maxMb = session.maxUploadMb
  const problem = uploadProblem(file, maxMb)

  async function submit(e) {
    e.preventDefault()
    if (busy) return
    if (problem) { setError(problem); return }
    setBusy(true)
    setError(null)
    try {
      const res = await api.uploadRun(file)
      navigate(`/runs/${res.run_id}`)
    } catch (err) {
      setError(uploadMessage(err, maxMb))
      setBusy(false)
    }
  }

  return (
    <form className={`upload ${compact ? 'compact' : ''}`} onSubmit={submit} aria-label="Upload a lab run file">
      <label className="field" htmlFor={inputId}>Lab run file (.json)</label>
      <div className="upload-row">
        <input id={inputId} type="file" accept=".json,application/json" aria-describedby={helpId}
          onChange={(e) => { setFile(e.target.files?.[0] || null); setError(null) }} />
        <button type="submit" className="btn primary" aria-disabled={Boolean(problem) || busy}>
          <Icon name="upload" /> {busy ? 'Uploading…' : 'Upload run'}
        </button>
      </div>
      <p id={helpId} className="small muted">
        The <span className="mono">purplebench-run</span> version 2 file that the lab runner writes, up to {maxMb} MB.
        It is checked and scored with the newest rule set, and shown as lab mode (not yet run against a real lab).
      </p>
      {error && <div className="state error" role="alert">{error}</div>}
    </form>
  )
}

/** Persistent notice beside admin controls on the hosted demo, where every visitor shares one database. */
export function DemoWriteNotice() {
  const session = useSession()
  if (!showDemoWriteNotice(session)) return null
  return (
    <p className="demo-write-notice" role="note">
      <Icon name="info" /> <span>{DEMO_WRITE_NOTICE}</span>
    </p>
  )
}

/**
 * Empty database: what PurpleBench needs and how to get there. Admins get the controls; guests are told
 * that the hosted demo is read-only.
 */
export function NoRunsCTA({ what = 'this page' }) {
  const session = useSession()
  const admin = session && !session.guest
  return (
    <section className="panel cta" aria-labelledby="cta-title">
      <div className="panel-head"><h2 id="cta-title">No runs yet</h2></div>
      <div className="panel-body">
        <p className="page-sub">
          A run evaluates one rule set against the telemetry of a campaign&apos;s techniques, and {what} is built
          from runs. Create a campaign, run it in your lab with the lab runner, then upload the run file it writes.
        </p>
        <ol className="cta-steps">
          <li>
            <strong>Create a campaign</strong>: pick the ATT&amp;CK techniques to test.
            {admin && <> <Link className="btn primary small" to="/campaigns/new"><Icon name="plus" size={14} /> New campaign</Link></>}
          </li>
          <li><strong>Run it in a lab</strong>: download the campaign file and run the lab runner against an isolated, snapshotted lab VM.</li>
          <li><strong>Upload the run file</strong>: the results, coverage and gaps appear here.</li>
        </ol>
        {admin && <DemoWriteNotice />}
        {admin ? <UploadRun compact /> : (
          <p className="muted small">Sign in as the admin to create campaigns and upload runs.</p>
        )}
      </div>
    </section>
  )
}
