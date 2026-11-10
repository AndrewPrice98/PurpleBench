import { useId, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, downloads } from '../api.js'
import { ATOMIC_URL, GITHUB_URL, attackUrl, formatDate, formatScore, plural } from '../lib.js'
import {
  LAB_TARGET_EXAMPLE, campaignFileName, campaignProblems, groupLibrary, runnerCommands,
} from '../model.js'
import {
  Empty, ErrorState, ExternalLink, Icon, Loading, ModeChip, TacticTag, useAsync, usePageTitle, useSession,
} from '../components/ui.jsx'
import { CopyBlock, DownloadLink, UploadRun } from '../components/common.jsx'

const LAB_README = `${GITHUB_URL}/blob/main/lab/README.md`

// -- list -----------------------------------------------------------------------------------------

export function CampaignList() {
  usePageTitle('Campaigns')
  const session = useSession()
  const admin = session && !session.guest
  const { data, loading, error, reload } = useAsync((signal) => api.campaigns(signal), [])
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <p className="eyebrow">Campaigns</p>
          <h1 tabIndex={-1}>Campaigns</h1>
          <p className="lede">
            A campaign is the list of ATT&amp;CK techniques to test. Each run evaluates one rule set against the
            telemetry of a campaign&apos;s techniques; the lab runner reads a campaign file to know what to execute.
          </p>
        </div>
        {admin && <Link className="btn primary" to="/campaigns/new"><Icon name="plus" size={16} /> New campaign</Link>}
      </header>
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.length === 0 && (
        <section className="card cta" aria-labelledby="none-title">
          <span className="ph-icon" aria-hidden="true"><Icon name="flag" size={22} /></span>
          <div className="cta-body">
            <h2 id="none-title">No campaigns yet</h2>
            <p>Create one by picking the techniques to test; then download its file for the lab runner.</p>
            {admin
              ? <div className="actions"><Link className="btn primary" to="/campaigns/new"><Icon name="plus" size={16} /> New campaign</Link></div>
              : <p className="muted small">Sign in as the admin to create campaigns.</p>}
          </div>
        </section>
      )}
      {data && data.length > 0 && (
        <ul className="campaign-cards">
          {data.map((c) => (
            <li key={c.id} className="card campaign-card">
              <h2><Link to={`/campaigns/${c.id}`} className="row-link">{c.name} <Icon name="arrow" size={16} /></Link></h2>
              {c.description && <p className="muted">{c.description}</p>}
              <p className="meta-line">
                <span>{plural(c.technique_count, 'technique')}</span>
                <span>{c.run_count ? plural(c.run_count, 'run') : 'Not run yet'}</span>
                {c.last_run_id && <Link to={`/runs/${c.last_run_id}`}>Latest: run {c.last_run_id}</Link>}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// -- detail ---------------------------------------------------------------------------------------

function LabSafety() {
  return (
    <div className="lab-warning" role="note" aria-labelledby="lab-warning-title">
      <p className="lw-title" id="lab-warning-title">
        <Icon name="warning" size={18} /> Lab only: the runner executes real attack techniques on the target
      </p>
      <ul>
        <li>Use a <strong>disposable lab VM on an isolated host-only network</strong>, never a work or personal machine.</li>
        <li><strong>Take a snapshot first</strong> and revert to it after every run.</li>
        <li>The runner refuses any target that is not in your local <span className="mono">lab-targets.json</span> allow-list
          {' '}<strong>and</strong> marked with the registry value <span className="mono">HKLM:\SOFTWARE\PurpleBench\LabTarget = 1</span>,
          which you set on purpose.</li>
        <li>It prints a destructive-action warning and runs only after you <strong>type the target name</strong> to confirm.
          <span className="mono"> -WhatIf</span> shows the plan without executing or contacting anything.</li>
        <li>Each test is followed by <span className="mono">Invoke-AtomicTest -Cleanup</span>. The web app itself never executes anything.</li>
      </ul>
      <p className="lw-honest">Lab mode has not yet been run against a real lab; lab results are labelled that way.</p>
    </div>
  )
}

function LabRunner({ campaign }) {
  const runnable = campaign.techniques.filter((t) => t.test_guid)
  const cmds = runnerCommands(campaign)
  const file = campaignFileName(campaign)
  return (
    <section className="card lab-card" aria-labelledby="lab-title">
      <h2 id="lab-title"><Icon name="target" size={18} /> Run it in a lab</h2>
      <LabSafety />
      <ol className="lab-steps">
        <li>
          <h3>Download the campaign file</h3>
          <p className="small muted">
            {runnable.length} of {plural(campaign.techniques.length, 'technique')} have an Atomic Red Team test and go
            into the file; the others are recorded-only techniques that the runner cannot execute.
          </p>
          <DownloadLink href={downloads.campaign(campaign.id)} fileName={file} className="btn primary">
            {file}
          </DownloadLink>
        </li>
        <li>
          <h3>Rehearse, then run, from the repository&apos;s <span className="mono">lab</span> folder</h3>
          <p className="small muted">
            Replace <span className="mono">{LAB_TARGET_EXAMPLE}</span> with your lab VM&apos;s name as listed in
            {' '}<span className="mono">lab-targets.json</span>. Setup: <ExternalLink href={LAB_README}>lab/README.md</ExternalLink>.
          </p>
          <CopyBlock label="1. Rehearse (executes nothing, contacts no host)" text={cmds.rehearse} />
          <CopyBlock label="2. Run against the lab VM (asks you to type the target name)" text={cmds.run} />
        </li>
        <li>
          <h3>Upload the run file</h3>
          <p className="small muted">
            The runner writes <span className="mono">purplebench-run-&lt;target&gt;-&lt;time&gt;.json</span>. Revert the VM to its
            snapshot, then upload the file here.
          </p>
          <UploadRun compact />
        </li>
      </ol>
    </section>
  )
}

export function CampaignDetail() {
  const { campaignId } = useParams()
  const { data: c, loading, error, reload } = useAsync((signal) => api.campaign(campaignId, signal), [campaignId])
  usePageTitle(c ? c.name : 'Campaign')
  if (loading && !c) return <div className="page"><Loading /></div>
  if (error) {
    return (
      <div className="page">
        <h1 tabIndex={-1} className="h-inline">Campaign</h1>
        <ErrorState error={error} onRetry={error.status === 404 ? undefined : reload} />
        <p><Link to="/campaigns">Back to all campaigns</Link></p>
      </div>
    )
  }
  return (
    <div className="page">
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/campaigns"><Icon name="back" size={14} /> All campaigns</Link>
      </nav>
      <header className="page-head">
        <div>
          <p className="eyebrow">Campaign {c.id}</p>
          <h1 tabIndex={-1}>{c.name}</h1>
          {c.description && <p className="lede">{c.description}</p>}
          <p className="meta-line">
            <span>{plural(c.techniques.length, 'technique')}</span>
            <span>{c.runs.length ? plural(c.runs.length, 'run') : 'Not run yet'}</span>
          </p>
        </div>
      </header>
      <div className="grid-2 campaign-grid">
        <section className="card flush" aria-labelledby="techs-title">
          <div className="card-head padded"><h2 id="techs-title">Techniques</h2></div>
          <table className="table cards compact">
            <thead>
              <tr><th scope="col">Technique</th><th scope="col">Tactics</th><th scope="col">Atomic Red Team test</th></tr>
            </thead>
            <tbody>
              {c.techniques.map((t) => (
                <tr key={t.id}>
                  <th scope="row" data-label="Technique">
                    {attackUrl(t.id) ? <ExternalLink href={attackUrl(t.id)} className="mono">{t.id}</ExternalLink> : <span className="mono">{t.id}</span>}
                    {' '}{t.name}
                  </th>
                  <td data-label="Tactics"><span className="tags">{t.tactics.map((x) => <TacticTag key={x} tactic={x} />)}</span></td>
                  <td data-label="Atomic Red Team test">
                    {t.test_guid
                      ? <>{t.atomic_test}<br /><span className="mono small guid">{t.test_guid}</span></>
                      : <span className="muted">None: recorded technique only, not in the lab file</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="table-note">Test names and GUIDs from <ExternalLink href={ATOMIC_URL}>Atomic Red Team</ExternalLink> (MIT).</p>
        </section>
        <section className="card flush" aria-labelledby="c-runs-title">
          <div className="card-head padded"><h2 id="c-runs-title">Runs</h2></div>
          {c.runs.length === 0 ? <div className="padded-box"><Empty>This campaign has not been run yet.</Empty></div> : (
            <table className="table cards compact">
              <thead>
                <tr><th scope="col">Run</th><th scope="col">Date</th><th scope="col">Mode</th><th scope="col">Rule set</th><th scope="col">Coverage</th></tr>
              </thead>
              <tbody>
                {[...c.runs].reverse().map((r) => (
                  <tr key={r.id}>
                    <th scope="row" data-label="Run" className="nowrap"><Link to={`/runs/${r.id}`}>Run {r.id}</Link></th>
                    <td data-label="Date" className="nowrap">{formatDate(r.started_at)}</td>
                    <td data-label="Mode"><ModeChip mode={r.mode} /></td>
                    <td data-label="Rule set" className="mono">{r.ruleset_version}</td>
                    <td data-label="Coverage">{formatScore(r.score)} <span className="muted small">of {r.tested} tested</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
      <LabRunner campaign={c} />
    </div>
  )
}

// -- create (admin) -------------------------------------------------------------------------------

async function loadNew(signal) {
  const [library, campaigns] = await Promise.all([api.library(signal), api.campaigns(signal)])
  return { library, campaigns }
}

export function CampaignNew() {
  usePageTitle('New campaign')
  const session = useSession()
  const navigate = useNavigate()
  const admin = session && !session.guest
  const { data, loading, error, reload } = useAsync(loadNew, [])
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [picked, setPicked] = useState([])
  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(false)
  const [submitError, setSubmitError] = useState(null)
  const [tried, setTried] = useState(false)
  const nameId = useId()
  const descId = useId()
  const searchId = useId()
  const problemsId = useId()
  const groups = useMemo(() => groupLibrary(data?.library.techniques || [], q), [data, q])
  const problems = campaignProblems({ name, techniques: picked }, (data?.campaigns || []).map((c) => c.name))
  const toggle = (id) => setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]))

  async function submit(e) {
    e.preventDefault()
    setTried(true)
    if (problems.length || busy) return
    setBusy(true)
    setSubmitError(null)
    try {
      const c = await api.createCampaign({ name: name.trim(), description: description.trim(), techniques: picked })
      navigate(`/campaigns/${c.id}`)
    } catch (err) {
      setSubmitError(err.status === 409 ? 'A campaign with this name already exists. Choose another name.'
        : err.status === 403 ? 'Only an admin can create campaigns.' : err.message)
      setBusy(false)
    }
  }

  const head = (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/campaigns"><Icon name="back" size={14} /> All campaigns</Link>
      </nav>
      <header className="page-head">
        <div>
          <p className="eyebrow">Campaigns</p>
          <h1 tabIndex={-1}>New campaign</h1>
          <p className="lede">Name the campaign and pick the techniques to test from the technique library.</p>
        </div>
      </header>
    </>
  )
  if (!admin) {
    return <div className="page">{head}<Empty>Only the admin can create campaigns. Sign in as the admin to continue.</Empty></div>
  }
  if (loading && !data) return <div className="page">{head}<Loading /></div>
  if (error) return <div className="page">{head}<ErrorState error={error} onRetry={reload} /></div>
  const atomicCount = picked.filter((id) => data.library.techniques.find((t) => t.id === id)?.atomic_test).length
  return (
    <div className="page">
      {head}
      <form className="card campaign-form" onSubmit={submit} aria-labelledby="cf-title" noValidate>
        <h2 id="cf-title" className="sr-only">Campaign details</h2>
        <label className="field" htmlFor={nameId}>Name</label>
        <input id={nameId} value={name} maxLength={200} onChange={(e) => setName(e.target.value)} autoComplete="off" />
        <label className="field" htmlFor={descId}>Description <span className="muted">(optional)</span></label>
        <textarea id={descId} rows={2} maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} />
        <fieldset className="picker">
          <legend>Techniques <span className="muted">· {picked.length} picked, {atomicCount} with an Atomic test</span></legend>
          <span className="filter-field search-field">
            <label htmlFor={searchId}>Filter</label>
            <input id={searchId} type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Id, name, tactic or test" />
          </span>
          {groups.length === 0 && <Empty>No technique matches.</Empty>}
          {groups.map((g) => (
            <div key={g.tactic} className="picker-group">
              <p className="picker-tactic">{g.name}</p>
              <ul className="picker-list">
                {g.techniques.map((t) => (
                  <li key={t.id}>
                    <label className="check">
                      <input type="checkbox" checked={picked.includes(t.id)} onChange={() => toggle(t.id)} />
                      <span>
                        <span className="mono tech-id">{t.id}</span> {t.name}
                        <span className="small muted picker-test">
                          {t.atomic_test ? ` · Atomic test: ${t.atomic_test.name}` : ' · recorded only, no Atomic test (the lab runner skips it)'}
                        </span>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          <p className="small muted">
            Library: {plural(data.library.techniques.length, 'technique')}, ATT&amp;CK v{data.library.meta?.attack?.version || '20'};
            tests from <ExternalLink href={ATOMIC_URL}>Atomic Red Team</ExternalLink> (MIT).
          </p>
        </fieldset>
        {problems.length > 0 && (
          <ul id={problemsId} className={`problems small ${tried ? 'tried' : ''}`} aria-live="polite">
            {problems.map((p) => <li key={p}>{p}</li>)}
          </ul>
        )}
        {submitError && <div className="state error" role="alert">{submitError}</div>}
        <div className="actions">
          <button type="submit" className="btn primary" aria-disabled={problems.length > 0 || busy}
            aria-describedby={problems.length ? problemsId : undefined}>
            {busy ? 'Creating…' : 'Create campaign'}
          </button>
          <Link className="btn ghost" to="/campaigns">Cancel</Link>
        </div>
      </form>
    </div>
  )
}
