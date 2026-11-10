import { Link, useSearchParams } from 'react-router-dom'
import { api, downloads } from '../api.js'
import { STATUS, STATUS_ORDER, formatScore, plural } from '../lib.js'
import { diffCoverage, matrixColumns, previousRun, runDownloadName, scoreDelta, statusCounts } from '../model.js'
import {
  Empty, ErrorState, ExternalLink, Icon, Loading, StatusChip, useAsync, usePageTitle,
} from '../components/ui.jsx'
import { DownloadLink, NoRunsCTA, RunSelect, runOptionLabel } from '../components/common.jsx'
import ModeNotice from '../components/ModeNotice.jsx'

const NAVIGATOR_URL = 'https://mitre-attack.github.io/attack-navigator/'

async function load(runParam, compareParam, signal) {
  const runs = await api.runs(signal)
  if (!runs.length) return { runs }
  const runId = runs.some((r) => String(r.id) === runParam) ? Number(runParam) : runs[runs.length - 1].id
  const auto = previousRun(runs, runId)
  let compare = null
  if (compareParam === 'none') compare = null
  else if (compareParam && runs.some((r) => String(r.id) === compareParam && r.id !== runId)) {
    const run = runs.find((r) => String(r.id) === compareParam)
    compare = { run, sameCampaign: run.campaign_id === runs.find((r) => r.id === runId).campaign_id }
  } else compare = auto
  const [coverage, prevCoverage] = await Promise.all([
    api.coverage(runId, signal),
    compare ? api.coverage(compare.run.id, signal) : Promise.resolve(null),
  ])
  return { runs, runId, coverage, compare, prevCoverage, auto }
}

const ARROW = { improved: 'up', regressed: 'down', changed: 'swap', added: 'plus', removed: 'minus' }
const DIRECTION = {
  improved: 'Improved', regressed: 'Regressed', changed: 'Changed', added: 'New in this run', removed: 'No longer tested',
}

function Cell({ t, change }) {
  return (
    <li className={`cell s-${t.status}`}>
      <Link to={`/executions/${t.execution_id}`} className="cell-link">
        <span className="cell-top">
          <span className="cell-id mono">{t.technique}</span>
          {change && (
            <span className={`cell-delta ${change.direction}`} title={`${DIRECTION[change.direction]} since the compared run`}>
              <Icon name={ARROW[change.direction]} size={14} />
              <span className="sr-only">{DIRECTION[change.direction]}</span>
            </span>
          )}
        </span>
        <span className="cell-name">{t.name}</span>
        <span className="cell-status"><StatusChip status={t.status} /></span>
        {change?.before && <span className="cell-was">was {STATUS[change.before]?.label.toLowerCase() || change.before}</span>}
      </Link>
    </li>
  )
}

function Matrix({ coverage, changes }) {
  const { columns, empty } = matrixColumns(coverage.techniques)
  const byId = new Map((changes || []).map((c) => [c.id, c]))
  return (
    <>
      <div className="matrix">
        {columns.map((col) => (
          <section key={col.slug} className="matrix-col" aria-labelledby={`tac-${col.slug}`}>
            <header className="matrix-head">
              <h3 id={`tac-${col.slug}`}>{col.name}</h3>
              <p>
                {col.id && <span className="mono">{col.id} · </span>}
                {col.tested ? `${col.detected}/${col.tested} detected` : 'nothing tested'}
              </p>
            </header>
            <ul className="cells">
              {col.techniques.map((t) => <Cell key={t.technique} t={t} change={byId.get(t.technique)} />)}
            </ul>
          </section>
        ))}
      </div>
      {empty.length > 0 && (
        <p className="small muted empty-tactics">
          <strong>Not in this campaign:</strong> {empty.map((t) => t.name).join(', ')}. ATT&amp;CK v20 has 15 Enterprise
          tactics; v19 split Defense Evasion into Stealth and Defense Impairment.
        </p>
      )}
    </>
  )
}

function Legend({ counts }) {
  return (
    <ul className="count-row matrix-legend" aria-label="Status legend with technique counts">
      {STATUS_ORDER.map((s) => (
        <li key={s}><StatusChip status={s} /> <strong>{counts[s] || 0}</strong></li>
      ))}
      <li><Icon name="up" size={14} /><Icon name="down" size={14} /> Changed since the compared run</li>
    </ul>
  )
}

function Diff({ data }) {
  const { coverage, compare, prevCoverage } = data
  if (!compare) {
    return (
      <section className="panel" aria-labelledby="diff-title">
        <div className="panel-head"><h2 id="diff-title">Change since an earlier run</h2></div>
        <Empty>{data.auto ? 'Comparison is off.' : 'This is the first run, so there is nothing to compare with.'}</Empty>
      </section>
    )
  }
  const delta = scoreDelta(prevCoverage.score, coverage.score)
  const diff = compare.sameCampaign ? diffCoverage(prevCoverage.techniques, coverage.techniques) : null
  const execOf = new Map(coverage.techniques.map((t) => [t.technique, t.execution_id]))
  const prevExecOf = new Map(prevCoverage.techniques.map((t) => [t.technique, t.execution_id]))
  return (
    <section className="panel" aria-labelledby="diff-title">
      <div className="panel-head">
        <h2 id="diff-title">Change since run {compare.run.id}</h2>
        <span className="muted small">{runOptionLabel(compare.run)}</span>
      </div>
      <p className="diff-score">
        Coverage <strong>{formatScore(prevCoverage.score)}</strong> → <strong>{formatScore(coverage.score)}</strong>
        {delta && <span className={`delta-text ${coverage.score >= prevCoverage.score ? 'up' : 'down'}`}> ({delta})</span>}
      </p>
      {!compare.sameCampaign ? (
        <p className="muted small diff-note">
          Run {compare.run.id} is a different campaign ({compare.run.campaign_name}), so the technique sets differ:
          only the score is comparable and no per-technique changes are shown.
        </p>
      ) : diff.changes.length === 0 ? <Empty>No technique changed status.</Empty> : (
        <>
          <p className="small muted diff-note">
            {plural(diff.improved, 'technique')} improved, {diff.regressed} regressed
            {diff.changed ? `, ${diff.changed} changed without a better or worse result` : ''}
            {diff.added ? `, ${diff.added} new` : ''}{diff.removed ? `, ${diff.removed} no longer tested` : ''}.
          </p>
          <table className="table cards compact diff-table">
            <caption className="sr-only">Techniques whose status changed since run {compare.run.id}</caption>
            <thead>
              <tr><th scope="col">Technique</th><th scope="col">Run {compare.run.id}</th><th scope="col">Run {coverage.run.id}</th><th scope="col">Change</th></tr>
            </thead>
            <tbody>
              {diff.changes.map((c) => (
                <tr key={c.id}>
                  <th scope="row" data-label="Technique">
                    {execOf.get(c.id)
                      ? <Link to={`/executions/${execOf.get(c.id)}`} className="tech-link"><span className="mono tech-id">{c.id}</span>{c.name}</Link>
                      : <><span className="mono tech-id">{c.id}</span>{c.name}</>}
                  </th>
                  <td data-label={`Run ${compare.run.id}`}>
                    {c.before ? (prevExecOf.get(c.id)
                      ? <Link to={`/executions/${prevExecOf.get(c.id)}`} className="chip-link"><StatusChip status={c.before} /><span className="sr-only"> in run {compare.run.id}</span></Link>
                      : <StatusChip status={c.before} />) : <span className="muted">not in the run</span>}
                  </td>
                  <td data-label={`Run ${coverage.run.id}`}>
                    {c.after ? <StatusChip status={c.after} /> : <span className="muted">not in the run</span>}
                  </td>
                  <td data-label="Change"><span className={`delta-text ${c.direction}`}><Icon name={ARROW[c.direction]} size={14} />{DIRECTION[c.direction]}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  )
}

export default function Coverage() {
  usePageTitle('Coverage')
  const [params, setParams] = useSearchParams()
  const runParam = params.get('run') || ''
  const compareParam = params.get('compare') || ''
  const { data, loading, error, reload } = useAsync((signal) => load(runParam, compareParam, signal), [runParam, compareParam])
  function set(key, value) {
    setParams((p) => {
      const next = new URLSearchParams(p)
      if (value) next.set(key, value)
      else next.delete(key)
      if (key === 'run') next.delete('compare')
      return next
    }, { replace: true })
  }
  const head = (
    <header className="page-head">
      <div>
        <h1 tabIndex={-1}>ATT&amp;CK coverage</h1>
        <p className="page-sub">Every technique a run tested, under its ATT&amp;CK v20 tactics. Each cell opens the result behind it.</p>
      </div>
      {data?.coverage && (
        <div className="head-score" aria-label={`Coverage score ${formatScore(data.coverage.score)}`}>
          <span className="head-score-num">{formatScore(data.coverage.score)}</span>
          <span className="head-score-sub">
            {data.coverage.counts.detected} of {data.coverage.tested} tested detected · {formatScore(data.coverage.partial_score)} counting partial as half
          </span>
        </div>
      )}
    </header>
  )
  if (loading && !data) return <div className="page">{head}<Loading /></div>
  if (error) return <div className="page">{head}<ErrorState error={error} onRetry={reload} /></div>
  if (!data.runs.length) return <div className="page">{head}<NoRunsCTA what="the coverage matrix" /></div>
  const { runs, runId, coverage, compare, prevCoverage } = data
  const changes = compare?.sameCampaign ? diffCoverage(prevCoverage.techniques, coverage.techniques).changes : []
  const earlier = runs.filter((r) => r.id !== runId)
  return (
    <div className={`page ${loading ? 'busy-page' : ''}`}>
      {head}
      <section className="toolbar alone" aria-label="Run and comparison">
        <RunSelect runs={runs} value={runId} onChange={(v) => set('run', v)} />
        <RunSelect runs={earlier} value={compare ? compare.run.id : 'none'} label="Compare with"
          onChange={(v) => set('compare', v)} extra={<option value="none">No comparison</option>} />
        <span className="filter-count">
          <DownloadLink href={downloads.navigator(runId)} fileName={runDownloadName.navigator(runId)}>
            Navigator layer (JSON)
          </DownloadLink>
        </span>
      </section>
      <ModeNotice run={coverage.run} />
      <section className="panel" aria-labelledby="matrix-title">
        <div className="panel-head">
          <h2 id="matrix-title">Run {coverage.run.id}: {coverage.run.campaign_name}</h2>
          <span className="muted small">Rule set {coverage.run.ruleset_version} · {plural(coverage.techniques.length, 'technique')}</span>
        </div>
        <div className="panel-body">
          <Legend counts={statusCounts(coverage.techniques)} />
          <Matrix coverage={coverage} changes={changes} />
        </div>
        <p className="panel-note">
          Navigator layer: ATT&amp;CK Navigator format 4.5, coloured by status with a comment per technique. Open it in{' '}
          <ExternalLink href={NAVIGATOR_URL}>ATT&amp;CK Navigator</ExternalLink> with Open Existing Layer → Upload from local.
        </p>
      </section>
      <Diff data={data} />
      {coverage.noisy_rules?.length > 0 && (
        <p className="counts-line">
          {plural(coverage.noisy_rules.length, 'noisy rule')} in this rule set earned no credit; see the{' '}
          <Link to={`/rules?run=${runId}&noise=noisy`}>noisy rules</Link>.
        </p>
      )}
    </div>
  )
}
