import { useId } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import {
  STATUS, STATUS_ORDER, TTD_LABEL, countEntries, filterExecutions, formatDate, formatScore, formatTtd, plural,
  tacticLabel, tacticsOf,
} from '../lib.js'
import {
  Chip, Empty, ErrorState, Icon, Loading, ModeChip, NoisyChip, RuleName, RuleText, StatusChip, TacticTag,
  useAsync, usePageTitle,
} from '../components/ui.jsx'
import ModeNotice from '../components/ModeNotice.jsx'

async function load(runId) {
  const [run, coverage, rules] = await Promise.all([
    api.run(runId),
    api.coverage(runId).catch(() => null),
    api.ruleCatalog().catch(() => new Map()),
  ])
  return { run, coverage, rules }
}

const GAP_STATE = {
  open: { tone: 'outline', glyph: '○', label: 'Open' },
  closed: { tone: 'detected', glyph: '✓', label: 'Closed' },
  accepted: { tone: 'neutral', glyph: '≡', label: 'Accepted' },
}

function Filters({ executions, status, tactic, setFilter, clear, shown, tacticNames }) {
  const statusId = useId()
  const tacticId = useId()
  const statusCounts = Object.fromEntries(STATUS_ORDER.map((s) => [s, executions.filter((e) => e.status === s).length]))
  return (
    <div className="filters" role="group" aria-label="Filter results">
      <span className="filter-field">
        <label htmlFor={statusId}>Status</label>
        <select id={statusId} value={status} onChange={(e) => setFilter('status', e.target.value)}>
          <option value="">All statuses</option>
          {STATUS_ORDER.filter((s) => statusCounts[s]).map((s) => (
            <option key={s} value={s}>{STATUS[s].label} ({statusCounts[s]})</option>
          ))}
        </select>
      </span>
      <span className="filter-field">
        <label htmlFor={tacticId}>Tactic</label>
        <select id={tacticId} value={tactic} onChange={(e) => setFilter('tactic', e.target.value)}>
          <option value="">All tactics</option>
          {tacticsOf(executions).map((t) => <option key={t} value={t}>{tacticNames.get(t) || tacticLabel(t)}</option>)}
        </select>
      </span>
      {(status || tactic) && (
        <button type="button" className="btn ghost small" onClick={clear}>
          Clear filters
        </button>
      )}
      <span className="filter-count" role="status">Showing {shown} of {plural(executions.length, 'execution')}</span>
    </div>
  )
}

function RulesCell({ execution, rulesByExec, catalog, noisy }) {
  const rules = rulesByExec.get(execution.id)
  if (rules?.length) {
    return (
      <ul className="rule-list">
        {rules.map((r) => (
          <li key={r.id}>
            <RuleName rule={catalog.get(r.id) || r} />
            {noisy.has(r.id) && <span className="noisy-note"> · noisy, no credit</span>}
          </li>
        ))}
      </ul>
    )
  }
  if (execution.rules_fired) return <span>{plural(execution.rules_fired, 'rule')} fired</span>
  return <span className="muted">None fired</span>
}

export default function RunDetail() {
  const { runId } = useParams()
  usePageTitle(`Run ${runId}`)
  const { data, loading, error, reload } = useAsync(() => load(runId), [runId])
  const [params, setParams] = useSearchParams()
  const status = STATUS[params.get('status')] ? params.get('status') : ''
  const tactic = params.get('tactic') || ''
  function setFilter(key, value) {
    setParams((p) => {
      const next = new URLSearchParams(p)
      if (value) next.set(key, value)
      else next.delete(key)
      return next
    }, { replace: true })
  }
  const clear = () => setParams(new URLSearchParams(), { replace: true })

  if (loading && !data) return <div className="page"><Loading /></div>
  if (error) {
    return (
      <div className="page">
        <h1 tabIndex={-1} className="h-inline">Run {runId}</h1>
        <ErrorState error={error} onRetry={error.status === 404 ? undefined : reload} />
        <p><Link to="/runs">Back to all runs</Link></p>
      </div>
    )
  }
  const { run, coverage, rules: catalog } = data
  const rulesByExec = new Map((coverage?.techniques || []).map((t) => [t.execution_id, t.rules]))
  const tacticNames = new Map((coverage?.tactics || []).map((t) => [t.tactic, t.name]))
  const noisyIds = new Set(run.noisy_rules.map((n) => n.rule.id))
  const shown = filterExecutions(run.executions, { status, tactic })
  return (
    <div className="page">
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/runs"><Icon name="back" size={14} /> All runs</Link>
      </nav>
      <header className="page-head">
        <div>
          <p className="eyebrow">Run {run.id} · {formatDate(run.started_at)}</p>
          <h1 tabIndex={-1}>{run.campaign_name}</h1>
          <p className="meta-line">
            <ModeChip mode={run.mode} />
            <span>Rule set <strong className="mono">{run.ruleset_version}</strong></span>
            <span>{plural(run.tested, 'technique')} tested</span>
          </p>
          {run.notes && <p className="lede">{run.notes}</p>}
        </div>
        <div className="head-score" aria-label={`Coverage score ${formatScore(run.score)}`}>
          <span className="head-score-num">{formatScore(run.score)}</span>
          <span className="head-score-sub">coverage · {formatScore(run.partial_score)} counting partial as half</span>
        </div>
      </header>
      <ModeNotice run={run} />
      <ul className="count-chips wide" aria-label="Results by status">
        {countEntries(run.counts).map(([s, n]) => (
          <li key={s}><StatusChip status={s} withHelp /> <strong>{n}</strong></li>
        ))}
      </ul>

      <section className="card flush" aria-labelledby="results-title">
        <div className="card-head padded">
          <h2 id="results-title">Results</h2>
        </div>
        <Filters executions={run.executions} status={status} tactic={tactic} setFilter={setFilter} clear={clear} shown={shown.length}
          tacticNames={tacticNames} />
        {shown.length === 0 ? <Empty>No results match these filters.</Empty> : (
          <table className="table cards results-table">
            <thead>
              <tr>
                <th scope="col">Technique</th>
                <th scope="col">Tactic</th>
                <th scope="col">Status</th>
                <th scope="col">Rules fired (author)</th>
                <th scope="col" className="ttd-col"><abbr title="Time from the execution start to the first matching event, by event timestamps">{TTD_LABEL}</abbr></th>
                <th scope="col">Reason</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((e) => (
                <tr key={e.id} className={`status-${e.status}`}>
                  <th scope="row" data-label="Technique">
                    <Link to={`/executions/${e.id}`} className="tech-link">
                      <span className="mono tech-id">{e.technique.id}</span> {e.technique.name}
                    </Link>
                  </th>
                  <td data-label="Tactic">
                    <span className="tags">{e.technique.tactics.map((t) => <TacticTag key={t} tactic={t} name={tacticNames.get(t)} />)}</span>
                  </td>
                  <td data-label="Status"><StatusChip status={e.status} withHelp /></td>
                  <td data-label="Rules fired"><RulesCell execution={e} rulesByExec={rulesByExec} catalog={catalog} noisy={noisyIds} /></td>
                  <td data-label={TTD_LABEL} className="nowrap mono">{formatTtd(e.ttd_ms)}</td>
                  <td data-label="Reason" className="reason"><RuleText text={e.reason} rules={catalog} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="table-note">
          <Icon name="clock" size={14} /> <strong>{TTD_LABEL}</strong> is the time from the execution start to the first
          event a credited rule matched, by event timestamps (clamped at 0, with a ±5 s clock-skew tolerance). It is
          not SIEM alerting latency.
        </p>
      </section>

      <div className="grid-2">
        <section className="card" aria-labelledby="run-gaps-title">
          <h2 id="run-gaps-title">Gaps found in this run</h2>
          {run.gaps.length === 0 ? <Empty>No gaps: every tested technique was detected.</Empty> : (
            <ul className="gap-list">
              {run.gaps.map((g) => {
                const st = GAP_STATE[g.status] || GAP_STATE.open
                return (
                  <li key={g.id} className="gap-item">
                    <div className="gap-head">
                      <StatusChip status={g.kind} />
                      <span className="gap-tech">{g.technique_id} {g.technique.name}</span>
                      <Chip tone={st.tone} glyph={st.glyph}>
                        {st.label}{g.status === 'closed' && g.closed_in_run ? ` in run ${g.closed_in_run}` : ''}
                      </Chip>
                    </div>
                    <p className="gap-notes"><RuleText text={g.notes} rules={catalog} /></p>
                  </li>
                )
              })}
            </ul>
          )}
        </section>
        <section className="card" aria-labelledby="run-noisy-title">
          <h2 id="run-noisy-title">Noisy rules in this rule set</h2>
          {run.noisy_rules.length === 0 ? <Empty>No rule fired on the benign baseline.</Empty> : (
            <>
              <p className="muted small">They fire on the benign baseline recording, so their matches earn no credit.</p>
              <ul className="noisy-list">
                {run.noisy_rules.map((n) => (
                  <li key={n.rule.id}><RuleName rule={n.rule} link /><NoisyChip hits={n.hits} /></li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>
    </div>
  )
}
