import { useId } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import {
  STATUS, STATUS_ORDER, TTD_LABEL, countEntries, filterExecutions, formatDate, formatScore, formatTtd, gapText, plural,
  tacticLabel, tacticsOf,
} from '../lib.js'
import {
  Empty, ErrorState, Icon, Loading, ModeChip, RuleName, RuleText, Select, StatusChip, TacticTag,
  useAsync, usePageTitle,
} from '../components/ui.jsx'
import { GapStateChip } from '../components/common.jsx'
import ModeNotice from '../components/ModeNotice.jsx'

async function load(runId, signal) {
  const [run, rules] = await Promise.all([api.run(runId, signal), api.ruleCatalog().catch(() => new Map())])
  return { run, rules }
}

function Filters({ executions, status, tactic, setFilter, clear, shown }) {
  const statusId = useId()
  const tacticId = useId()
  const statusCounts = Object.fromEntries(STATUS_ORDER.map((s) => [s, executions.filter((e) => e.status === s).length]))
  return (
    <div className="filters" role="group" aria-label="Filter results">
      <span className="filter-field">
        <label htmlFor={statusId}>Status</label>
        <Select id={statusId} value={status} onChange={(e) => setFilter('status', e.target.value)}>
          <option value="">All statuses</option>
          {STATUS_ORDER.filter((s) => statusCounts[s]).map((s) => (
            <option key={s} value={s}>{STATUS[s].label} ({statusCounts[s]})</option>
          ))}
        </Select>
      </span>
      <span className="filter-field">
        <label htmlFor={tacticId}>Tactic</label>
        <Select id={tacticId} value={tactic} onChange={(e) => setFilter('tactic', e.target.value)}>
          <option value="">All tactics</option>
          {tacticsOf(executions).map((t) => <option key={t} value={t}>{tacticLabel(t)}</option>)}
        </Select>
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

/** The rules that matched in this execution, each with its author, from the run detail itself. */
function RulesCell({ execution, catalog }) {
  const rules = execution.rules || []
  if (rules.length) {
    return (
      <ul className="rule-list">
        {rules.map((r) => (
          <li key={r.id}>
            <RuleName rule={catalog.get(r.id) || r} />
            {r.noisy && <span className="noisy-note"> · noisy, no credit</span>}
          </li>
        ))}
      </ul>
    )
  }
  return <span className="muted">None fired</span>
}

export default function RunDetail() {
  const { runId } = useParams()
  usePageTitle(`Run ${runId}`)
  const { data, loading, error, reload } = useAsync((signal) => load(runId, signal), [runId])
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
  const { run, rules: catalog } = data
  const shown = filterExecutions(run.executions, { status, tactic })
  return (
    <div className="page">
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/runs"><Icon name="back" size={14} /> All runs</Link>
      </nav>
      <header className="page-head">
        <div>
          <h1 tabIndex={-1}>{run.campaign_name}</h1>
          <p className="meta-line">
            <span>Run {run.id} · {formatDate(run.started_at)}</span>
            <ModeChip mode={run.mode} />
            <span>Rule set <strong className="mono">{run.ruleset_version}</strong></span>
            <span>{plural(run.tested, 'technique')} tested</span>
          </p>
          {run.notes && <p className="page-sub">{run.notes}</p>}
        </div>
        <div className="head-score" aria-label={`Coverage score ${formatScore(run.score)}`}>
          <span className="head-score-num">{formatScore(run.score)}</span>
          <span className="head-score-sub">coverage · {formatScore(run.partial_score)} counting partial as half</span>
        </div>
      </header>
      <ModeNotice run={run} />
      <ul className="count-row" aria-label="Results by status">
        {countEntries(run.counts).map(([s, n]) => (
          <li key={s}><StatusChip status={s} withHelp /> <strong>{n}</strong></li>
        ))}
      </ul>

      <section className="panel" aria-labelledby="results-title">
        <div className="panel-head rule">
          <h2 id="results-title">Results</h2>
        </div>
        <Filters executions={run.executions} status={status} tactic={tactic} setFilter={setFilter} clear={clear} shown={shown.length} />
        {shown.length === 0 ? <Empty>No results match these filters.</Empty> : (
          <table className="table wide results-table">
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
                <tr key={e.id}>
                  <th scope="row" data-label="Technique">
                    <Link to={`/executions/${e.id}`} className="tech-link">
                      <span className="mono tech-id">{e.technique.id}</span>{e.technique.name}
                    </Link>
                  </th>
                  <td data-label="Tactic">
                    <span className="tags">{e.technique.tactics.map((t) => <TacticTag key={t} tactic={t} />)}</span>
                  </td>
                  <td data-label="Status"><StatusChip status={e.status} withHelp /></td>
                  <td data-label="Rules fired"><RulesCell execution={e} catalog={catalog} /></td>
                  <td data-label={TTD_LABEL} className="nowrap mono num">{formatTtd(e.ttd_ms)}</td>
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
        <section className="panel" aria-labelledby="run-gaps-title">
          <div className="panel-head rule"><h2 id="run-gaps-title">Gaps found in this run</h2></div>
          {run.gaps.length === 0 ? <Empty>No gaps: every tested technique was detected.</Empty> : (
            <ul className="gap-list">
              {run.gaps.map((g) => (
                <li key={g.id} className="gap-item">
                  <div className="gap-head">
                    <StatusChip status={g.kind} />
                    <span className="gap-tech"><span className="mono">{g.technique_id}</span> {g.technique.name}</span>
                    <GapStateChip gap={g} />
                  </div>
                  <p className="gap-notes"><RuleText text={gapText(g)} rules={catalog} /></p>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="panel" aria-labelledby="run-noisy-title">
          <div className="panel-head rule"><h2 id="run-noisy-title">Noisy rules in this rule set</h2></div>
          {run.mode === 'lab' ? <Empty>Not measured: lab runs have no benign baseline to measure noise against.</Empty>
            : run.noisy_rules.length === 0 ? <Empty>No rule fired on the benign baseline.</Empty> : (
              <>
                <table className="table compact noisy-table">
                  <thead><tr><th scope="col">Rule (author)</th><th scope="col" className="num">Baseline hits</th></tr></thead>
                  <tbody>
                    {run.noisy_rules.map((n) => (
                      <tr key={n.rule.id}>
                        <td><RuleName rule={n.rule} link /></td>
                        <td className="num">{n.hits}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="panel-note">They fire on the benign baseline recording, so their matches earn no credit.</p>
              </>
            )}
        </section>
      </div>
    </div>
  )
}
