import { Link } from 'react-router-dom'
import { api } from '../api.js'
import {
  GAP_KIND, STATUS, countEntries, formatDate, formatScore, gapText, pickStartHere, plural, tacticLabel,
} from '../lib.js'
import {
  Empty, ErrorState, Icon, Loading, ModeChip, RuleName, RuleText, StatusChip, useAsync, usePageTitle,
} from '../components/ui.jsx'
import { Gauge, TacticBars, TrendChart } from '../components/charts.jsx'
import ModeNotice from '../components/ModeNotice.jsx'
import { NoRunsCTA } from '../components/common.jsx'

const GAP_STATUS = { missed: 'missed', partial: 'partial', telemetry_gap: 'telemetry_gap' }

async function loadStartHere(closedGaps, latestRunId, signal) {
  const pick = pickStartHere(closedGaps, latestRunId)
  if (!pick) return null
  try {
    const [fromRun, toRun, fromRules] = await Promise.all([
      api.run(pick.fromRun, signal), api.run(pick.toRun, signal), api.rules({ run: pick.fromRun }, signal)])
    const find = (run) => run.executions.find((e) => e.technique.id === pick.gap.technique_id) || null
    const enabledBefore = new Set(fromRules.rules.filter((r) => r.in_ruleset).map((r) => r.id))
    return {
      ...pick, fromRun, toRun, fromExec: find(fromRun), toExec: find(toRun),
      added: pick.rules.length > 0 && pick.rules.every((r) => !enabledBefore.has(r.id)),
    }
  } catch (err) {
    if (err?.name === 'AbortError') throw err
    return { ...pick, fromRun: null, toRun: null }
  }
}

async function load(signal) {
  const overview = await api.overview(signal)
  if (!overview.latest) return { overview }
  const latestId = overview.latest.run.id
  const [coverage, closed, rules] = await Promise.all([
    api.coverage(latestId, signal), api.gaps({ status: 'closed', limit: 1000 }, signal), api.ruleCatalog()])
  const startHere = await loadStartHere(closed.gaps, latestId, signal)
  return { overview, coverage, rules, startHere }
}

/** One plain row pointing at the most telling closed gap: a miss in an earlier run, detected in a later one. */
function ClosedGap({ story, rules }) {
  const { gap, fromRun, toRun, fromExec, toExec } = story
  const tech = gap.technique
  const was = { missed: 'missed', partial: 'only partly detected', telemetry_gap: 'unmatchable (telemetry gap)' }[gap.kind] || gap.kind
  const nowStatus = toExec?.status || 'detected'
  const closers = story.rules
  return (
    <section className="pointer-row" aria-labelledby="closed-title">
      <strong id="closed-title">
        Closed gap: {tech.name} ({tech.id}) was {was} in run {gap.run_id} and {STATUS[nowStatus]?.label.toLowerCase() || nowStatus} in
        run {gap.closed_in_run}.
      </strong>
      <span>
        In run {gap.run_id}{fromRun ? ` (${fromRun.campaign_name}, rule set ${fromRun.ruleset_version})` : ''}{' '}
        {gap.kind === 'missed' ? 'no rule in the rule set earned credit on this recording' : `the result was ${GAP_KIND[gap.kind]?.toLowerCase()}`}.{' '}
        {closers.length > 0 && (
          <>
            {story.added ? `Rule set ${toRun?.ruleset_version || ''} added ` : 'Then '}
            {closers.map((r, i) => (
              <span key={r.id}>{i > 0 && (i === closers.length - 1 ? ' and ' : ', ')}<RuleName rule={rules.get(r.id) || r} /></span>
            ))}
            {story.added ? `, and run ${gap.closed_in_run} detects the same technique.` : ` fired in run ${gap.closed_in_run}.`}
          </>
        )}
      </span>
      <span className="pointer-links">
        {fromExec && (
          <Link to={`/executions/${fromExec.id}`}>
            See the {gap.kind === 'missed' ? 'miss' : 'result'}<span className="sr-only"> in run {gap.run_id}</span>
          </Link>
        )}
        {toExec && (
          <Link to={`/executions/${toExec.id}`}>See the detection<span className="sr-only"> in run {gap.closed_in_run}</span></Link>
        )}
      </span>
    </section>
  )
}

function Summary({ latest, coverage }) {
  const { run } = latest
  return (
    <section className="panel kpis" aria-labelledby="score-title">
      <div className="kpi gauge">
        <h2 id="score-title" className="kpi-label">
          Coverage score
          <Link to={`/runs/${run.id}`} className="panel-link">Run {run.id} results <Icon name="arrow" size={14} /></Link>
        </h2>
        <Gauge score={latest.score} partialScore={latest.partial_score} detected={latest.counts.detected} tested={latest.tested} />
        <p className="kpi-sub">
          Latest run: {run.campaign_name}, {formatDate(run.started_at)}, rule set {run.ruleset_version}. Detected ÷ tested
          techniques{coverage?.noisy_rules?.length ? '; noisy rules earn no credit' : ''}.
        </p>
      </div>
      {countEntries(latest.counts).map(([s, n]) => (
        <div className="kpi" key={s}>
          <span className="kpi-label"><StatusChip status={s} withHelp /></span>
          <span className="kpi-num">{n}</span>
        </div>
      ))}
    </section>
  )
}

function TrendPanel({ trend }) {
  return (
    <section className="panel" aria-labelledby="trend-title">
      <div className="panel-head">
        <h2 id="trend-title">Coverage over runs</h2>
        <Link to="/runs" className="panel-link">All runs <Icon name="arrow" size={14} /></Link>
      </div>
      <div className="panel-body">
        {trend.length ? <TrendChart trend={trend} /> : <Empty>No runs yet.</Empty>}
        <p className="muted small">Each run evaluates a newer rule set against its campaign&apos;s recorded telemetry; runs alternate between the two campaigns.</p>
      </div>
      <details className="fold">
        <summary><Icon name="chevronRight" size={14} className="chev" /> Show the numbers</summary>
        <div className="table-wrap">
          <table className="table compact">
            <caption className="sr-only">Coverage score per run</caption>
            <thead><tr><th scope="col">Run</th><th scope="col">Campaign</th><th scope="col">Date</th><th scope="col" className="num">Score</th><th scope="col" className="num">Partial as half</th></tr></thead>
            <tbody>
              {trend.map((t) => (
                <tr key={t.run_id}>
                  <th scope="row"><Link to={`/runs/${t.run_id}`}>Run {t.run_id}</Link> <span className="muted">{t.ruleset_version}</span></th>
                  <td>{t.campaign_name}</td>
                  <td className="nowrap">{formatDate(t.started_at)}</td>
                  <td className="num">{formatScore(t.score)}</td>
                  <td className="num">{formatScore(t.partial_score)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  )
}

function TacticPanel({ coverage }) {
  return (
    <section className="panel" aria-labelledby="tactic-title">
      <div className="panel-head">
        <h2 id="tactic-title">Detected by tactic</h2>
        <span className="muted small">Run {coverage.run.id}</span>
      </div>
      <div className="panel-body">
        <TacticBars tactics={coverage.tactics.map((t) => ({ ...t, name: t.name || tacticLabel(t.tactic) }))} />
        <ul className="legend">
          {['detected', 'partial', 'missed', 'telemetry_gap'].map((s) => (
            <li key={s}><span className={`key seg ${STATUS[s].tone}`} aria-hidden="true" /> {STATUS[s].label}</li>
          ))}
        </ul>
      </div>
    </section>
  )
}

function TopGaps({ gaps, coverage, rules }) {
  const execOf = new Map((coverage?.techniques || []).map((t) => [t.technique, t.execution_id]))
  return (
    <section className="panel" aria-labelledby="gaps-title">
      <div className="panel-head rule">
        <h2 id="gaps-title">Top open gaps</h2>
        <Link to="/gaps" className="panel-link">All gaps <Icon name="arrow" size={14} /></Link>
      </div>
      {gaps.length === 0 ? <Empty>No open gaps in the latest run.</Empty> : (
        <ul className="gap-list">
          {gaps.map((g) => (
            <li key={g.id} className="gap-item">
              <div className="gap-head">
                <StatusChip status={GAP_STATUS[g.kind] || g.kind} />
                {execOf.get(g.technique_id)
                  ? <Link to={`/executions/${execOf.get(g.technique_id)}`} className="gap-tech"><span className="mono">{g.technique_id}</span> {g.technique.name}</Link>
                  : <span className="gap-tech"><span className="mono">{g.technique_id}</span> {g.technique.name}</span>}
              </div>
              <p className="gap-notes"><RuleText text={gapText(g)} rules={rules} /></p>
              {g.rule_idea && <p className="gap-idea"><strong>Rule idea:</strong> {g.rule_idea}</p>}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function NoisyRules({ noisy }) {
  return (
    <section className="panel" aria-labelledby="noisy-title">
      <div className="panel-head rule">
        <h2 id="noisy-title">Noisy rules</h2>
        <Link to="/rules?noise=noisy" className="panel-link">All rules <Icon name="arrow" size={14} /></Link>
      </div>
      {noisy.length === 0 ? <Empty>No rule fired on the benign baseline.</Empty> : (
        <table className="table compact noisy-table">
          <thead><tr><th scope="col">Rule (author)</th><th scope="col" className="num">Baseline hits</th></tr></thead>
          <tbody>
            {noisy.map((n) => (
              <tr key={n.rule.id}>
                <td><RuleName rule={n.rule} link /></td>
                <td className="num">{n.hits}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="panel-note">
        These rules also fire on the benign baseline recording, so their matches earn no detection credit. A rule
        counts as noisy above {noisy[0]?.threshold ?? 0} baseline hits.
      </p>
    </section>
  )
}

export default function Overview() {
  usePageTitle('Overview')
  const { data, loading, error, reload } = useAsync(load, [])
  return (
    <div className="page overview">
      <header className="page-head">
        <div>
          <h1 tabIndex={-1}>Overview</h1>
          <p className="page-sub">Atomic Red Team techniques replayed through recorded Windows telemetry, scored against Sigma rules.</p>
        </div>
      </header>
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && !data.overview.latest && <NoRunsCTA what="this overview" />}
      {data?.overview.latest && (
        <>
          <ModeNotice run={data.overview.latest.run} />
          {data.startHere && <ClosedGap story={data.startHere} rules={data.rules} />}
          <Summary latest={data.overview.latest} coverage={data.coverage} />
          <div className="grid-2">
            <TrendPanel trend={data.overview.trend} />
            <TacticPanel coverage={data.coverage} />
          </div>
          <div className="grid-2">
            <TopGaps gaps={data.overview.top_gaps} coverage={data.coverage} rules={data.rules} />
            <NoisyRules noisy={data.overview.noisy_rules} />
          </div>
          <p className="counts-line">
            {plural(data.overview.counts.campaigns, 'campaign')} · {plural(data.overview.counts.runs, 'run')} ·{' '}
            {plural(data.overview.counts.rules, 'bundled rule')} · <ModeChip mode={data.overview.latest.run.mode} plain />
          </p>
        </>
      )}
    </div>
  )
}
