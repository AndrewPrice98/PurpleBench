import { Link } from 'react-router-dom'
import { api } from '../api.js'
import {
  GAP_KIND, STATUS, countEntries, formatDate, formatScore, gapText, pickStartHere, plural, tacticLabel,
} from '../lib.js'
import {
  Empty, ErrorState, Icon, Loading, ModeChip, NoisyChip, RuleName, RuleText, StatusChip, useAsync, usePageTitle,
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

function RunLabel({ run }) {
  return <>Run {run.id} <span className="muted">· rule set {run.ruleset_version}</span></>
}

function StartHere({ story, rules }) {
  const { gap, fromRun, toRun, fromExec, toExec } = story
  const tech = gap.technique
  const was = { missed: 'missed', partial: 'only partly detected', telemetry_gap: 'unmatchable (telemetry gap)' }[gap.kind] || gap.kind
  const nowStatus = toExec?.status || 'detected'
  const closers = story.rules
  return (
    <section className="card start-here" aria-labelledby="start-title">
      <p className="eyebrow accent"><Icon name="flag" size={14} /> Start here</p>
      <h2 id="start-title">
        {tech.name} ({tech.id}) was {was} in run {gap.run_id} and {STATUS[nowStatus]?.label.toLowerCase() || nowStatus} in
        run {gap.closed_in_run}
      </h2>
      <p className="lede">
        In run {gap.run_id}{fromRun ? ` (${fromRun.campaign_name}, rule set ${fromRun.ruleset_version})` : ''}{' '}
        {gap.kind === 'missed' ? 'no rule in the rule set fired on this recording' : `the result was ${GAP_KIND[gap.kind]?.toLowerCase()}`}.{' '}
        {closers.length > 0 && (
          <>
            {story.added ? `Rule set ${toRun?.ruleset_version || ''} added ` : 'Then '}
            {closers.map((r, i) => (
              <span key={r.id}>{i > 0 && (i === closers.length - 1 ? ' and ' : ', ')}<RuleName rule={rules.get(r.id) || r} /></span>
            ))}
            {story.added ? `, and run ${gap.closed_in_run} detects the same technique.` : ` fired in run ${gap.closed_in_run}.`}
          </>
        )}
      </p>
      <ol className="story" aria-label="How the gap closed">
        <li className="story-step">
          <span className="story-run">{fromRun ? <RunLabel run={fromRun} /> : `Run ${gap.run_id}`}</span>
          <StatusChip status={fromExec?.status || GAP_STATUS[gap.kind]} />
          {fromExec && <Link to={`/executions/${fromExec.id}`} className="story-link">See the {gap.kind === 'missed' ? 'miss' : 'result'}<span className="sr-only"> in run {gap.run_id}</span></Link>}
        </li>
        <li className="story-step rule-step" aria-label="Rule that closed the gap">
          <span className="story-plus" aria-hidden="true">+</span>
          <span>{closers.length ? plural(closers.length, 'rule') : 'rule change'}{story.added ? ' added' : ''}</span>
        </li>
        <li className="story-step">
          <span className="story-run">{toRun ? <RunLabel run={toRun} /> : `Run ${gap.closed_in_run}`}</span>
          <StatusChip status={nowStatus} />
          {toExec && <Link to={`/executions/${toExec.id}`} className="story-link">See the detection<span className="sr-only"> in run {gap.closed_in_run}</span></Link>}
        </li>
      </ol>
    </section>
  )
}

function ScoreCard({ latest, coverage }) {
  const { run } = latest
  return (
    <section className="card score-card" aria-labelledby="score-title">
      <div className="card-head">
        <h2 id="score-title">Coverage score</h2>
        <Link to={`/runs/${run.id}`} className="card-link">Run {run.id} results <Icon name="arrow" size={14} /></Link>
      </div>
      <p className="muted small">
        Latest run: {run.campaign_name}, {formatDate(run.started_at)}, rule set {run.ruleset_version}.
      </p>
      <Gauge score={latest.score} detected={latest.counts.detected} tested={latest.tested} />
      <ul className="count-chips" aria-label="Results by status">
        {countEntries(latest.counts).map(([s, n]) => (
          <li key={s}><StatusChip status={s} withHelp /> <strong>{n}</strong></li>
        ))}
      </ul>
      <p className="small muted">
        Detected ÷ tested techniques. Counting partial as half: {formatScore(latest.partial_score)}.
        {coverage?.noisy_rules?.length ? ' Noisy rules earn no credit.' : ''}
      </p>
    </section>
  )
}

function TrendCard({ trend }) {
  return (
    <section className="card trend-card" aria-labelledby="trend-title">
      <div className="card-head">
        <h2 id="trend-title">Coverage over runs</h2>
        <Link to="/runs" className="card-link">All runs <Icon name="arrow" size={14} /></Link>
      </div>
      <p className="muted small">Each run evaluates a newer rule set against its campaign&apos;s recorded telemetry; runs alternate between the two campaigns.</p>
      {trend.length ? <TrendChart trend={trend} /> : <Empty>No runs yet.</Empty>}
      <ul className="legend">
        <li><span className="key strict" aria-hidden="true" /> Coverage score</li>
        <li><span className="key partial" aria-hidden="true" /> Counting partial as half</li>
      </ul>
      <details className="data-table">
        <summary>Show the numbers</summary>
        <div className="table-wrap">
          <table className="table compact">
            <caption className="sr-only">Coverage score per run</caption>
            <thead><tr><th scope="col">Run</th><th scope="col">Campaign</th><th scope="col">Date</th><th scope="col">Score</th><th scope="col">Partial as half</th></tr></thead>
            <tbody>
              {trend.map((t) => (
                <tr key={t.run_id}>
                  <th scope="row"><Link to={`/runs/${t.run_id}`}>Run {t.run_id}</Link> <span className="muted">{t.ruleset_version}</span></th>
                  <td>{t.campaign_name}</td>
                  <td className="nowrap">{formatDate(t.started_at)}</td>
                  <td>{formatScore(t.score)}</td>
                  <td>{formatScore(t.partial_score)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  )
}

function TacticCard({ coverage }) {
  return (
    <section className="card" aria-labelledby="tactic-title">
      <div className="card-head">
        <h2 id="tactic-title">Detected by tactic</h2>
        <span className="muted small">Run {coverage.run.id}</span>
      </div>
      <TacticBars tactics={coverage.tactics.map((t) => ({ ...t, name: t.name || tacticLabel(t.tactic) }))} />
      <ul className="legend">
        {['detected', 'partial', 'missed', 'telemetry_gap'].map((s) => (
          <li key={s}><span className={`key seg ${STATUS[s].tone}`} aria-hidden="true" /> {STATUS[s].label}</li>
        ))}
      </ul>
    </section>
  )
}

function TopGaps({ gaps, coverage, rules }) {
  const execOf = new Map((coverage?.techniques || []).map((t) => [t.technique, t.execution_id]))
  return (
    <section className="card" aria-labelledby="gaps-title">
      <div className="card-head">
        <h2 id="gaps-title">Top open gaps</h2>
        <span className="muted small">Latest run</span>
      </div>
      {gaps.length === 0 ? <Empty>No open gaps in the latest run.</Empty> : (
        <ul className="gap-list">
          {gaps.map((g) => (
            <li key={g.id} className="gap-item">
              <div className="gap-head">
                <StatusChip status={GAP_STATUS[g.kind] || g.kind} />
                {execOf.get(g.technique_id)
                  ? <Link to={`/executions/${execOf.get(g.technique_id)}`} className="gap-tech">{g.technique_id} {g.technique.name}</Link>
                  : <span className="gap-tech">{g.technique_id} {g.technique.name}</span>}
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
    <section className="card" aria-labelledby="noisy-title">
      <div className="card-head">
        <h2 id="noisy-title"><Icon name="noise" size={18} /> Noisy rules</h2>
        <span className="muted small">Latest run</span>
      </div>
      <p className="muted small">
        These rules also fire on the benign baseline recording, so their matches earn no detection credit. A rule
        counts as noisy above {noisy[0]?.threshold ?? 0} baseline hits.
      </p>
      {noisy.length === 0 ? <Empty>No rule fired on the benign baseline.</Empty> : (
        <ul className="noisy-list">
          {noisy.map((n) => (
            <li key={n.rule.id}>
              <RuleName rule={n.rule} link />
              <NoisyChip hits={n.hits} />
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

export default function Overview() {
  usePageTitle('Overview')
  const { data, loading, error, reload } = useAsync(load, [])
  return (
    <div className="page overview">
      <header className="hero">
        <p className="eyebrow">Purple-team detection validation</p>
        <h1 tabIndex={-1}>Detection coverage, measured</h1>
        <p className="lede">
          PurpleBench replays <span className="attack-word">Atomic Red Team techniques</span> through recorded Windows
          telemetry and checks which <span className="detect-word">Sigma rules</span> fire, so detection coverage is
          measured run by run instead of assumed.
        </p>
      </header>
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && !data.overview.latest && <NoRunsCTA what="this overview" />}
      {data?.overview.latest && (
        <>
          <ModeNotice run={data.overview.latest.run} full />
          {data.startHere && <StartHere story={data.startHere} rules={data.rules} />}
          <div className="grid-2 score-row">
            <ScoreCard latest={data.overview.latest} coverage={data.coverage} />
            <TrendCard trend={data.overview.trend} />
          </div>
          <div className="grid-2">
            <TacticCard coverage={data.coverage} />
            <TopGaps gaps={data.overview.top_gaps} coverage={data.coverage} rules={data.rules} />
          </div>
          <NoisyRules noisy={data.overview.noisy_rules} />
          <p className="counts-line muted small">
            {plural(data.overview.counts.campaigns, 'campaign')} · {plural(data.overview.counts.runs, 'run')} ·{' '}
            {plural(data.overview.counts.rules, 'bundled rule')}
            {' · '}<ModeChip mode={data.overview.latest.run.mode} />
          </p>
        </>
      )}
    </div>
  )
}
