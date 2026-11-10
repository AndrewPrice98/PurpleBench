import { Link, useSearchParams } from 'react-router-dom'
import { api, downloads } from '../api.js'
import {
  ATOMIC_URL, ATTACK_DATA_URL, DRL_URL, MISSED_MEANING, NOT_TESTED, SIGMAHQ_URL, STATUS, TTD_LABEL, countEntries,
  formatDate, formatDateTime, formatScore, formatTtd, gapText, plural,
} from '../lib.js'
import { diffCoverage, previousRun, runDownloadName, scoreDelta } from '../model.js'
import {
  ErrorState, ExternalLink, Icon, LinkedText, Loading, ModeChip, RuleName, RuleText, StatusChip, useAsync,
  usePageTitle,
} from '../components/ui.jsx'
import { DownloadLink, GapStateChip, NoRunsCTA, RunSelect } from '../components/common.jsx'

async function load(runParam, signal) {
  const runs = await api.runs(signal)
  if (!runs.length) return { runs }
  const runId = runs.some((r) => String(r.id) === runParam) ? Number(runParam) : runs[runs.length - 1].id
  const prev = previousRun(runs, runId)
  const [run, coverage, prevCoverage, rules] = await Promise.all([
    api.run(runId, signal), api.coverage(runId, signal),
    prev ? api.coverage(prev.run.id, signal) : Promise.resolve(null),
    api.ruleCatalog().catch(() => new Map()),
  ])
  return { runs, runId, run, coverage, prev, prevCoverage, rules }
}

function Downloads({ runId }) {
  return (
    <div className="download-row">
      <DownloadLink href={downloads.reportHtml(runId)} fileName={runDownloadName.reportHtml(runId)} className="btn primary">
        HTML report
      </DownloadLink>
      <DownloadLink href={downloads.reportMd(runId)} fileName={runDownloadName.reportMd(runId)}>Markdown report</DownloadLink>
      <DownloadLink href={downloads.navigator(runId)} fileName={runDownloadName.navigator(runId)}>Navigator layer</DownloadLink>
    </div>
  )
}

function Preview({ data }) {
  const { run, coverage, prev, prevCoverage, rules } = data
  const techs = coverage.techniques
  const notTested = techs.filter((t) => NOT_TESTED.has(t.status))
  const noisy = new Set(run.noisy_rules.map((n) => n.rule.id))
  const firedRules = new Map()
  for (const t of techs) for (const r of t.rules) firedRules.set(r.id, r)
  const diff = prev?.sameCampaign ? diffCoverage(prevCoverage.techniques, techs) : null
  const delta = prev ? scoreDelta(prevCoverage.score, coverage.score) : null
  return (
    <article className="card report-preview" aria-labelledby="rp-title">
      <header className="rp-head">
        <p className="eyebrow">Preview, built from the same data as the downloads</p>
        <h2 id="rp-title">PurpleBench exercise report: {run.campaign_name} (run {run.id})</h2>
        <p className="meta-line"><ModeChip mode={run.mode} /><span>Started {formatDateTime(run.started_at)}</span></p>
      </header>

      <section aria-labelledby="rp-scope">
        <h3 id="rp-scope">1. Scope</h3>
        <dl className="facts">
          <div><dt>Campaign</dt><dd><Link to={`/campaigns/${run.campaign_id}`}>{run.campaign_name}</Link></dd></div>
          <div><dt>Rule set</dt><dd className="mono">{run.ruleset_version}</dd></div>
          <div><dt>Techniques tested</dt><dd>{run.tested} of {techs.length}</dd></div>
          <div>
            <dt>Coverage score</dt>
            <dd><strong>{formatScore(coverage.score)}</strong> detected ÷ tested · {formatScore(coverage.partial_score)} counting partial as half</dd>
          </div>
          <div>
            <dt>Results</dt>
            <dd className="tags">{countEntries(coverage.counts).map(([s, n]) => <span key={s}><StatusChip status={s} /> {n}</span>)}</dd>
          </div>
        </dl>
        <p className="small muted">{MISSED_MEANING}</p>
      </section>

      <section aria-labelledby="rp-env">
        <h3 id="rp-env">2. Environment and mode</h3>
        <p>{run.mode_note}</p>
        <p className="small"><LinkedText text={run.source} /></p>
        <p className="small muted">{TTD_LABEL} is measured by event timestamps from the execution start; it is not SIEM alerting latency.</p>
      </section>

      <section aria-labelledby="rp-tactics">
        <h3 id="rp-tactics">3. Techniques tested by tactic</h3>
        <div className="table-wrap">
          <table className="table compact">
            <thead><tr><th scope="col">Tactic</th><th scope="col">Techniques</th><th scope="col">Tested</th><th scope="col">Detected</th><th scope="col">Score</th></tr></thead>
            <tbody>
              {coverage.tactics.map((t) => (
                <tr key={t.tactic}>
                  <th scope="row">{t.name}</th>
                  <td className="mono small">{techs.filter((x) => x.tactics.includes(t.tactic)).map((x) => x.technique).join(', ')}</td>
                  <td>{t.tested}</td>
                  <td>{t.counts.detected}</td>
                  <td>{formatScore(t.score)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="rp-results">
        <h3 id="rp-results">4. Results</h3>
        <table className="table cards compact">
          <thead><tr><th scope="col">Technique</th><th scope="col">Status</th><th scope="col">Rules fired (author)</th><th scope="col">{TTD_LABEL}</th></tr></thead>
          <tbody>
            {techs.map((t) => (
              <tr key={t.technique}>
                <th scope="row" data-label="Technique">
                  <Link to={`/executions/${t.execution_id}`} className="tech-link"><span className="mono tech-id">{t.technique}</span> {t.name}</Link>
                </th>
                <td data-label="Status"><StatusChip status={t.status} /></td>
                <td data-label="Rules fired">
                  {t.rules.length ? (
                    <ul className="rule-list">
                      {t.rules.map((r) => (
                        <li key={r.id}>
                          <RuleName rule={rules.get(r.id) || r} />
                          {noisy.has(r.id) && <span className="noisy-note"> · noisy, no credit</span>}
                        </li>
                      ))}
                    </ul>
                  ) : <span className="muted">—</span>}
                </td>
                <td data-label={TTD_LABEL} className="mono nowrap">{t.ttd_seconds == null ? '—' : formatTtd(t.ttd_seconds * 1000)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section aria-labelledby="rp-change">
        <h3 id="rp-change">5. Coverage change</h3>
        {!prev ? <p>No previous run to compare with.</p> : (
          <>
            <p>
              Compared with run {prev.run.id} (rule set {prev.run.ruleset_version}, {formatDate(prev.run.started_at)})
              {prev.sameCampaign ? ' of the same campaign' : `, a different campaign (${prev.run.campaign_name}): only the score is comparable`}.
              {' '}Score {formatScore(prevCoverage.score)} before, {formatScore(coverage.score)} now{delta ? ` (${delta})` : ''}.
            </p>
            {diff && (diff.changes.length === 0 ? <p>No technique changed status.</p> : (
              <ul className="change-list">
                {diff.changes.map((c) => (
                  <li key={c.id}>
                    <span className="mono">{c.id}</span> {c.name}:{' '}
                    {c.before ? STATUS[c.before]?.label : 'not in the run'} → {c.after ? STATUS[c.after]?.label : 'not in the run'}
                  </li>
                ))}
              </ul>
            ))}
          </>
        )}
      </section>

      <section aria-labelledby="rp-gaps">
        <h3 id="rp-gaps">6. Gaps and recommendations</h3>
        {run.gaps.length === 0 ? <p>No gaps recorded for this run.</p> : (
          <ul className="gap-list">
            {run.gaps.map((g) => (
              <li key={g.id} className="gap-item">
                <div className="gap-head">
                  <StatusChip status={g.kind} />
                  <span className="gap-tech"><span className="mono">{g.technique_id}</span> {g.technique.name}</span>
                  <GapStateChip gap={g} />
                </div>
                <p className="gap-notes"><RuleText text={gapText(g)} rules={rules} /></p>
                {g.telemetry_needed && <p className="gap-idea"><strong>Telemetry needed:</strong> {g.telemetry_needed}</p>}
                {g.rule_idea && <p className="gap-idea"><strong>Rule idea:</strong> {g.rule_idea}</p>}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="rp-noisy">
        <h3 id="rp-noisy">7. Noisy rules</h3>
        {run.mode === 'lab' ? <p>Rule noise was not measured for this run (no benign baseline in lab mode).</p>
          : run.noisy_rules.length === 0 ? <p>No rule was noisy on the baseline.</p> : (
            <ul className="rule-list">
              {run.noisy_rules.map((n) => <li key={n.rule.id}><RuleName rule={n.rule} /> · {plural(n.hits, 'baseline hit')}</li>)}
            </ul>
          )}
      </section>

      <section aria-labelledby="rp-untested">
        <h3 id="rp-untested">8. Untested and did not run</h3>
        {notTested.length === 0 ? <p>None.</p> : (
          <ul className="change-list">
            {notTested.map((t) => <li key={t.technique}><span className="mono">{t.technique}</span> {t.name}: {STATUS[t.status].label}. {t.reason}</li>)}
          </ul>
        )}
      </section>

      <section aria-labelledby="rp-attr">
        <h3 id="rp-attr">Attribution</h3>
        <ul className="plain-list small">
          <li>Technique and test metadata: <ExternalLink href={ATOMIC_URL}>Atomic Red Team</ExternalLink> (MIT).</li>
          {run.mode === 'recorded' && <li>Recorded telemetry: <ExternalLink href={ATTACK_DATA_URL}>Splunk attack_data</ExternalLink> (Apache-2.0).</li>}
          <li>
            Rules: <ExternalLink href={SIGMAHQ_URL}>SigmaHQ</ExternalLink> (<ExternalLink href={DRL_URL}>Detection Rule License 1.1</ExternalLink>)
            and custom rules. Rules that fired in this run:{' '}
            {[...firedRules.values()].map((r, i) => (
              <span key={r.id}>{i > 0 && '; '}<RuleName rule={rules.get(r.id) || r} /></span>
            ))}
            {firedRules.size === 0 && 'none'}.
          </li>
          <li>ATT&amp;CK® is a trademark of The MITRE Corporation.</li>
        </ul>
      </section>
    </article>
  )
}

export default function Reports() {
  usePageTitle('Reports')
  const [params, setParams] = useSearchParams()
  const runParam = params.get('run') || ''
  const { data, loading, error, reload } = useAsync((signal) => load(runParam, signal), [runParam])
  const head = (
    <header className="page-head">
      <div>
        <p className="eyebrow">Reports</p>
        <h1 tabIndex={-1}>Exercise reports</h1>
        <p className="lede">
          A purple-team exercise report for each run: scope, mode and data sources, results by tactic, the change
          since the previous run, gaps with recommendations, noisy rules, and the rule authors. The HTML report is
          self-contained and printable, with no scripts.
        </p>
      </div>
    </header>
  )
  if (loading && !data) return <div className="page">{head}<Loading /></div>
  if (error) return <div className="page">{head}<ErrorState error={error} onRetry={reload} /></div>
  if (!data.runs.length) return <div className="page">{head}<NoRunsCTA what="every report" /></div>
  return (
    <div className="page">
      {head}
      <section className="card flush" aria-labelledby="all-reports-title">
        <div className="card-head padded"><h2 id="all-reports-title">Downloads by run</h2></div>
        <table className="table cards reports-table">
          <thead><tr><th scope="col">Run</th><th scope="col">Campaign</th><th scope="col">Mode</th><th scope="col">Coverage</th><th scope="col">Downloads</th></tr></thead>
          <tbody>
            {[...data.runs].reverse().map((r) => (
              <tr key={r.id} className={r.id === data.runId ? 'current' : ''}>
                <th scope="row" data-label="Run">
                  <Link to={`/reports?run=${r.id}`} aria-current={r.id === data.runId ? 'true' : undefined}>Run {r.id}</Link>
                  <span className="muted small"> · {r.ruleset_version} · {formatDate(r.started_at)}</span>
                </th>
                <td data-label="Campaign">{r.campaign_name}</td>
                <td data-label="Mode"><ModeChip mode={r.mode} /></td>
                <td data-label="Coverage">{formatScore(r.score)}</td>
                <td data-label="Downloads" className="dl-cell">
                  <a href={downloads.reportHtml(r.id)} download={runDownloadName.reportHtml(r.id)}>HTML<span className="sr-only"> report for run {r.id}</span></a>
                  <a href={downloads.reportMd(r.id)} download={runDownloadName.reportMd(r.id)}>Markdown<span className="sr-only"> report for run {r.id}</span></a>
                  <a href={downloads.navigator(r.id)} download={runDownloadName.navigator(r.id)}>Navigator<span className="sr-only"> layer for run {r.id}</span></a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="card toolbar" aria-label="Report for one run">
        <div className="filters flush-filters">
          <RunSelect runs={data.runs} value={data.runId} label="Preview run" onChange={(v) => setParams(v ? { run: v } : {}, { replace: true })} />
        </div>
        <Downloads runId={data.runId} />
      </section>
      {loading ? <Loading /> : <Preview data={data} />}
      <p className="small muted"><Icon name="info" size={14} /> The preview is drawn from the API data; the downloads are rendered by the server from the same run.</p>
    </div>
  )
}
