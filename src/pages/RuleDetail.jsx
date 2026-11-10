import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { DRL_URL, SIGMAHQ_URL, attackUrl, plural } from '../lib.js'
import { hitsByRun } from '../model.js'
import {
  Chip, Empty, ErrorState, ExternalLink, Icon, Loading, NoisyChip, RelationChip, useAsync, usePageTitle,
} from '../components/ui.jsx'
import { SourceLabel, SupportChip } from './Rules.jsx'

async function load(ruleId, signal) {
  const [rule, runs, library] = await Promise.all([
    api.rule(ruleId, signal), api.runs(signal), api.library(signal).catch((err) => {
      if (err?.name === 'AbortError') throw err
      return { techniques: [] }
    }),
  ])
  return { rule, runs, techniques: new Map(library.techniques.map((t) => [t.id, t])) }
}

function Attribution({ rule }) {
  const sigma = rule.source === 'sigmahq'
  return (
    <aside className="attribution-box" aria-label="Rule attribution and licence">
      <p className="ab-title">
        {sigma ? 'SigmaHQ rule' : 'Custom PurpleBench rule'} by <strong className="rule-author-strong">{rule.author || 'author unknown'}</strong>
      </p>
      {sigma ? (
        <p>
          From the <ExternalLink href={SIGMAHQ_URL}>SigmaHQ</ExternalLink> repository, shown and evaluated unmodified
          under the <ExternalLink href={DRL_URL}>Detection Rule License 1.1</ExternalLink>, which requires the author
          to be named wherever the rule is used.
          {rule.url && <> <ExternalLink href={rule.url}>Rule file on GitHub</ExternalLink> (pinned commit).</>}
        </p>
      ) : (
        <p>
          Written for PurpleBench in the same Sigma format. Licence: {rule.licence === 'DRL-1.1'
            ? <ExternalLink href={DRL_URL}>Detection Rule License 1.1</ExternalLink> : (rule.licence || 'not stated')}.
          {rule.file && <> File <span className="mono">{rule.file}</span>.</>}
        </p>
      )}
    </aside>
  )
}

function WhereFired({ rule, runs, techniques }) {
  const groups = hitsByRun(rule.hits)
  const runById = new Map(runs.map((r) => [r.id, r]))
  if (!groups.length) {
    return <Empty>This rule has not fired in any run{rule.status !== 'ok' ? ': it is not evaluated (unsupported)' : ''}.</Empty>
  }
  return (
    <>
      {rule.hits_capped && <p className="small muted" role="note">Showing the first {rule.hits.length} of {rule.hits_total} executions.</p>}
      <ul className="fired-runs">
        {groups.map(({ runId, hits }) => {
          const run = runById.get(runId)
          return (
            <li key={runId}>
              <p className="fired-run-head">
                <Link to={`/runs/${runId}`}>Run {runId}</Link>
                {run && <span className="muted small"> · {run.campaign_name} · rule set {run.ruleset_version}</span>}
              </p>
              <ul className="fired-execs">
                {hits.map((h) => (
                  <li key={h.execution_id}>
                    <Link to={`/executions/${h.execution_id}`} className="tech-link">
                      <span className="mono tech-id">{h.technique_id}</span> {techniques.get(h.technique_id)?.name || ''}
                    </Link>
                    <span className="fired-exec-meta">
                      <span className="small muted">{plural(h.count, 'matching event')}</span>
                      <RelationChip relation={h.relation} />
                      {Boolean(h.noisy) && <NoisyChip />}
                    </span>
                  </li>
                ))}
              </ul>
            </li>
          )
        })}
      </ul>
    </>
  )
}

export default function RuleDetail() {
  const { ruleId } = useParams()
  const { data, loading, error, reload } = useAsync((signal) => load(ruleId, signal), [ruleId])
  const rule = data?.rule
  usePageTitle(rule ? rule.title : 'Rule')
  if (loading && !data) return <div className="page"><Loading /></div>
  if (error) {
    return (
      <div className="page">
        <h1 tabIndex={-1} className="h-inline">Rule</h1>
        <ErrorState error={error} onRetry={error.status === 404 ? undefined : reload} />
        <p><Link to="/rules">Back to all rules</Link></p>
      </div>
    )
  }
  const log = rule.logsource || {}
  return (
    <div className="page">
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/rules"><Icon name="back" size={14} /> All rules</Link>
      </nav>
      <header className="page-head">
        <div>
          <p className="eyebrow">{rule.source === 'sigmahq' ? 'SigmaHQ rule' : 'Custom rule'}{rule.level ? ` · ${rule.level}` : ''}</p>
          <h1 tabIndex={-1}>{rule.title}</h1>
          <p className="meta-line">
            <span className="rule-name"><span className="rule-author">by {rule.author || 'author unknown'}</span></span>
            <SourceLabel rule={rule} />
            <SupportChip rule={rule} />
          </p>
        </div>
      </header>
      <Attribution rule={rule} />
      {rule.status !== 'ok' && (
        <div className="state" role="note">
          <strong>Not evaluated.</strong> {rule.reason}. PurpleBench lists the rule with the reason instead of treating
          it as never matching.
        </div>
      )}
      <div className="grid-2 rule-grid">
        <section className="card" aria-labelledby="about-title">
          <h2 id="about-title">About the rule</h2>
          {rule.description && <p className="desc">{rule.description}</p>}
          <dl className="facts">
            <div><dt>Rule id</dt><dd className="mono small">{rule.id}</dd></div>
            <div>
              <dt>Techniques</dt>
              <dd className="tags">
                {rule.techniques.length ? rule.techniques.map((t) => (attackUrl(t)
                  ? <ExternalLink key={t} href={attackUrl(t)} className="mono">{t}</ExternalLink>
                  : <span key={t} className="mono">{t}</span>)) : <span className="muted">none tagged</span>}
              </dd>
            </div>
            <div>
              <dt>Log source</dt>
              <dd>{['product', 'category', 'service'].filter((k) => log[k]).map((k) => (
                <Chip key={k} tone="outline">{k}: {log[k]}</Chip>))}</dd>
            </div>
            {rule.sigma_status && <div><dt>Sigma status</dt><dd>{rule.sigma_status}</dd></div>}
            {(rule.date || rule.modified) && (
              <div><dt>Dates</dt><dd>{rule.date && <>written {rule.date}</>}{rule.modified && <>{rule.date ? ', ' : ''}modified {rule.modified}</>}</dd></div>
            )}
            {rule.falsepositives?.length > 0 && (
              <div>
                <dt>False positives</dt>
                <dd><ul className="plain-list">{rule.falsepositives.map((f, i) => <li key={i}>{f}</li>)}</ul></dd>
              </div>
            )}
            {rule.references?.length > 0 && (
              <div>
                <dt>References</dt>
                <dd>
                  <ul className="plain-list">
                    {rule.references.map((r, i) => (
                      <li key={i}>{/^https?:\/\//.test(r) ? <ExternalLink href={r}>{r}</ExternalLink> : r}</li>
                    ))}
                  </ul>
                </dd>
              </div>
            )}
          </dl>
        </section>
        <section className="card" aria-labelledby="fired-title">
          <h2 id="fired-title">Where it fired</h2>
          <p className="small muted">Every execution whose recorded events this rule matched, by run.</p>
          <WhereFired rule={rule} runs={data.runs} techniques={data.techniques} />
        </section>
      </div>
      <section className="card" aria-labelledby="yaml-title">
        <div className="card-head">
          <h2 id="yaml-title">Rule file (YAML)</h2>
          <span className="muted small">The text the evaluator read, shown as text</span>
        </div>
        <pre className="yaml" tabIndex={0} aria-labelledby="yaml-title"><code>{rule.yaml}</code></pre>
      </section>
    </div>
  )
}
