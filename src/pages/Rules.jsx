import { useId } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { DRL_URL, SIGMAHQ_URL, plural } from '../lib.js'
import { filterRules } from '../model.js'
import {
  Chip, Empty, ErrorState, ExternalLink, Icon, Loading, NoisyChip, useAsync, usePageTitle,
} from '../components/ui.jsx'
import { RunSelect } from '../components/common.jsx'

async function load(runParam, signal) {
  const runs = await api.runs(signal)
  const run = runs.some((r) => String(r.id) === runParam) ? runParam : ''
  const body = await api.rules(run ? { run } : {}, signal)
  return { runs, ...body }
}

const FILTERS = {
  source: { label: 'Source', options: [['', 'All sources'], ['sigmahq', 'SigmaHQ'], ['custom', 'Custom']] },
  status: { label: 'Support', options: [['', 'Any support'], ['ok', 'Supported'], ['unsupported', 'Unsupported']] },
  set: { label: 'Rule set', options: [['', 'In or out of the set'], ['in', 'In the run’s rule set'], ['out', 'Not in the rule set']], run: true },
  fired: { label: 'Fired', options: [['', 'Fired or not'], ['yes', 'Fired in the run'], ['no', 'Did not fire']], run: true },
  noise: { label: 'Noise', options: [['', 'Noisy or quiet'], ['noisy', 'Noisy on the baseline'], ['quiet', 'Quiet on the baseline']], run: true },
}

function FilterSelect({ name, value, onChange }) {
  const id = useId()
  const f = FILTERS[name]
  return (
    <span className="filter-field">
      <label htmlFor={id}>{f.label}</label>
      <select id={id} value={value} onChange={(e) => onChange(name, e.target.value)}>
        {f.options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
    </span>
  )
}

export function SourceLabel({ rule }) {
  return (
    <span className="source-label">
      {rule.source === 'sigmahq' ? 'SigmaHQ' : 'Custom'}
      <span className="muted"> · {rule.licence === 'DRL-1.1' ? 'DRL 1.1' : rule.licence || 'licence not stated'}</span>
    </span>
  )
}

export function SupportChip({ rule }) {
  return rule.status === 'ok'
    ? <Chip tone="outline" glyph="✓" title="Every Sigma feature it uses is in the evaluator's supported subset.">Supported</Chip>
    : <Chip tone="gap" glyph="⊘" title={`Not evaluated: ${rule.reason}`}>Unsupported</Chip>
}

export default function Rules() {
  usePageTitle('Rules')
  const [params, setParams] = useSearchParams()
  const runParam = params.get('run') || ''
  const searchId = useId()
  const { data, loading, error, reload } = useAsync((signal) => load(runParam, signal), [runParam])
  const filters = Object.fromEntries(Object.keys(FILTERS).map((k) => [k, params.get(k) || '']))
  const q = params.get('q') || ''
  function set(key, value) {
    setParams((p) => {
      const next = new URLSearchParams(p)
      if (value) next.set(key, value)
      else next.delete(key)
      return next
    }, { replace: true })
  }
  const run = data?.run
  const active = { ...filters, q }
  if (!run) { active.set = ''; active.fired = ''; active.noise = '' }
  const shown = data ? filterRules(data.rules, active) : []
  const any = Object.values(active).some(Boolean)
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <p className="eyebrow">Rules</p>
          <h1 tabIndex={-1}>Detection rules</h1>
          <p className="lede">
            Every bundled Sigma rule, with its author. SigmaHQ rules are kept unmodified under the{' '}
            <ExternalLink href={DRL_URL}>Detection Rule License 1.1</ExternalLink>; custom rules are PurpleBench&apos;s
            own. Rules that use Sigma features outside the evaluator&apos;s subset are listed as unsupported, never
            silently treated as not matching.
          </p>
        </div>
      </header>
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <section className="card flush" aria-labelledby="rules-title">
          <div className="card-head padded">
            <h2 id="rules-title">{plural(data.rules.length, 'bundled rule')}</h2>
            <span className="muted small">
              {run ? <>Hits and noise for run {run.id} (rule set {run.ruleset_version})</> : 'No runs yet: hits and noise appear once a run exists'}
            </span>
          </div>
          <div className="filters" role="group" aria-label="Filter rules">
            {data.runs.length > 0 && (
              <RunSelect runs={data.runs} value={run?.id} onChange={(v) => set('run', v)} label="Run" />
            )}
            <span className="filter-field search-field">
              <label htmlFor={searchId}>Search</label>
              <input id={searchId} type="search" value={q} placeholder="Title, author, id or technique"
                onChange={(e) => set('q', e.target.value)} />
            </span>
            {Object.keys(FILTERS).filter((k) => run || !FILTERS[k].run).map((k) => (
              <FilterSelect key={k} name={k} value={filters[k]} onChange={set} />
            ))}
            {any && (
              <button type="button" className="btn ghost small"
                onClick={() => setParams(run && runParam ? new URLSearchParams({ run: runParam }) : new URLSearchParams(), { replace: true })}>
                Clear filters
              </button>
            )}
            <span className="filter-count" role="status">Showing {shown.length} of {plural(data.rules.length, 'rule')}</span>
          </div>
          {shown.length === 0 ? <Empty>No rules match these filters.</Empty> : (
            <table className="table cards rules-table">
              <thead>
                <tr>
                  <th scope="col">Rule (author)</th>
                  <th scope="col">Source · licence</th>
                  <th scope="col">Support</th>
                  {run && <th scope="col">In rule set {run.ruleset_version}</th>}
                  {run && <th scope="col">Fired in run {run.id}</th>}
                  {run && <th scope="col">Baseline noise</th>}
                  <th scope="col">Techniques</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={r.id}>
                    <th scope="row" data-label="Rule">
                      <span className="rule-name">
                        <Link to={`/rules/${r.id}`} className="tech-link">{r.title}</Link>
                        <span className="rule-author"> ({r.author || 'author unknown'})</span>
                      </span>
                      {r.level && <span className={`level ${r.level} small`}> · {r.level}</span>}
                    </th>
                    <td data-label="Source · licence"><SourceLabel rule={r} /></td>
                    <td data-label="Support">
                      <SupportChip rule={r} />
                      {r.status !== 'ok' && <p className="small muted reason-text">{r.reason}</p>}
                    </td>
                    {run && (
                      <td data-label={`In rule set ${run.ruleset_version}`}>
                        {r.in_ruleset ? <span className="yes"><span aria-hidden="true">✓</span> Yes</span> : <span className="muted">No</span>}
                      </td>
                    )}
                    {run && (
                      <td data-label={`Fired in run ${run.id}`} className="nowrap">
                        {r.executions_fired ? plural(r.executions_fired, 'execution') : <span className="muted">—</span>}
                      </td>
                    )}
                    {run && (
                      <td data-label="Baseline noise">
                        {r.noisy ? <NoisyChip hits={r.baseline_hits} />
                          : r.baseline_hits != null ? <span className="muted">{plural(r.baseline_hits, 'hit')}</span>
                            : <span className="muted" title="Not measured: the rule is not in this rule set, or the run is a lab run with no baseline.">not measured</span>}
                      </td>
                    )}
                    <td data-label="Techniques">
                      <span className="tags">{r.techniques.length ? r.techniques.map((t) => <span key={t} className="tactic-tag mono">{t}</span>) : <span className="muted">none tagged</span>}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="table-note">
            <Icon name="info" size={14} /> SigmaHQ rules come from the <ExternalLink href={SIGMAHQ_URL}>SigmaHQ repository</ExternalLink>,
            pinned to one commit. Noise is the number of benign-baseline events a rule matches; a noisy rule earns no
            detection credit.
          </p>
        </section>
      )}
    </div>
  )
}

