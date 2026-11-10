import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { STATUS, countEntries, formatDate, formatScore } from '../lib.js'
import {
  ErrorState, Icon, Loading, ModeChip, useAsync, usePageTitle, useSession,
} from '../components/ui.jsx'
import { NoRunsCTA, UploadRun } from '../components/common.jsx'

function ScoreBar({ score }) {
  return (
    <span className="score-bar">
      <span className="score-bar-track" aria-hidden="true">
        <span className="score-bar-fill" style={{ width: `${score ?? 0}%` }} />
      </span>
      <strong>{formatScore(score)}</strong>
    </span>
  )
}

function Counts({ counts }) {
  return (
    <ul className="mini-counts">
      {countEntries(counts).map(([s, n]) => (
        <li key={s} className={`mini ${STATUS[s].tone}`} title={STATUS[s].label}>
          <span aria-hidden="true">{STATUS[s].glyph}</span> {n}
          <span className="sr-only"> {STATUS[s].label.toLowerCase()}</span>
        </li>
      ))}
    </ul>
  )
}

export default function Runs() {
  usePageTitle('Runs')
  const session = useSession()
  const admin = session && !session.guest
  const { data, loading, error, reload } = useAsync((signal) => api.runs(signal), [])
  const runs = data ? [...data].reverse() : []
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <p className="eyebrow">Runs</p>
          <h1 tabIndex={-1}>Test runs</h1>
          <p className="lede">
            A run evaluates one rule set against the telemetry of every technique in a campaign. Newest first.
          </p>
        </div>
      </header>
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.length === 0 && <NoRunsCTA what="this list" />}
      {admin && data && data.length > 0 && (
        <details className="card upload-card">
          <summary><Icon name="upload" size={16} /> Upload a lab run</summary>
          <UploadRun />
        </details>
      )}
      {runs.length > 0 && (
        <section className="card flush" aria-labelledby="runs-title">
          <h2 id="runs-title" className="sr-only">All runs</h2>
          <table className="table cards runs-table">
            <thead>
              <tr>
                <th scope="col">Run</th>
                <th scope="col">Campaign</th>
                <th scope="col">Date</th>
                <th scope="col">Rule set</th>
                <th scope="col">Mode</th>
                <th scope="col">Coverage</th>
                <th scope="col">Results</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <th scope="row" data-label="Run">
                    <Link to={`/runs/${r.id}`} className="row-link">
                      Run {r.id}<span className="sr-only">: {r.campaign_name}, rule set {r.ruleset_version}</span>
                      <Icon name="arrow" size={14} />
                    </Link>
                  </th>
                  <td data-label="Campaign">{r.campaign_name}</td>
                  <td data-label="Date" className="nowrap">{formatDate(r.started_at)}</td>
                  <td data-label="Rule set"><span className="mono">{r.ruleset_version}</span></td>
                  <td data-label="Mode"><ModeChip mode={r.mode} /></td>
                  <td data-label="Coverage"><ScoreBar score={r.score} /><span className="muted small"> of {r.tested} tested</span></td>
                  <td data-label="Results"><Counts counts={r.counts} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  )
}
