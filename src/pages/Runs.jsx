import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { STATUS, countEntries, formatDate, formatScore } from '../lib.js'
import {
  ErrorState, Icon, Loading, ModeChip, useAsync, usePageTitle, useSession,
} from '../components/ui.jsx'
import { DemoWriteNotice, NoRunsCTA, UploadRun } from '../components/common.jsx'

function ScoreBar({ score }) {
  return (
    <span className="score-cell">
      <strong>{formatScore(score)}</strong>
      <span className="meter" aria-hidden="true"><span className="meter-fill" style={{ width: `${score ?? 0}%` }} /></span>
    </span>
  )
}

export function Counts({ counts }) {
  return (
    <ul className="count-row">
      {countEntries(counts).map(([s, n]) => (
        <li key={s} title={STATUS[s].label}>
          <span className={`status s-${s}`}>
            <strong>{n}</strong><span className="sr-only"> {STATUS[s].label.toLowerCase()}</span>
          </span>
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
          <h1 tabIndex={-1}>Test runs</h1>
          <p className="page-sub">Each run evaluates one rule set against the telemetry of every technique in a campaign. Newest first.</p>
        </div>
      </header>
      {admin && <DemoWriteNotice />}
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.length === 0 && <NoRunsCTA what="this list" />}
      {runs.length > 0 && (
        <section className="panel" aria-labelledby="runs-title">
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
                    </Link>
                  </th>
                  <td data-label="Campaign">{r.campaign_name}</td>
                  <td data-label="Date" className="nowrap">{formatDate(r.started_at)}</td>
                  <td data-label="Rule set"><span className="mono">{r.ruleset_version}</span></td>
                  <td data-label="Mode"><ModeChip mode={r.mode} plain /></td>
                  <td data-label="Coverage"><ScoreBar score={r.score} /><span className="muted small"> of {r.tested} tested</span></td>
                  <td data-label="Results"><Counts counts={r.counts} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          {admin && (
            <details className="fold upload-details">
              <summary><Icon name="upload" /> Upload a lab run</summary>
              <UploadRun />
            </details>
          )}
        </section>
      )}
    </div>
  )
}
