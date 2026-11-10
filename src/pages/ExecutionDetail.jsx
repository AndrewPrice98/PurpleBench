import { useId, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import {
  NOT_TESTED, STATUS, TTD_LABEL, attackUrl, eventName, firstLink, formatClock, formatDateTime, formatOffset,
  formatTtd, matchTotal, plural, summaryField, KEY_FIELDS, timelineModel, tsMs,
} from '../lib.js'
import { clampSegments, highlightPlan, highlightSegments, parseDetection } from '../sigma.js'
import {
  Chip, Empty, ErrorState, ExternalLink, Icon, Loading, ModeChip, NoisyChip, RelationChip, RuleName, RuleText,
  StatusChip, TacticTag, useAsync, usePageTitle,
} from '../components/ui.jsx'
import { TtdTimeline } from '../components/charts.jsx'
import ModeNotice from '../components/ModeNotice.jsx'

const PAGE = 25
const CLAMP = 360
const MATCHES_PER_PAGE = 5

async function load(id, signal) {
  const [execution, rules] = await Promise.all([
    api.execution(id, { offset: 0, limit: PAGE }, signal),
    api.ruleCatalog().catch(() => new Map()),
  ])
  return { execution, rules }
}

/** Parsed detection blocks for the rules that fired, by rule id (for highlighting). */
function useDetections(hits) {
  const ids = hits.map((h) => h.rule.id).join(',')
  const { data } = useAsync(async (signal) => {
    const out = new Map()
    await Promise.all(hits.map(async (h) => {
      try {
        const rule = await api.rule(h.rule.id, signal)
        out.set(h.rule.id, parseDetection(rule.yaml))
      } catch (err) {
        if (err?.name === 'AbortError') throw err
        /* otherwise: no highlighting for this rule */
      }
    }))
    return out
  }, [ids])
  return data || new Map()
}

// -- attack pane ----------------------------------------------------------------------------------

function AttackPane({ ex }) {
  const a = ex.atomic_test
  const tech = ex.technique
  const datasetLink = firstLink(ex.run.source)
  const mitre = attackUrl(tech.id)
  return (
    <section className="pane attack" aria-labelledby="attack-title">
      <h2 id="attack-title"><Icon name="target" size={20} /> Attack</h2>
      <dl className="facts">
        <div>
          <dt>Technique</dt>
          <dd>
            <span className="mono">{tech.id}</span> {tech.name}
            {mitre && <> · <ExternalLink href={mitre}>ATT&amp;CK</ExternalLink></>}
          </dd>
        </div>
        <div>
          <dt>Tactics</dt>
          <dd className="tags">{tech.tactics.map((t) => <TacticTag key={t} tactic={t} />)}</dd>
        </div>
        {a ? (
          <>
            <div>
              <dt>Atomic Red Team test</dt>
              <dd>{a.name}<br /><span className="mono small guid">{a.guid}</span></dd>
            </div>
            <div>
              <dt>Executor</dt>
              <dd>
                <span className="mono">{a.executor}</span>
                {a.elevation_required && <Chip tone="outline" glyph="▲">Needs elevation</Chip>}
              </dd>
            </div>
          </>
        ) : (
          <div>
            <dt>Test</dt>
            <dd>
              Recorded technique execution
              <p className="muted small">
                {ex.status === 'untested'
                  ? 'No Atomic Red Team test is linked, and the recorded dataset holds no execution of this technique.'
                  : 'No Atomic Red Team test is linked to this result: the dataset records the technique being performed, so there is no test command to show.'}
              </p>
            </dd>
          </div>
        )}
      </dl>
      {a?.description && <p className="desc">{a.description}</p>}
      {a?.command && (
        <div className="command">
          <p className="command-label" id="cmd-label">
            Command <span className="muted">· display only, PurpleBench never runs it</span>
          </p>
          <pre tabIndex={0} aria-labelledby="cmd-label"><code>{a.command}</code></pre>
          {a.cleanup_command && (
            <details className="cleanup">
              <summary>Cleanup command</summary>
              <pre tabIndex={0} aria-label="Cleanup command"><code>{a.cleanup_command}</code></pre>
            </details>
          )}
          {a.note && <p className="small muted">{a.note}</p>}
          {a.source_url && <p className="small"><ExternalLink href={a.source_url}>Test definition on GitHub</ExternalLink> (MIT)</p>}
        </div>
      )}
      <dl className="facts source">
        <div>
          <dt>Mode</dt>
          <dd><ModeChip mode={ex.run.mode} /></dd>
        </div>
        <div>
          <dt>Telemetry</dt>
          <dd>
            {ex.run.mode === 'recorded' ? 'Public dataset recording' : 'Lab run file'}
            {datasetLink && <> · <ExternalLink href={datasetLink}>dataset</ExternalLink></>}
          </dd>
        </div>
        <div>
          <dt>Execution window</dt>
          <dd>
            {ex.started_at
              ? <>{formatDateTime(ex.started_at)}{ex.ended_at && <><br />to {formatDateTime(ex.ended_at)}</>}</>
              : <span className="muted">None: no execution was recorded</span>}
          </dd>
        </div>
      </dl>
    </section>
  )
}

// -- detection pane -------------------------------------------------------------------------------

function sourceLabel(source) {
  return source === 'sigmahq' ? 'SigmaHQ' : source === 'custom' ? 'Custom rule' : source
}

function RulesFired({ hits, order, startedAt, catalog }) {
  const sorted = [...hits].sort((a, b) => (order.get(a.rule.id) ?? 99) - (order.get(b.rule.id) ?? 99))
  return (
    <ol className="fired">
      {sorted.map((h) => {
        const rule = catalog.get(h.rule.id) || h.rule
        const offset = startedAt ? (tsMs(h.first_ts) - tsMs(startedAt)) / 1000 : null
        return (
          <li key={h.rule.id} className={h.noisy ? 'noisy' : ''}>
            <span className="fired-num" aria-hidden="true">{order.get(h.rule.id) || '·'}</span>
            <div className="fired-body">
              <p className="fired-title"><RuleName rule={rule} link /></p>
              <p className="fired-meta">
                <span className="src">{sourceLabel(rule.source)}</span>
                {rule.level && <span className={`level ${rule.level}`}>{rule.level}</span>}
                <RelationChip relation={h.relation} />
                {h.noisy && <NoisyChip hits={h.noise_hits} />}
              </p>
              <p className="fired-stats small muted">
                {plural(h.count, 'matching event')} · first match {formatClock(h.first_ts)} UTC
                {offset !== null && !Number.isNaN(offset) && <> ({formatOffset(offset)} from the start)</>}
              </p>
            </div>
          </li>
        )
      })}
    </ol>
  )
}

function TtdBlock({ ex, model }) {
  return (
    <div className="ttd-block">
      <div className="ttd-head">
        <p className="ttd-label"><Icon name="clock" size={16} /> {TTD_LABEL}</p>
        <p className="ttd-value">{formatTtd(ex.ttd_ms)}</p>
      </div>
      <p className="small muted">
        {ex.ttd_note} Events up to {model?.skewSeconds ?? 5} s before the start count as clock skew, so an early
        first match shows as 0. This is the best case on known telemetry.
      </p>
      {model && model.markers.length > 0 && <TtdTimeline model={model} />}
    </div>
  )
}

function FieldTable({ fields, truncated, plan, showAll }) {
  const entries = Object.entries(fields)
  const rows = entries.map(([k, v]) => {
    const segs = highlightSegments(v, plan.get(k))
    return { k, v, segs, hit: segs.some((s) => s.mark) }
  })
  const visible = showAll ? rows : rows.filter((r) => r.hit || KEY_FIELDS.includes(r.k))
  return (
    <table className="fields">
      <caption className="sr-only">Event fields; matching values are marked</caption>
      <tbody>
        {(visible.length ? visible : rows).map((r) => {
          const { segs, hidden } = showAll ? { segs: r.segs, hidden: 0 } : clampSegments(r.segs, CLAMP)
          return (
            <tr key={r.k} className={r.hit ? 'hit' : ''}>
              <th scope="row">{r.k}{r.hit && <span className="sr-only"> (matches the rule)</span>}</th>
              <td>
                <span className="fv">
                  {segs.map((s, i) => (s.mark ? <mark key={i}>{s.text}</mark> : <span key={i}>{s.text}</span>))}
                </span>
                {hidden > 0 && <span className="muted small"> … {hidden.toLocaleString()} more characters</span>}
                {truncated.includes(r.k) && <span className="muted small"> (truncated by the API)</span>}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

function EventCard({ ev, start, detections, hitsById, catalog }) {
  const [showAll, setShowAll] = useState(false)
  const plan = useMemo(() => highlightPlan(
    ev.matched_rules.map((id) => detections.get(id)).filter(Boolean), Object.keys(ev.fields)), [ev, detections])
  const offset = start ? (tsMs(ev.ts) - tsMs(start)) / 1000 : null
  const total = Object.keys(ev.fields).length
  return (
    <article className="event-card">
      <header className="event-head">
        <span className="mono">{formatClock(ev.ts)}</span>
        {offset !== null && !Number.isNaN(offset) && <span className="muted mono">{formatOffset(offset)}</span>}
        <span className="event-kind">{eventName(ev.channel, ev.event_id)}</span>
        {ev.record_id != null && <span className="muted small">record {ev.record_id}</span>}
      </header>
      <p className="event-rules small">
        Matched by{' '}
        {ev.matched_rules.map((id, i) => (
          <span key={id}>{i > 0 && ', '}<RuleName rule={catalog.get(id) || hitsById.get(id) || { id, title: id }} /></span>
        ))}
      </p>
      <FieldTable fields={ev.fields} truncated={ev.truncated_fields} plan={plan} showAll={showAll} />
      {total > 0 && (
        <button type="button" className="btn ghost small" onClick={() => setShowAll((v) => !v)} aria-expanded={showAll}>
          {showAll ? 'Show key fields only' : `Show all ${total} fields in full`}
        </button>
      )}
    </article>
  )
}

/** By default show the rule that earned the credit, when noisy rules also matched. */
function defaultRuleFilter(hits) {
  const credited = hits.filter((h) => !h.noisy).sort((a, b) => tsMs(a.first_ts) - tsMs(b.first_ts))
  return credited.length && credited.length < hits.length ? credited[0].rule.id : ''
}

function MatchedEvents({ ex, detections, catalog, order }) {
  const [page, setPage] = useState(0)
  const [ruleFilter, setRuleFilter] = useState(() => defaultRuleFilter(ex.hits))
  const filterId = useId()
  // One request per page: the server filters to matched events (and to one rule) before paging.
  const { data, loading, error, reload } = useAsync((signal) => api.execution(ex.id, {
    offset: page * MATCHES_PER_PAGE, limit: MATCHES_PER_PAGE, matched: true, rule: ruleFilter,
  }, signal), [ex.id, page, ruleFilter])
  const events = data?.events
  const items = events?.items || []
  const total = matchTotal(ex.hits, ruleFilter)
  const hitsById = new Map(ex.hits.map((h) => [h.rule.id, h.rule]))
  const ruleOptions = [...ex.hits].sort((a, b) => (order.get(a.rule.id) ?? 99) - (order.get(b.rule.id) ?? 99))
  const first = page * MATCHES_PER_PAGE + 1
  const last = page * MATCHES_PER_PAGE + items.length
  const selected = ruleFilter ? ex.hits.find((h) => h.rule.id === ruleFilter) : null
  return (
    <section className="matched" aria-labelledby="matched-title">
      <h3 id="matched-title">Matching events</h3>
      <p className="small muted">
        Highlights text from the rule&apos;s conditions; it does not show which condition matched. Only events
        the evaluator matched are marked.
      </p>
      {ex.hits.length > 1 && (
        <div className="filters inline-filters">
          <label htmlFor={filterId}>Show matches of</label>
          <select id={filterId} value={ruleFilter} onChange={(e) => { setRuleFilter(e.target.value); setPage(0) }}>
            <option value="">All rules that fired</option>
            {ruleOptions.map((h) => (
              <option key={h.rule.id} value={h.rule.id}>
                {order.get(h.rule.id) ? `${order.get(h.rule.id)}. ` : ''}{h.rule.title} ({h.rule.author || 'author unknown'})
                {' · '}{plural(h.count, 'event')}{h.noisy ? ' (noisy)' : ''}
              </option>
            ))}
          </select>
        </div>
      )}
      <p className="small" role="status">
        {total != null
          ? `${plural(total, 'matching event')}${selected ? ` for ${selected.rule.title} (${selected.rule.author || 'author unknown'})` : ''}.`
          : `Events that any of the ${ex.hits.length} rules matched; each rule's count is in the list above.`}
      </p>
      {error && <ErrorState error={error} onRetry={reload} />}
      {loading && !data && <Loading label="Loading matching events…" />}
      {events && !events.available && <Empty>{events.note || 'The events for this execution are not available.'}</Empty>}
      {events?.available && items.length === 0 && !loading && <Empty>No matching events on this page.</Empty>}
      <div className={loading && data ? 'busy' : ''}>
        {items.map((ev) => (
          <EventCard key={`${ev.channel}-${ev.record_id}-${ev.ts}`} ev={ev} start={ex.started_at} detections={detections}
            hitsById={hitsById} catalog={catalog} />
        ))}
      </div>
      {events?.available && (page > 0 || events.has_more) && (
        <div className="pager">
          <button type="button" className="btn secondary small" aria-disabled={page === 0 || loading}
            onClick={() => page > 0 && !loading && setPage(page - 1)}>Previous</button>
          <span>
            Matches {items.length ? first : 0}–{last}{total != null ? ` of ${total}` : (events.has_more ? '' : ' (end)')}
          </span>
          <button type="button" className="btn secondary small" aria-disabled={!events.has_more || loading}
            onClick={() => events.has_more && !loading && setPage(page + 1)}>Next</button>
        </div>
      )}
    </section>
  )
}

function EventRow({ ev, start, detections }) {
  const [open, setOpen] = useState(false)
  const plan = useMemo(() => (ev.matched
    ? highlightPlan(ev.matched_rules.map((id) => detections.get(id)).filter(Boolean), Object.keys(ev.fields))
    : new Map()), [ev, detections])
  const summary = summaryField(ev.fields)
  const offset = start ? (tsMs(ev.ts) - tsMs(start)) / 1000 : null
  const id = `ev-${ev.channel}-${ev.record_id}`.replace(/[^A-Za-z0-9_-]/g, '_')
  return (
    <>
      <tr className={ev.matched ? 'matched' : ''}>
        <td data-label="Time" className="mono nowrap">
          {offset !== null && !Number.isNaN(offset) ? formatOffset(offset) : formatClock(ev.ts)}
        </td>
        <td data-label="Event">{eventName(ev.channel, ev.event_id)}</td>
        <td data-label="Summary" className="summary">
          {summary && <><span className="muted">{summary[0]}:</span> <span className="fv">{summary[1]}</span></>}
        </td>
        <td data-label="Match">{ev.matched ? <Chip tone="match" glyph="◆">Match</Chip> : <span className="muted">—</span>}</td>
        <td data-label="Fields">
          <button type="button" className="btn ghost small" aria-expanded={open} aria-controls={id}
            onClick={() => setOpen((v) => !v)}>
            {open ? 'Hide' : 'Fields'}<span className="sr-only"> of the event at {formatClock(ev.ts)}</span>
          </button>
        </td>
      </tr>
      {open && (
        <tr className="field-row" id={id}>
          <td colSpan={5}><FieldTable fields={ev.fields} truncated={ev.truncated_fields} plan={plan} showAll /></td>
        </tr>
      )}
    </>
  )
}

function AllEvents({ ex, detections }) {
  const [offset, setOffset] = useState(0)
  const { data, loading, error, reload } = useAsync(
    (signal) => (offset === 0 ? Promise.resolve(ex) : api.execution(ex.id, { offset, limit: PAGE }, signal)), [ex, offset])
  const events = data?.events
  return (
    <section className="all-events" aria-labelledby="all-title">
      <h3 id="all-title">All events in the window</h3>
      {events?.window && (
        <p className="small muted">
          {formatDateTime(events.window.start)} to {formatDateTime(events.window.end)}, including the skew tolerance.
          Times are offsets from the execution start.
        </p>
      )}
      {error && <ErrorState error={error} onRetry={reload} />}
      {events && !events.available && <Empty>{events.note || 'The events for this execution are not available.'}</Empty>}
      {events?.available && (
        <>
          <div className={`table-wrap ${loading ? 'busy' : ''}`}>
            <table className="table cards events-table">
              <caption className="sr-only">Events {offset + 1} to {offset + events.items.length}</caption>
              <thead>
                <tr><th scope="col">Time</th><th scope="col">Event</th><th scope="col">Summary</th><th scope="col">Match</th><th scope="col"><span className="sr-only">Fields</span></th></tr>
              </thead>
              <tbody>
                {events.items.map((ev) => (
                  <EventRow key={`${ev.channel}-${ev.record_id}-${ev.ts}`} ev={ev} start={ex.started_at} detections={detections} />
                ))}
              </tbody>
            </table>
          </div>
          <div className="pager">
            <button type="button" className="btn secondary small" aria-disabled={offset === 0 || loading}
              onClick={() => offset > 0 && !loading && setOffset(Math.max(0, offset - PAGE))}>Previous</button>
            <span role="status">Events {events.items.length ? offset + 1 : 0}–{offset + events.items.length}{events.has_more ? '' : ' (end)'}</span>
            <button type="button" className="btn secondary small" aria-disabled={!events.has_more || loading}
              onClick={() => events.has_more && !loading && setOffset(offset + PAGE)}>Next</button>
          </div>
        </>
      )}
    </section>
  )
}

function DetectionPane({ ex, catalog }) {
  const detections = useDetections(ex.hits)
  const status = STATUS[ex.status] || { label: ex.status, help: '' }
  const notTested = NOT_TESTED.has(ex.status)
  const model = useMemo(() => timelineModel({ startedAt: ex.started_at, endedAt: ex.ended_at, hits: ex.hits }), [ex])
  const order = new Map((model?.markers || []).map((m, i) => [m.id, i + 1]))
  return (
    <section className="pane detect" aria-labelledby="detect-title">
      <h2 id="detect-title"><Icon name="radar" size={20} /> Detection</h2>
      <div className={`verdict ${status.tone || ''}`}>
        <StatusChip status={ex.status} />
        <p>{status.help}</p>
        {ex.reason && <p className="reason"><RuleText text={ex.reason} rules={catalog} /></p>}
      </div>
      {notTested ? (
        <div className="explain">
          <p>
            <strong>Nothing was scored for this technique.</strong>{' '}
            {ex.status === 'untested'
              ? 'The recorded dataset holds no execution of it, so there is no test window and no rule could have fired. It does not count towards the coverage score.'
              : 'The lab runner reported that the test did not run, so there are no events to evaluate. It does not count towards the coverage score.'}
          </p>
        </div>
      ) : (
        <>
          <h3>Rules fired</h3>
          {ex.hits.length === 0
            ? <Empty>{ex.status === 'telemetry_gap'
              ? 'No rule fired: the rules for this technique need telemetry that this recording does not contain.'
              : 'No rule in this rule set fired on this telemetry.'}</Empty>
            : <RulesFired hits={ex.hits} order={order} startedAt={ex.started_at} catalog={catalog} />}
          {ex.hits.length > 0 && <TtdBlock ex={ex} model={model} />}
          {ex.hits.length > 0 && <MatchedEvents ex={ex} detections={detections} catalog={catalog} order={order} />}
        </>
      )}
      {!notTested && <AllEvents ex={ex} detections={detections} />}
    </section>
  )
}

export default function ExecutionDetail() {
  const { executionId } = useParams()
  const { data, loading, error, reload } = useAsync((signal) => load(executionId, signal), [executionId])
  const ex = data?.execution
  usePageTitle(ex ? `${ex.technique.id} in run ${ex.run.id}` : 'Execution')
  if (loading && !data) return <div className="page"><Loading /></div>
  if (error) {
    return (
      <div className="page">
        <h1 tabIndex={-1} className="h-inline">Execution</h1>
        <ErrorState error={error} onRetry={error.status === 404 ? undefined : reload} />
        <p><Link to="/runs">Back to all runs</Link></p>
      </div>
    )
  }
  return (
    <div className="page">
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/runs">Runs</Link>
        <span aria-hidden="true">/</span>
        <Link to={`/runs/${ex.run.id}`}>Run {ex.run.id}</Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">{ex.technique.id}</span>
      </nav>
      <header className="page-head">
        <div>
          <p className="eyebrow">Run {ex.run.id} · {ex.run.campaign_name} · rule set {ex.run.ruleset_version}</p>
          <h1 tabIndex={-1}><span className="mono">{ex.technique.id}</span> {ex.technique.name}</h1>
          <p className="meta-line">
            <StatusChip status={ex.status} withHelp />
            {ex.hits.length > 0 && <span>{plural(ex.hits.length, 'rule')} fired</span>}
            {ex.ttd_ms != null && <span>{TTD_LABEL}: <strong className="mono">{formatTtd(ex.ttd_ms)}</strong></span>}
          </p>
        </div>
      </header>
      <ModeNotice run={ex.run} />
      <div className="panes">
        <AttackPane ex={ex} />
        <DetectionPane ex={ex} catalog={data.rules} />
      </div>
    </div>
  )
}
