// Pure helpers and vocabulary, with no React, so Node's test runner can import them.

export const GITHUB_URL = 'https://github.com/AndrewPrice98/PurpleBench'
export const THIRD_PARTY_URL = `${GITHUB_URL}/blob/main/THIRD_PARTY.md`
export const DRL_URL = 'https://github.com/SigmaHQ/Detection-Rule-License'
export const ATOMIC_URL = 'https://github.com/redcanaryco/atomic-red-team'
export const ATTACK_DATA_URL = 'https://github.com/splunk/attack_data'
export const SIGMAHQ_URL = 'https://github.com/SigmaHQ/sigma'

export const MISSED_MEANING =
  '"Missed" means no rule in this rule set fired on this telemetry. It says nothing about any security product.'
export const BEST_CASE =
  'Scores are a best case: each rule set is evaluated on telemetry known to contain the technique, inside the test window.'
export const TTD_LABEL = 'Event-time to first match'

// -- status vocabulary: every status has a text label, a tone and a glyph ----------------------

export const STATUS = {
  detected: {
    label: 'Detected', glyph: '✓', tone: 'detected',
    help: 'At least one non-noisy rule tagged for this technique fired on this telemetry.',
  },
  partial: {
    label: 'Partial', glyph: '◐', tone: 'partial',
    help: 'Only rules for a parent or related technique, or only noisy rules, fired. No full credit.',
  },
  missed: {
    label: 'Missed', glyph: '✕', tone: 'missed',
    help: 'No rule in this rule set fired on this telemetry. It says nothing about any security product.',
  },
  telemetry_gap: {
    label: 'Telemetry gap', glyph: '⌀', tone: 'gap',
    help: 'The rules that would apply cannot match: the telemetry lacks the channel or fields they need.',
  },
  untested: {
    label: 'Untested', glyph: '–', tone: 'neutral',
    help: 'Not scored: there is no recorded execution of this technique to test the rules against.',
  },
  did_not_run: {
    label: 'Did not run', glyph: '⊘', tone: 'neutral',
    help: 'The lab runner reported that this test did not run, so there is nothing to score.',
  },
}

export const STATUS_ORDER = ['detected', 'partial', 'missed', 'telemetry_gap', 'untested', 'did_not_run']
/** Statuses that are not counted as tested (and are not in the coverage score). */
export const NOT_TESTED = new Set(['untested', 'did_not_run'])

export const RELATION = {
  exact: { label: 'Exact technique', help: 'The rule is tagged with this technique.' },
  parent: { label: 'Parent technique', help: 'The rule is tagged with the parent technique only.' },
  related: { label: 'Related technique', help: 'The rule is tagged with a different technique.' },
}

export const GAP_KIND = {
  missed: 'Missed',
  telemetry_gap: 'Telemetry gap',
  partial: 'Partial',
}

const TACTIC_NAMES = {
  'command-and-control': 'Command and Control',
  'privilege-escalation': 'Privilege Escalation',
  'credential-access': 'Credential Access',
  'lateral-movement': 'Lateral Movement',
  'defense-evasion': 'Defense Evasion',
  'defense-impairment': 'Defense Impairment',
  'initial-access': 'Initial Access',
  'resource-development': 'Resource Development',
}

/** "credential-access" -> "Credential Access". */
export function tacticLabel(slug) {
  if (!slug) return ''
  if (TACTIC_NAMES[slug]) return TACTIC_NAMES[slug]
  return slug.split('-').map((w) => (w === 'and' ? w : w.charAt(0).toUpperCase() + w.slice(1))).join(' ')
}

export function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`
}

// -- time ----------------------------------------------------------------------------------------

/** Milliseconds since the epoch for an ISO timestamp; tolerates microseconds. NaN if unusable. */
export function tsMs(iso) {
  if (typeof iso !== 'string' || !iso) return Number.NaN
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/.exec(iso.trim())
  if (!m) return Number.NaN
  const frac = m[2] ? `.${(m[2].slice(1) + '000').slice(0, 3)}` : ''
  return Date.parse(`${m[1]}${frac}${m[3] || 'Z'}`)
}

/** Time from the execution start to the first matching event, for people. */
export function formatTtd(ms) {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return '—'
  if (ms < 1000) return `${Math.round(ms)} ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`
  const min = Math.floor(ms / 60000)
  const s = Math.round((ms % 60000) / 1000)
  return s ? `${min} min ${s} s` : `${min} min`
}

/** A signed offset in seconds: "+0.006 s", "−0.67 s", "+14.2 s". */
export function formatOffset(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return '—'
  const sign = seconds < 0 ? '−' : '+'
  const a = Math.abs(seconds)
  let text
  if (a === 0) return '0 s'
  if (a < 0.1) text = a.toFixed(3)
  else if (a < 10) text = a.toFixed(2)
  else text = a.toFixed(1)
  return `${sign}${text} s`
}

const pad = (n, w = 2) => String(n).padStart(w, '0')

/** Dates are shown in UTC, which is how the API stores them. */
export function formatDate(iso) {
  const t = tsMs(iso)
  if (Number.isNaN(t)) return iso || '—'
  return new Date(t).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' })
}

/** "2020-11-03 15:52:59 UTC" */
export function formatDateTime(iso) {
  const t = tsMs(iso)
  if (Number.isNaN(t)) return iso || '—'
  const d = new Date(t)
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} `
    + `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`
}

/** "15:52:59.300" (UTC), for event rows. */
export function formatClock(iso) {
  const t = tsMs(iso)
  if (Number.isNaN(t)) return iso || '—'
  const d = new Date(t)
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(d.getUTCMilliseconds(), 3)}`
}

export function formatScore(score) {
  return score === null || score === undefined ? '—' : `${Number(score).toFixed(score % 1 ? 1 : 0)}%`
}

// -- text with links and rule references ----------------------------------------------------------

const URL_RE = /https?:\/\/[^\s<>"')\]]+/g

/** Split text into plain and link segments (http and https only), dropping trailing punctuation. */
export function splitLinks(text) {
  const out = []
  if (!text) return out
  let last = 0
  for (const m of String(text).matchAll(URL_RE)) {
    let href = m[0]
    while (/[.,;:!?]$/.test(href)) href = href.slice(0, -1)
    if (m.index > last) out.push({ text: text.slice(last, m.index) })
    out.push({ text: href, href })
    last = m.index + href.length
  }
  if (last < text.length) out.push({ text: text.slice(last) })
  return out
}

/** The first https link in a text, or null. */
export function firstLink(text) {
  return splitLinks(text).find((s) => s.href)?.href || null
}

const UUID_REF = /\s?\[([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\]/g

/**
 * Split a reason or note into text and rule segments so every rule title can be shown with its
 * author (SigmaHQ Detection Rule License 1.1). Recognises "Title [uuid]" and bare titles of known
 * rules (at least 10 characters long, the API's own rule for notes).
 *
 * @param {string} text
 * @param {Map<string, {id: string, title: string}>|Record<string, {id: string, title: string}>} rules by id
 * @returns {Array<{text: string} | {rule: object, text: string}>}
 */
export function splitRuleRefs(text, rules) {
  if (!text) return []
  const byId = rules instanceof Map ? rules : new Map(Object.entries(rules || {}))
  const segs = []
  let last = 0
  for (const m of String(text).matchAll(UUID_REF)) {
    const id = m[1].toLowerCase()
    const rule = byId.get(id)
    let start = m.index
    if (rule && rule.title && text.slice(0, m.index).endsWith(rule.title) && m.index - rule.title.length >= last) {
      start = m.index - rule.title.length
    }
    if (start > last) segs.push({ text: text.slice(last, start) })
    segs.push({ rule: rule || { id, title: id }, text: text.slice(start, m.index + m[0].length) })
    last = m.index + m[0].length
  }
  if (last < text.length) segs.push({ text: text.slice(last) })
  // Bare titles in the remaining plain text, longest first so a title inside another is not split out.
  const titled = [...byId.values()].filter((r) => r.title && r.title.length >= 10)
    .sort((a, b) => b.title.length - a.title.length)
  let result = segs
  for (const rule of titled) {
    const next = []
    for (const s of result) {
      if (s.rule) { next.push(s); continue }
      const parts = s.text.split(rule.title)
      parts.forEach((p, i) => {
        if (i > 0) next.push({ rule, text: rule.title })
        if (p) next.push({ text: p })
      })
    }
    result = next
  }
  return result
}

// -- overview: the "Start here" story -------------------------------------------------------------

const KIND_RANK = { missed: 0, telemetry_gap: 1, partial: 2 }

/**
 * The rules that closed a gap: those named after "Closed in run N (...):" in the importer's notes
 * (`system_notes`; the analyst's own `notes` never name the closing rule). Falls back to the last rule
 * named in the notes.
 */
export function closingRules(gap) {
  const rules = gap?.rules || []
  const notes = gap?.system_notes || ''
  const at = notes.search(/Closed in run \d+/)
  if (at >= 0) {
    const tail = notes.slice(at)
    const found = rules.filter((r) => r.title && tail.includes(r.title))
    if (found.length) return found
  }
  return rules.length ? [rules[rules.length - 1]] : []
}

/**
 * The biggest gap that a later rule set closed: closed in the latest run first, then missed before
 * telemetry gap before partial, then the most recent closing run, then the technique id.
 */
export function pickStartHere(gaps, latestRunId) {
  const closed = (gaps || []).filter((g) => g.status === 'closed' && g.closed_in_run != null)
  if (!closed.length) return null
  const sorted = [...closed].sort((a, b) => (
    (b.closed_in_run === latestRunId) - (a.closed_in_run === latestRunId)
    || (KIND_RANK[a.kind] ?? 9) - (KIND_RANK[b.kind] ?? 9)
    || b.closed_in_run - a.closed_in_run
    || String(a.technique_id).localeCompare(String(b.technique_id))
  ))
  const gap = sorted[0]
  return { gap, rules: closingRules(gap), fromRun: gap.run_id, toRun: gap.closed_in_run }
}

/** The gap text to show: the importer's notes followed by the analyst's (the API's `display_notes`). */
export function gapText(gap) {
  if (!gap) return ''
  if (gap.display_notes != null) return gap.display_notes
  return [gap.system_notes, gap.notes ? `Analyst notes: ${gap.notes}` : ''].filter(Boolean).join(' ')
}

// -- run results ----------------------------------------------------------------------------------

/** Filter executions by status and tactic ('' means any). */
export function filterExecutions(executions, { status = '', tactic = '' } = {}) {
  return (executions || []).filter((e) => (!status || e.status === status)
    && (!tactic || (e.technique?.tactics || []).includes(tactic)))
}

/** Distinct tactics across executions, in first-seen order. */
export function tacticsOf(executions) {
  const seen = []
  for (const e of executions || []) {
    for (const t of e.technique?.tactics || []) if (!seen.includes(t)) seen.push(t)
  }
  return seen
}

/** Status counts in display order, skipping zeros. */
export function countEntries(counts) {
  return STATUS_ORDER.filter((s) => counts?.[s]).map((s) => [s, counts[s]])
}

// -- charts ---------------------------------------------------------------------------------------

/**
 * Points for a 0–100 line chart. Values may be null (no tested executions): they get no point.
 * @returns {Array<{x: number, y: number|null, value: number|null}>}
 */
export function linePoints(values, { width, height, padX = 0, padTop = 0, padBottom = 0 }) {
  const n = values.length
  const inner = width - 2 * padX
  const h = height - padTop - padBottom
  return values.map((v, i) => ({
    x: n === 1 ? width / 2 : padX + (inner * i) / (n - 1),
    y: v === null || v === undefined ? null : padTop + h * (1 - Math.max(0, Math.min(100, v)) / 100),
    value: v ?? null,
  }))
}

/** An SVG path through the points that have a value; a gap breaks the line. */
export function linePath(points) {
  let d = ''
  let pen = false
  for (const p of points) {
    if (p.y === null) { pen = false; continue }
    d += `${pen ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`
    pen = true
  }
  return d
}

/** A semicircular gauge arc from the left end, sweeping `fraction` (0–1) of the half circle. */
export function gaugeArc(cx, cy, r, fraction) {
  const f = Math.max(0, Math.min(1, fraction))
  const angle = Math.PI * (1 - f)
  const x = cx + r * Math.cos(angle)
  const y = cy - r * Math.sin(angle)
  return `M${(cx - r).toFixed(2)} ${cy.toFixed(2)} A${r} ${r} 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)}`
}

/**
 * The time-to-detect timeline: offsets (seconds) of each rule's first matching event from the
 * execution start, the skew tolerance, and a domain wide enough to show them.
 */
export function timelineModel({ startedAt, endedAt, hits = [], skewSeconds = 5 }) {
  const start = tsMs(startedAt)
  if (Number.isNaN(start)) return null
  const end = tsMs(endedAt)
  const markers = hits.map((h) => {
    const t = tsMs(h.first_ts)
    const offset = Number.isNaN(t) ? null : (t - start) / 1000
    return {
      id: h.rule?.id, title: h.rule?.title, author: h.rule?.author, noisy: Boolean(h.noisy),
      relation: h.relation, offset, early: offset !== null && offset < 0,
    }
  }).filter((m) => m.offset !== null).sort((a, b) => a.offset - b.offset)
  const latest = markers.length ? Math.max(...markers.map((m) => m.offset)) : 0
  const lo = -skewSeconds
  const hi = Math.max(10, latest * 1.15 + 1)
  return {
    domain: [lo, hi], skewSeconds, markers,
    windowSeconds: Number.isNaN(end) ? null : (end - start) / 1000,
    first: markers.find((m) => !m.noisy) || markers[0] || null,
  }
}

/** Text alternative for the TTD timeline: every marker with its rule title and author (DRL 1.1). */
export function timelineLabel(model) {
  if (!model || !model.markers.length) return 'Timeline from the execution start. No rule matched.'
  return `Timeline from the execution start. ${model.markers.map((m, i) => (
    `${i + 1}: ${m.title || m.id} (${m.author || 'author unknown'}) first matched at ${formatOffset(m.offset)}`
    + `${m.noisy ? ' (noisy)' : ''}`)).join('; ')}.`
}

/** Map a domain value onto [x0, x1]. */
export function scale(value, [d0, d1], [x0, x1]) {
  if (d1 === d0) return x0
  return x0 + ((value - d0) / (d1 - d0)) * (x1 - x0)
}

// -- events ---------------------------------------------------------------------------------------

const SYSMON_EVENTS = {
  1: 'Process creation', 2: 'File creation time changed', 3: 'Network connection', 4: 'Sysmon state changed',
  5: 'Process terminated', 6: 'Driver loaded', 7: 'Image loaded', 8: 'CreateRemoteThread', 9: 'Raw access read',
  10: 'Process access', 11: 'File created', 12: 'Registry object added or deleted', 13: 'Registry value set',
  14: 'Registry object renamed', 15: 'File stream created', 16: 'Sysmon config changed', 17: 'Pipe created',
  18: 'Pipe connected', 19: 'WMI filter', 20: 'WMI consumer', 21: 'WMI binding', 22: 'DNS query',
  23: 'File deleted', 24: 'Clipboard changed', 25: 'Process tampering', 26: 'File delete logged',
}
const SECURITY_EVENTS = {
  1102: 'Audit log cleared', 4624: 'Logon', 4625: 'Failed logon', 4648: 'Explicit credential logon',
  4672: 'Special privileges assigned', 4688: 'Process creation', 4697: 'Service installed',
  4698: 'Scheduled task created', 4720: 'User account created', 4728: 'Member added to global group',
  4732: 'Member added to local group', 4769: 'Kerberos service ticket requested', 5140: 'Network share accessed',
  5145: 'Network share object checked',
}

/** "Sysmon 1 · Process creation", "Security 4624 · Logon", "System 7045". */
export function eventName(channel, eventId) {
  const ch = String(channel || '')
  if (/sysmon/i.test(ch)) return `Sysmon ${eventId}${SYSMON_EVENTS[eventId] ? ` · ${SYSMON_EVENTS[eventId]}` : ''}`
  if (/^security$/i.test(ch)) return `Security ${eventId}${SECURITY_EVENTS[eventId] ? ` · ${SECURITY_EVENTS[eventId]}` : ''}`
  if (/^system$/i.test(ch) && Number(eventId) === 7045) return 'System 7045 · Service installed'
  return `${ch || 'Event'} ${eventId ?? ''}`.trim()
}

/**
 * How many events the matched-events view holds: a rule's own match count when one rule is selected (or
 * only one fired). With several rules and no selection the union is not known (an event can match more
 * than one rule), so null.
 */
export function matchTotal(hits, ruleId = '') {
  const list = hits || []
  if (ruleId) return list.find((h) => h.rule?.id === ruleId)?.count ?? null
  return list.length === 1 ? list[0].count ?? null : null
}

/** Fields that best describe an event, most telling first. */
export const KEY_FIELDS = [
  'CommandLine', 'Image', 'NewProcessName', 'ParentImage', 'ParentProcessName', 'ParentCommandLine',
  'SourceImage', 'TargetImage', 'GrantedAccess', 'TargetObject', 'Details', 'TargetFilename', 'ImageLoaded',
  'QueryName', 'DestinationIp', 'DestinationPort', 'DestinationHostname', 'PipeName', 'ServiceName',
  'TaskName', 'TargetUserName', 'User', 'SubjectUserName',
]

/** The one field shown for an event in a list row: [name, value] or null. */
export function summaryField(fields) {
  if (!fields) return null
  for (const k of KEY_FIELDS) if (fields[k]) return [k, fields[k]]
  const first = Object.entries(fields).find(([k, v]) => v && k !== 'UtcTime' && k !== 'RuleName')
  return first || null
}

/** ATT&CK technique page: T1003.001 -> https://attack.mitre.org/techniques/T1003/001/ */
export function attackUrl(id) {
  const m = /^T(\d{4})(?:\.(\d{3}))?$/.exec(id || '')
  if (!m) return null
  return `https://attack.mitre.org/techniques/T${m[1]}/${m[2] ? `${m[2]}/` : ''}`
}
