// Pure logic for the coverage, rules, gaps, campaigns and reports pages (no React, tested with node --test).

import { NOT_TESTED, STATUS, tacticLabel, tsMs } from './lib.js'

// -- ATT&CK matrix ---------------------------------------------------------------------------------

/**
 * ATT&CK Enterprise v20 tactics in matrix order. v19 split Defense Evasion into Stealth (TA0005) and
 * Defense Impairment (TA0112), so there is no Defense Evasion column.
 */
export const TACTICS_V20 = [
  ['reconnaissance', 'TA0043'], ['resource-development', 'TA0042'], ['initial-access', 'TA0001'],
  ['execution', 'TA0002'], ['persistence', 'TA0003'], ['privilege-escalation', 'TA0004'],
  ['stealth', 'TA0005'], ['defense-impairment', 'TA0112'], ['credential-access', 'TA0006'],
  ['discovery', 'TA0007'], ['lateral-movement', 'TA0008'], ['collection', 'TA0009'],
  ['command-and-control', 'TA0011'], ['exfiltration', 'TA0010'], ['impact', 'TA0040'],
].map(([slug, id]) => ({ slug, id, name: tacticLabel(slug) }))

/**
 * Matrix columns for a coverage response: one column per v20 tactic that has techniques (a technique in
 * several tactics appears in each), techniques sorted by id. Tactics with nothing tested in the run are
 * returned separately so the page can still name all fifteen. Unknown tactic slugs get their own column
 * at the end rather than disappearing.
 */
export function matrixColumns(techniques) {
  const by = new Map()
  for (const t of techniques || []) {
    for (const tac of t.tactics || []) {
      if (!by.has(tac)) by.set(tac, [])
      by.get(tac).push(t)
    }
  }
  const known = new Set(TACTICS_V20.map((t) => t.slug))
  const cols = TACTICS_V20.filter((t) => by.has(t.slug)).map((t) => ({ ...t, techniques: by.get(t.slug) }))
  for (const [slug, list] of by) {
    if (!known.has(slug)) cols.push({ slug, id: null, name: tacticLabel(slug), techniques: list })
  }
  for (const c of cols) {
    c.techniques = [...c.techniques].sort((a, b) => techCompare(a.technique, b.technique))
    c.tested = c.techniques.filter((t) => !NOT_TESTED.has(t.status)).length
    c.detected = c.techniques.filter((t) => t.status === 'detected').length
  }
  return { columns: cols, empty: TACTICS_V20.filter((t) => !by.has(t.slug)) }
}

/** T1003 < T1003.001 < T1003.002 < T1005, by number rather than by string. */
export function techCompare(a, b) {
  const parse = (id) => {
    const m = /^T(\d+)(?:\.(\d+))?$/.exec(id || '')
    return m ? [Number(m[1]), m[2] ? Number(m[2]) : -1] : [Number.MAX_SAFE_INTEGER, 0]
  }
  const [a1, a2] = parse(a)
  const [b1, b2] = parse(b)
  return a1 - b1 || a2 - b2 || String(a).localeCompare(String(b))
}

/** Status counts over coverage techniques, every status present (zeros included). */
export function statusCounts(techniques) {
  const counts = Object.fromEntries(Object.keys(STATUS).map((s) => [s, 0]))
  for (const t of techniques || []) counts[t.status] = (counts[t.status] || 0) + 1
  return counts
}

// -- comparison with the previous run ----------------------------------------------------------------

const runKey = (r) => [tsMs(r.started_at), r.id]
const before = (a, b) => {
  const [ta, ia] = runKey(a)
  const [tb, ib] = runKey(b)
  return ta < tb || (ta === tb && ia < ib)
}

/**
 * The run to compare with, as the exercise report does: the latest earlier run of the same campaign, or
 * else the latest earlier run of any campaign (whose technique set differs, so only the score compares).
 * @returns {{run: object, sameCampaign: boolean} | null}
 */
export function previousRun(runs, runId) {
  const list = runs || []
  const cur = list.find((r) => r.id === runId)
  if (!cur) return null
  const earlier = list.filter((r) => r.id !== cur.id && before(r, cur))
    .sort((a, b) => (before(a, b) ? -1 : before(b, a) ? 1 : 0))
  const same = earlier.filter((r) => r.campaign_id === cur.campaign_id)
  if (same.length) return { run: same[same.length - 1], sameCampaign: true }
  if (earlier.length) return { run: earlier[earlier.length - 1], sameCampaign: false }
  return null
}

// Higher is better. Missed and telemetry gap are equally undetected; untested and did-not-run are unscored.
const RANK = { detected: 3, partial: 2, missed: 1, telemetry_gap: 1 }

/**
 * Per-technique change between two coverage results.
 * direction: improved | regressed | changed (same rank, or a not-tested status on either side) |
 * added (not in the earlier run) | removed (not in this run).
 */
export function diffCoverage(prevTechniques, curTechniques) {
  const prev = new Map((prevTechniques || []).map((t) => [t.technique, t]))
  const cur = new Map((curTechniques || []).map((t) => [t.technique, t]))
  const ids = [...new Set([...prev.keys(), ...cur.keys()])].sort(techCompare)
  const changes = []
  for (const id of ids) {
    const p = prev.get(id)
    const c = cur.get(id)
    if (p && c && p.status === c.status) continue
    let direction
    if (!p) direction = 'added'
    else if (!c) direction = 'removed'
    else {
      const rp = RANK[p.status]
      const rc = RANK[c.status]
      direction = rp == null || rc == null || rp === rc ? 'changed' : rc > rp ? 'improved' : 'regressed'
    }
    changes.push({ id, name: (c || p).name, before: p?.status ?? null, after: c?.status ?? null, direction })
  }
  const count = (d) => changes.filter((x) => x.direction === d).length
  return {
    changes,
    improved: count('improved'), regressed: count('regressed'), changed: count('changed'),
    added: count('added'), removed: count('removed'),
  }
}

/** "+14.3 points", "−7.1 points", "no change"; null when either score is missing. */
export function scoreDelta(prevScore, curScore) {
  if (prevScore == null || curScore == null) return null
  const d = Math.round((curScore - prevScore) * 10) / 10
  if (d === 0) return 'no change'
  return `${d > 0 ? '+' : '−'}${Math.abs(d).toFixed(1)} points`
}

// -- rules ---------------------------------------------------------------------------------------------

export const RULE_SOURCES = { sigmahq: 'SigmaHQ', custom: 'Custom' }

/**
 * Filter the rule list. Every filter is optional ('' means any):
 * source (sigmahq|custom), status (ok|unsupported), noise (noisy|quiet), set (in|out: in the run's rule set),
 * fired (yes|no: fired in the run), q (free text over title, author, id and technique ids).
 */
export function filterRules(rules, { source = '', status = '', noise = '', set = '', fired = '', q = '' } = {}) {
  const needle = q.trim().toLowerCase()
  return (rules || []).filter((r) => (!source || r.source === source)
    && (!status || r.status === status)
    && (!noise || (noise === 'noisy') === Boolean(r.noisy))
    && (!set || (set === 'in') === Boolean(r.in_ruleset))
    && (!fired || (fired === 'yes') === (r.executions_fired > 0))
    && (!needle || [r.title, r.author, r.id, ...(r.techniques || [])]
      .some((v) => String(v || '').toLowerCase().includes(needle))))
}

/** Rule hits ("where it fired") grouped by run, runs in ascending order. */
export function hitsByRun(hits) {
  const by = new Map()
  for (const h of hits || []) {
    if (!by.has(h.run_id)) by.set(h.run_id, [])
    by.get(h.run_id).push(h)
  }
  return [...by.entries()].sort((a, b) => a[0] - b[0]).map(([runId, list]) => ({ runId, hits: list }))
}

// -- gaps --------------------------------------------------------------------------------------------

export const GAP_STATES = {
  open: { tone: 'outline', glyph: '○', label: 'Open', help: 'Still undetected in later runs of this campaign.' },
  closed: { tone: 'detected', glyph: '✓', label: 'Closed', help: 'A later rule set detects it.' },
  accepted: { tone: 'neutral', glyph: '≡', label: 'Accepted', help: 'An analyst accepted the risk.' },
}

/** Whether the gap edit form holds a change worth saving. */
export function gapDirty(gap, draft) {
  return (draft.status !== gap.status) || ((draft.notes || '').trim() !== (gap.notes || '').trim())
}

/** PATCH body with only what changed. */
export function gapPatch(gap, draft) {
  const body = {}
  if (draft.status !== gap.status) body.status = draft.status
  if ((draft.notes || '').trim() !== (gap.notes || '').trim()) body.notes = (draft.notes || '').trim()
  return body
}

// -- campaigns --------------------------------------------------------------------------------------

export const LAB_TARGET_EXAMPLE = 'LAB-WS01'

/** The server's slug for download names: lower-case, runs of other characters to "-", at most 40. */
export function slugify(text) {
  const s = String(text || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
    .slice(0, 40).replace(/^-+|-+$/g, '')
  return s || 'campaign'
}

/** The file name the campaign export downloads as (matches the API's Content-Disposition). */
export function campaignFileName(campaign) {
  return `purplebench-campaign-${campaign.id}-${slugify(campaign.name)}.json`
}

/**
 * The lab runner commands for a campaign file, run from the repository's lab folder: a -WhatIf rehearsal
 * that executes and contacts nothing, then the real run.
 */
export function runnerCommands(campaign, target = LAB_TARGET_EXAMPLE) {
  const file = `.\\${campaignFileName(campaign)}`
  const base = `.\\Invoke-PurpleBenchRun.ps1 -Target ${target} -Campaign ${file}`
  return { rehearse: `${base} -WhatIf`, run: `${base} -Credential (Get-Credential)` }
}

/** Problems that stop a campaign from being created (shown next to the disabled button). */
export function campaignProblems({ name = '', techniques = [] }, existingNames = []) {
  const problems = []
  const n = name.trim()
  if (!n) problems.push('Give the campaign a name.')
  else if (n.length > 200) problems.push('The name is longer than 200 characters.')
  else if (existingNames.some((x) => x === n)) problems.push('A campaign with this name already exists.')
  if (!techniques.length) problems.push('Pick at least one technique.')
  else if (techniques.length > 100) problems.push('Pick at most 100 techniques.')
  return problems
}

/** Library techniques grouped by their first v20 tactic, in matrix order, filtered by free text. */
export function groupLibrary(techniques, q = '') {
  const needle = q.trim().toLowerCase()
  const shown = (techniques || []).filter((t) => !needle
    || [t.id, t.name, t.atomic_test?.name, ...(t.tactics || []).map(tacticLabel)]
      .some((v) => String(v || '').toLowerCase().includes(needle)))
  const order = TACTICS_V20.map((t) => t.slug)
  const first = (t) => {
    const idx = (t.tactics || []).map((x) => order.indexOf(x)).filter((i) => i >= 0)
    return idx.length ? order[Math.min(...idx)] : (t.tactics || [])[0] || 'other'
  }
  const groups = new Map()
  for (const t of shown) {
    const k = first(t)
    if (!groups.has(k)) groups.set(k, [])
    groups.get(k).push(t)
  }
  return [...groups.entries()]
    .sort((a, b) => ((order.indexOf(a[0]) + 1) || 99) - ((order.indexOf(b[0]) + 1) || 99))
    .map(([tactic, list]) => ({ tactic, name: tacticLabel(tactic), techniques: list.sort((a, b) => techCompare(a.id, b.id)) }))
}

// -- uploads ---------------------------------------------------------------------------------------

/** A clear message for a failed run upload, from the API status and detail. */
export function uploadMessage(err, maxMb) {
  const detail = err?.message || 'The upload failed.'
  switch (err?.status) {
    case 413: return `The file is too large${maxMb ? ` (the limit is ${maxMb} MB)` : ''}. ${detail}`
    case 415: return `The file must be a JSON run file written by the lab runner. ${detail}`
    case 401: return 'Your session has expired. Sign in again and retry.'
    case 403: return 'Only an admin can upload runs. Sign in as the admin.'
    case 400: case 422: return `The run file was refused: ${detail}`
    case 0: return detail
    default: return `The upload failed: ${detail}`
  }
}

/** Local checks before sending: a .json file, not empty, under the limit. */
export function uploadProblem(file, maxMb) {
  if (!file) return 'Choose a run file first.'
  if (!/\.json$/i.test(file.name || '')) return 'Choose the .json run file the lab runner wrote.'
  if (file.size === 0) return 'The file is empty.'
  if (maxMb && file.size > maxMb * 1024 * 1024) return `The file is ${(file.size / 1048576).toFixed(1)} MB; the limit is ${maxMb} MB.`
  return null
}

// -- ATT&CK Navigator layer (format 4.5) -------------------------------------------------------------

const TID = /^T\d{4}(\.\d{3})?$/
const COLOR = /^#[0-9a-fA-F]{6}$/

/**
 * Problems found checking a layer against the layer format 4.5 fields PurpleBench writes (the same checks
 * as backend navigator.validate_layer). An empty list means valid.
 */
export function validateLayer(layer) {
  const errs = []
  if (!layer || typeof layer !== 'object' || Array.isArray(layer)) return ['layer is not an object']
  if (typeof layer.name !== 'string' || !layer.name) errs.push('name is required (string)')
  if (!['enterprise-attack', 'mobile-attack', 'ics-attack'].includes(layer.domain)) errs.push('domain is required')
  const v = layer.versions
  if (!v || typeof v !== 'object') errs.push('versions is required')
  else {
    if (v.layer !== '4.5') errs.push('versions.layer must be "4.5"')
    if (typeof v.navigator !== 'string') errs.push('versions.navigator is required (string)')
    if ('attack' in v && typeof v.attack !== 'string') errs.push('versions.attack must be a string')
  }
  if ('description' in layer && typeof layer.description !== 'string') errs.push('description must be a string')
  const techs = layer.techniques ?? []
  if (!Array.isArray(techs)) return [...errs, 'techniques must be an array']
  const seen = new Set()
  techs.forEach((t, i) => {
    const p = `techniques[${i}]`
    if (!t || typeof t !== 'object') { errs.push(`${p} is not an object`); return }
    const key = `${t.techniqueID}|${t.tactic ?? ''}`
    if (typeof t.techniqueID !== 'string' || !TID.test(t.techniqueID)) errs.push(`${p}.techniqueID must look like T1234 or T1234.567`)
    else if (seen.has(key)) errs.push(`${p}: duplicate entry for ${t.techniqueID}`)
    else seen.add(key)
    if ('tactic' in t && !(typeof t.tactic === 'string' && /^[a-z-]+$/.test(t.tactic))) errs.push(`${p}.tactic must be a tactic shortname`)
    if ('score' in t && typeof t.score !== 'number') errs.push(`${p}.score must be a number`)
    if ('color' in t && !(typeof t.color === 'string' && COLOR.test(t.color))) errs.push(`${p}.color must be #rrggbb`)
    if ('comment' in t && typeof t.comment !== 'string') errs.push(`${p}.comment must be a string`)
    if ('enabled' in t && typeof t.enabled !== 'boolean') errs.push(`${p}.enabled must be a boolean`)
    ;(t.metadata || []).forEach((m, j) => {
      if (!m || typeof m.name !== 'string' || typeof m.value !== 'string') errs.push(`${p}.metadata[${j}] needs string name and value`)
    })
  })
  ;(layer.legendItems || []).forEach((li, j) => {
    if (!li || typeof li.label !== 'string' || !COLOR.test(String(li.color))) errs.push(`legendItems[${j}] needs a label and a #rrggbb color`)
  })
  const g = layer.gradient
  if (g != null && !(g && Array.isArray(g.colors) && g.colors.length && g.colors.every((c) => COLOR.test(String(c)))
    && typeof g.minValue === 'number' && typeof g.maxValue === 'number')) errs.push('gradient needs colors, minValue and maxValue')
  return errs
}
