// Read just enough of a Sigma rule's `detection` block to show *why* an event matched: which fields
// a rule's positive selections reference and which literal values they look for. This is a reading
// aid for highlighting, not an evaluator; the backend's evaluator decided the match.

/** Rule field -> event field names that carry it (Security 4688 vs Sysmon process creation). */
const ALIASES = {
  image: ['newprocessname'],
  parentimage: ['parentprocessname'],
  user: ['subjectusername'],
  md5: ['hashes'], sha1: ['hashes'], sha256: ['hashes'], imphash: ['hashes'],
}

/** Modifiers whose values can be found as text inside the event value. */
const TEXT_MODIFIERS = new Set(['contains', 'startswith', 'endswith', 'all', 'windash', 'cased'])

function stripComment(line) {
  let quote = null
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i]
    if (quote) {
      if (c === quote) {
        if (quote === "'" && line[i + 1] === "'") { i += 1; continue }
        quote = null
      } else if (c === '\\' && quote === '"') {
        i += 1
      }
    } else if (c === "'" || c === '"') {
      quote = c
    } else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i).replace(/\s+$/, '')
    }
  }
  return line.replace(/\s+$/, '')
}

/** A YAML scalar as Sigma uses it: quoted strings, plain strings, null. */
export function unquote(raw) {
  const s = raw.trim()
  if (s === '' || s === '~' || s === 'null' || s === 'Null' || s === 'NULL') return null
  if (s.length >= 2 && s[0] === "'" && s[s.length - 1] === "'") return s.slice(1, -1).replaceAll("''", "'")
  if (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"') {
    return s.slice(1, -1).replace(/\\(["\\/nt])/g, (_, ch) => ({ n: '\n', t: '\t' }[ch] ?? ch))
  }
  return s
}

function flowList(raw) {
  const s = raw.trim()
  if (!(s.startsWith('[') && s.endsWith(']'))) return null
  const inner = s.slice(1, -1)
  const out = []
  let cur = ''
  let quote = null
  for (const c of inner) {
    if (quote) { cur += c; if (c === quote) quote = null; continue }
    if (c === "'" || c === '"') { quote = c; cur += c; continue }
    if (c === ',') { out.push(unquote(cur)); cur = ''; continue }
    cur += c
  }
  if (cur.trim()) out.push(unquote(cur))
  return out
}

const KEY_RE = /^([^\s'"#:][^:]*?|'[^']*'|"[^"]*"):(?:\s+(.*))?$/

/**
 * Parse the detection block of a Sigma rule (YAML text).
 * @returns {{ items: Array<{identifier: string, field: string|null, modifiers: string[], values: Array<string|null>}>,
 *             condition: string }}
 */
export function parseDetection(yaml) {
  const items = []
  let condition = ''
  if (!yaml) return { items, condition }
  const lines = String(yaml).split(/\r?\n/)
  const startAt = lines.findIndex((l) => /^detection:\s*$/.test(stripComment(l)))
  if (startAt < 0) return { items, condition }
  let idIndent = null
  let identifier = null
  let field = null // { item, indent }
  for (let i = startAt + 1; i < lines.length; i += 1) {
    const line = stripComment(lines[i])
    if (!line.trim()) continue
    const indent = line.length - line.trimStart().length
    if (indent === 0) break
    const content = line.trim()
    if (idIndent === null) idIndent = indent
    if (indent <= idIndent) {
      const m = KEY_RE.exec(content)
      if (!m) { identifier = null; continue }
      const name = unquote(m[1])
      field = null
      if (name === 'condition') {
        condition = m[2] ? String(unquote(m[2])) : ''
        identifier = '__condition'
        continue
      }
      identifier = name === 'timeframe' ? null : name
      if (identifier && m[2] !== undefined && m[2] !== '') {
        // "keywords: 'value'" is a single keyword.
        items.push({ identifier, field: null, modifiers: [], values: [unquote(m[2])] })
      }
      continue
    }
    if (!identifier) continue
    if (identifier === '__condition') {
      if (content.startsWith('-')) condition = [condition, unquote(content.slice(1))].filter(Boolean).join(' or ')
      continue
    }
    let body = content
    let bodyIndent = indent
    if (content.startsWith('- ') || content === '-') {
      body = content.slice(1).trim()
      bodyIndent = indent + 2
      const km = KEY_RE.exec(body)
      if (!km) {
        const value = unquote(body)
        if (field && field.open && field.indent <= indent) field.item.values.push(value)
        else items.push({ identifier, field: null, modifiers: [], values: [value] })
        continue
      }
    }
    const km = KEY_RE.exec(body)
    if (!km) continue
    const [name, ...modifiers] = String(unquote(km[1])).split('|')
    const item = { identifier, field: name, modifiers: modifiers.map((x) => x.toLowerCase()), values: [] }
    items.push(item)
    const inline = km[2] !== undefined && km[2] !== ''
    field = { item, indent: bodyIndent, open: !inline }
    if (inline) {
      const list = flowList(km[2])
      if (list) item.values.push(...list)
      else item.values.push(unquote(km[2]))
    }
  }
  return { items, condition }
}

function globToRegExp(glob) {
  return new RegExp(`^${glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*').replaceAll('?', '.')}$`)
}

/**
 * Identifiers that only appear negated in the condition ("not filter", "not 1 of filter_*",
 * "not (a or b)"). Their fields are exclusions and are not highlighted.
 */
export function negatedIdentifiers(condition, identifiers) {
  const out = new Set()
  if (!condition) return out
  const tokens = condition.match(/\(|\)|[^\s()]+/g) || []
  const expand = (pattern) => {
    if (pattern === 'them') return identifiers
    const re = globToRegExp(pattern)
    return identifiers.filter((id) => re.test(id))
  }
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens[i].toLowerCase() !== 'not') continue
    let j = i + 1
    if (tokens[j] === '(') {
      let depth = 0
      for (; j < tokens.length; j += 1) {
        if (tokens[j] === '(') depth += 1
        else if (tokens[j] === ')') { depth -= 1; if (depth === 0) break }
        else if (!/^(and|or|not|of|all|\d+)$/i.test(tokens[j])) expand(tokens[j]).forEach((x) => out.add(x))
      }
    } else if (/^(\d+|all|any)$/i.test(tokens[j] || '') && (tokens[j + 1] || '').toLowerCase() === 'of') {
      expand(tokens[j + 2] || '').forEach((x) => out.add(x))
    } else if (tokens[j]) {
      expand(tokens[j]).forEach((x) => out.add(x))
    }
  }
  // An identifier that is also used positively elsewhere stays highlighted.
  const positive = condition.replace(/not\s+(\([^)]*\)|(\d+|all|any)\s+of\s+\S+|\S+)/gi, ' ')
  const posTokens = positive.match(/[^\s()]+/g) || []
  for (let k = 0; k < posTokens.length; k += 1) {
    const t = posTokens[k]
    if (/^(and|or|of|\d+|all|any)$/i.test(t)) continue
    expand(t).forEach((x) => out.delete(x))
  }
  return out
}

/** Text fragments to look for in a value: wildcards split the literal, windash adds dash variants. */
export function valueNeedles(value, modifiers = []) {
  if (value === null || value === undefined) return []
  const mods = new Set(modifiers)
  for (const m of mods) if (!TEXT_MODIFIERS.has(m)) return []
  const frags = String(value).split(/(?<!\\)[*?]/).map((f) => f.replace(/\\([*?\\])/g, '$1')).filter((f) => f.trim())
  if (!mods.has('windash')) return frags
  const out = []
  for (const f of frags) {
    out.push(f)
    if (f.includes('-')) for (const d of ['/', '–', '—', '―']) out.push(f.replaceAll('-', d))
  }
  return out
}

function fieldMatches(ruleField, eventField) {
  const a = ruleField.toLowerCase()
  const b = eventField.toLowerCase()
  return a === b || (ALIASES[a] || []).includes(b)
}

/**
 * For the rules that matched an event: event field name -> text fragments to highlight. Fields of
 * negated (filter) selections are left out.
 * @param {Array<{items: Array, condition: string}>} detections parsed rules
 * @param {string[]} eventFields
 */
export function highlightPlan(detections, eventFields) {
  const plan = new Map()
  for (const det of detections) {
    const ids = [...new Set(det.items.map((it) => it.identifier))]
    const negated = negatedIdentifiers(det.condition, ids)
    for (const it of det.items) {
      if (negated.has(it.identifier)) continue
      const needles = it.values.flatMap((v) => valueNeedles(v, it.modifiers))
      const targets = it.field === null ? eventFields : eventFields.filter((f) => fieldMatches(it.field, f))
      for (const f of targets) {
        if (!plan.has(f)) plan.set(f, [])
        plan.get(f).push(...needles)
      }
    }
  }
  return plan
}

/**
 * Split a value into plain and marked segments where any needle occurs (case-insensitive).
 * @returns {Array<{text: string, mark: boolean}>}
 */
export function highlightSegments(value, needles) {
  const text = String(value ?? '')
  if (!text || !needles?.length) return [{ text, mark: false }]
  const lower = text.toLowerCase()
  const ranges = []
  for (const n of new Set(needles.filter(Boolean))) {
    const ln = n.toLowerCase()
    let at = lower.indexOf(ln)
    while (at >= 0 && ranges.length < 500) {
      ranges.push([at, at + ln.length])
      at = lower.indexOf(ln, at + Math.max(1, ln.length))
    }
  }
  if (!ranges.length) return [{ text, mark: false }]
  ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1])
  const merged = []
  for (const r of ranges) {
    const last = merged[merged.length - 1]
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1])
    else merged.push([...r])
  }
  const segs = []
  let pos = 0
  for (const [a, b] of merged) {
    if (a > pos) segs.push({ text: text.slice(pos, a), mark: false })
    segs.push({ text: text.slice(a, b), mark: true })
    pos = b
  }
  if (pos < text.length) segs.push({ text: text.slice(pos), mark: false })
  return segs
}

/**
 * Keep at most `max` characters of segmented text, but always reach the first marked segment so a
 * long value (a call trace, say) still shows why it matched. Returns { segs, hidden }.
 */
export function clampSegments(segs, max) {
  const total = segs.reduce((n, s) => n + s.text.length, 0)
  if (total <= max) return { segs, hidden: 0 }
  let firstMarkEnd = 0
  let pos = 0
  for (const s of segs) {
    pos += s.text.length
    if (s.mark) { firstMarkEnd = pos; break }
  }
  const limit = Math.max(max, firstMarkEnd)
  const out = []
  let used = 0
  for (const s of segs) {
    if (used >= limit) break
    const take = s.text.slice(0, limit - used)
    out.push({ text: take, mark: s.mark })
    used += take.length
  }
  return { segs: out, hidden: total - used }
}
