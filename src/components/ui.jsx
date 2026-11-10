import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { RELATION, STATUS, splitLinks, splitRuleRefs, tacticLabel } from '../lib.js'

// -- status chips: glyph + text label + tone, so they never rely on color alone ----------------

export function Chip({ tone = 'neutral', glyph, children, title, className = '' }) {
  return (
    <span className={`chip ${tone} ${className}`} title={title}>
      {glyph && <span className="chip-glyph" aria-hidden="true">{glyph}</span>}
      {children}
    </span>
  )
}

export function StatusChip({ status, withHelp = false }) {
  const s = STATUS[status] || { label: status, tone: 'neutral', glyph: '?' }
  return <Chip tone={s.tone} glyph={s.glyph} title={withHelp ? s.help : undefined}>{s.label}</Chip>
}

export function RelationChip({ relation }) {
  const r = RELATION[relation] || { label: relation || 'Unknown relation', help: '' }
  return <Chip tone={`rel-${relation || 'none'}`} title={r.help}>{r.label}</Chip>
}

export function NoisyChip({ hits }) {
  return (
    <Chip tone="noisy" glyph="≈" title="Fires on the benign baseline, so it earns no detection credit.">
      Noisy{hits != null ? ` · ${hits} baseline ${hits === 1 ? 'hit' : 'hits'}` : ''}
    </Chip>
  )
}

export function ModeChip({ mode }) {
  return mode === 'lab'
    ? <Chip tone="mode-lab" glyph="⚗" title="Lab mode: not yet run against a real lab.">Lab</Chip>
    : <Chip tone="mode-recorded" glyph="●" title="Recorded mode: telemetry from a public dataset; nothing was executed.">Recorded</Chip>
}

export function TacticTag({ tactic, name }) {
  return <span className="tactic-tag">{name || tacticLabel(tactic)}</span>
}

// -- states ---------------------------------------------------------------------------------

export function Loading({ label = 'Loading…' }) {
  return (
    <div className="state" role="status">
      <span className="spinner" aria-hidden="true" /> {label}
    </div>
  )
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="state error" role="alert">
      <strong>Something went wrong.</strong> {error?.message || String(error)}
      {onRetry && <> <button type="button" className="link" onClick={onRetry}>Try again</button></>}
    </div>
  )
}

export function Empty({ children }) {
  return <div className="state">{children}</div>
}

// -- icons ------------------------------------------------------------------------------------

export function Icon({ name, size = 16, label }) {
  const paths = {
    github: <path d="M10 1.5a8.5 8.5 0 0 0-2.7 16.6c.4 0 .6-.2.6-.4v-1.5c-2.4.5-2.9-1-2.9-1-.4-1-1-1.3-1-1.3-.8-.5 0-.5 0-.5.9 0 1.3.9 1.3.9.8 1.3 2 1 2.5.7 0-.6.3-1 .6-1.2-1.9-.2-3.9-1-3.9-4.2 0-.9.3-1.7.9-2.3-.1-.2-.4-1.1.1-2.3 0 0 .7-.2 2.3.9a8 8 0 0 1 4.2 0c1.6-1.1 2.3-.9 2.3-.9.5 1.2.2 2 .1 2.3.5.6.9 1.4.9 2.3 0 3.3-2 4-3.9 4.2.3.3.6.8.6 1.6v2.4c0 .2.2.5.6.4A8.5 8.5 0 0 0 10 1.5Z" fill="currentColor" stroke="none" />,
    back: <path d="M12.5 4.5 7 10l5.5 5.5" />,
    arrow: <><path d="M4 10h11" /><path d="m11 5.5 4.5 4.5-4.5 4.5" /></>,
    lock: <><rect x="4" y="9" width="12" height="8.5" rx="1.5" /><path d="M7 9V6.5a3 3 0 0 1 6 0V9" /></>,
    external: <><path d="M11 3.5h5.5V9" /><path d="M16.5 3.5 9 11" /><path d="M14 12v4a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h4" /></>,
    info: <><circle cx="10" cy="10" r="7.5" /><path d="M10 9v5" /><path d="M10 6.2v.1" /></>,
    record: <><circle cx="10" cy="10" r="7.5" /><circle cx="10" cy="10" r="3" fill="currentColor" stroke="none" /></>,
    target: <><circle cx="10" cy="10" r="7.5" /><circle cx="10" cy="10" r="4" /><path d="M10 1v4M10 15v4M1 10h4M15 10h4" /></>,
    radar: <><path d="M10 2.5a7.5 7.5 0 1 0 7.5 7.5" /><path d="M10 6a4 4 0 1 0 4 4" /><path d="m10 10 6-6" /><circle cx="10" cy="10" r="1" fill="currentColor" stroke="none" /></>,
    flag: <><path d="M4.5 17.5V3" /><path d="M4.5 3.5h10l-2 3.5 2 3.5h-10" /></>,
    clock: <><circle cx="10" cy="10" r="7.5" /><path d="M10 5.5V10l3 2" /></>,
    list: <><path d="M7 5h10M7 10h10M7 15h10" /><path d="M3 5h.01M3 10h.01M3 15h.01" /></>,
    noise: <><path d="M2 10h2l1.5-4 2 9 2-12 2 11 2-7 1.5 3H18" /></>,
    check: <path d="m4.5 10.5 3.5 3.5 7.5-8" />,
    construct: <><path d="M3 17h14" /><path d="M5 17V9l5-5 5 5v8" /><path d="M8.5 17v-4h3v4" /></>,
  }
  return (
    <svg className="icon" width={size} height={size} viewBox="0 0 20 20" fill="none" stroke="currentColor"
      strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"
      aria-hidden={label ? undefined : 'true'} role={label ? 'img' : undefined} aria-label={label}
      focusable="false">
      {paths[name]}
    </svg>
  )
}

/** The PurpleBench mark: a red (attack) and a blue (detection) circle overlapping in violet. */
export function BrandMark({ size = 26 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" aria-hidden="true" focusable="false" className="brand-svg">
      <circle cx="7.6" cy="10" r="6.4" fill="var(--attack)" opacity="0.9" />
      <circle cx="12.4" cy="10" r="6.4" fill="var(--detect)" opacity="0.9" />
      <path d="M10 4.07A6.4 6.4 0 0 1 10 15.93A6.4 6.4 0 0 1 10 4.07Z" fill="var(--accent)" />
    </svg>
  )
}

export function ExternalLink({ href, children, className }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className={className}>
      {children}<Icon name="external" size={12} /><span className="sr-only"> (opens in a new tab)</span>
    </a>
  )
}

/** Text whose http(s) URLs become links; everything is rendered as text. */
export function LinkedText({ text }) {
  return (
    <>
      {splitLinks(text || '').map((s, i) => (s.href
        ? <ExternalLink key={i} href={s.href}>{s.text}</ExternalLink>
        : <span key={i}>{s.text}</span>))}
    </>
  )
}

/** A rule title with its author (SigmaHQ Detection Rule License 1.1 attribution). */
export function RuleName({ rule, link = false }) {
  if (!rule) return null
  const title = rule.title || rule.id
  return (
    <span className="rule-name">
      {link && rule.url ? <ExternalLink href={rule.url}>{title}</ExternalLink> : <span className="rule-title">{title}</span>}
      <span className="rule-author"> ({rule.author || 'author unknown'})</span>
    </span>
  )
}

/** A reason or note with every rule title shown with its author. */
export function RuleText({ text, rules }) {
  if (!text) return null
  return (
    <>
      {splitRuleRefs(text, rules || new Map()).map((s, i) => (s.rule
        ? <RuleName key={i} rule={s.rule} />
        : <span key={i}>{s.text}</span>))}
    </>
  )
}

// -- session and data hooks -----------------------------------------------------------------

export const SessionContext = createContext(null)

/** { user, guest, demo, version, authConfigured } */
export function useSession() {
  return useContext(SessionContext)
}

export function usePageTitle(title) {
  useEffect(() => {
    document.title = title ? `${title} · PurpleBench` : 'PurpleBench'
  }, [title])
}

/** Run an async loader whenever deps change. Ignores stale responses. */
export function useAsync(loader, deps) {
  const [state, setState] = useState({ loading: true, error: null, data: null })
  const [tick, setTick] = useState(0)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(loader, deps)
  useEffect(() => {
    let live = true
    setState((s) => ({ ...s, loading: true, error: null }))
    load()
      .then((data) => live && setState({ loading: false, error: null, data }))
      .catch((error) => live && setState({ loading: false, error, data: null }))
    return () => { live = false }
  }, [load, tick])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { ...state, reload }
}

/** Prefers-reduced-motion, live. */
export function useReducedMotion() {
  const query = '(prefers-reduced-motion: reduce)'
  const [reduced, setReduced] = useState(() => (typeof window !== 'undefined' && window.matchMedia
    ? window.matchMedia(query).matches : false))
  useEffect(() => {
    if (!window.matchMedia) return undefined
    const mq = window.matchMedia(query)
    const on = () => setReduced(mq.matches)
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [])
  return reduced
}
