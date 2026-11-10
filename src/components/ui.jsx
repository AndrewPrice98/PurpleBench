import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import {
  ArrowDown, ArrowLeft, ArrowLeftRight, ArrowRight, ArrowUp, ChevronDown, ChevronRight, CircleDashed, Clock, Copy, Download,
  ExternalLink as ExternalLinkIcon, FileText, GitBranch, Grid3x3, Info, Layers, LayoutDashboard, ListChecks, Lock, Menu, Minus,
  Plus, ScrollText, TriangleAlert, Upload, X,
} from 'lucide-react'
import { RELATION, STATUS, splitLinks, splitRuleRefs, tacticLabel } from '../lib.js'

// -- status and tags: a 6 px dot with text, or a compact tag; never colour alone ------------------

const TAG_TONE = {
  noisy: 'amber', 'mode-lab': 'amber', 'rel-exact': 'accent', match: 'accent',
}

/** A compact tag: tinted background, no border, no icon. */
export function Chip({ tone = 'neutral', children, title, className = '' }) {
  return <span className={`tag ${TAG_TONE[tone] || ''} ${className}`.trim()} title={title}>{children}</span>
}

export function StatusChip({ status, withHelp = false }) {
  const s = STATUS[status] || { label: status, help: '' }
  return <span className={`status s-${status}`} title={withHelp ? s.help : undefined}>{s.label}</span>
}

export function RelationChip({ relation }) {
  const r = RELATION[relation] || { label: relation || 'Unknown relation', help: '' }
  return <Chip tone={`rel-${relation || 'none'}`} title={r.help}>{r.label}</Chip>
}

export function NoisyChip({ hits }) {
  return (
    <Chip tone="noisy" title="Fires on the benign baseline, so it earns no detection credit.">
      Noisy{hits != null ? ` · ${hits} baseline ${hits === 1 ? 'hit' : 'hits'}` : ''}
    </Chip>
  )
}

/** Recorded or lab. `plain` renders text only, for table cells. */
export function ModeChip({ mode, plain = false }) {
  const lab = mode === 'lab'
  const title = lab
    ? 'Lab mode: not yet run against a real lab.'
    : 'Recorded mode: telemetry from a public dataset; nothing was executed.'
  if (plain) return <span title={title}>{lab ? 'Lab' : 'Recorded'}</span>
  return <Chip tone={lab ? 'mode-lab' : 'mode-recorded'} title={title}>{lab ? 'Lab' : 'Recorded'}</Chip>
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

// -- icons: lucide, 16 px, 1.5 stroke, currentColor -----------------------------------------------

const ICONS = {
  github: GitBranch, back: ArrowLeft, arrow: ArrowRight, lock: Lock, external: ExternalLinkIcon, info: Info, clock: Clock,
  download: Download, upload: Upload, copy: Copy, plus: Plus, warning: TriangleAlert, chevron: ChevronDown,
  chevronRight: ChevronRight, menu: Menu, close: X, up: ArrowUp, down: ArrowDown, minus: Minus, swap: ArrowLeftRight,
  overview: LayoutDashboard, campaigns: Layers, runs: ListChecks, coverage: Grid3x3, rules: ScrollText,
  gaps: CircleDashed, reports: FileText,
}

export function Icon({ name, size = 16, label, className = '' }) {
  const Glyph = ICONS[name]
  if (!Glyph) return null
  return (
    <Glyph className={`icon ${className}`.trim()} size={size} strokeWidth={1.5} absoluteStrokeWidth
      aria-hidden={label ? undefined : 'true'} role={label ? 'img' : undefined} aria-label={label}
      focusable="false" />
  )
}

/**
 * The PurpleBench mark: two outlined rings (red team, blue team) whose overlap is filled violet.
 * Colours come from CSS variables; public/logo-mark.svg is the same drawing with fixed colours.
 */
export function BrandMark({ size = 26 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false" className="brand-svg">
      <path d="M12 5.65A7.25 7.25 0 0 1 12 18.35A7.25 7.25 0 0 1 12 5.65Z" fill="var(--accent)" />
      <circle cx="8.5" cy="12" r="7.25" fill="none" stroke="var(--ring-red)" strokeWidth="1.75" />
      <circle cx="15.5" cy="12" r="7.25" fill="none" stroke="var(--ring-blue)" strokeWidth="1.75" />
    </svg>
  )
}

/** A styled native select: a real <select> underneath, so keyboard and screen readers work unchanged. */
export function Select({ children, className = '', ...props }) {
  return (
    <span className={`select ${className}`.trim()}>
      <select {...props}>{children}</select>
      <Icon name="chevron" size={14} />
    </span>
  )
}

export function ExternalLink({ href, children, className }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className={className}>
      {children}<Icon name="external" size={12} className="ext" /><span className="sr-only"> (opens in a new tab)</span>
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

/**
 * Run an async loader whenever deps change. The loader receives an AbortSignal: requests still in flight
 * are aborted when the deps change or the component unmounts, and stale responses are ignored.
 */
export function useAsync(loader, deps) {
  const [state, setState] = useState({ loading: true, error: null, data: null })
  const [tick, setTick] = useState(0)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(loader, deps)
  useEffect(() => {
    const ctrl = new AbortController()
    setState((s) => ({ ...s, loading: true, error: null }))
    load(ctrl.signal)
      .then((data) => { if (!ctrl.signal.aborted) setState({ loading: false, error: null, data }) })
      .catch((error) => {
        if (!ctrl.signal.aborted && error?.name !== 'AbortError') setState({ loading: false, error, data: null })
      })
    return () => ctrl.abort()
  }, [load, tick])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  const setData = useCallback((fn) => setState((s) => ({ ...s, data: fn(s.data) })), [])
  return { ...state, reload, setData }
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
