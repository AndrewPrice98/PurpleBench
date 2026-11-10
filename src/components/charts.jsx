import { useLayoutEffect, useRef, useState } from 'react'
import {
  STATUS, formatOffset, formatScore, gaugeArc, linePath, linePoints, scale,
} from '../lib.js'

/** Width of an element in CSS pixels, kept current with a ResizeObserver. */
function useWidth(fallback = 600) {
  const ref = useRef(null)
  const [width, setWidth] = useState(fallback)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return undefined
    setWidth(el.clientWidth || fallback)
    if (typeof ResizeObserver === 'undefined') return undefined
    const ro = new ResizeObserver(([entry]) => {
      const w = Math.round(entry.contentRect.width)
      if (w > 0) setWidth(w)
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [fallback])
  return [ref, width]
}

// -- coverage gauge -----------------------------------------------------------------------------

export function Gauge({ score, detected, tested }) {
  const fraction = score == null ? 0 : score / 100
  const label = score == null
    ? 'Coverage score: no tested techniques yet.'
    : `Coverage score ${formatScore(score)}: ${detected} of ${tested} tested techniques detected.`
  return (
    <figure className="gauge">
      <svg viewBox="0 0 200 124" role="img" aria-label={label}>
        <defs>
          <linearGradient id="gauge-grad" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0" stopColor="var(--attack)" />
            <stop offset="0.5" stopColor="var(--accent)" />
            <stop offset="1" stopColor="var(--detect)" />
          </linearGradient>
        </defs>
        <path d={gaugeArc(100, 100, 82, 1)} className="gauge-track" />
        {score != null && score > 0 && (
          <path d={gaugeArc(100, 100, 82, fraction)} className="gauge-value" pathLength="100"
            style={{ '--len': 100 }} />
        )}
        <text x="100" y="86" textAnchor="middle" className="gauge-score">{formatScore(score)}</text>
        <text x="100" y="106" textAnchor="middle" className="gauge-caption">
          {tested ? `${detected} of ${tested} detected` : 'nothing tested'}
        </text>
        <text x="18" y="122" textAnchor="middle" className="gauge-tick">0</text>
        <text x="182" y="122" textAnchor="middle" className="gauge-tick">100</text>
      </svg>
    </figure>
  )
}

// -- coverage over runs --------------------------------------------------------------------------

export function TrendChart({ trend }) {
  const [ref, width] = useWidth(640)
  const height = 230
  const padX = width < 480 ? 54 : 66
  const padTop = 26
  const padBottom = 46
  const strict = linePoints(trend.map((t) => t.score), { width, height, padX, padTop, padBottom })
  const partial = linePoints(trend.map((t) => t.partial_score), { width, height, padX, padTop, padBottom })
  const y = (v) => padTop + (height - padTop - padBottom) * (1 - v / 100)
  const label = `Coverage score over ${trend.length} runs: ${trend.map((t) => (
    `run ${t.run_id} (rule set ${t.ruleset_version}) ${formatScore(t.score)}`)).join(', ')}.`
  const compact = width < 480
  return (
    <div className="trend" ref={ref}>
      <svg width={width} height={height} role="img" aria-label={label} className="trend-svg">
        {[0, 25, 50, 75, 100].map((v) => (
          <g key={v} className="grid">
            <line x1={padX - 12} x2={width - padX + 12} y1={y(v)} y2={y(v)} />
            <text x={padX - 18} y={y(v) + 4} textAnchor="end">{v}%</text>
          </g>
        ))}
        <path d={linePath(partial)} className="trend-line partial" />
        <path d={linePath(strict)} className="trend-line strict" pathLength="100" />
        {strict.map((p, i) => (p.y === null ? null : (
          <g key={trend[i].run_id} className="trend-point">
            <circle cx={p.x} cy={p.y} r="5" />
            <text x={p.x} y={p.y - 11} textAnchor="middle" className="trend-value">{formatScore(p.value)}</text>
          </g>
        )))}
        {strict.map((p, i) => (
          <g key={`x${trend[i].run_id}`} className="trend-x">
            <text x={p.x} y={height - padBottom + 20} textAnchor="middle">Run {trend[i].run_id}</text>
            <text x={p.x} y={height - padBottom + 36} textAnchor="middle" className="sub">
              {compact ? trend[i].ruleset_version : `rule set ${trend[i].ruleset_version}`}
            </text>
          </g>
        ))}
      </svg>
    </div>
  )
}

// -- tactic bars ---------------------------------------------------------------------------------

const BAR_PARTS = ['detected', 'partial', 'missed', 'telemetry_gap']

export function TacticBars({ tactics }) {
  return (
    <ul className="tactic-bars">
      {tactics.map((t) => {
        const tested = t.tested || 0
        const parts = BAR_PARTS.filter((s) => t.counts?.[s])
        const words = parts.map((s) => `${t.counts[s]} ${STATUS[s].label.toLowerCase()}`).join(', ')
        return (
          <li key={t.tactic}>
            <span className="tb-name">{t.name}</span>
            <span className="tb-bar" aria-hidden="true">
              {tested > 0 && parts.map((s) => (
                <span key={s} className={`tb-seg ${STATUS[s].tone}`} style={{ width: `${(100 * t.counts[s]) / tested}%` }} />
              ))}
            </span>
            <span className="tb-num">
              {tested ? <><strong>{t.counts?.detected || 0}</strong>/{tested}</> : <span className="muted">untested</span>}
            </span>
            <span className="sr-only">: {tested ? `${words} of ${tested} tested (${formatScore(t.score)} detected)` : 'nothing tested'}.</span>
          </li>
        )
      })}
    </ul>
  )
}

// -- time to detect timeline ---------------------------------------------------------------------

function niceStep(span) {
  for (const s of [0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600]) if (span / s <= 6) return s
  return Math.ceil(span / 6)
}

export function TtdTimeline({ model }) {
  const [ref, width] = useWidth(520)
  if (!model) return null
  const padX = 18
  const lanes = Math.max(1, model.markers.length)
  const top = 30
  const laneH = 24
  const axisY = top + lanes * laneH + 8
  const height = axisY + 34
  const x = (v) => scale(v, model.domain, [padX, width - padX])
  const step = niceStep(model.domain[1] - model.domain[0])
  const ticks = []
  for (let v = Math.ceil(model.domain[0] / step) * step; v <= model.domain[1] + 1e-9; v += step) ticks.push(v)
  const label = model.markers.length
    ? `Timeline from the execution start. ${model.markers.map((m, i) => (
      `${i + 1}: ${m.title} first matched at ${formatOffset(m.offset)}${m.noisy ? ' (noisy)' : ''}`)).join('; ')}.`
    : 'Timeline from the execution start. No rule matched.'
  return (
    <div className="ttd" ref={ref}>
      <svg width={width} height={height} role="img" aria-label={label}>
        <rect x={x(model.domain[0])} y={top - 12} width={x(0) - x(model.domain[0])} height={axisY - top + 12}
          className="ttd-skew" />
        <text x={(x(model.domain[0]) + x(0)) / 2} y={top - 16} textAnchor="middle" className="ttd-skew-label">
          ±{model.skewSeconds} s skew
        </text>
        <line x1={x(0)} x2={x(0)} y1={top - 12} y2={axisY} className="ttd-start" />
        <text x={x(0) + 5} y={top - 16} className="ttd-start-label">execution start</text>
        <line x1={padX} x2={width - padX} y1={axisY} y2={axisY} className="ttd-axis" />
        {ticks.map((v) => (
          <g key={v} className="ttd-tick">
            <line x1={x(v)} x2={x(v)} y1={axisY} y2={axisY + 5} />
            <text x={x(v)} y={axisY + 18} textAnchor="middle">{v === 0 ? '0' : `${v > 0 ? '+' : '−'}${Math.abs(v)} s`}</text>
          </g>
        ))}
        {model.markers.map((m, i) => {
          const cy = top + i * laneH + laneH / 2
          return (
            <g key={m.id || i} className={`ttd-marker ${m.noisy ? 'noisy' : ''}`}>
              <line x1={x(0)} x2={x(m.offset)} y1={cy} y2={cy} className="ttd-span" />
              <circle cx={x(m.offset)} cy={cy} r="9" />
              <text x={x(m.offset)} y={cy + 4} textAnchor="middle">{i + 1}</text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
