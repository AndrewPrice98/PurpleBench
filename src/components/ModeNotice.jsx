import { ATOMIC_URL, BEST_CASE, DRL_URL, MISSED_MEANING, SIGMAHQ_URL } from '../lib.js'
import { ExternalLink, Icon, LinkedText } from './ui.jsx'

/**
 * Where a result came from, as one line: recorded mode (telemetry from a public dataset, nothing executed)
 * or lab mode (not yet run against a real lab), with what "missed" means. The sources, the attribution and
 * the best-case caveat sit behind "About this data".
 */
export default function ModeNotice({ run }) {
  if (!run) return null
  const lab = run.mode === 'lab'
  return (
    <details className={`mode-bar ${lab ? 'lab' : 'recorded'}`}>
      <summary>
        <span className="mode-dot" aria-hidden="true" />
        <span className="mode-title">{lab ? 'Lab mode, not yet run against a real lab' : 'Recorded mode, nothing was executed'}</span>
        <span className="mode-miss">{MISSED_MEANING}</span>
        <span className="mode-more">About this data <Icon name="chevron" size={14} /></span>
      </summary>
      <div className="mode-detail">
        <p><LinkedText text={run.source || run.mode_note} /></p>
        <p>
          Test names and commands come from <ExternalLink href={ATOMIC_URL}>Atomic Red Team</ExternalLink> (MIT)
          and are shown for reference only. Rules are from <ExternalLink href={SIGMAHQ_URL}>SigmaHQ</ExternalLink>{' '}
          (<ExternalLink href={DRL_URL}>DRL 1.1</ExternalLink>, each shown with its author) plus custom rules.
        </p>
        <p>{BEST_CASE}</p>
      </div>
    </details>
  )
}
