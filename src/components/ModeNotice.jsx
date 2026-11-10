import { ATOMIC_URL, BEST_CASE, DRL_URL, MISSED_MEANING, SIGMAHQ_URL } from '../lib.js'
import { ExternalLink, Icon, LinkedText } from './ui.jsx'

/**
 * Where a result came from. Recorded mode: telemetry from a public dataset, nothing executed.
 * Lab mode: not yet run against a real lab. `full` adds the attribution and scoring caveats.
 */
export default function ModeNotice({ run, full = false }) {
  if (!run) return null
  const lab = run.mode === 'lab'
  return (
    <aside className={`mode-notice ${lab ? 'lab' : 'recorded'} ${full ? 'full' : ''}`} aria-label="Data source">
      <span className="mn-icon" aria-hidden="true"><Icon name={lab ? 'flag' : 'record'} size={20} /></span>
      <div className="mn-body">
        <p className="mn-title">
          {lab ? 'Lab mode · not yet run against a real lab' : 'Recorded mode · nothing was executed'}
        </p>
        <p className="mn-source"><LinkedText text={run.source || run.mode_note} /></p>
        {full && (
          <>
            <p>
              Test names and commands come from <ExternalLink href={ATOMIC_URL}>Atomic Red Team</ExternalLink> (MIT)
              and are shown for reference only. Rules are from <ExternalLink href={SIGMAHQ_URL}>SigmaHQ</ExternalLink>{' '}
              (<ExternalLink href={DRL_URL}>DRL 1.1</ExternalLink>, each shown with its author) plus custom rules.
            </p>
            <p className="mn-caveats">{MISSED_MEANING} {BEST_CASE}</p>
          </>
        )}
        {!full && <p className="mn-caveats">{MISSED_MEANING}</p>}
      </div>
    </aside>
  )
}
