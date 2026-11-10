import { Link } from 'react-router-dom'
import { Icon, usePageTitle } from '../components/ui.jsx'

/** A page that ships later in this release: says what it will hold and where to look meanwhile. */
export default function Placeholder({ title, what }) {
  usePageTitle(title)
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <p className="eyebrow">Coming in this release</p>
          <h1 tabIndex={-1}>{title}</h1>
        </div>
      </header>
      <section className="card placeholder" aria-labelledby="ph-title">
        <span className="ph-icon" aria-hidden="true"><Icon name="construct" size={22} /></span>
        <div>
          <h2 id="ph-title">This page is being built</h2>
          <p>{what}</p>
          <p className="muted">
            Meanwhile, the overview and the run results already show every technique, rule and gap, with the
            rule authors and the recorded events behind each result.
          </p>
          <div className="actions">
            <Link className="btn primary" to="/">Go to the overview <Icon name="arrow" size={16} /></Link>
            <Link className="btn secondary" to="/runs">Browse the runs</Link>
          </div>
        </div>
      </section>
    </div>
  )
}
