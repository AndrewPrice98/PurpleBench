import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { BrowserRouter, NavLink, Route, Routes, useLocation } from 'react-router-dom'
import { api } from './api.js'
import { ATOMIC_URL, ATTACK_DATA_URL, DRL_URL, GITHUB_URL, SIGMAHQ_URL, THIRD_PARTY_URL } from './lib.js'
import {
  BrandMark, Empty, ErrorState, ExternalLink, Icon, Loading, SessionContext, useSession,
} from './components/ui.jsx'
import Overview from './pages/Overview.jsx'
import Runs from './pages/Runs.jsx'
import RunDetail from './pages/RunDetail.jsx'
import ExecutionDetail from './pages/ExecutionDetail.jsx'
import Placeholder from './pages/Placeholder.jsx'
import Login from './pages/Login.jsx'

const NAV = [
  ['/', 'Overview'],
  ['/campaigns', 'Campaigns'],
  ['/runs', 'Runs'],
  ['/coverage', 'Coverage'],
  ['/rules', 'Rules'],
  ['/gaps', 'Gaps'],
  ['/reports', 'Reports'],
]

function Brand() {
  return (
    <NavLink to="/" className="brand" aria-label="PurpleBench, overview">
      <BrandMark size={28} />
      <span className="brand-text">
        <span className="brand-name">PurpleBench</span>
        <span className="brand-sub">Detection validation</span>
      </span>
    </NavLink>
  )
}

function AccountArea({ onLogout, onSignIn }) {
  const { user, guest, demo, authConfigured } = useSession()
  if (guest) {
    return (
      <div className="account">
        <span className="badge demo" title="Hosted demo with recorded-mode runs. Browsing is read-only.">
          <Icon name="lock" size={13} /> Demo · read-only
        </span>
        {authConfigured && (
          <button type="button" className="btn ghost small" onClick={onSignIn}>Sign in</button>
        )}
      </div>
    )
  }
  return (
    <div className="account">
      {demo && <span className="badge demo" title="Hosted demo with recorded-mode runs.">Demo</span>}
      <span className="account-user" title="Signed in">{user}</span>
      <button type="button" className="btn ghost small" onClick={onLogout}>Sign out</button>
    </div>
  )
}

/** Move focus to the page heading after navigation so screen readers announce the new page. */
function useFocusOnNavigate(mainRef) {
  const { pathname } = useLocation()
  const previous = useRef(pathname)
  useEffect(() => {
    if (previous.current === pathname) return undefined
    previous.current = pathname
    window.scrollTo(0, 0)
    let frame = 0
    const started = performance.now()
    const tryFocus = () => {
      const heading = mainRef.current?.querySelector('h1')
      if (heading) heading.focus({ preventScroll: true })
      else if (performance.now() - started < 3000) frame = requestAnimationFrame(tryFocus)
    }
    frame = requestAnimationFrame(tryFocus)
    return () => cancelAnimationFrame(frame)
  }, [pathname, mainRef])
}

function Footer() {
  const { version } = useSession()
  return (
    <footer className="footer">
      <div className="footer-inner">
        <p className="attribution">
          Built on{' '}
          <ExternalLink href={ATOMIC_URL}>Atomic Red Team</ExternalLink> test metadata (MIT),{' '}
          recorded telemetry from <ExternalLink href={ATTACK_DATA_URL}>Splunk attack_data</ExternalLink> (Apache-2.0) and{' '}
          <ExternalLink href={SIGMAHQ_URL}>SigmaHQ</ExternalLink> rules (
          <ExternalLink href={DRL_URL}>Detection Rule License 1.1</ExternalLink>). Rule authors are named wherever a
          rule appears. ATT&amp;CK® is a trademark of The MITRE Corporation.{' '}
          <ExternalLink href={THIRD_PARTY_URL}>Sources and licences</ExternalLink>
        </p>
        <p className="footer-meta">
          PurpleBench v{version} · &quot;Missed&quot; means no rule in this rule set fired on this telemetry ·{' '}
          <ExternalLink href={GITHUB_URL}>Source on GitHub</ExternalLink>
        </p>
      </div>
    </footer>
  )
}

const PLACEHOLDERS = {
  campaigns: ['Campaigns', 'The technique plans behind each run, their run history, and the campaign file the lab runner reads.'],
  coverage: ['Coverage', 'An ATT&CK-matrix heatmap of detected, partial and missed techniques per run, the change since the previous run, and the ATT&CK Navigator layer download.'],
  rules: ['Rules', 'Every bundled Sigma rule with its author, licence, support status, hits and baseline noise, and the YAML it was evaluated from.'],
  gaps: ['Gaps', 'Every missed, partial and telemetry-gap result with the telemetry or rule idea that would close it.'],
  reports: ['Reports', 'Printable purple-team exercise reports for each run, in HTML and Markdown.'],
}

function Shell({ onLogout, onSignIn }) {
  const mainRef = useRef(null)
  useFocusOnNavigate(mainRef)
  return (
    <div className="app">
      <a className="skip-link" href="#main">Skip to content</a>
      <header className="topbar">
        <div className="topbar-inner">
          <Brand />
          <div className="topbar-right">
            <a className="gh-link" href={GITHUB_URL} target="_blank" rel="noreferrer">
              <Icon name="github" size={18} /><span className="gh-text">GitHub</span>
              <span className="sr-only"> (opens in a new tab)</span>
            </a>
            <AccountArea onLogout={onLogout} onSignIn={onSignIn} />
          </div>
        </div>
        <nav className="nav" aria-label="Main">
          <ul>
            {NAV.map(([to, label]) => (
              <li key={to}><NavLink to={to} end={to === '/'}>{label}</NavLink></li>
            ))}
          </ul>
        </nav>
      </header>
      <main id="main" className="main" ref={mainRef}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/runs" element={<Runs />} />
          <Route path="/runs/:runId" element={<RunDetail />} />
          <Route path="/executions/:executionId" element={<ExecutionDetail />} />
          {Object.entries(PLACEHOLDERS).map(([path, [title, what]]) => (
            <Route key={path} path={`/${path}/*`} element={<Placeholder title={title} what={what} />} />
          ))}
          <Route path="*" element={<Empty><h1 tabIndex={-1} className="h-inline">Page not found.</h1></Empty>} />
        </Routes>
      </main>
      <Footer />
    </div>
  )
}

function App() {
  // checking -> (anon | user); 'unconfigured' when the server has no admin and no guest access
  const [state, setState] = useState({ phase: 'checking' })

  const check = useCallback(async () => {
    try {
      const health = await api.health()
      const base = { version: health.version, demo: health.demo, authConfigured: health.auth_configured }
      if (!health.guest && !health.auth_configured) return setState({ phase: 'unconfigured' })
      let me
      try {
        me = await api.me()
      } catch (err) {
        if (err.status === 401) return setState({ phase: 'anon', ...base })
        throw err
      }
      return setState({ phase: 'user', user: me.username, guest: me.guest, ...base })
    } catch (error) {
      return setState({ phase: 'error', error })
    }
  }, [])

  useEffect(() => { check() }, [check])

  // Any API call that comes back 401 (session expired) returns to the sign-in screen.
  useEffect(() => {
    const expire = () => setState((s) => (s.phase === 'user'
      ? { ...s, phase: 'anon', notice: 'Your session has expired. Sign in again.' }
      : s))
    window.addEventListener('purplebench:unauthorized', expire)
    return () => window.removeEventListener('purplebench:unauthorized', expire)
  }, [])

  const session = useMemo(() => (state.phase === 'user' ? {
    user: state.user, guest: state.guest, demo: state.demo, version: state.version,
    authConfigured: state.authConfigured,
  } : null), [state])

  async function logout() {
    try { await api.logout() } catch { /* clearing local state is enough */ }
    // In demo mode this lands back on the guest view; otherwise on the sign-in page.
    await check()
  }

  if (state.phase === 'checking') return <div className="center-wrap"><Loading label="Connecting…" /></div>
  if (state.phase === 'error') {
    return <div className="center-wrap"><ErrorState error={state.error} onRetry={check} /></div>
  }
  if (state.phase === 'unconfigured') {
    return (
      <div className="center-wrap">
        <div className="state error" role="alert">
          No admin account is configured on the server. Run{' '}
          <code>python -m purplebench create-admin</code> (or set the PURPLEBENCH_* environment variables on
          your host) and restart the API.
        </div>
      </div>
    )
  }
  if (state.phase === 'anon') {
    return (
      <Login notice={state.notice} onLogin={check}
        onCancel={state.canCancel ? () => setState((s) => ({ ...s, phase: 'user', canCancel: false })) : undefined} />
    )
  }
  return (
    <SessionContext.Provider value={session}>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Shell onLogout={logout}
          onSignIn={() => setState((s) => ({ ...s, phase: 'anon', canCancel: true, notice: undefined }))} />
      </BrowserRouter>
    </SessionContext.Provider>
  )
}

export default App
