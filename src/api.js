// Thin wrapper around the PurpleBench REST API.
//
// Authentication uses an httpOnly session cookie that the browser sends automatically with
// same-origin requests, so no token is ever handled in JavaScript. Any 401 fires a
// "purplebench:unauthorized" event and the app returns to the sign-in screen.

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`/api${path}`, { credentials: 'same-origin', ...options })
  } catch (err) {
    if (err?.name === 'AbortError') throw err
    throw new ApiError('Cannot reach the PurpleBench API.', 0)
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body.detail) {
        detail = typeof body.detail === 'string'
          ? body.detail
          : body.detail.map?.((d) => d.msg).join('; ') || JSON.stringify(body.detail)
      }
    } catch { /* not JSON */ }
    if (res.status === 401 && !path.startsWith('/auth/')) {
      window.dispatchEvent(new Event('purplebench:unauthorized'))
    }
    throw new ApiError(detail, res.status)
  }
  return res.json()
}

const send = (method, body) => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export function qs(params) {
  const sp = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    sp.append(key, value)
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

const enc = encodeURIComponent
const withSignal = (signal, options = {}) => (signal ? { ...options, signal } : options)

// The bundled rule catalog (titles and authors) changes only with a deployment: fetched once.
let rulesPromise = null
// Rule details (YAML included) that have loaded; in-flight requests stay per caller so they can be aborted.
const ruleDetails = new Map()

/** Same-origin download URLs (the session cookie goes with them). */
export const downloads = {
  navigator: (runId) => `/api/coverage/navigator.json${qs({ run: runId })}`,
  reportMd: (runId) => `/api/runs/${enc(runId)}/report.md`,
  reportHtml: (runId) => `/api/runs/${enc(runId)}/report.html`,
  campaign: (id) => `/api/campaigns/${enc(id)}/export.json`,
}

export const api = {
  health: () => request('/health'),
  me: () => request('/auth/me'),
  login: (username, password) => request('/auth/login', send('POST', { username, password })),
  logout: () => request('/auth/logout', { method: 'POST' }),

  overview: (signal) => request('/overview', withSignal(signal)),
  runs: (signal) => request('/runs', withSignal(signal)),
  run: (id, signal) => request(`/runs/${enc(id)}`, withSignal(signal)),
  coverage: (runId, signal) => request(`/coverage${qs({ run: runId })}`, withSignal(signal)),
  gaps: (params = {}, signal) => request(`/gaps${qs(params)}`, withSignal(signal)),
  patchGap: (id, body) => request(`/gaps/${enc(id)}`, send('PATCH', body)),
  library: (signal) => request('/library', withSignal(signal)),
  campaigns: (signal) => request('/campaigns', withSignal(signal)),
  campaign: (id, signal) => request(`/campaigns/${enc(id)}`, withSignal(signal)),
  createCampaign: (body) => request('/campaigns', send('POST', body)),
  /** Upload a lab run file (multipart field "file"). */
  uploadRun(file) {
    const form = new FormData()
    form.append('file', file, file.name || 'run.json')
    return request('/runs', { method: 'POST', body: form })
  },
  /**
   * One page of an execution's events. `matched` keeps only events a rule matched and `rule` only those
   * one rule matched; both filters apply on the server before paging.
   */
  execution: (id, { offset = 0, limit = 50, matched = false, rule = '' } = {}, signal) => (
    request(`/executions/${enc(id)}${qs({ offset, limit, matched: matched ? 'true' : '', rule })}`, withSignal(signal))),

  /** Map of rule id -> rule object (with author) for every bundled rule. */
  ruleCatalog() {
    if (!rulesPromise) {
      rulesPromise = request('/rules')
        .then((body) => new Map(body.rules.map((r) => [r.id, r])))
        .catch((err) => { rulesPromise = null; throw err })
    }
    return rulesPromise
  },
  /** Rules with, for a run, hits, noise and whether its rule set enables each one. */
  rules: (params = {}, signal) => request(`/rules${qs(params)}`, withSignal(signal)),
  /** Rule detail (YAML text included); kept for the session once loaded. */
  async rule(id, signal) {
    if (ruleDetails.has(id)) return ruleDetails.get(id)
    const body = await request(`/rules/${enc(id)}`, withSignal(signal))
    ruleDetails.set(id, body)
    return body
  },
}
