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

// The bundled rule catalog (titles and authors) changes only with a deployment: fetched once.
let rulesPromise = null
const ruleDetails = new Map()

export const api = {
  health: () => request('/health'),
  me: () => request('/auth/me'),
  login: (username, password) => request('/auth/login', send('POST', { username, password })),
  logout: () => request('/auth/logout', { method: 'POST' }),

  overview: () => request('/overview'),
  runs: () => request('/runs'),
  run: (id) => request(`/runs/${enc(id)}`),
  coverage: (runId) => request(`/coverage${qs({ run: runId })}`),
  gaps: (params = {}) => request(`/gaps${qs(params)}`),
  execution: (id, { offset = 0, limit = 50 } = {}, signal) => (
    request(`/executions/${enc(id)}${qs({ offset, limit })}`, signal ? { signal } : {})),

  /** Map of rule id -> rule object (with author) for every bundled rule. */
  ruleCatalog() {
    if (!rulesPromise) {
      rulesPromise = request('/rules')
        .then((body) => new Map(body.rules.map((r) => [r.id, r])))
        .catch((err) => { rulesPromise = null; throw err })
    }
    return rulesPromise
  },
  /** Rules with, for a run, whether its rule set enables each one. */
  rules: (params = {}) => request(`/rules${qs(params)}`),
  /** Rule detail (YAML text included); cached for the session. */
  rule(id) {
    if (!ruleDetails.has(id)) {
      const p = request(`/rules/${enc(id)}`).catch((err) => { ruleDetails.delete(id); throw err })
      ruleDetails.set(id, p)
    }
    return ruleDetails.get(id)
  },
}
