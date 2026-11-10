// Browser smoke test for the PurpleBench demo (guest, read-only) using the installed Chrome.
//
//   1. python -m purplebench demo --serve --db <temp file>      (API on 127.0.0.1:8000)
//   2. npm run build && npm run preview                          (UI on 127.0.0.1:4173, proxies /api)
//   3. cd e2e && npm ci && node smoke.mjs [--shots ../docs/screenshots]
//
// Checks: a guest is read-only (no admin controls, writes refused), one page per area renders its key content
// with no console errors, ATT&CK v20 names are used, and rule authors are shown. --shots saves 1400 px screenshots.
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'

const base = process.env.PURPLEBENCH_URL || 'http://127.0.0.1:4173'
const shotsAt = process.argv.includes('--shots') ? process.argv[process.argv.indexOf('--shots') + 1] : null
if (shotsAt) mkdirSync(shotsAt, { recursive: true })

const failures = []
const check = (ok, what) => { if (!ok) failures.push(what); console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`) }

const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' })
const page = await (await browser.newContext({ viewport: { width: 1400, height: 900 } })).newPage()
const consoleErrors = []
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()) })
page.on('pageerror', (e) => consoleErrors.push(String(e)))

async function visit(path, name, expectText, shot) {
  consoleErrors.length = 0
  const res = await page.goto(base + path, { waitUntil: 'networkidle' })
  check(res && res.ok(), `${name}: page loads`)
  await page.locator('h1').first().waitFor({ timeout: 15000 })
  const text = await page.locator('main, body').first().innerText()
  for (const t of [].concat(expectText)) check(text.includes(t), `${name}: shows "${t}"`)
  check(!/Something went wrong/.test(text), `${name}: no error state`)
  check(consoleErrors.length === 0, `${name}: no console errors${consoleErrors.length ? ` (${consoleErrors[0]})` : ''}`)
  if (shotsAt && shot) {
    // 1400 px wide; tall pages are cut at 2400 px to keep the repository small
    const height = await page.evaluate(() => document.documentElement.scrollHeight)
    await page.screenshot({ path: `${shotsAt}/${shot}.png`, fullPage: true, clip: { x: 0, y: 0, width: 1400, height: Math.min(height, 2400) } })
  }
  return text
}

// -- guest is read-only -------------------------------------------------------------------------------
const overview = await visit('/', 'overview', ['Recorded mode'], '01-overview')
check(/Demo/.test(overview) || /read-only/i.test(overview), 'overview: marked as the demo')
const campaigns = await visit('/campaigns', 'campaigns', ['Ransomware precursors'], '05-campaigns')
check(!/New campaign/.test(campaigns), 'guest: no "New campaign" control')
await visit('/campaigns/new', 'guest new campaign', ['Only the admin can create campaigns'])
const write = await page.request.post(`${base}/api/campaigns`, { data: { name: 'smoke', techniques: ['T1059.001'] } })
check(write.status() === 403, `guest: POST /api/campaigns refused (${write.status()})`)
check((await page.request.post(`${base}/api/auth/login`, { data: { username: 'admin', password: 'x' } })).status() === 503,
  'guest: nobody can sign in when no admin is configured')

// -- one page per area --------------------------------------------------------------------------------
await visit('/runs', 'runs', ['Test runs'], '02-runs')
const runLink = await page.locator('a[href^="/runs/"]').first().getAttribute('href')
await visit(runLink, 'run detail', ['Recorded mode'], '03-run-detail')
const execLink = await page.locator('a[href^="/executions/"]').first().getAttribute('href')
await visit(execLink, 'execution detail', ['Matching events'], '04-execution')
const cov = await visit('/coverage', 'coverage', ['Stealth', 'Defense Impairment'], '06-coverage')
const columns = await page.locator('h3').allInnerTexts()
check(!columns.some((t) => /Defense Evasion/.test(t)), 'coverage: no Defense Evasion column (ATT&CK v20 split it)')
const rules = await visit('/rules', 'rules', ['Florian Roth'], '07-rules')
check(/Andrew T\. Price II/.test(rules), 'rules: custom rule author shown')
const ruleLink = await page.locator('a[href^="/rules/"]').first().getAttribute('href')
await visit(ruleLink, 'rule detail', ['Detection Rule License'], '08-rule')
await visit('/gaps', 'gaps', ['Detection gaps'], '09-gaps')
await visit('/reports', 'reports', ['report'], '10-reports')
const gone = await visit('/no-such-page', 'unknown route', ['Page not found'])

await browser.close()
if (failures.length) {
  console.error(`\n${failures.length} check(s) failed:\n- ${failures.join('\n- ')}`)
  process.exit(1)
}
console.log('\nSmoke test passed.')
