import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  TACTICS_V20, campaignFileName, campaignProblems, diffCoverage, filterRules, gapDirty, gapPatch, groupLibrary,
  hitsByRun, matrixColumns, previousRun, runnerCommands, scoreDelta, slugify, statusCounts, techCompare,
  uploadMessage, uploadProblem, validateLayer,
} from './model.js'

test('the v20 matrix has 15 tactics with Stealth and Defense Impairment and no Defense Evasion', () => {
  assert.equal(TACTICS_V20.length, 15)
  const slugs = TACTICS_V20.map((t) => t.slug)
  assert.ok(slugs.includes('stealth') && slugs.includes('defense-impairment'))
  assert.ok(!slugs.includes('defense-evasion'))
  assert.deepEqual(TACTICS_V20.find((t) => t.slug === 'defense-impairment'), { slug: 'defense-impairment', id: 'TA0112', name: 'Defense Impairment' })
  assert.equal(slugs.indexOf('stealth') + 1, slugs.indexOf('defense-impairment'))
})

const COV = [
  { technique: 'T1053.005', name: 'Scheduled Task', tactics: ['execution', 'persistence', 'privilege-escalation'], status: 'detected' },
  { technique: 'T1003.002', name: 'SAM', tactics: ['credential-access'], status: 'missed' },
  { technique: 'T1003.001', name: 'LSASS', tactics: ['credential-access'], status: 'detected' },
  { technique: 'T1558.003', name: 'Kerberoasting', tactics: ['credential-access'], status: 'untested' },
  { technique: 'T1685', name: 'Disable or Modify Tools', tactics: ['defense-impairment'], status: 'telemetry_gap' },
  { technique: 'T9999', name: 'Odd', tactics: ['made-up'], status: 'did_not_run' },
]

test('matrix columns follow v20 order, repeat multi-tactic techniques and count tested', () => {
  const { columns, empty } = matrixColumns(COV)
  assert.deepEqual(columns.map((c) => c.slug),
    ['execution', 'persistence', 'privilege-escalation', 'defense-impairment', 'credential-access', 'made-up'])
  const cred = columns.find((c) => c.slug === 'credential-access')
  assert.deepEqual(cred.techniques.map((t) => t.technique), ['T1003.001', 'T1003.002', 'T1558.003'])
  assert.equal(cred.tested, 2) // untested is not tested
  assert.equal(cred.detected, 1)
  assert.equal(columns.filter((c) => c.techniques.some((t) => t.technique === 'T1053.005')).length, 3)
  assert.equal(empty.length, 15 - 5)
  assert.ok(empty.some((t) => t.slug === 'stealth'))
  assert.deepEqual(matrixColumns([]).columns, [])
})

test('technique ids sort numerically', () => {
  assert.deepEqual(['T1105', 'T1003.002', 'T1003', 'T1003.001', 'T1021.002'].sort(techCompare),
    ['T1003', 'T1003.001', 'T1003.002', 'T1021.002', 'T1105'])
})

test('status counts include zeros', () => {
  const c = statusCounts(COV)
  assert.equal(c.detected, 2)
  assert.equal(c.partial, 0)
  assert.equal(c.untested, 1)
})

const RUNS = [
  { id: 1, campaign_id: 1, started_at: '2026-09-28T09:00:00Z' },
  { id: 2, campaign_id: 2, started_at: '2026-10-12T09:00:00Z' },
  { id: 3, campaign_id: 1, started_at: '2026-10-26T09:00:00Z' },
  { id: 4, campaign_id: 2, started_at: '2026-11-09T09:00:00Z' },
  { id: 5, campaign_id: 3, started_at: '2026-11-10T09:00:00Z' },
]

test('previous run: same campaign first, else any earlier run, else none', () => {
  assert.deepEqual(previousRun(RUNS, 4), { run: RUNS[1], sameCampaign: true })
  assert.deepEqual(previousRun(RUNS, 3), { run: RUNS[0], sameCampaign: true })
  assert.deepEqual(previousRun(RUNS, 2), { run: RUNS[0], sameCampaign: false })
  assert.deepEqual(previousRun(RUNS, 5), { run: RUNS[3], sameCampaign: false })
  assert.equal(previousRun(RUNS, 1), null)
  assert.equal(previousRun(RUNS, 42), null)
  // Order is by start time, not by id.
  const odd = [{ id: 9, campaign_id: 1, started_at: '2026-01-02T00:00:00Z' }, { id: 3, campaign_id: 1, started_at: '2026-01-05T00:00:00Z' }]
  assert.equal(previousRun(odd, 3).run.id, 9)
  assert.equal(previousRun(odd, 9), null)
})

test('coverage diff: improved, regressed, changed, added and removed', () => {
  const prev = [
    { technique: 'T1', name: 'a', status: 'missed' },
    { technique: 'T2', name: 'b', status: 'detected' },
    { technique: 'T3', name: 'c', status: 'missed' },
    { technique: 'T4', name: 'd', status: 'partial' },
    { technique: 'T5', name: 'e', status: 'detected' },
    { technique: 'T7', name: 'g', status: 'untested' },
  ]
  const cur = [
    { technique: 'T1', name: 'a', status: 'detected' },
    { technique: 'T2', name: 'b', status: 'partial' },
    { technique: 'T3', name: 'c', status: 'telemetry_gap' },
    { technique: 'T4', name: 'd', status: 'partial' },
    { technique: 'T6', name: 'f', status: 'missed' },
    { technique: 'T7', name: 'g', status: 'detected' },
  ]
  const d = diffCoverage(prev, cur)
  assert.deepEqual(d.changes.map((c) => [c.id, c.direction]),
    [['T1', 'improved'], ['T2', 'regressed'], ['T3', 'changed'], ['T5', 'removed'], ['T6', 'added'], ['T7', 'changed']])
  assert.deepEqual([d.improved, d.regressed, d.changed, d.added, d.removed], [1, 1, 2, 1, 1])
  assert.deepEqual(d.changes[0], { id: 'T1', name: 'a', before: 'missed', after: 'detected', direction: 'improved' })
  assert.equal(diffCoverage(cur, cur).changes.length, 0)
})

test('score delta wording', () => {
  assert.equal(scoreDelta(71.4, 85.7), '+14.3 points')
  assert.equal(scoreDelta(85.7, 78.6), '−7.1 points')
  assert.equal(scoreDelta(50, 50), 'no change')
  assert.equal(scoreDelta(null, 50), null)
})

const RULES = [
  { id: 'a1', title: 'LSASS Dump', author: 'Florian Roth', source: 'sigmahq', status: 'ok', noisy: false, in_ruleset: true, executions_fired: 2, techniques: ['T1003.001'] },
  { id: 'b2', title: 'Base64 PowerShell', author: 'frack113', source: 'sigmahq', status: 'ok', noisy: true, in_ruleset: true, executions_fired: 1, techniques: ['T1059.001'] },
  { id: 'c3', title: '7-Zip Archive', author: 'Andrew T. Price II', source: 'custom', status: 'ok', noisy: false, in_ruleset: false, executions_fired: 0, techniques: ['T1560.001'] },
  { id: 'd4', title: 'Count Rule', author: 'x', source: 'sigmahq', status: 'unsupported', reason: 'aggregation', noisy: false, in_ruleset: false, executions_fired: 0, techniques: [] },
]

test('rule filters', () => {
  const ids = (f) => filterRules(RULES, f).map((r) => r.id)
  assert.deepEqual(ids({}), ['a1', 'b2', 'c3', 'd4'])
  assert.deepEqual(ids({ source: 'custom' }), ['c3'])
  assert.deepEqual(ids({ status: 'unsupported' }), ['d4'])
  assert.deepEqual(ids({ noise: 'noisy' }), ['b2'])
  assert.deepEqual(ids({ noise: 'quiet', set: 'in' }), ['a1'])
  assert.deepEqual(ids({ fired: 'yes' }), ['a1', 'b2'])
  assert.deepEqual(ids({ fired: 'no', source: 'sigmahq' }), ['d4'])
  assert.deepEqual(ids({ q: 'price' }), ['c3'])
  assert.deepEqual(ids({ q: 't1003' }), ['a1'])
  assert.deepEqual(ids({ q: '  ' }), ['a1', 'b2', 'c3', 'd4'])
})

test('rule hits group by run', () => {
  const g = hitsByRun([{ run_id: 3, execution_id: 30 }, { run_id: 1, execution_id: 2 }, { run_id: 3, execution_id: 31 }])
  assert.deepEqual(g.map((x) => [x.runId, x.hits.map((h) => h.execution_id)]), [[1, [2]], [3, [30, 31]]])
})

test('gap edits: dirty only when something changed; patch carries only the changes', () => {
  const gap = { status: 'open', notes: 'old' }
  assert.equal(gapDirty(gap, { status: 'open', notes: 'old ' }), false)
  assert.equal(gapDirty(gap, { status: 'accepted', notes: 'old' }), true)
  assert.equal(gapDirty({ status: 'open', notes: '' }, { status: 'open', notes: 'x' }), true)
  assert.deepEqual(gapPatch(gap, { status: 'accepted', notes: 'old' }), { status: 'accepted' })
  assert.deepEqual(gapPatch(gap, { status: 'open', notes: ' new ' }), { notes: 'new' })
  assert.deepEqual(gapPatch(gap, { status: 'closed', notes: '' }), { status: 'closed', notes: '' })
})

test('campaign file names match the API and runner commands use them', () => {
  assert.equal(slugify('Initial access to credential theft'), 'initial-access-to-credential-theft')
  assert.equal(slugify('  ***  '), 'campaign')
  assert.equal(slugify('A'.repeat(39) + ' b c'), `${'a'.repeat(39)}`)
  assert.equal(campaignFileName({ id: 3, name: 'Lab smoke test!' }), 'purplebench-campaign-3-lab-smoke-test.json')
  const cmd = runnerCommands({ id: 3, name: 'Lab smoke test' })
  assert.equal(cmd.rehearse, '.\\Invoke-PurpleBenchRun.ps1 -Target LAB-WS01 -Campaign .\\purplebench-campaign-3-lab-smoke-test.json -WhatIf')
  assert.match(cmd.run, /-Credential \(Get-Credential\)$/)
  assert.ok(!/WhatIf/.test(cmd.run))
})

test('campaign form problems', () => {
  assert.deepEqual(campaignProblems({ name: '', techniques: [] }), ['Give the campaign a name.', 'Pick at least one technique.'])
  assert.deepEqual(campaignProblems({ name: 'X', techniques: ['T1082'] }), [])
  assert.deepEqual(campaignProblems({ name: 'Dup', techniques: ['T1082'] }, ['Dup']), ['A campaign with this name already exists.'])
  assert.equal(campaignProblems({ name: 'x'.repeat(201), techniques: ['T1'] }).length, 1)
})

test('library groups by first tactic in matrix order and filters by text', () => {
  const lib = [
    { id: 'T1082', name: 'System Information Discovery', tactics: ['discovery'], atomic_test: { name: 'systeminfo' } },
    { id: 'T1053.005', name: 'Scheduled Task', tactics: ['execution', 'persistence'] },
    { id: 'T1047', name: 'WMI', tactics: ['execution'] },
  ]
  const g = groupLibrary(lib)
  assert.deepEqual(g.map((x) => [x.tactic, x.techniques.map((t) => t.id)]), [['execution', ['T1047', 'T1053.005']], ['discovery', ['T1082']]])
  assert.deepEqual(groupLibrary(lib, 'persistence').map((x) => x.techniques.map((t) => t.id)), [['T1053.005']])
  assert.deepEqual(groupLibrary(lib, 'SYSTEMINFO')[0].techniques[0].id, 'T1082')
  assert.deepEqual(groupLibrary(lib, 'nothing'), [])
})

test('upload messages and local checks', () => {
  assert.match(uploadMessage({ status: 413, message: 'Run file too large (max 4 MB)' }, 4), /too large \(the limit is 4 MB\)/)
  assert.match(uploadMessage({ status: 400, message: 'version must be 2' }), /refused: version must be 2/)
  assert.match(uploadMessage({ status: 403, message: 'x' }), /Only an admin/)
  assert.match(uploadMessage({ status: 415, message: 'x' }), /JSON run file/)
  assert.equal(uploadProblem(null), 'Choose a run file first.')
  assert.match(uploadProblem({ name: 'run.txt', size: 5 }), /\.json/)
  assert.equal(uploadProblem({ name: 'run.json', size: 0 }), 'The file is empty.')
  assert.match(uploadProblem({ name: 'run.json', size: 5 * 1048576 }, 4), /limit is 4 MB/)
  assert.equal(uploadProblem({ name: 'run.JSON', size: 100 }, 4), null)
})

test('Navigator layer validation matches the layer 4.5 fields', () => {
  const good = {
    name: 'PurpleBench run 4', domain: 'enterprise-attack', description: 'x',
    versions: { attack: '20', navigator: '5.3.2', layer: '4.5' },
    techniques: [{ techniqueID: 'T1003.001', color: '#3b82f6', comment: 'Detected', enabled: true, score: 100,
      metadata: [{ name: 'status', value: 'detected' }] }],
    legendItems: [{ label: 'Detected', color: '#3b82f6' }],
    gradient: { colors: ['#ef4444', '#3b82f6'], minValue: 0, maxValue: 100 },
  }
  assert.deepEqual(validateLayer(good), [])
  assert.deepEqual(validateLayer(null), ['layer is not an object'])
  assert.ok(validateLayer({ ...good, versions: { ...good.versions, layer: '4.4' } }).some((e) => /4\.5/.test(e)))
  assert.ok(validateLayer({ ...good, techniques: [{ techniqueID: '1003' }] }).some((e) => /techniqueID/.test(e)))
  assert.ok(validateLayer({ ...good, techniques: [good.techniques[0], good.techniques[0]] }).some((e) => /duplicate/.test(e)))
  assert.ok(validateLayer({ ...good, techniques: [{ ...good.techniques[0], color: 'blue' }] }).some((e) => /color/.test(e)))
  assert.ok(validateLayer({ ...good, domain: 'x' }).some((e) => /domain/.test(e)))
  assert.ok(validateLayer({ ...good, gradient: { colors: [] } }).some((e) => /gradient/.test(e)))
})
