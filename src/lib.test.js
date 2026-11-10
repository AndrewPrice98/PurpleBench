import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  STATUS, STATUS_ORDER, closingRules, countEntries, filterExecutions, firstLink, formatClock, formatDate,
  formatDateTime, formatOffset, formatScore, formatTtd, gaugeArc, linePath, linePoints, pickStartHere, scale,
  splitLinks, splitRuleRefs, tacticLabel, tacticsOf, timelineModel, tsMs, eventName, summaryField, attackUrl,
} from './lib.js'

test('every status has a label, glyph, tone and help text', () => {
  for (const s of STATUS_ORDER) {
    assert.ok(STATUS[s].label && STATUS[s].glyph && STATUS[s].tone && STATUS[s].help, s)
  }
  assert.match(STATUS.missed.help, /no rule in this rule set fired on this telemetry/i)
})

test('tactic labels', () => {
  assert.equal(tacticLabel('credential-access'), 'Credential Access')
  assert.equal(tacticLabel('command-and-control'), 'Command and Control')
  assert.equal(tacticLabel('stealth'), 'Stealth')
  assert.equal(tacticLabel('some-new-tactic'), 'Some New Tactic')
  assert.equal(tacticLabel(''), '')
})

test('timestamps with microseconds parse to milliseconds', () => {
  assert.equal(tsMs('2020-11-03T15:52:59.300564Z'), Date.UTC(2020, 10, 3, 15, 52, 59, 300))
  assert.equal(tsMs('2020-11-03T15:52:59Z'), Date.UTC(2020, 10, 3, 15, 52, 59))
  assert.equal(tsMs('2020-11-03T15:52:59.3'), Date.UTC(2020, 10, 3, 15, 52, 59, 300))
  assert.ok(Number.isNaN(tsMs('yesterday')))
  assert.ok(Number.isNaN(tsMs(null)))
})

test('formatting', () => {
  assert.equal(formatTtd(null), '—')
  assert.equal(formatTtd(0), '0 ms')
  assert.equal(formatTtd(14), '14 ms')
  assert.equal(formatTtd(2500), '2.5 s')
  assert.equal(formatTtd(125000), '2 min 5 s')
  assert.equal(formatTtd(120000), '2 min')
  assert.equal(formatOffset(0), '0 s')
  assert.equal(formatOffset(0.006), '+0.006 s')
  assert.equal(formatOffset(-0.67), '−0.67 s')
  assert.equal(formatOffset(14.21), '+14.2 s')
  assert.equal(formatDate('2026-11-09T09:00:00Z'), 'Nov 9, 2026')
  assert.equal(formatDateTime('2020-11-03T15:52:59.300564Z'), '2020-11-03 15:52:59 UTC')
  assert.equal(formatClock('2020-11-03T15:52:59.300564Z'), '15:52:59.300')
  assert.equal(formatScore(85.7), '85.7%')
  assert.equal(formatScore(100), '100%')
  assert.equal(formatScore(null), '—')
})

test('links are split out of text without trailing punctuation', () => {
  const segs = splitLinks('Sysmon from Splunk attack_data; https://github.com/splunk/attack_data. Nothing ran.')
  assert.deepEqual(segs, [
    { text: 'Sysmon from Splunk attack_data; ' },
    { text: 'https://github.com/splunk/attack_data', href: 'https://github.com/splunk/attack_data' },
    { text: '. Nothing ran.' },
  ])
  assert.equal(firstLink('see javascript:alert(1) and ftp://x'), null)
  assert.deepEqual(splitLinks(''), [])
})

const RULES = new Map([
  ['5afee48e-67dd-4e03-a783-f74259dcf998', { id: '5afee48e-67dd-4e03-a783-f74259dcf998', title: 'Potential LSASS Process Dump Via Procdump', author: 'Florian Roth (Nextron Systems)' }],
  ['5ef9853e-4d0e-4a70-846f-a9ca37d876da', { id: '5ef9853e-4d0e-4a70-846f-a9ca37d876da', title: 'Potential Credential Dumping Activity Via LSASS', author: 'Samir Bousseaden, Michael Haag' }],
  ['aaaaaaaa-0000-0000-0000-000000000001', { id: 'aaaaaaaa-0000-0000-0000-000000000001', title: '7-Zip Archive Created With Split Volumes Or Maximum Compression', author: 'Andrew T. Price II' }],
])

test('rule references in reasons become rule segments (title [uuid] and bare titles)', () => {
  const text = 'detected by Potential LSASS Process Dump Via Procdump [5afee48e-67dd-4e03-a783-f74259dcf998]; '
    + 'noisy rule(s) for this technique earned no credit: Potential Credential Dumping Activity Via LSASS '
    + '[5ef9853e-4d0e-4a70-846f-a9ca37d876da] (2 baseline hits)'
  const segs = splitRuleRefs(text, RULES)
  assert.deepEqual(segs.map((s) => (s.rule ? `<${s.rule.author}>` : s.text)), [
    'detected by ', '<Florian Roth (Nextron Systems)>', '; noisy rule(s) for this technique earned no credit: ',
    '<Samir Bousseaden, Michael Haag>', ' (2 baseline hits)',
  ])
  const bare = splitRuleRefs('Closed in run 4 (rule set v4): 7-Zip Archive Created With Split Volumes Or Maximum Compression.', RULES)
  assert.deepEqual(bare.map((s) => (s.rule ? `<${s.rule.id}>` : s.text)), [
    'Closed in run 4 (rule set v4): ', '<aaaaaaaa-0000-0000-0000-000000000001>', '.',
  ])
  const unknown = splitRuleRefs('fired: Mystery [bbbbbbbb-0000-0000-0000-000000000002]', RULES)
  assert.equal(unknown[1].rule.id, 'bbbbbbbb-0000-0000-0000-000000000002')
  assert.deepEqual(splitRuleRefs('', RULES), [])
  assert.deepEqual(splitRuleRefs('no rules here', {}), [{ text: 'no rules here' }])
})

const R7Z = { id: 'r7z', title: '7-Zip Archive Created With Split Volumes Or Maximum Compression', author: 'Andrew T. Price II' }
const RB64 = { id: 'rb64', title: 'Suspicious Execution of Powershell with Base64', author: 'frack113' }
const RSYS = { id: 'rsys', title: 'Suspicious Execution of Systeminfo', author: 'frack113' }
const GAPS = [
  { id: 1, run_id: 1, technique_id: 'T1059.001', kind: 'missed', status: 'closed', closed_in_run: 3, rules: [], notes: 'Missed. Closed in run 3 (rule set v3): X.' },
  { id: 11, run_id: 2, technique_id: 'T1082', kind: 'partial', status: 'closed', closed_in_run: 4, rules: [RB64, RSYS], notes: `Partial: noisy rule: ${RB64.title} (5 baseline hits). Closed in run 4 (rule set v4): ${RSYS.title}.` },
  { id: 13, run_id: 2, technique_id: 'T1560.001', kind: 'missed', status: 'closed', closed_in_run: 4, rules: [R7Z], notes: `Missed. Closed in run 4 (rule set v4): ${R7Z.title}.` },
  { id: 19, run_id: 4, technique_id: 'T1021.002', kind: 'partial', status: 'open', closed_in_run: null, rules: [], notes: '' },
]

test('closing rules are the ones named after "Closed in run"', () => {
  assert.deepEqual(closingRules(GAPS[1]).map((r) => r.id), ['rsys'])
  assert.deepEqual(closingRules({ rules: [RB64, RSYS], notes: 'no marker' }).map((r) => r.id), ['rsys'])
  assert.deepEqual(closingRules({ rules: [], notes: '' }), [])
})

test('start here: a missed gap closed in the latest run beats partial and older closes', () => {
  const pick = pickStartHere(GAPS, 4)
  assert.equal(pick.gap.id, 13)
  assert.equal(pick.fromRun, 2)
  assert.equal(pick.toRun, 4)
  assert.deepEqual(pick.rules.map((r) => r.id), ['r7z'])
  // Nothing closed in the latest run: the biggest earlier close.
  assert.equal(pickStartHere(GAPS, 5).gap.id, 13)
  assert.equal(pickStartHere(GAPS.filter((g) => g.id !== 13), 5).gap.id, 1)
  assert.equal(pickStartHere([GAPS[3]], 4), null)
  assert.equal(pickStartHere([], 4), null)
})

const EXECS = [
  { id: 1, status: 'missed', technique: { tactics: ['execution'] } },
  { id: 2, status: 'detected', technique: { tactics: ['execution', 'persistence'] } },
  { id: 3, status: 'detected', technique: { tactics: ['stealth'] } },
]

test('results filters by status and tactic', () => {
  assert.deepEqual(filterExecutions(EXECS, { status: 'detected' }).map((e) => e.id), [2, 3])
  assert.deepEqual(filterExecutions(EXECS, { tactic: 'persistence' }).map((e) => e.id), [2])
  assert.deepEqual(filterExecutions(EXECS, { status: 'detected', tactic: 'execution' }).map((e) => e.id), [2])
  assert.deepEqual(filterExecutions(EXECS, {}).map((e) => e.id), [1, 2, 3])
  assert.deepEqual(tacticsOf(EXECS), ['execution', 'persistence', 'stealth'])
  assert.deepEqual(countEntries({ detected: 2, partial: 0, missed: 1 }), [['detected', 2], ['missed', 1]])
})

test('line chart points and path skip missing values', () => {
  const pts = linePoints([0, 50, null, 100], { width: 300, height: 120, padX: 10, padTop: 10, padBottom: 10 })
  assert.deepEqual(pts.map((p) => p.x.toFixed(2)), ['10.00', '103.33', '196.67', '290.00'])
  assert.deepEqual(pts.map((p) => p.y), [110, 60, null, 10])
  assert.equal(linePath(pts), 'M10.0 110.0L103.3 60.0M290.0 10.0')
  assert.equal(linePoints([40], { width: 200, height: 100 })[0].x, 100)
})

test('gauge arc ends where the fraction says', () => {
  assert.equal(gaugeArc(100, 100, 80, 0), 'M20.00 100.00 A80 80 0 0 1 20.00 100.00')
  assert.equal(gaugeArc(100, 100, 80, 1), 'M20.00 100.00 A80 80 0 0 1 180.00 100.00')
  assert.equal(gaugeArc(100, 100, 80, 0.5), 'M20.00 100.00 A80 80 0 0 1 100.00 20.00')
  assert.equal(gaugeArc(100, 100, 80, 2), gaugeArc(100, 100, 80, 1))
})

test('TTD timeline: offsets from the start, early (skew) marks, first non-noisy match', () => {
  const m = timelineModel({
    startedAt: '2020-11-03T15:52:59.300564Z',
    endedAt: '2020-11-03T15:54:59.300564Z',
    hits: [
      { rule: { id: 'a', title: 'A' }, first_ts: '2020-11-03T15:52:59.300564Z', noisy: false, relation: 'exact' },
      { rule: { id: 'b', title: 'B' }, first_ts: '2020-11-03T15:52:58.630989Z', noisy: true, relation: 'exact' },
      { rule: { id: 'c', title: 'C' }, first_ts: 'garbage', noisy: false },
    ],
  })
  assert.deepEqual(m.markers.map((x) => [x.id, x.offset, x.early]), [['b', -0.67, true], ['a', 0, false]])
  assert.equal(m.first.id, 'a')
  assert.equal(m.windowSeconds, 120)
  assert.deepEqual(m.domain, [-5, 10])
  assert.equal(timelineModel({ startedAt: null }), null)
  const late = timelineModel({ startedAt: '2020-01-01T00:00:00Z', hits: [{ rule: { id: 'x' }, first_ts: '2020-01-01T00:00:40Z' }] })
  assert.ok(late.domain[1] > 40)
  assert.equal(late.windowSeconds, null)
  assert.equal(scale(0, [-5, 10], [0, 300]), 100)
})

test('event names, summary fields and ATT&CK links', () => {
  assert.equal(eventName('Microsoft-Windows-Sysmon/Operational', 10), 'Sysmon 10 · Process access')
  assert.equal(eventName('Security', 4688), 'Security 4688 · Process creation')
  assert.equal(eventName('System', 7045), 'System 7045 · Service installed')
  assert.equal(eventName('Application', 1000), 'Application 1000')
  assert.deepEqual(summaryField({ UtcTime: 'x', Image: 'a.exe', CommandLine: 'a.exe -x' }), ['CommandLine', 'a.exe -x'])
  assert.deepEqual(summaryField({ UtcTime: 'x', Foo: 'bar' }), ['Foo', 'bar'])
  assert.equal(summaryField({}), null)
  assert.equal(attackUrl('T1003.001'), 'https://attack.mitre.org/techniques/T1003/001/')
  assert.equal(attackUrl('T1105'), 'https://attack.mitre.org/techniques/T1105/')
  assert.equal(attackUrl('javascript:alert(1)'), null)
})
