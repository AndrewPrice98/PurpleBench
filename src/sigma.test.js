import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  clampSegments, highlightPlan, highlightSegments, negatedIdentifiers, parseDetection, unquote, valueNeedles,
} from './sigma.js'

const PROCDUMP = `title: Potential LSASS Process Dump Via Procdump
id: 5afee48e-67dd-4e03-a783-f74259dcf998
logsource:
    category: process_creation
    product: windows
detection:
    selection_flags:
        CommandLine|contains|windash:
            - ' -ma '
            - ' -mm ' # Mini dump
    selection_process:
        CommandLine|contains:
            - ' ls' # Short for lsass
            - ' keyiso'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
`

test('parses selections, modifiers, list values and inline comments', () => {
  const det = parseDetection(PROCDUMP)
  assert.equal(det.condition, 'all of selection_*')
  assert.deepEqual(det.items, [
    { identifier: 'selection_flags', field: 'CommandLine', modifiers: ['contains', 'windash'], values: [' -ma ', ' -mm '] },
    { identifier: 'selection_process', field: 'CommandLine', modifiers: ['contains'], values: [' ls', ' keyiso'] },
  ])
})

test('parses lists of maps, inline values, flow lists, keywords and null', () => {
  const det = parseDetection(`detection:
  selection_img:
    - Image|endswith: '\\rundll32.exe'
    - OriginalFileName: 'RUNDLL32.EXE'
  selection_cli:
    CommandLine|contains|all: [ 'javascript:', "mshtml" ]
    ParentImage: null
  keywords:
    - 'vbscript'
  filter_main:
    Image|startswith: 'C:\\Windows\\'
  condition: 1 of selection_* and keywords and not filter_main
`)
  assert.equal(det.condition, '1 of selection_* and keywords and not filter_main')
  assert.deepEqual(det.items.map((i) => [i.identifier, i.field, i.modifiers.join('|'), i.values]), [
    ['selection_img', 'Image', 'endswith', ['\\rundll32.exe']],
    ['selection_img', 'OriginalFileName', '', ['RUNDLL32.EXE']],
    ['selection_cli', 'CommandLine', 'contains|all', ['javascript:', 'mshtml']],
    ['selection_cli', 'ParentImage', '', [null]],
    ['keywords', null, '', ['vbscript']],
    ['filter_main', 'Image', 'startswith', ['C:\\Windows\\']],
  ])
})

test('a list at the same indent as its key belongs to the key', () => {
  const det = parseDetection('detection:\n  sel:\n    Image|endswith:\n    - a.exe\n    - b.exe\n  condition: sel\n')
  assert.deepEqual(det.items, [{ identifier: 'sel', field: 'Image', modifiers: ['endswith'], values: ['a.exe', 'b.exe'] }])
})

test('no detection block gives no items', () => {
  assert.deepEqual(parseDetection('title: x\n'), { items: [], condition: '' })
  assert.deepEqual(parseDetection(''), { items: [], condition: '' })
})

test('unquote handles YAML quoting and null', () => {
  assert.equal(unquote("'it''s'"), "it's")
  assert.equal(unquote('"a\\"b"'), 'a"b')
  assert.equal(unquote(' plain '), 'plain')
  assert.equal(unquote('null'), null)
  assert.equal(unquote("'C:\\Windows\\'"), 'C:\\Windows\\')
})

test('negated identifiers: plain, "1 of", groups, and positive use wins', () => {
  const ids = ['selection', 'filter_a', 'filter_b', 'other']
  assert.deepEqual([...negatedIdentifiers('selection and not filter_a', ids)], ['filter_a'])
  assert.deepEqual([...negatedIdentifiers('selection and not 1 of filter_*', ids)].sort(), ['filter_a', 'filter_b'])
  assert.deepEqual([...negatedIdentifiers('selection and not (filter_a or other)', ids)].sort(), ['filter_a', 'other'])
  assert.deepEqual([...negatedIdentifiers('(selection and not other) or other', ids)], [])
  assert.deepEqual([...negatedIdentifiers('all of them', ids)], [])
})

test('value needles: wildcards split, escapes kept, windash variants, unsupported modifiers skipped', () => {
  assert.deepEqual(valueNeedles('*\\lsass.exe', ['endswith']), ['\\lsass.exe'])
  assert.deepEqual(valueNeedles('a*b?c', []), ['a', 'b', 'c'])
  assert.deepEqual(valueNeedles('100\\*', []), ['100*'])
  assert.deepEqual(valueNeedles(' -ma ', ['contains', 'windash']), [' -ma ', ' /ma ', ' –ma ', ' —ma ', ' ―ma '])
  assert.deepEqual(valueNeedles('^a.*b$', ['re']), [])
  assert.deepEqual(valueNeedles('10.0.0.0/8', ['cidr']), [])
  assert.deepEqual(valueNeedles(null, []), [])
})

test('highlight plan covers positive selections, aliases and keywords, not filters', () => {
  const det = parseDetection(`detection:
  selection:
    Image|endswith: '\\procdump.exe'
  filter:
    ParentImage|endswith: '\\explorer.exe'
  keywords:
    - 'lsass'
  condition: (selection or keywords) and not filter
`)
  const plan = highlightPlan([det], ['NewProcessName', 'ParentProcessName', 'CommandLine'])
  assert.deepEqual(plan.get('NewProcessName'), ['\\procdump.exe', 'lsass'])
  assert.deepEqual(plan.get('ParentProcessName'), ['lsass'])
  assert.deepEqual(plan.get('CommandLine'), ['lsass'])
})

test('highlight segments are case-insensitive, merged and lossless', () => {
  const v = 'C:\\Tools\\WidgetTool.exe -quiet -zz target.exe C:\\out.bin'
  const segs = highlightSegments(v, [' -zz ', 'widgettool', 'tool.exe', ' ta'])
  assert.equal(segs.map((s) => s.text).join(''), v)
  assert.deepEqual(segs.filter((s) => s.mark).map((s) => s.text), ['WidgetTool.exe', ' -zz ta'])
  assert.deepEqual(highlightSegments('abc', []), [{ text: 'abc', mark: false }])
  assert.deepEqual(highlightSegments('abc', ['zz']), [{ text: 'abc', mark: false }])
  assert.deepEqual(highlightSegments('', ['a']), [{ text: '', mark: false }])
})

test('clamping long values keeps the first match visible', () => {
  const segs = [{ text: 'a'.repeat(10), mark: false }, { text: 'XX', mark: true }, { text: 'b'.repeat(10), mark: false }]
  assert.deepEqual(clampSegments(segs, 100), { segs, hidden: 0 })
  assert.deepEqual(clampSegments(segs, 5), { segs: [{ text: 'a'.repeat(10), mark: false }, { text: 'XX', mark: true }], hidden: 10 })
  assert.deepEqual(clampSegments(segs, 15), { segs: [{ text: 'a'.repeat(10), mark: false }, { text: 'XX', mark: true }, { text: 'bbb', mark: false }], hidden: 7 })
  assert.deepEqual(clampSegments([{ text: 'z'.repeat(8), mark: false }], 3), { segs: [{ text: 'zzz', mark: false }], hidden: 5 })
})
