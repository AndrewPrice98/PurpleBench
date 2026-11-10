# Sigma support in PurpleBench

PurpleBench evaluates Sigma rules itself (`backend/purplebench/sigma/`), directly on normalised Windows
events. It targets the **Sigma Rules Specification 2.1.0** (https://github.com/SigmaHQ/sigma-specification,
release `v2.1.0`), including its modifiers and taxonomy appendices. It implements a documented subset.

Every rule gets one of four statuses when evaluated:

| Status | Meaning |
|---|---|
| `match` | At least one event satisfies the rule. The result lists the matching record ids in time order and the first timestamp. |
| `no_match` | The rule could have matched this telemetry, and nothing did. |
| `telemetry_gap` | The rule cannot match this telemetry: its channel or event id is absent, or a field it needs never occurs there. The detail names the missing channel, event id or fields. |
| `unsupported` | The rule uses something outside the subset below. The detail gives the exact reason. |

A rule outside the subset is **never** evaluated as "no match", and a rule that cannot see its
telemetry is **never** reported as "missed".

## Supported

### Detection structure

- Search identifiers as **maps** (all field items must match, AND) or **lists of maps** (any map, OR).
- A **list of values** for a field is OR. With `|all` it is AND.
- Identifier names: letters, digits and `_`.

```yaml
detection:
    selection_img:            # list of maps: OR
        - Image|endswith: '\net.exe'
        - OriginalFileName: 'net.exe'
    selection_cli:            # map: AND; list of values: AND because of |all
        CommandLine|contains|all:
            - 'user'
            - '/add'
    condition: all of selection_*
```

### Values

- Strings compare **case-insensitively** by default, against the whole value.
- Wildcards: `*` matches any run of characters (including newlines), `?` matches one character.
- Escapes: `\*` and `\?` are a literal star and question mark; `\\` is one backslash; a backslash
  before any other character (or at the end) is a literal backslash. So `\\*` is a backslash followed
  by a wildcard, and `\\\\` is two backslashes. Example: `'C:\Windows\\*.exe'` matches
  `C:\Windows\notepad.exe`, but `'C:\Windows\*.exe'` only matches the literal text `C:\Windows*.exe`.
- `null`: matches when the field is **absent or empty**. (Windows Event XML cannot tell an empty
  `<Data>` from a missing value, so both count.)
- `''`: matches a present, empty field only.
- Integers: compared numerically when the event value is a base-10 integer (`ProcessId: 100` matches
  `0100`), otherwise as text. Booleans compare as the text `true`/`false`.
- A field that is absent from an event never matches a value (it does match `null` and `|exists: false`).

### Modifiers

| Modifier | Behaviour |
|---|---|
| `contains`, `startswith`, `endswith` | Substring, prefix, suffix (wildcards still apply inside the value). |
| `all` | AND across the value list. A single value with `all` is invalid in the specification and is reported as unsupported. |
| `cased` | Case-sensitive comparison. |
| `exists` | `true`/`false`: the field is present or absent. Presence only; an empty value counts as present. |
| `windash` | Each of `-`, `/`, en dash (U+2013), em dash (U+2014) and horizontal bar (U+2015) in the value matches any of the five. Combines with `contains`, `startswith`, `endswith`. |
| `re` | Python regular expression, **searched** anywhere in the value, case-sensitive by default. Sub-modifiers `re|i` (ignore case), `re|m` (multi-line `^`/`$`), `re|s` (dot matches newline). See the regex guard below. |

Example: `CommandLine|windash|contains: ' -enc '` matches `powershell /enc ...` and
`powershell –enc ...` (en dash).

### Conditions

- `and`, `or`, `not`, parentheses (operators are matched case-insensitively).
- `1 of <pattern>`, `all of <pattern>`, where `*` in the pattern matches any characters.
- `1 of them`, `all of them`. As the specification says, `them` leaves out identifiers that start
  with `_`. An explicit pattern (`1 of _x*`) can still select them.
- Precedence, least to most binding: `or`, `and`, `not`, `x of`, parentheses. So
  `a or b and c` is `a or (b and c)` and `not 1 of filter*` negates the whole `1 of`.
- A **list of conditions** is OR (specification: "each of them generates a query").

### Log sources (`product: windows`)

From the specification's taxonomy appendix:

| Logsource | Channel and event ids |
|---|---|
| `category: process_creation` | Sysmon 1, **and** Security 4688 (with the field map below) |
| `category: network_connection` / `image_load` / `create_remote_thread` / `process_access` / `file_event` / `dns_query` | Sysmon 3 / 7 / 8 / 10 / 11 / 22 |
| `category: registry_event` / `registry_add` / `registry_delete` / `registry_set` / `registry_rename` | Sysmon 12, 13, 14 / 12 / 12 / 13 / 14 |
| `category: pipe_created`, `wmi_event`, `create_stream_hash`, `file_delete`, `file_delete_detected`, `driver_load`, `process_termination`, `raw_access_thread`, `process_tampering`, `clipboard_capture`, `file_change`, `sysmon_status`, `sysmon_error`, `file_block_*`, `file_executable_detected` | The Sysmon event ids the taxonomy gives (17/18, 19-21, 15, 23, 26, 6, 5, 9, 25, 24, 2, 4/16, 255, 27/28, 29) |
| `category: ps_script` / `ps_module` | `Microsoft-Windows-PowerShell/Operational` and `PowerShellCore/Operational`, 4104 / 4103 |
| `category: ps_classic_start` / `ps_classic_provider_start` / `ps_classic_script` | `Windows PowerShell` 400 / 600 / 800 |
| `service: <name>` | Every service in the taxonomy table (security, system, sysmon, powershell, powershell-classic, taskscheduler, wmi, windefend, application, ...), all event ids of its channel(s) |

`EventID`, `Channel` and `Computer` are readable in every rule (from the event envelope). Sysmon's
`Hashes` value is also readable as the taxonomy fields `md5`, `sha1`, `sha256` and `Imphash`.

### Field mapping: Security 4688 as process_creation

Rules use Sysmon field names. For Security event 4688 they are read as follows:

| Rule field | 4688 field |
|---|---|
| `Image` | `NewProcessName` |
| `CommandLine` | `CommandLine` |
| `ParentImage` | `ParentProcessName` |
| `User` | `SubjectDomainName\SubjectUserName` (the creating account) |
| `ProcessId` | `NewProcessId`, hex converted to decimal |
| `ParentProcessId` | `ProcessId` (the creator), hex converted to decimal |
| `IntegrityLevel` | `MandatoryLabel`, SID converted to the Sysmon name (`S-1-16-12288` -> `High`) |
| `LogonId` | `SubjectLogonId` |

Any other process_creation field (`OriginalFileName`, `Hashes`, `ParentCommandLine`,
`CurrentDirectory`, `Product`, ...) does not exist in 4688.

## Telemetry gaps

For each source of a rule (for example Sysmon 1 and Security 4688 for process_creation), the
evaluator checks the telemetry profile: which channels and event ids occur, and which EventData field
names each one carries.

- The channel does not occur: gap (`channel 'Security' is not in the telemetry (needed for Security event 4688)`).
- The candidate event ids are the source's own (a category) or every event id the profile has for
  the channel (a service). `EventID` and `Channel` tests are decided literally for each candidate,
  with every other field unknown; a candidate that makes the condition definitely false is not
  relevant to the rule and is skipped. If no candidate is relevant, the source is a gap
  (`no Security event 4769 in the telemetry`, `no Sysmon event 8 in the telemetry`).
- A field the rule uses never occurs in a candidate: the condition is evaluated three-valued, with
  every search identifier that needs the absent field set to false and every other one unknown. If
  the result is definitely false, the candidate is a gap (`Sysmon event 1 never has field(s) ParentUser`).
  A missing field that only appears in a filter (`selection and not filter`) does not make a gap.
  For a service source, other event ids that lack the fields are not listed when at least one
  event id can be evaluated.

A rule is a `telemetry_gap` only when **none** of its sources can be evaluated. Otherwise it is
evaluated on the sources that can be, and the result's `gaps` list (and detail) names the others.

The profile is a required argument of `evaluate(rule, events, profile)` and `evaluate_all`. To judge
an execution window against everything a mode can record, pass the corpus profile
(`recorded_profile()` covers all committed recorded telemetry); passing `EventIndex(events).profile`
judges against exactly those events. In recorded mode only the Sysmon channel exists, so every Security,
System and PowerShell rule is a telemetry gap there (a documented limitation of the recorded data).

## Regular expressions and wildcards

`|re` patterns run on the third-party `regex` module with a **50 ms time limit per match**. A match
that runs out of time counts as no match for that event; the result reports the number of timed-out
matches (`regex_timeouts`, and in the detail) and a warning is logged. After **5 timed-out matches
in one evaluation** the rule is abandoned: the result is `unsupported` with
`regex too slow: |re timed out 5 times; rule abandoned`, so one rule's regex time stays near 0.25 s
however many events it is evaluated on. Before that, a cheap static
check rejects some patterns when the rule loads (the rule becomes `unsupported` with the reason):

- longer than 1,024 characters;
- backreferences (`\1`, `(?P=name)`);
- a group repeated without bound (`*`, `+`, `{n,}`) whose body contains a quantifier or an
  alternation, such as `(a+)+` or `(a|aa)*`. Bounded repetition such as `(\d{1,3}\.){3}` passes;
- a pattern that does not compile (including repeat counts that are too large).

The static check does not catch every slow pattern (for example `(\w+\s?){1,25}!`); the time limit
does. A `|re` pattern sees at most the first 32,768 characters of a value (Windows limits a command
line to 32,767).

Wildcard values (`*`, `?`, with or without `windash`) are not turned into regular expressions. They
are matched by a linear glob matcher: the pieces between `*` are found left to right with plain
string search, so the time grows with the length of the value, never exponentially.

## Malformed rules

Loading never raises for rule content. Logsource values must be strings, a condition may nest at
most 64 levels of parentheses and `not`, and any error while parsing (including deeply nested YAML)
makes the rule `unsupported` with `rule could not be parsed: <ExceptionType>`. If a rule fails while
being evaluated, `evaluate_all` reports it as `unsupported` (`rule could not be evaluated:
<ExceptionType>`) and evaluates the others.

## Not supported (reported as `unsupported`, with the reason)

| Feature | Example reason |
|---|---|
| Encoding modifiers `base64`, `base64offset`, `utf16`, `utf16le`, `utf16be`, `wide` | `selection.CommandLine|base64offset|contains: modifier 'base64offset' is not supported` |
| `cidr` | `selection.DestinationIp|cidr: modifier 'cidr' is not supported` |
| `expand` (placeholders), `fieldref` | `modifier 'expand' is not supported` |
| Numeric and time modifiers `lt`, `lte`, `gt`, `gte`, `neq`, `minute`, `hour`, `day`, `week`, `month`, `year` | `modifier 'gt' is not supported` |
| Unknown modifiers, conflicting match types (`contains|startswith`), `windash` with `re` | `unknown modifier 'x'`, `modifiers 'contains' and 'startswith' cannot be combined` |
| Aggregations (`| count() > 5`), `timeframe` | `condition uses '|' (aggregation, deprecated in Sigma 2; use correlation rules)` |
| `near` | `condition has unexpected token 'near'` |
| `2 of x*` (anything but `1 of` / `all of`) | `condition '2 of' is not supported (only '1 of' and 'all of')` |
| Keyword (full-text) search identifiers (lists of plain strings, `'|all':` keys) | `keywords: keyword (full-text) search identifiers are not supported` |
| Correlation rules and filter (meta) rules (separate specifications) | `Sigma correlation rule (separate specification, not supported)` |
| Sigma 1.x multi-document collections (`action: global`) | `multi-document YAML (Sigma 1.x rule collection) is not supported` |
| Logsources outside the mapping (other products, ETW-only categories such as `file_access`) | `logsource product 'linux' is not mapped (only 'windows' is)` |
| Rules that are invalid per the specification (`null` inside a value list, `all` on one value, undefined identifiers, a pattern matching nothing) | `undefined search identifier 'x'` |
| Conditions nested more than 64 levels; logsource values that are not strings | `condition nests deeper than 64 levels` |
| Files over 256 KiB, non-UTF-8, YAML that does not parse (YAML is read with `safe_load`) | `YAML does not parse: ScannerError` |

## Differences from pySigma worth knowing

- `windash` follows the specification text (every dash-like character in the value is
  interchangeable). pySigma only rewrites a dash or slash that starts a word, so PurpleBench can match
  a little more broadly.
- `|re` is a search (unanchored), as in most pySigma backends. Anchor with `^`/`$` when needed.
- `null` matches absent or empty fields (see Values).
