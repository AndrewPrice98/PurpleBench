# SigmaHQ rules: third-party notice

The `*.yml` files in this folder are detection rules from the SigmaHQ project,
https://github.com/SigmaHQ/sigma, release `r2026-07-01`, commit
`552f3fee420ef232a8e5790c4fae591847e32347`. They are byte-for-byte copies of the upstream files
(no changes; `.gitattributes` disables end-of-line conversion so the bytes stay identical).

- **Licence:** Detection Rule License (DRL) 1.1. Full text: `LICENSE.Detection.Rules.md` in this folder,
  also at https://github.com/SigmaHQ/Detection-Rule-License.
- **Authors:** each rule's `author` field names its authors. PurpleBench keeps that field unchanged and
  shows it with every detection result and export based on a rule match (DRL 1.1, "use" obligation).
- **Source of each rule:** `SOURCES.json` lists every file with its upstream path, a link to the rule at
  the pinned commit and the sha256 of the upstream bytes (a test checks the files against it).
- The rules are provided "AS IS", without warranty of any kind.

PurpleBench's own rules are in `../custom/` (author Andrew T. Price II, also under DRL 1.1).
