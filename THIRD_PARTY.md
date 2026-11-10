# Third-party content and licences

Verified 2026-11-10. Full evidence and URLs are in `DECISIONS.md`.

## Atomic Red Team (test metadata)

- Source: https://github.com/redcanaryco/atomic-red-team (`atomics/<ID>/<ID>.yaml`), checked at commit `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`.
- Licence: MIT, Copyright (c) 2018 Red Canary, Inc. https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt
- Use: test names, GUIDs, descriptions and command text, stored as read-only display data in `backend/data/library.json` (licence copy: `backend/data/ATOMIC_RED_TEAM_LICENSE.txt`). The web app does not run test commands.

## Splunk attack_data (recorded telemetry)

- Source: https://github.com/splunk/attack_data, `datasets/attack_techniques/<ID>/...`, checked at commit `c8af10d015d392fca97f9eb65181e9f06bc18e40`.
- Licence: Apache License 2.0. https://raw.githubusercontent.com/splunk/attack_data/master/LICENSE
- Use: trimmed, normalised subsets of selected Windows Sysmon event logs (the events in each test window plus a benign lead-in baseline), committed under `backend/data/telemetry/`. The Apache-2.0 text (`LICENSE-Apache-2.0.txt`), a trimming notice (`NOTICE.md`) and, per file in `manifest.json`, the original dataset path, URL, commit, author and window derivation accompany them. Dataset authors are named in each upstream `.yml` manifest and copied into the manifest.
- Upstream NOTICE: the repository has no `NOTICE` file at the pinned commit (full tree checked), so none is carried; `NOTICE.md` in the telemetry folder is PurpleBench's own modification notice.
- Fallback (not used): OTRF Security-Datasets, https://github.com/OTRF/Security-Datasets, MIT `LICENSE` file but a conflicting "GPL-3.0" line in its README, so it is not committed unless clarified.

## SigmaHQ rules

- Source: https://github.com/SigmaHQ/sigma, release `r2026-07-01`, commit `552f3fee420ef232a8e5790c4fae591847e32347`. 58 rules are bundled unmodified in `backend/rules/sigmahq/` (per-file upstream path, link and sha256 in `SOURCES.json`; notice in `NOTICE.md`; DRL 1.1 text in `LICENSE.Detection.Rules.md`).
- Licence: Detection Rule License (DRL) 1.1. https://github.com/SigmaHQ/Detection-Rule-License (`LICENSE.Detection.Rules.md`).
- Obligations met: each bundled rule keeps its `author`, `id` and `license` fields unchanged; the rule author is shown on results and exports; a link to the rule set and to the DRL is provided; SigmaHQ is credited here and in the README.
- Rules are provided "AS IS", without warranty.
- PurpleBench's own rules (`backend/rules/custom/`, author Andrew T. Price II) are also licensed under DRL 1.1.

## Specifications and formats

- Sigma Rules Specification 2.1.0, https://github.com/SigmaHQ/sigma-specification (public domain). Implemented independently; no code is copied.
- MITRE ATT&CK Enterprise v20 (data release 20.1), https://github.com/mitre-attack/attack-stix-data. ATT&CK is (c) The MITRE Corporation; use is subject to the ATT&CK Terms of Use at https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ (not fetched in this task; confirm before publishing the catalog).
- ATT&CK Navigator layer format 4.5, https://github.com/mitre-attack/attack-navigator (Apache-2.0).
