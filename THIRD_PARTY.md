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
- **Not used: OTRF Security-Datasets** (https://github.com/OTRF/Security-Datasets). Licence conflict: the `LICENSE` file is MIT but the README also states GPL-3.0, so no OTRF data is committed or used unless the project clarifies it.

## SigmaHQ rules

- Source: https://github.com/SigmaHQ/sigma, release `r2026-07-01`, commit `552f3fee420ef232a8e5790c4fae591847e32347`. 58 rules are bundled unmodified in `backend/rules/sigmahq/` (per-file upstream path, link and sha256 in `SOURCES.json`; notice in `NOTICE.md`; DRL 1.1 text in `LICENSE.Detection.Rules.md`).
- Licence: Detection Rule License (DRL) 1.1. https://github.com/SigmaHQ/Detection-Rule-License (`LICENSE.Detection.Rules.md`).
- Obligations met: each bundled rule keeps its `author`, `id` and `license` fields unchanged; the rule author is shown on results and exports; a link to the rule set and to the DRL is provided; SigmaHQ is credited here and in the README.
- Rules are provided "AS IS", without warranty.
- PurpleBench's own rules (`backend/rules/custom/`, author Andrew T. Price II) are also licensed under DRL 1.1.

## Specifications and formats

- Sigma Rules Specification 2.1.0, https://github.com/SigmaHQ/sigma-specification (public domain). Implemented independently; no code is copied.
- MITRE ATT&CK Enterprise v20 (data release 20.1), https://github.com/mitre-attack/attack-stix-data. Used under the ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ (fetched 2026-11-10), which grant a royalty-free licence and require this notice to be reproduced:

  > © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
  >
  > MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.

  The notice appears in this file, the README, the UI footer and report page, report Appendix B, and the description of every exported Navigator layer. IDs, names and tactics come from `backend/data/library.json`.
- ATT&CK Navigator layer format 4.5, https://github.com/mitre-attack/attack-navigator (Apache-2.0).

## Front-end assets bundled with the dashboard

- **Inter** (variable font), npm package `@fontsource-variable/inter` 5.x, https://github.com/rsms/inter. Licence: SIL Open Font License 1.1, Copyright 2016 The Inter Project Authors. The font files are served from the application's own origin, bundled by Vite; no font CDN is contacted. The licence text ships in the npm package (`node_modules/@fontsource-variable/inter/LICENSE`).
- **Lucide** icons, npm package `lucide-react` 1.x, https://lucide.dev. Licence: ISC, Copyright (c) 2026 Lucide Icons and Contributors. Only the icons the dashboard uses are included in the bundle.

## Development tools (not shipped)

- Playwright 1.61.0 (`e2e/`, Apache-2.0) drives the installed Chrome for the browser smoke test; a dev dependency of `e2e/` only.
