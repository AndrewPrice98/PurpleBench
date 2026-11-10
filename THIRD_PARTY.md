# Third-party content and licences

Verified 2026-11-10. Full evidence and URLs are in `DECISIONS.md`.

## Atomic Red Team (test metadata)

- Source: https://github.com/redcanaryco/atomic-red-team (`atomics/<ID>/<ID>.yaml`), checked at commit `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`.
- Licence: MIT, Copyright (c) 2018 Red Canary, Inc. https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt
- Use: test names, GUIDs and descriptions only. The web app does not run test commands.

## Splunk attack_data (recorded telemetry)

- Source: https://github.com/splunk/attack_data, `datasets/attack_techniques/<ID>/...`, checked at commit `c8af10d015d392fca97f9eb65181e9f06bc18e40`.
- Licence: Apache License 2.0. https://raw.githubusercontent.com/splunk/attack_data/master/LICENSE
- Use: trimmed subsets of selected Windows Sysmon and Security event logs (the events in each test window plus a benign baseline). When subsets are committed, the Apache-2.0 text, the original dataset path and a note that the files were trimmed accompany them. Dataset authors are named in each upstream `.yml` manifest.
- Fallback (not used): OTRF Security-Datasets, https://github.com/OTRF/Security-Datasets, MIT `LICENSE` file but a conflicting "GPL-3.0" line in its README, so it is not committed unless clarified.

## SigmaHQ rules

- Source: https://github.com/SigmaHQ/sigma (release `r2026-07-01`).
- Licence: Detection Rule License (DRL) 1.1. https://github.com/SigmaHQ/Detection-Rule-License (`LICENSE.Detection.Rules.md`).
- Obligations met: each bundled rule keeps its `author`, `id` and `license` fields unchanged; the rule author is shown on results and exports; a link to the rule set and to the DRL is provided; SigmaHQ is credited here and in the README.
- Rules are provided "AS IS", without warranty.

## Specifications and formats

- Sigma Rules Specification 2.1.0, https://github.com/SigmaHQ/sigma-specification (public domain). Implemented independently; no code is copied.
- MITRE ATT&CK Enterprise v20 (data release 20.1), https://github.com/mitre-attack/attack-stix-data. ATT&CK is (c) The MITRE Corporation; use is subject to the ATT&CK Terms of Use at https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ (not fetched in this task; confirm before publishing the catalog).
- ATT&CK Navigator layer format 4.5, https://github.com/mitre-attack/attack-navigator (Apache-2.0).
