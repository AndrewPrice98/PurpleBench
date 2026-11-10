# Recorded telemetry notice

The `*.jsonl.gz` files in this directory are **trimmed, normalised subsets** of Windows Sysmon event
logs from Splunk's `attack_data` repository (https://github.com/splunk/attack_data, commit `c8af10d015d392fca97f9eb65181e9f06bc18e40`), licensed under
the Apache License 2.0 (text in `LICENSE-Apache-2.0.txt`).

Changes made by PurpleBench: events were parsed from Windows Event XML, normalised to JSON (original
EventData field names kept), reduced to the events of one test window on one host (or, for
`baseline.jsonl.gz`, to benign lead-in events), and re-compressed. Event values are unchanged apart
from timestamp precision (7→6 fractional digits) and conversion from XML to JSON. Events the parser
could not read are counted per file in `manifest.json` (`source.parse`).
Each file's exact upstream path, URL, dataset author and window derivation are listed in `manifest.json`.

Dataset authors are named in the upstream `.yml` manifests and copied into `manifest.json`.
The data are recordings of simulated attacks on lab machines (hostnames such as `win-dc-*.attackrange.local`).
