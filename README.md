# PurpleBench

Purple-team detection validation for Windows: map Atomic Red Team tests to recorded Sysmon telemetry and check which Sigma rules fire.

Status: scaffold (version 0.1.0). No features yet.

Detection "missed" means "no rule in this rule set fired on this telemetry". It never claims a product's coverage. Lab mode is "not yet run against a real lab".

## Attribution

PurpleBench builds on the Atomic Red Team (MIT), Splunk attack_data (Apache-2.0) and SigmaHQ rules (Detection Rule License 1.1). See [THIRD_PARTY.md](THIRD_PARTY.md) for sources and licences and [DECISIONS.md](DECISIONS.md) for the verified facts.
