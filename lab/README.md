# PurpleBench lab mode

> **Lab mode has not yet been run against a real lab.** The runner, the run-file format and the importer are
> tested statically and with synthetic run files only. The first real run is still to do; expect rough edges
> (Atomic prerequisites, WinRM setup, event volume) and treat the first results with care.

Lab mode runs Atomic Red Team tests on a disposable Windows VM you own, collects that VM's Sysmon and Security
events, and writes a run file that the PurpleBench app imports and scores with the Sigma rules, exactly as it
scores recorded telemetry. The web app itself never executes commands, never connects to a host and never
downloads attack tooling; only `Invoke-PurpleBenchRun.ps1`, run by you, does.

## What the runner refuses to do

`Invoke-PurpleBenchRun.ps1` stops unless all of this holds (each point is checked by the tests in
`backend/tests/test_lab_runner_static.py` and by the CI job that parses the script):

1. The `-Target` name is listed in your local `lab/lab-targets.json` (copy `lab-targets.example.json`; the file is
   git-ignored). Exact names only, no wildcards.
2. The target carries `HKLM:\SOFTWARE\PurpleBench\LabTarget = 1` (a DWORD), which you set on purpose (below),
   it answers to the host name you gave, and `Invoke-AtomicRedTeam` is already installed on it.
3. You read the destructive-action warning and type the target name. `-WhatIf` skips the prompt because it
   executes nothing, contacts no host and writes no file.
4. After every test the runner calls `Invoke-AtomicTest -Cleanup`. Cleanup is best effort: **revert the
   snapshot when you are done.**

The runner never downloads anything, never evaluates fetched text, never calls `-GetPrereqs` (which downloads), and
only talks WinRM to the one target. For each test it records a status in the run file: `ran`, `failed` (the error
text is kept), `prereqs_missing` (checked first with `-CheckPrereqs`; the wording of that output has not been
verified against a real install, so check the first run) or `skipped` (the run was aborted). A test that did not run
is imported as **did not run**, with the reason, and is excluded from the coverage score like an untested
technique. It is never counted as a miss. The same goes for a test whose event collection failed.
`failed` is conservative: the test is left out of the score even if it partly ran (its error text is shown, and
its events are still stored for you to read).

## Lab setup

Use a machine that holds nothing you care about. Do not join it to a domain or a network you do not control.

1. **Hypervisor and network.** Create a **host-only** (isolated) virtual network, for example in VirtualBox or
   Hyper-V (private switch). Attach to it only: the Windows target, optionally your Kali VM (as the "attacker"
   box for your own exercises), and your operator machine's host-only adapter. No NAT, no bridge on the target.
   Give the target a static address, for example `192.168.56.20`.
2. **Windows target.** Windows Server 2022 from Microsoft's Evaluation Center (the 180-day evaluation ISO,
   <https://www.microsoft.com/evalcenter/>). Name the computer `LAB-WS01` (or whatever you list in
   `lab-targets.json`; the name must match, the runner compares it with the computer's real name). Windows
   reports `COMPUTERNAME` as the 15-character NetBIOS name, so keep the name at 15 characters or fewer and pass
   the computer name to `-Target`, not an IP address.
3. **Sysmon.** Install Microsoft Sysinternals Sysmon
   (<https://learn.microsoft.com/sysinternals/downloads/sysmon>) with a documented configuration. This project
   suggests **olafhartong/sysmon-modular** (<https://github.com/olafhartong/sysmon-modular>, MIT licence;
   use its merged `sysmonconfig.xml`). The popular SwiftOnSecurity/sysmon-config
   (<https://github.com/SwiftOnSecurity/sysmon-config>) works as well, but GitHub shows no machine-readable
   licence for it, so check its LICENSE file before you redistribute it. Neither config is bundled here.
   Whatever you choose, **record the config name and commit in your exercise notes**: which events exist
   decides what the Sigma rules can see (a rule without its event is a telemetry gap, not a miss).
   Install from the extracted Sysmon folder: `sysmon64.exe -accepteula -i sysmonconfig.xml`.
4. **Security process-creation auditing (event 4688 with command line).**
   `auditpol /set /subcategory:"Process Creation" /success:enable` and enable
   *Administrative Templates > System > Audit Process Creation > Include command line in process creation events*
   (registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`,
   `ProcessCreationIncludeCmdLine_Enabled` = 1). Raise the Security log size (for example 256 MB) so a campaign's
   events are not overwritten.
5. **Invoke-AtomicRedTeam, on the target.** Install it **on the VM itself**, by hand, from the official project
   (<https://github.com/redcanaryco/invoke-atomicredteam>, MIT; Atomic tests, MIT, from
   <https://github.com/redcanaryco/atomic-red-team>). Use a copy you have inspected, copied into the VM from your
   host (for example over a shared folder). The runner works through a **remote** session, and a remote session
   does not see modules installed in your own user profile. Install **Invoke-AtomicRedTeam and its dependency
   `powershell-yaml` for all users**: copy each module folder (`Invoke-AtomicRedTeam\<version>` and
   `powershell-yaml\<version>`) into `C:\Program Files\WindowsPowerShell\Modules\` on the VM, from an elevated
   prompt. Check from a fresh elevated PowerShell that `Get-Module -ListAvailable Invoke-AtomicRedTeam` lists it;
   the runner refuses to start otherwise. The atomics folder is expected at `C:\AtomicRedTeam\atomics` (change
   with `-AtomicsPath`). Install prerequisites for the tests you plan to run yourself, while the VM is still isolated;
   the runner does not fetch any.
   Windows Defender will often quarantine Atomic test files and the tests themselves. Decide deliberately how
   you handle that on the lab VM only (for example an exclusion for `C:\AtomicRedTeam` there). Do not weaken
   Defender on your own machine.
6. **WinRM, limited to the lab network.** On the target: `Enable-PSRemoting -SkipNetworkProfileCheck`, then
   restrict the firewall rule *Windows Remote Management (HTTP-In)* to the host-only subnet
   (`Set-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' -RemoteAddress 192.168.56.0/24`).
   Create a local lab-only administrator account for the runner and keep its password out of any file.
   On your operator machine the target is addressed **by the name you pass to `-Target`** (WinRM matches the
   TrustedHosts entry against that string, not against the IP). For a workgroup target:
   1. Pin the name to the lab address in the operator's hosts file (`C:\Windows\System32\drivers\etc\hosts`, as
      administrator), so name resolution cannot be answered by anything else on the network (LLMNR and NBNS can
      be spoofed): `192.168.56.20 LAB-WS01`.
   2. Add only that name to TrustedHosts, without overwriting existing entries:
      `Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'LAB-WS01' -Concatenate` (never `*`).
   3. Use `-Credential` (the runner requires it for a real run).
   Prefer WinRM over HTTPS (`-UseSSL`) if you have set up a certificate.
7. **Set the marker.** This is your deliberate "yes, this machine may be attacked" switch. On the target, in an
   elevated PowerShell:
   ```powershell
   New-Item -Path 'HKLM:\SOFTWARE\PurpleBench' -Force | Out-Null
   New-ItemProperty -Path 'HKLM:\SOFTWARE\PurpleBench' -Name LabTarget -PropertyType DWord -Value 1 -Force | Out-Null
   ```
   Never set it on a machine you did not just build for this.
8. **Snapshot.** With everything above done and the VM idle, take a snapshot called `clean-baseline`.

## Running a campaign

1. In the app, export a campaign (`GET /campaigns/{id}/export.json`) to a file such as `campaign.json`. Format:
   `{"format":"purplebench-campaign","version":1,"name":"...","tests":[{"technique_id":"T1003.001","test_guid":"<Atomic test GUID>"}]}`.
2. Copy `lab-targets.example.json` to `lab-targets.json` and list your VM.
3. **Revert the VM to `clean-baseline`** and boot it.
4. Rehearse: `.\Invoke-PurpleBenchRun.ps1 -Target LAB-WS01 -Campaign .\campaign.json -WhatIf`
   (prints the plan, executes and contacts nothing).
5. Run for real: `.\Invoke-PurpleBenchRun.ps1 -Target LAB-WS01 -Campaign .\campaign.json -Credential (Get-Credential)`.
   Read the warning, make sure the snapshot exists, type the target name.
6. Per test the runner records the start time (the target's clock), checks prerequisites, runs the test, waits
   `-SettleSeconds` (default 120, so the 120 s after the end have really elapsed), collects Sysmon and Security
   events from 5 s before the start to 120 s after the end (oldest first, capped by `-MaxEventsPerTest`; a
   capped test is flagged), then runs cleanup and pauses `-PauseAfterCleanupSeconds` (default 10) so cleanup
   activity does not fall into the next test's window. Before anything runs it also checks that the Sysmon
   channel exists and that the Security log is readable, and refuses otherwise. A window with no events is
   normal; any other collection failure is recorded on that test. The run file
   `purplebench-run-<target>-<time>.json` is created (never overwritten) at the end, and also if a later test
   aborts the run, with the remaining tests marked `skipped`. A campaign of N tests takes at least
   N x (120 + 10) seconds plus the test time.
7. **Revert the VM to `clean-baseline`.** Always.
8. Import the file (run-file import, `purplebench.runfile.import_run`; the upload route is added with the API).

## Run file and import

The run file is `purplebench-run` **version 2**: per execution `technique_id`, `test_guid`, `started_at`,
`ended_at`, `run_status`, `error`, `collection_error`, `truncated`, `dropped_oversize` and `events_xml`. Events are shipped as the
`Event.ToXml()` text Windows produces and normalised only on import by the project's one event parser (defusedxml,
DTDs refused), with all timestamps in the invariant culture.

`backend/purplebench/runfile.py` validates the file before storing anything: size cap (32 MB), JSON nesting depth,
schema (unknown keys are refused), timestamps, GUID and technique id formats, event and field counts, string
lengths, no NUL or control characters in names. An **event with an over-limit field** (for example a 1 MB command
line, or a field over 65,536 characters) is left out and counted, not truncated and not a reason to refuse the
file; the runner already drops events whose XML exceeds 60,000 characters (`dropped_oversize`). Both counts are
shown in the execution's reason, and a capped collection (`truncated`) is worded separately. The 32 MB file cap is
the importer's; the runner warns when its output approaches it (split the campaign if it does). Lab runs are scored with the newest rule set unless one is chosen.
Two deliberate differences from recorded mode, written into every lab run's notes: no benign baseline is
collected, so **rule noise is not measured**; and the telemetry profile is the events of the run itself, so a rule
whose event type never occurred in the lab reads as a telemetry gap. Because there is no baseline, the collected
windows also contain the **WinRM harness itself** (for example `wsmprovhost.exe` and the remote commands that
launch each test); read lab results with that in mind, and expect some rules to fire on the harness.

## Checks without a lab

- `python -m pytest backend/tests/test_lab_runner_static.py backend/tests/test_runfile.py` (script text safety
  checks; run-file validation and import with synthetic files).
- `lab/Test-AllowList.ps1` lets the tests call the runner's allow-list function alone (extracted with the parser; the
  runner is not run) with hostile list entries.
- `powershell -File lab/Test-RunnerStatic.ps1` parses the script with the PowerShell AST and fails on parse errors,
  forbidden commands (download or dynamic-execution cmdlets), dynamic invocation, or an `Invoke-Command` that is
  not bound to the one session. It never runs the runner. The CI job `lab-script` runs it on `windows-latest`.
- Manual parameter-validation check (Pester is not used because it would have to execute the runner): on your
  operator machine, **before** setting up the lab, run
  `.\Invoke-PurpleBenchRun.ps1 -Target NOT-LISTED -Campaign .\campaign.json` and expect
  `REFUSED: target 'NOT-LISTED' is not in the allow-list`, and `-Target 'bad name!'` to fail parameter validation.
  Neither contacts any host.
