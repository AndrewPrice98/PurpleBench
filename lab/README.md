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
only talks WinRM to the one target. Tests whose prerequisites are missing simply fail and are reported.

## Lab setup

Use a machine that holds nothing you care about. Do not join it to a domain or a network you do not control.

1. **Hypervisor and network.** Create a **host-only** (isolated) virtual network, for example in VirtualBox or
   Hyper-V (private switch). Attach to it only: the Windows target, optionally your Kali VM (as the "attacker"
   box for your own exercises), and your operator machine's host-only adapter. No NAT, no bridge on the target.
   Give the target a static address, for example `192.168.56.20`.
2. **Windows target.** Windows Server 2022 from Microsoft's Evaluation Center (the 180-day evaluation ISO,
   <https://www.microsoft.com/evalcenter/>). Name the computer `LAB-WS01` (or whatever you list in
   `lab-targets.json`; the name must match, the runner compares it with the computer's real name).
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
   <https://github.com/redcanaryco/atomic-red-team>). Read its install instructions and use a copy you have
   inspected, or one you copied into the VM from your host over a shared folder. The runner expects the module
   to be importable as `Invoke-AtomicRedTeam` and the atomics folder at `C:\AtomicRedTeam\atomics` (change with
   `-AtomicsPath`). Install prerequisites for the tests you plan to run yourself, while the VM is still isolated;
   the runner does not fetch any.
   Windows Defender will often quarantine Atomic test files and the tests themselves. Decide deliberately how
   you handle that on the lab VM only (for example an exclusion for `C:\AtomicRedTeam` there). Do not weaken
   Defender on your own machine.
6. **WinRM, limited to the lab network.** On the target: `Enable-PSRemoting -SkipNetworkProfileCheck`, then
   restrict the firewall rule *Windows Remote Management (HTTP-In)* to the host-only subnet
   (`Set-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' -RemoteAddress 192.168.56.0/24`).
   Create a local lab-only administrator account for the runner and keep its password out of any file.
   On your operator machine, for a workgroup target add **only** that target to TrustedHosts:
   `Set-Item WSMan:\localhost\Client\TrustedHosts -Value 192.168.56.20` (never `*`) and use `-Credential`.
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
6. Per test the runner records the start time (the target's clock), runs the test, waits `-SettleSeconds`
   (default 30), collects Sysmon and Security events from 5 s before the start to 120 s after the end, normalizes
   them, then runs cleanup. The run file `purplebench-run-<target>-<time>.json` is written at the end (it is
   written even if a later test aborts the run, with the tests completed so far).
7. **Revert the VM to `clean-baseline`.** Always.
8. Import the file (run-file import, `purplebench.runfile.import_run`; the upload route is added with the API).

## Run file and import

`backend/purplebench/runfile.py` validates the file before storing anything: size cap (64 MB), JSON nesting depth,
schema, timestamps, GUID and technique id formats, event and field counts, string lengths (a 1 MB command line
is rejected, not truncated), no NUL bytes. Lab runs are scored with the newest rule set unless one is chosen.
Two deliberate differences from recorded mode, written into every lab run's notes: no benign baseline is
collected, so **rule noise is not measured**; and the telemetry profile is the events of the run itself, so a rule
whose event type never occurred in the lab reads as a telemetry gap.

## Checks without a lab

- `python -m pytest backend/tests/test_lab_runner_static.py backend/tests/test_runfile.py` (script text safety
  checks; run-file validation and import with synthetic files).
- `powershell -File lab/Test-RunnerStatic.ps1` parses the script with the PowerShell AST and fails on parse errors,
  forbidden commands (download or dynamic-execution cmdlets), dynamic invocation, or an `Invoke-Command` that is
  not bound to the one session. It never runs the runner. The CI job `lab-script` runs it on `windows-latest`.
- Manual parameter-validation check (Pester is not used because it would have to execute the runner): on your
  operator machine, **before** setting up the lab, run
  `.\Invoke-PurpleBenchRun.ps1 -Target NOT-LISTED -Campaign .\campaign.json` and expect
  `REFUSED: target 'NOT-LISTED' is not in the allow-list`, and `-Target 'bad name!'` to fail parameter validation.
  Neither contacts any host.
