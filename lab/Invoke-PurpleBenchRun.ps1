<#
.SYNOPSIS
    PurpleBench lab runner: runs the Atomic Red Team tests of a campaign on ONE named lab VM and writes a
    run file that the PurpleBench app imports.

.DESCRIPTION
    THIS SCRIPT RUNS ATTACK SIMULATIONS ON THE TARGET. Use it only against a disposable lab VM on an
    isolated host-only network, with a snapshot taken first.

    Safety guards (all mandatory, none can be switched off):
      1. The target must be listed in the local allow-list file (lab-targets.json) AND carry the registry
         marker HKLM:\SOFTWARE\PurpleBench\LabTarget = 1 (DWORD) that the operator set on purpose.
      2. A destructive-action warning is printed and the operator must type the target name to continue.
         Only -WhatIf skips the prompt, and -WhatIf executes nothing and contacts no host.
      3. Each test is followed by Invoke-AtomicTest -Cleanup.
      4. Nothing is fetched from the internet and no fetched text is evaluated. Invoke-AtomicRedTeam must
         already be installed on the TARGET (see lab/README.md); this script never installs tools. The only
         network traffic is WinRM to the named target.

    Windows PowerShell 5.1 and PowerShell 7. Every refusal exits with code 1.

.PARAMETER Target
    Host name of the lab VM (letters, digits, dot, dash, underscore). Must be in the allow-list. Use the
    computer name (at most 15 characters, the NetBIOS name), not an IP address.

.PARAMETER Campaign
    Path of the campaign JSON exported by the PurpleBench app:
    {"format":"purplebench-campaign","version":1,"name":"...","tests":[{"technique_id":"T1003.001","test_guid":"<guid>"}]}

.PARAMETER Credential
    Credential for WinRM on the target (a lab account, never a domain account). Required for a real run.

.PARAMETER OutFile
    Where to write the run file. Default: purplebench-run-<target>-<UTC time>.json in the current folder.
    An existing file is never overwritten.

.PARAMETER LabTargetsFile
    The allow-list: {"targets":["LAB-WS01"]}. Default: lab-targets.json next to this script.

.PARAMETER SettleSeconds
    Seconds to wait after each test before collecting events (default 120, the length of the post-test window).

.PARAMETER PauseAfterCleanupSeconds
    Seconds to wait after cleanup before the next test starts (default 10), so cleanup activity does not fall
    into the next test's window.

.PARAMETER AtomicsPath
    Path of the Atomic Red Team "atomics" folder ON THE TARGET (default C:\AtomicRedTeam\atomics).

.PARAMETER WhatIf
    Show what would run. Executes nothing, contacts no host, writes no file.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,254}\z')]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Campaign,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutFile,

    [string]$LabTargetsFile,

    [ValidateRange(0, 600)]
    [int]$SettleSeconds = 120,

    [ValidateRange(0, 300)]
    [int]$PauseAfterCleanupSeconds = 10,

    [ValidatePattern('^[A-Za-z]:\\[A-Za-z0-9 _.\\-]{1,200}\z')]
    [string]$AtomicsPath = 'C:\AtomicRedTeam\atomics',

    [ValidateRange(100, 20000)]
    [int]$MaxEventsPerTest = 10000,

    [switch]$UseSSL
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $LabTargetsFile) {
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
    $LabTargetsFile = Join-Path $scriptDir 'lab-targets.json'
}

$PreSeconds = 5      # collect from start - 5 s (clock skew tolerance)
$PostSeconds = 120   # collect until end + 120 s
$MaxTests = 500
$MaxEventXmlChars = 400000
$TechniquePattern = '^T\d{4}(\.\d{3})?\z'
$GuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z'
$inv = [System.Globalization.CultureInfo]::InvariantCulture
$rt = [System.Globalization.DateTimeStyles]::RoundtripKind

function Stop-Refused {
    param([string]$Reason)
    Write-Host "REFUSED: $Reason Nothing was executed." -ForegroundColor Red
    exit 1
}

function Test-AllowListed {
    param([string]$Name, [string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Stop-Refused "allow-list file '$Path' not found. Copy lab-targets.example.json to lab-targets.json and list your lab VM." }
    $doc = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $doc -or -not ($doc.PSObject.Properties.Name -contains 'targets')) { Stop-Refused "allow-list file '$Path' has no 'targets' list." }
    foreach ($entry in @($doc.targets)) {
        if ($entry -is [string] -and $entry.Length -gt 0 -and $entry -eq $Name) { return $true }
    }
    return $false
}

function ConvertTo-IsoUtc {
    param([DateTime]$Value)
    return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ', $inv)
}

function Get-RoundtripDate {
    param([string]$Text)
    return [DateTime]::Parse($Text, $inv, $rt)
}

# --- 1a. allow-list (local, before any network traffic) ---------------------------------------------------
if (-not (Test-AllowListed -Name $Target -Path $LabTargetsFile)) {
    Stop-Refused "target '$Target' is not in the allow-list '$LabTargetsFile'."
}

# --- campaign ----------------------------------------------------------------------------------------------
$camp = Get-Content -LiteralPath $Campaign -Raw -Encoding UTF8 | ConvertFrom-Json
if ($camp.format -ne 'purplebench-campaign' -or $camp.version -ne 1) {
    Stop-Refused "the campaign file is not a purplebench-campaign version 1 export."
}
$campaignName = [string]$camp.name
if ([string]::IsNullOrWhiteSpace($campaignName) -or $campaignName.Length -gt 200 -or $campaignName -match '\p{Cc}') {
    Stop-Refused "the campaign name is missing, longer than 200 characters or contains control characters."
}
$tests = @($camp.tests)
if ($tests.Count -eq 0 -or $tests.Count -gt $MaxTests) {
    Stop-Refused "the campaign must hold between 1 and $MaxTests tests."
}
foreach ($t in $tests) {
    if (([string]$t.technique_id) -notmatch $TechniquePattern) { Stop-Refused "bad technique id in campaign: '$($t.technique_id)'." }
    if (([string]$t.test_guid) -notmatch $GuidPattern) { Stop-Refused "bad test GUID in campaign for $($t.technique_id)." }
}

if (-not $OutFile) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ', $inv)
    $OutFile = Join-Path (Get-Location).Path "purplebench-run-$Target-$stamp.json"
}
$OutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)

# --- -WhatIf: show the plan, execute nothing, contact nothing ---------------------------------------------
if ($WhatIfPreference) {
    Write-Host "WhatIf: target '$Target' is in the allow-list. No host is contacted and nothing is executed."
    Write-Host "WhatIf: the registry marker HKLM:\SOFTWARE\PurpleBench\LabTarget = 1 would be checked on '$Target'."
    foreach ($t in $tests) {
        $null = $PSCmdlet.ShouldProcess($Target, "check prerequisites, run Invoke-AtomicTest $($t.technique_id) -TestGuids $($t.test_guid), collect Sysmon and Security events, then Invoke-AtomicTest -Cleanup")
    }
    Write-Host "WhatIf: the run file would be written to '$OutFile'."
    return
}

if (-not $Credential) { Stop-Refused "a real run needs -Credential (a lab account on '$Target')." }
if (Test-Path -LiteralPath $OutFile) { Stop-Refused "output file '$OutFile' already exists; refusing to overwrite." }

# --- remote helpers (script blocks run on the target, only through the one session) ------------------------
$sessionArgs = @{ ComputerName = $Target; Credential = $Credential; ErrorAction = 'Stop' }
if ($UseSSL) { $sessionArgs.UseSSL = $true }

$markerBlock = {
    $item = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\PurpleBench' -Name 'LabTarget' -ErrorAction SilentlyContinue
    $value = $null
    if ($null -ne $item) { $value = $item.LabTarget }
    $sysmon = $false
    try { $sysmon = [bool](Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop).IsEnabled } catch { $sysmon = $false }
    $security = $false
    try {
        $null = Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop
        $security = $true
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $security = $true }
    }
    [pscustomobject]@{
        Marker   = $value
        Computer = $env:COMPUTERNAME
        Atomic   = [bool](Get-Module -ListAvailable -Name 'Invoke-AtomicRedTeam')
        Sysmon   = $sysmon
        Security = $security
    }
}

$utcNowBlock = { [DateTime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture) }

$runBlock = {
    param([string]$TechniqueId, [string]$TestGuid, [string]$Atomics)
    $status = 'ran'
    $message = ''
    try {
        Import-Module -Name 'Invoke-AtomicRedTeam' -ErrorAction Stop
        $pre = (Invoke-AtomicTest $TechniqueId -TestGuids $TestGuid -PathToAtomicsFolder $Atomics -CheckPrereqs -Confirm:$false *>&1 | Out-String)
        if ($pre -match 'not met') {
            $status = 'prereqs_missing'
            $message = ($pre -replace '\s+', ' ').Trim()
        }
        else {
            $errs = $null
            $null = Invoke-AtomicTest $TechniqueId -TestGuids $TestGuid -PathToAtomicsFolder $Atomics -Confirm:$false -ErrorAction Continue -ErrorVariable errs
            if ($errs -and @($errs).Count -gt 0) {
                $status = 'failed'
                $message = ((@($errs) | ForEach-Object { $_.ToString() }) -join '; ')
            }
        }
    }
    catch {
        $status = 'failed'
        $message = $_.Exception.Message
    }
    [pscustomobject]@{ Status = $status; Error = $message }
}

$cleanupBlock = {
    param([string]$TechniqueId, [string]$TestGuid, [string]$Atomics)
    Import-Module -Name 'Invoke-AtomicRedTeam' -ErrorAction Stop
    Invoke-AtomicTest $TechniqueId -TestGuids $TestGuid -PathToAtomicsFolder $Atomics -Cleanup -Confirm:$false
}

# Streams one event XML string per pipeline object (so no single remoting object grows large), then one
# summary object. Only "no matching events" counts as an empty window; any other failure is reported.
$collectBlock = {
    param([string]$FromIso, [string]$ToIso, [int]$MaxEvents, [int]$MaxChars)
    $style = [System.Globalization.DateTimeStyles]::RoundtripKind
    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    $from = [DateTime]::Parse($FromIso, $ci, $style).ToLocalTime()
    $to = [DateTime]::Parse($ToIso, $ci, $style).ToLocalTime()
    $truncated = $false
    $problems = New-Object System.Collections.Generic.List[string]
    foreach ($log in @('Microsoft-Windows-Sysmon/Operational', 'Security')) {
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $from; EndTime = $to } -MaxEvents $MaxEvents -Oldest -ErrorAction Stop)
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                $problems.Add("$log : $($_.Exception.Message)")
            }
        }
        if ($events.Count -ge $MaxEvents) { $truncated = $true }
        foreach ($e in $events) {
            $xml = [string]$e.ToXml()
            if ($xml.Length -gt $MaxChars) { $truncated = $true; continue }
            $xml
        }
    }
    [pscustomobject]@{ Truncated = $truncated; CollectionError = ($problems -join '; ') }
}

# --- 1b. connect, then check the on-target marker (read-only) -----------------------------------------------
$session = $null
$executions = New-Object System.Collections.Generic.List[object]
$runStarted = ConvertTo-IsoUtc ((Get-Date).ToUniversalTime())
try {
    $session = New-PSSession @sessionArgs
    $info = Invoke-Command -Session $session -ScriptBlock $markerBlock

    if (($info.Marker -isnot [int]) -or ($info.Marker -ne 1)) {
        Stop-Refused "the registry marker HKLM:\SOFTWARE\PurpleBench\LabTarget = 1 (DWORD) is not set on '$Target'. Only the operator may set it, on a lab VM."
    }
    $shortName = ($Target -split '\.')[0]
    if ($shortName.Length -gt 15) { $shortName = $shortName.Substring(0, 15) }  # COMPUTERNAME is the 15-character NetBIOS name
    if ($info.Computer -ne $shortName) {
        Stop-Refused "'$Target' answered as computer '$($info.Computer)'. Use the real computer name of the lab VM that is in the allow-list."
    }
    if (-not $info.Atomic) {
        Stop-Refused "Invoke-AtomicRedTeam is not visible to remote sessions on '$Target'. Install it there for all users yourself (see lab/README.md); this script never installs tools."
    }
    if (-not $info.Sysmon) { Stop-Refused "the Sysmon channel (Microsoft-Windows-Sysmon/Operational) does not exist or is disabled on '$Target'." }
    if (-not $info.Security) { Stop-Refused "the Security log cannot be read by the account used on '$Target'." }

    # --- 2. warning and typed confirmation ------------------------------------------------------------------
    Write-Warning @"

  DESTRUCTIVE ACTION. This runs $($tests.Count) Atomic Red Team test(s) of the campaign '$campaignName' ON '$Target'.
  The tests simulate real attacks (credential access, persistence, defense evasion, ransomware precursors) and can
  damage or lock the machine. They are meant for a disposable VM on an isolated host-only network.

  BEFORE YOU CONTINUE: take a snapshot of '$Target' now, so you can revert it afterwards.
  Cleanup runs after each test, but cleanup is not a guarantee: revert the snapshot when the run is finished.

"@
    $typed = Read-Host "Type the target name ($Target) to confirm, anything else aborts"
    if ($typed -cne $Target) { Stop-Refused "the typed name did not match '$Target'." }

    # --- 3. tests ---------------------------------------------------------------------------------------------
    $n = 0
    $aborted = $null
    $lastUtc = Invoke-Command -Session $session -ScriptBlock $utcNowBlock
    foreach ($t in $tests) {
        $n++
        $tech = [string]$t.technique_id
        $guid = [string]$t.test_guid
        $exec = [ordered]@{
            technique_id = $tech; test_guid = $guid.ToLowerInvariant(); started_at = ''; ended_at = ''
            run_status = 'skipped'; error = ''; collection_error = ''; truncated = $false; events_xml = @()
        }
        if ($aborted) {
            $exec.started_at = ConvertTo-IsoUtc (Get-RoundtripDate $lastUtc)
            $exec.ended_at = $exec.started_at
            $exec.error = "not run: $aborted"
            $executions.Add($exec)
            continue
        }
        Write-Host "[$n/$($tests.Count)] $tech $guid"
        $started = $null
        $ranCleanup = $false
        try {
            try {
                $started = Invoke-Command -Session $session -ScriptBlock $utcNowBlock
                $lastUtc = $started
            }
            catch {
                $aborted = "the session to '$Target' was lost: $($_.Exception.Message)"
                $started = $lastUtc
                $exec.error = "not run: $aborted"
            }
            if (-not $aborted) {
                $ranCleanup = $true
                $exec.run_status = 'failed'
                try {
                    $res = Invoke-Command -Session $session -ScriptBlock $runBlock -ArgumentList $tech, $guid, $AtomicsPath
                    $exec.run_status = [string]$res.Status
                    $exec.error = [string]$res.Error
                }
                catch {
                    $exec.error = $_.Exception.Message
                }
                if ($exec.run_status -ne 'ran') { Write-Warning "Test $tech : $($exec.run_status) $($exec.error)" }
            }
            $ended = $started
            if (-not $aborted) {
                try { $ended = Invoke-Command -Session $session -ScriptBlock $utcNowBlock; $lastUtc = $ended } catch { $ended = $started }
                if ($SettleSeconds -gt 0) { Start-Sleep -Seconds $SettleSeconds }
                $from = (Get-RoundtripDate $started).AddSeconds(-$PreSeconds).ToString('o', $inv)
                $to = (Get-RoundtripDate $ended).AddSeconds($PostSeconds).ToString('o', $inv)
                try {
                    $got = @(Invoke-Command -Session $session -ScriptBlock $collectBlock -ArgumentList $from, $to, $MaxEventsPerTest, $MaxEventXmlChars)
                    $exec.events_xml = @($got | Where-Object { $_ -is [string] })
                    $summary = @($got | Where-Object { $_ -isnot [string] }) | Select-Object -Last 1
                    if ($null -eq $summary) {
                        $exec.collection_error = 'the collection returned no summary'
                    }
                    else {
                        $exec.truncated = [bool]$summary.Truncated
                        $exec.collection_error = [string]$summary.CollectionError
                    }
                }
                catch {
                    $exec.events_xml = @()
                    $exec.collection_error = $_.Exception.Message
                }
                if ($exec.truncated) { Write-Warning "Event collection for $tech reached its cap; the events may be incomplete." }
                if ($exec.collection_error) { Write-Warning "Event collection for $tech failed: $($exec.collection_error)" }
            }
            $exec.started_at = ConvertTo-IsoUtc (Get-RoundtripDate $started)
            $exec.ended_at = ConvertTo-IsoUtc (Get-RoundtripDate $ended)
            $executions.Add($exec)
        }
        finally {
            # Cleanup after every test that started, even when it failed or collection threw.
            if ($ranCleanup) {
                try {
                    $null = Invoke-Command -Session $session -ScriptBlock $cleanupBlock -ArgumentList $tech, $guid, $AtomicsPath
                }
                catch {
                    Write-Warning "Cleanup for $tech failed: $($_.Exception.Message). Revert the snapshot before the next run."
                }
                if ($PauseAfterCleanupSeconds -gt 0) { Start-Sleep -Seconds $PauseAfterCleanupSeconds }
            }
        }
    }
}
finally {
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    if ($executions.Count -gt 0) {
        $run = [ordered]@{
            format     = 'purplebench-run'
            version    = 2
            mode       = 'lab'
            target     = $Target
            started_at = $runStarted
            campaign   = $campaignName
            executions = $executions.ToArray()
        }
        $json = ConvertTo-Json -InputObject $run -Depth 6 -Compress
        $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
        $fs = New-Object System.IO.FileStream($OutFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
        Write-Host "Run file written: $OutFile ($($executions.Count) execution(s)). Import it in PurpleBench, then revert the lab VM to its snapshot."
    }
}
