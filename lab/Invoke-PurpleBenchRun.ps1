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
      4. Nothing is downloaded and no content fetched from anywhere is evaluated. Invoke-AtomicRedTeam must
         already be installed on the TARGET; this script never installs or downloads tools. The only network
         traffic is WinRM to the named target.

    Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Target
    Host name of the lab VM (letters, digits, dot, dash, underscore). Must be in the allow-list.

.PARAMETER Campaign
    Path of the campaign JSON exported by the PurpleBench app:
    {"format":"purplebench-campaign","version":1,"name":"...","tests":[{"technique_id":"T1003.001","test_guid":"<guid>"}]}

.PARAMETER Credential
    Credential for WinRM on the target (a lab account, never a domain account).

.PARAMETER OutFile
    Where to write the run file. Default: purplebench-run-<target>-<UTC time>.json in the current folder.
    An existing file is never overwritten.

.PARAMETER LabTargetsFile
    The allow-list: {"targets":["LAB-WS01"]}. Default: lab-targets.json next to this script.

.PARAMETER SettleSeconds
    Seconds to wait after each test before collecting events (default 30).

.PARAMETER AtomicsPath
    Path of the Atomic Red Team "atomics" folder ON THE TARGET (default C:\AtomicRedTeam\atomics).

.PARAMETER WhatIf
    Show what would run. Executes nothing, contacts no host, writes no file.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$')]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Campaign,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutFile,

    [string]$LabTargetsFile,

    [ValidateRange(0, 600)]
    [int]$SettleSeconds = 30,

    [ValidatePattern('^[A-Za-z]:\\[A-Za-z0-9 _.\\-]{1,200}$')]
    [string]$AtomicsPath = 'C:\AtomicRedTeam\atomics',

    [ValidateRange(100, 100000)]
    [int]$MaxEventsPerTest = 20000,

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
$MaxFieldChars = 60000
$TechniquePattern = '^T\d{4}(\.\d{3})?$'
$GuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

function Stop-Refused {
    param([string]$Reason)
    throw "REFUSED: $Reason Nothing was executed."
}

# --- 1a. allow-list (local, before any network traffic) ---------------------------------------------------
function Test-AllowListed {
    param([string]$Name, [string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Stop-Refused "allow-list file '$Path' not found. Copy lab-targets.example.json to lab-targets.json and list your lab VM."
    }
    $doc = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $doc -or -not ($doc.PSObject.Properties.Name -contains 'targets')) {
        Stop-Refused "allow-list file '$Path' has no 'targets' list."
    }
    foreach ($entry in @($doc.targets)) {
        # Exact, case-insensitive name comparison: no wildcards, no patterns.
        if ($entry -is [string] -and $entry.Length -gt 0 -and $entry -eq $Name) { return $true }
    }
    return $false
}

if (-not (Test-AllowListed -Name $Target -Path $LabTargetsFile)) {
    Stop-Refused "target '$Target' is not in the allow-list '$LabTargetsFile'."
}

# --- campaign ----------------------------------------------------------------------------------------------
$camp = Get-Content -LiteralPath $Campaign -Raw -Encoding UTF8 | ConvertFrom-Json
if ($camp.format -ne 'purplebench-campaign' -or $camp.version -ne 1) {
    throw "Campaign file is not a purplebench-campaign version 1 export."
}
$campaignName = [string]$camp.name
if ([string]::IsNullOrWhiteSpace($campaignName) -or $campaignName.Length -gt 200) {
    throw "Campaign name is missing or longer than 200 characters."
}
$tests = @($camp.tests)
if ($tests.Count -eq 0 -or $tests.Count -gt $MaxTests) {
    throw "Campaign must hold between 1 and $MaxTests tests."
}
foreach ($t in $tests) {
    if (([string]$t.technique_id) -notmatch $TechniquePattern) { throw "Bad technique id in campaign: '$($t.technique_id)'." }
    if (([string]$t.test_guid) -notmatch $GuidPattern) { throw "Bad test GUID in campaign for $($t.technique_id)." }
}

if (-not $OutFile) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $OutFile = Join-Path (Get-Location).Path "purplebench-run-$Target-$stamp.json"
}

# --- -WhatIf: show the plan, execute nothing, contact nothing ---------------------------------------------
if ($WhatIfPreference) {
    Write-Host "WhatIf: target '$Target' is in the allow-list. No host is contacted and nothing is executed."
    Write-Host "WhatIf: the registry marker HKLM:\SOFTWARE\PurpleBench\LabTarget = 1 would be checked on '$Target'."
    foreach ($t in $tests) {
        $null = $PSCmdlet.ShouldProcess($Target, "run Invoke-AtomicTest $($t.technique_id) -TestGuids $($t.test_guid), collect Sysmon and Security events, then Invoke-AtomicTest -Cleanup")
    }
    Write-Host "WhatIf: the run file would be written to '$OutFile'."
    return
}

if (Test-Path -LiteralPath $OutFile) { throw "Output file '$OutFile' already exists; refusing to overwrite." }

# --- remote helpers (script blocks run on the target, only through the one session) ------------------------
$sessionArgs = @{ ComputerName = $Target; ErrorAction = 'Stop' }
if ($Credential) { $sessionArgs.Credential = $Credential }
if ($UseSSL) { $sessionArgs.UseSSL = $true }

$markerBlock = {
    $item = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\PurpleBench' -Name 'LabTarget' -ErrorAction SilentlyContinue
    $value = $null
    if ($null -ne $item) { $value = $item.LabTarget }
    [pscustomobject]@{
        Marker   = $value
        Computer = $env:COMPUTERNAME
        Atomic   = [bool](Get-Module -ListAvailable -Name 'Invoke-AtomicRedTeam')
        UtcNow   = [DateTime]::UtcNow.ToString('o')
    }
}

$utcNowBlock = { [DateTime]::UtcNow.ToString('o') }

$runBlock = {
    param([string]$TechniqueId, [string]$TestGuid, [string]$Atomics)
    Import-Module -Name 'Invoke-AtomicRedTeam' -ErrorAction Stop
    Invoke-AtomicTest $TechniqueId -TestGuids $TestGuid -PathToAtomicsFolder $Atomics -Confirm:$false
}

$cleanupBlock = {
    param([string]$TechniqueId, [string]$TestGuid, [string]$Atomics)
    Import-Module -Name 'Invoke-AtomicRedTeam' -ErrorAction Stop
    Invoke-AtomicTest $TechniqueId -TestGuids $TestGuid -PathToAtomicsFolder $Atomics -Cleanup -Confirm:$false
}

$collectBlock = {
    param([string]$FromIso, [string]$ToIso, [int]$MaxEvents, [int]$MaxChars)
    $style = [System.Globalization.DateTimeStyles]::RoundtripKind
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $from = [DateTime]::Parse($FromIso, $inv, $style).ToLocalTime()
    $to = [DateTime]::Parse($ToIso, $inv, $style).ToLocalTime()
    $out = New-Object System.Collections.Generic.List[object]
    $truncated = $false
    foreach ($log in @('Microsoft-Windows-Sysmon/Operational', 'Security')) {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $from; EndTime = $to } `
                -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
        if ($events.Count -ge $MaxEvents) { $truncated = $true }
        foreach ($e in $events) {
            $doc = New-Object System.Xml.XmlDocument
            $doc.XmlResolver = $null
            $doc.LoadXml($e.ToXml())
            $fields = [ordered]@{}
            $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
            $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
            $unnamed = 0
            foreach ($d in $doc.SelectNodes('//e:EventData/e:Data', $ns)) {
                $name = $d.GetAttribute('Name')
                if ([string]::IsNullOrEmpty($name)) { $unnamed++; $name = "Data$unnamed" }
                $text = [string]$d.InnerText
                if ($text.Length -gt $MaxChars) { $text = $text.Substring(0, $MaxChars) + '...[truncated by runner]' }
                $fields[$name] = $text
            }
            $out.Add([ordered]@{
                    ts        = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')
                    channel   = [string]$e.LogName
                    event_id  = [int]$e.Id
                    host      = [string]$e.MachineName
                    record_id = [int64]$e.RecordId
                    fields    = $fields
                })
        }
    }
    [pscustomobject]@{ Events = $out.ToArray(); Truncated = $truncated }
}

# --- 1b. connect, then check the on-target marker (read-only) -----------------------------------------------
$session = $null
$executions = New-Object System.Collections.Generic.List[object]
$runStarted = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
try {
    $session = New-PSSession @sessionArgs
    $info = Invoke-Command -Session $session -ScriptBlock $markerBlock

    if (($info.Marker -isnot [int]) -or ($info.Marker -ne 1)) {
        Stop-Refused "the registry marker HKLM:\SOFTWARE\PurpleBench\LabTarget = 1 (DWORD) is not set on '$Target'. Only the operator may set it, on a lab VM."
    }
    $shortName = ($Target -split '\.')[0]
    if ($info.Computer -ne $shortName) {
        Stop-Refused "'$Target' answered as computer '$($info.Computer)'. Use the real host name of the lab VM that is in the allow-list."
    }
    if (-not $info.Atomic) {
        Stop-Refused "Invoke-AtomicRedTeam is not installed on '$Target'. Install it there yourself (see lab/README.md); this script never downloads tools."
    }

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
    foreach ($t in $tests) {
        $n++
        $tech = [string]$t.technique_id
        $guid = [string]$t.test_guid
        Write-Host "[$n/$($tests.Count)] $tech $guid"
        $started = Invoke-Command -Session $session -ScriptBlock $utcNowBlock
        try {
            try {
                $null = Invoke-Command -Session $session -ScriptBlock $runBlock -ArgumentList $tech, $guid, $AtomicsPath
            }
            catch {
                Write-Warning "Test $tech failed to run: $($_.Exception.Message). Events are still collected."
            }
            $ended = Invoke-Command -Session $session -ScriptBlock $utcNowBlock
            if ($SettleSeconds -gt 0) { Start-Sleep -Seconds $SettleSeconds }
            $from = ([DateTime]::Parse($started, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).AddSeconds(-$PreSeconds).ToString('o')
            $to = ([DateTime]::Parse($ended, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).AddSeconds($PostSeconds).ToString('o')
            $got = Invoke-Command -Session $session -ScriptBlock $collectBlock -ArgumentList $from, $to, $MaxEventsPerTest, $MaxFieldChars
            if ($got.Truncated) { Write-Warning "Event collection for $tech reached the cap of $MaxEventsPerTest events per log; the rest was not collected." }
            $executions.Add([ordered]@{
                    technique_id = $tech
                    test_guid    = $guid.ToLowerInvariant()
                    started_at   = ([DateTime]::Parse($started, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')
                    ended_at     = ([DateTime]::Parse($ended, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')
                    events       = @($got.Events)
                })
        }
        finally {
            # Cleanup after every test, even when it failed or collection threw.
            try {
                $null = Invoke-Command -Session $session -ScriptBlock $cleanupBlock -ArgumentList $tech, $guid, $AtomicsPath
            }
            catch {
                Write-Warning "Cleanup for $tech failed: $($_.Exception.Message). Revert the snapshot before the next run."
            }
        }
    }
}
finally {
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    if ($executions.Count -gt 0) {
        $run = [ordered]@{
            format     = 'purplebench-run'
            version    = 1
            mode       = 'lab'
            target     = $Target
            started_at = $runStarted
            campaign   = $campaignName
            executions = $executions.ToArray()
        }
        $json = ConvertTo-Json -InputObject $run -Depth 8 -Compress
        [System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "Run file written: $OutFile ($($executions.Count) execution(s)). Import it in PurpleBench, then revert the lab VM to its snapshot."
    }
}
