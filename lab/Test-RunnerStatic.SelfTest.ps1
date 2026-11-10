<#
.SYNOPSIS
    Proves that Test-RunnerStatic.ps1 can fail. Never runs the lab runner and writes nothing to disk:
    each case is the real runner text with one change, checked in memory, and must produce the expected problem.
    The baseline (unchanged runner) must pass. Exits 1 if any case does not behave as expected.
.NOTES
    The added lines are harmless (a nonexistent log name, localhost, -WhatIf) and are only parsed, never run.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
$checker = Join-Path $root 'Test-RunnerStatic.ps1'
$runnerPath = Join-Path $root 'Invoke-PurpleBenchRun.ps1'
$runner = [System.IO.File]::ReadAllText($runnerPath)

$failures = New-Object System.Collections.Generic.List[string]
function Test-Case([string]$Name, [string]$Text, [string]$Expect) {
    $result = & $checker -ScriptText $Text -PassThru
    $problems = @($result)
    if ($Expect -eq '') {
        if ($problems.Count -ne 0) { $failures.Add("${Name}: expected a pass, got: $($problems -join ' | ')") }
        else { Write-Host "ok   $Name (passes)" }
        return
    }
    if ($problems.Count -eq 0) { $failures.Add("${Name}: the checker passed but should have failed with '$Expect'") }
    elseif (-not ($problems | Where-Object { $_ -like "*$Expect*" })) { $failures.Add("${Name}: failed, but not with '$Expect': $($problems -join ' | ')") }
    else { Write-Host "ok   $Name (fails: $Expect)" }
}

Test-Case 'baseline: the real runner' $runner ''

# A forbidden command appended to the real runner must be reported by name.
# Words that antivirus products look for are split with "~" in the table; the "~" is removed before checking,
# so no complete command line is stored in this file.
$added = [ordered]@{
    "Invoke-E~xpression 'Get-Date'"                                = "forbidden command 'Invoke-Expression'"
    "iex 'Get-Date'"                                              = "forbidden command 'iex'"
    "Invoke-W~ebRequest -Uri 'http://localhost/'"                  = "forbidden command 'Invoke-WebRequest'"
    "iwr 'http://localhost/'"                                     = "forbidden command 'iwr'"
    "curl 'http://localhost/'"                                    = "forbidden command 'curl'"
    "wget 'http://localhost/'"                                    = "forbidden command 'wget'"
    "Start-Bit~sTransfer -Source 'http://localhost/a' -Destination 'a'" = "forbidden command 'Start-BitsTransfer'"
    "(New-Object Net.WebClient).DownloadString('http://localhost/')" = 'forbidden'
    "[Net.WebClient]::new().DownloadFile('http://localhost/', 'a')"  = 'forbidden'
    "Set-MpPr~eference -DisableRealtimeMonitoring `$false"          = "forbidden command 'Set-MpPreference'"
    "Add-MpPr~eference -ExclusionPath 'C:\nowhere'"                 = "forbidden command 'Add-MpPreference'"
    "New-S~ervice -Name 'NoSuchService' -BinaryPathName 'C:\nowhere.exe' -WhatIf" = "forbidden command 'New-Service'"
    "Format~-Volume -DriveLetter Z -WhatIf"                         = "forbidden command 'Format-Volume'"
    "Clear-E~ventLog -LogName 'NoSuchLog'"                          = "forbidden command 'Clear-EventLog'"
    "wevtutil cl NoSuchLog"                                        = 'wevtutil must not clear logs'
    "wevtutil clear-log NoSuchLog"                                 = 'wevtutil must not clear logs'
    "vssa~dmin list shadows"                                        = "forbidden native command 'vssadmin'"
    "Remove-Item -Recurse -Force 'C:\Windows\Temp\nowhere'"        = 'Remove-Item -Recurse on a system path'
    "Remove-Item -Recurse -Force 'C:\'"                            = 'Remove-Item -Recurse on a system path'
    "Remove-Item -Recurse `$env:SystemRoot\nowhere"                = 'Remove-Item -Recurse'
    "Remove-Item -Recurse `$somePath"                              = 'computed path'
    "& `$cmd"                                                      = 'dynamic invocation'
    "Invoke-Command -ComputerName other -ScriptBlock { 1 }"        = 'Invoke-Command must use -Session'
}
foreach ($key in $added.Keys) { $line = $key.Replace('~', ''); Test-Case "add: $line" ($runner + "`r`n" + $line + "`r`n") $added[$key] }

# Removing a safety gate must be reported.
function Remove-Once([string]$Text, [string]$Needle, [string]$With, [bool]$All = $false) {
    if ($All) { return $Text.Replace($Needle, $With) }
    $i = $Text.IndexOf($Needle, [StringComparison]::Ordinal)
    if ($i -lt 0) { throw "self-test needs '$Needle' in the runner" }
    return $Text.Substring(0, $i) + $With + $Text.Substring($i + $Needle.Length)
}
$gates = [ordered]@{
    'allow-list call renamed'          = @{ Needle = 'Test-AllowListed -Name $Target'; With = 'Test-Listed -Name $Target'; Expect = 'Test-AllowListed' }
    'LabTarget marker removed'         = @{ Needle = 'LabTarget'; With = 'Marker'; Expect = "missing required safety element 'LabTarget'"; All = $true }
    'typed confirmation removed'       = @{ Needle = 'Read-Host'; With = 'Get-Date'; Expect = 'Read-Host' }
    'typed confirmation made loose'    = @{ Needle = '-cne $Target'; With = '-ne $Target'; Expect = 'must compare exactly' }
    'Credential parameter removed'     = @{ Needle = '[System.Management.Automation.PSCredential]$Credential,'; With = ''; Expect = 'missing parameter -Credential' }
    'Credential parameter retyped'     = @{ Needle = '[System.Management.Automation.PSCredential]$Credential'; With = '[string]$Credential'; Expect = 'must be a PSCredential' }
    'Credential refusal removed'       = @{ Needle = 'if (-not $Credential)'; With = 'if (-not $Other)'; Expect = 'refusal when -Credential is not supplied' }
    'Target no longer mandatory'       = @{ Needle = '[Parameter(Mandatory = $true)]'; With = '[Parameter()]'; Expect = 'must be Mandatory' }
    'refusal no longer exits non-zero' = @{ Needle = 'exit 1'; With = 'exit 0'; Expect = 'exit 1' }
}
foreach ($name in $gates.Keys) {
    $g = $gates[$name]
    Test-Case "gate: $name" (Remove-Once $runner $g.Needle $g.With ([bool]$g.All)) $g.Expect
}

# The committed fixture with a forbidden command (parsed from disk, as CI does for the runner).
$fixture = Join-Path $root 'selftest\forbidden-command.fixture.ps1'
$out = @(& $checker -Path $fixture -PassThru)
if (-not ($out | Where-Object { $_ -like "*forbidden command 'Invoke-Expression'*" })) { $failures.Add("fixture: expected a forbidden Invoke-Expression, got: $($out -join ' | ')") }
else { Write-Host 'ok   fixture file (fails: forbidden Invoke-Expression)' }

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    exit 1
}
Write-Host "Static checker self-test passed ($($added.Count + $gates.Count + 2) cases)."
