<#
.SYNOPSIS
    Proves that Test-RunnerStatic.ps1 can fail. Never runs the lab runner and writes nothing to disk: each case is
    the real runner text with one change, checked in memory, and must produce the expected problem. The baseline
    (the unchanged runner) must pass. Exits 1 if any case does not behave as expected.
.NOTES
    The changes are harmless text (a nonexistent log name, localhost, -WhatIf) that is only parsed, never run.
    Words that antivirus products look for are split with "~" in the tables below; the "~" is removed before
    checking, so no complete risky command line is stored in this file.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
$checker = Join-Path $root 'Test-RunnerStatic.ps1'
$runnerPath = Join-Path $root 'Invoke-PurpleBenchRun.ps1'
$runner = [System.IO.File]::ReadAllText($runnerPath).Replace("`r`n", "`n")

$failures = New-Object System.Collections.Generic.List[string]
$script:count = 0
function Test-Case([string]$Name, [string]$Text, [string]$Expect) {
    $script:count++
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
function Edit-Runner([string]$Needle, [string]$With) {
    $Needle = $Needle.Replace('~', ''); $With = $With.Replace('~', '')
    $i = $runner.IndexOf($Needle, [StringComparison]::Ordinal)
    if ($i -lt 0) { throw "self-test needs '$Needle' in the runner" }
    return $runner.Substring(0, $i) + $With + $runner.Substring($i + $Needle.Length)
}

Test-Case 'baseline: the real runner' $runner ''

# 1. A line appended to the real runner must be reported (clearer names for the deny-listed ones; the rest by the allow-list).
$added = [ordered]@{
    "Invoke-E~xpression 'Get-Date'"                                      = "forbidden command 'Invoke-Expression'"
    "iex 'Get-Date'"                                                    = "forbidden command 'iex'"
    "Invoke-W~ebRequest -Uri 'http://localhost/'"                        = "forbidden command 'Invoke-WebRequest'"
    "iwr 'http://localhost/'"                                           = "forbidden command 'iwr'"
    "curl 'http://localhost/'"                                          = "forbidden command 'curl'"
    "wget 'http://localhost/'"                                          = "forbidden command 'wget'"
    "Start-Bit~sTransfer -Source 'http://localhost/a' -Destination 'a'" = "forbidden command 'Start-BitsTransfer'"
    "(New-Object Net.Web~Client).Down~loadString('http://localhost/')"   = "forbidden member 'DownloadString'"
    "[Net.Web~Client]::new().Down~loadFile('http://localhost/', 'a')"    = "forbidden member 'DownloadFile'"
    "`$w.Down~loadData('http://localhost/')"                             = "forbidden member 'DownloadData'"
    "`$w.Up~loadString('http://localhost/', 'x')"                        = "forbidden member 'UploadString'"
    "`$w.Open~Read('http://localhost/')"                                 = "forbidden member 'OpenRead'"
    "Set-MpPr~eference -DisableRealtimeMonitoring `$false"               = "forbidden command 'Set-MpPreference'"
    "Add-MpPr~eference -ExclusionPath 'C:\nowhere'"                      = "forbidden command 'Add-MpPreference'"
    "New-S~ervice -Name 'NoSuchService' -BinaryPathName 'C:\nowhere.exe' -WhatIf" = "forbidden command 'New-Service'"
    "Format~-Volume -DriveLetter Z -WhatIf"                              = "forbidden command 'Format-Volume'"
    "Clear-Event~Log -LogName 'NoSuchLog'"                               = "forbidden command 'Clear-EventLog'"
    "wev~tutil cl NoSuchLog"                                            = "forbidden native command 'wevtutil'"
    "vss~admin list shadows"                                            = "forbidden native command 'vssadmin'"
    "Remove-Item -Recurse -Force 'C:\Windows\Temp\nowhere'"             = "forbidden command 'Remove-Item'"
    "Remove-Item -Recurse `$somePath"                                   = "forbidden command 'Remove-Item'"
    "& `$cmd"                                                           = 'dynamic invocation'
    "Invoke-Command -ComputerName other -ScriptBlock { 1 }"             = 'parameter -ComputerName is not allowed'
    # --- bypasses found in review: aliases and Start-Process
    "start notepad"                                                     = "forbidden command 'start'"
    "saps notepad"                                                      = "forbidden command 'saps'"
    "Start-Pro~cess notepad"                                            = "forbidden command 'Start-Process'"
    # --- native powershell with -EncodedCommand, and the parameter on any command
    "power~shell.exe -EncodedCommand AAAA"                              = "forbidden native command 'powershell.exe'"
    "pw~sh -enc AAAA"                                                   = "forbidden native command 'pwsh'"
    "power~shell -e AAAA"                                               = "forbidden native command 'powershell'"
    "Write-Host hello -enc AAAA"                                        = 'abbreviation of -EncodedCommand'
    "Get-Date -ec AAAA"                                                 = 'abbreviation of -EncodedCommand'
    "Write-Host hello -EncodedCommand AAAA"                             = 'abbreviation of -EncodedCommand'
    # --- native LOLBins
    "cmd /c echo hello"                                                 = "forbidden native command 'cmd'"
    "cert~util"                                                         = "forbidden native command 'certutil'"
    "bits~admin"                                                        = "forbidden native command 'bitsadmin'"
    "m~shta"                                                            = "forbidden native command 'mshta'"
    "rund~ll32"                                                         = "forbidden native command 'rundll32'"
    "regs~vr32"                                                         = "forbidden native command 'regsvr32'"
    "reg query HKLM\Software"                                           = "forbidden native command 'reg'"
    "sc query"                                                          = "forbidden native command 'sc'"
    "net~sh"                                                            = "forbidden native command 'netsh'"
    "schta~sks /query"                                                  = "forbidden native command 'schtasks'"
    "C:\Tools\some.exe"                                                 = 'looks like a path or a native executable'
    "unknowntool.exe /x"                                                = 'looks like a path or a native executable'
    # --- aliases
    "Set-Alias zz Get-Date`nzz"                                       = "forbidden command 'Set-Alias'"
    "New-Alias zz Get-Date"                                             = "forbidden command 'New-Alias'"
    "sal zz Get-Date"                                                   = "forbidden command 'sal'"
    "nal zz Get-Date"                                                   = "forbidden command 'nal'"
    "zz"                                                                = "command 'zz' is not on the allow-list"
    # --- dynamic evaluation and loading code
    "`$ExecutionContext.InvokeCommand.Invoke~Script('1')"                = "forbidden member 'InvokeScript'"
    "`$ExecutionContext.InvokeCommand.Expand~String('x')"                = "forbidden member 'ExpandString'"
    "`$ExecutionContext.SessionState"                                   = '$ExecutionContext may only be used'
    "[Reflection.Assembly]::Lo~ad(`$b)"                                  = "forbidden member 'Load'"
    "[System.Reflection.Assembly]::Load~From('x')"                       = "forbidden member 'LoadFrom'"
    "[System.Reflection.Assembly]::Load~File('x')"                       = "forbidden member 'LoadFile'"
    "[scriptblock]::Cre~ate('1')"                                        = "forbidden member 'Create'"
    "`$sb.Invoke()"                                                     = "forbidden member 'Invoke'"
    "`$x.`$name()"                                                      = 'member name is not a literal'
    "[IO.File]::WriteAllText('a', 'b')"                                 = 'static .NET member'
    "New-Object System.Net.Sockets.Tcp~Client"                          = 'New-Object type'
    "`$x.Foo()"                                                         = 'is not on the allow-list'
    # --- scripts, modules and call operators
    "& `".\other.ps1`""                                                 = 'call operator'
    ". .\other.ps1"                                                     = 'call operator'
    "& 'C:\x\y.exe'"                                                    = 'call operator'
    "Invoke-Command -Session `$session -FilePath .\other.ps1"           = '-FilePath is not allowed'
    "Invoke-Command -Session `$session -ScriptBlock { 1 }"              = 'must be a variable'
    "Import-Mod~ule \\server\share\m.psm1"                              = "command 'Import-Module' is not on the allow-list"
    "Set-ItemPro~perty 'HKLM:\SOFTWARE\Policies\Micro~soft\Windows Def~ender' -Name 'X' -Value 1" = "forbidden command 'Set-ItemProperty'"
    "Stop-Ser~vice -Name 'NoSuchService'"                               = "forbidden command 'Stop-Service'"
    "Disable-NetFire~wallProfile -Profile Domain"                       = "forbidden command 'Disable-NetFirewallProfile'"
    "'a' > out.txt"                                                     = 'redirection to a file is forbidden'
    "function Evil { 1 }"                                               = "is not one of the runner's own functions"
    "`$markerBlock = { 1 }"                                             = 'assigned exactly once'
}
foreach ($key in $added.Keys) { $line = $key.Replace('~', ''); Test-Case "add: $line" ($runner + "`n" + $line + "`n") $added[$key] }

# 2. The same dangers inside a script block that is sent to the target (the remote allow-list is tighter).
$importLine = "Import-Module -Name 'Invoke-AtomicRedTeam' -ErrorAction Stop"
$remote = [ordered]@{
    "power~shell -enc AAAA"                          = "forbidden native command 'powershell'"
    "Start-Pro~cess notepad"                         = "forbidden command 'Start-Process'"
    "cmd /c echo hello"                              = "forbidden native command 'cmd'"
    "Write-Host hello"                               = 'not on the allow-list for script blocks sent to the target'
    "Get-Date"                                       = 'not on the allow-list for script blocks sent to the target'
    "Invoke-E~xpression 'Get-Date'"                  = "forbidden command 'Invoke-Expression'"
    "Import-Module -Name 'C:\x\m.psm1' -ErrorAction Stop" = 'may only import'
    "Import-Module -Name \\server\share\m.psm1"      = 'may only import'
    "Import-Module -Name 'Invoke-AtomicRedTeam' -Force" = 'parameter -Force is not allowed'
    "New-Object System.Net.Web~Client"               = 'New-Object type'
    "`$x = [Reflection.Assembly]::Lo~ad(`$b)"        = "forbidden member 'Load'"
}
foreach ($key in $remote.Keys) {
    $line = $key.Replace('~', '')
    Test-Case "remote: $line" (Edit-Runner $importLine $line) $remote[$key]
}
Test-Case 'remote: Invoke-AtomicTest -GetPrereqs' (Edit-Runner '-CheckPrereqs' '-GetPrereqs') 'parameter -GetPrereqs is not allowed'

# 3. Removing or weakening a safety gate must be reported.
$gates = [ordered]@{
    'allow-list call renamed'          = @('Test-AllowListed -Name $Target', 'Test-Listed -Name $Target', 'missing the allow-list gate')
    'allow-list compares with -like'   = @('$entry -eq $Name', '$entry -like $Name', 'compare names exactly')
    'typed confirmation removed'       = @('Read-Host', 'Get-Date', 'prompt exactly once')
    'typed confirmation made loose'    = @('-cne $Target', '-ne $Target', 'typed-confirmation gate')
    'typed mismatch no longer refuses' = @("Stop-Refused ""the typed name did not match '`$Target'.""", 'Write-Host "no"', 'typed-confirmation gate')
    'remote call before confirmation'  = @('    $typed = Read-Host', "    `$null = Invoke-Command -Session `$session -ScriptBlock `$cleanupBlock -ArgumentList 'T1003.001', 'x', 'C:\a'`n    `$typed = Read-Host", 'before the typed confirmation')
    'Credential parameter removed'     = @('[System.Management.Automation.PSCredential]$Credential,', '', 'missing parameter -Credential')
    'Credential parameter retyped'     = @('[System.Management.Automation.PSCredential]$Credential', '[string]$Credential', 'must be a PSCredential')
    'Credential refusal removed'       = @('if (-not $Credential)', 'if (-not $Other)', 'refusal when -Credential is not supplied')
    'WhatIf branch needs a credential' = @('if ($WhatIfPreference) {', 'if ($WhatIfPreference -and $Credential) {', 'missing the -WhatIf branch')
    'WhatIf branch uses the credential' = @('Write-Host "WhatIf: target', '$null = $Credential; Write-Host "WhatIf: target', 'must not use a credential')
    'WhatIf branch does not end'       = @("    return`n}", "    Write-Host 'x'`n}", 'must end the script')
    'Target no longer mandatory'       = @('[Parameter(Mandatory = $true)]', '[Parameter()]', 'must be Mandatory')
    'refusal no longer exits non-zero' = @('exit 1', 'exit 0', 'exit with code 1')
    'marker test inverted'             = @('$info.Marker -ne 1', '$info.Marker -eq 1', 'marker gate')
    'marker mismatch no longer refuses' = @('Stop-Refused "the registry marker', 'Write-Host "the registry marker', 'marker gate')
    'marker block no longer reads LabTarget' = @("-Name 'LabTarget'", "-Name 'Other'", 'marker block must read')
    'session to another computer'      = @('ComputerName = $Target', 'ComputerName = $Other', 'must set ComputerName')
    'session with extra arguments'     = @('New-PSSession @sessionArgs', 'New-PSSession @sessionArgs -Name x', 'only')
    'session name changed after build' = @('$sessionArgs.UseSSL = $true', '$sessionArgs.ComputerName = $Other', 'must not be changed')
    'no -Session on a remote call'     = @('Invoke-Command -Session $session -ScriptBlock $utcNowBlock', 'Invoke-Command -ScriptBlock $utcNowBlock', 'must use -Session')
    'unknown remote block'             = @('-ScriptBlock $cleanupBlock', '-ScriptBlock $otherBlock', 'otherBlock')
    'New-Object type changed'          = @('System.Text.UTF8Encoding', 'System.Net.Web~Client', 'New-Object type')
}
foreach ($name in $gates.Keys) {
    $g = $gates[$name]
    Test-Case "gate: $name" (Edit-Runner $g[0] $g[1]) $g[2]
}

# 4. The committed fixture with a forbidden command (parsed from disk, as CI does for the runner).
$script:count++
$fixture = Join-Path $root 'selftest\forbidden-command.fixture.ps1'
$out = @(& $checker -Path $fixture -PassThru)
if (-not ($out | Where-Object { $_ -like "*forbidden command 'Invoke-Expression'*" })) { $failures.Add("fixture: expected a forbidden Invoke-Expression, got: $($out -join ' | ')") }
else { Write-Host 'ok   fixture file (fails: forbidden Invoke-Expression)' }

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    exit 1
}
Write-Host "Static checker self-test passed ($($script:count) cases)."
