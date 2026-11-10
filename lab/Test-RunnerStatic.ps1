<#
.SYNOPSIS
    Static safety check of the lab runner. Parses the script with the PowerShell parser (never runs it)
    and fails on parse errors, forbidden commands, dynamic code execution or missing safety elements.
    Required elements are looked up in the code tokens only, so a comment cannot satisfy a check.
#>
[CmdletBinding()]
param(
    [string]$Path,
    # Check script text instead of a file (used by Test-RunnerStatic.SelfTest.ps1, so nothing is written to disk).
    [string]$ScriptText,
    # Return the list of problems instead of exiting (self-test only).
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
if (-not $Path -and -not $ScriptText) {
    $root = $PSScriptRoot
    if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
    $Path = Join-Path $root 'Invoke-PurpleBenchRun.ps1'
}
$tokens = $null
$errors = $null
if ($ScriptText) {
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($ScriptText, [ref]$tokens, [ref]$errors)
} else {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Path).Path, [ref]$tokens, [ref]$errors)
}

$problems = New-Object System.Collections.Generic.List[string]
foreach ($e in $errors) { $problems.Add("parse error at line $($e.Extent.StartLineNumber): $($e.Message)") }

$forbiddenCommands = @(
    'Invoke-Expression', 'iex', 'Invoke-WebRequest', 'iwr', 'Invoke-RestMethod', 'irm', 'curl', 'wget',
    'Start-BitsTransfer', 'Install-Module', 'Install-Package', 'Save-Module', 'Save-Package', 'Install-Script',
    'Enable-PSRemoting', 'Set-Item', 'Set-WSManInstance', 'Add-MpPreference', 'Set-MpPreference',
    'Start-Process', 'Add-Type', 'Invoke-Item', 'Set-ExecutionPolicy', 'Enter-PSSession', 'Invoke-WmiMethod',
    'Invoke-CimMethod', 'Register-ScheduledTask', 'New-Service', 'Set-Service',
    'Format-Volume', 'Clear-EventLog', 'Remove-EventLog', 'Clear-Disk', 'Initialize-Disk', 'Remove-Partition',
    'Stop-Computer', 'Restart-Computer'
)
# Native tools the runner has no reason to call. wevtutil is forbidden only with its clear-log verbs.
$forbiddenNative = @('vssadmin', 'bcdedit', 'diskpart', 'cipher', 'format', 'format.com')
$systemPath = '(?i)(\\|%|\$env:)?(windows|systemroot|windir|system32|syswow64|programfiles|programdata|systemdrive|users\\[^\\]*\\appdata)|^[a-z]:\\?$|^\\?$'
$forbiddenMembers = @('DownloadString', 'DownloadFile', 'DownloadData', 'DownloadStringAsync', 'OpenRead', 'WebClient', 'HttpClient')

$commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
foreach ($c in $commands) {
    $name = $c.GetCommandName()
    if ($null -eq $name) {
        $problems.Add("line $($c.Extent.StartLineNumber): command name is not a literal ('$($c.Extent.Text)'); dynamic invocation is forbidden")
        continue
    }
    if ($forbiddenCommands -contains $name) { $problems.Add("line $($c.Extent.StartLineNumber): forbidden command '$name'") }
    if ($forbiddenNative -contains $name) { $problems.Add("line $($c.Extent.StartLineNumber): forbidden native command '$name'") }
    if ($name -eq 'wevtutil' -and $c.Extent.Text -match '(?i)\s(cl|clear-log)(\s|$)') {
        $problems.Add("line $($c.Extent.StartLineNumber): wevtutil must not clear logs")
    }
    if ($name -eq 'Remove-Item' -or $name -eq 'ri' -or $name -eq 'rm' -or $name -eq 'del' -or $name -eq 'rd' -or $name -eq 'rmdir') {
        $isRecurse = $false
        $pathArgs = New-Object System.Collections.Generic.List[string]
        foreach ($el in ($c.CommandElements | Select-Object -Skip 1)) {
            if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                if ($el.ParameterName -match '^(r|re|rec|recu|recur|recurs|recurse)$') { $isRecurse = $true }
            } else { $pathArgs.Add($el.Extent.Text.Trim('"', "'")) }
        }
        if ($isRecurse) {
            foreach ($pa in $pathArgs) {
                if ($pa -match $systemPath) { $problems.Add("line $($c.Extent.StartLineNumber): Remove-Item -Recurse on a system path ('$pa')") }
                elseif ($pa -match '\$') { $problems.Add("line $($c.Extent.StartLineNumber): Remove-Item -Recurse with a computed path (cannot prove it is not a system path)") }
            }
        }
    }
    if ($c.Extent.Text -match 'Net\.WebClient|Net\.Http|GetPrereqs') { $problems.Add("line $($c.Extent.StartLineNumber): forbidden download construct") }
    if ($name -eq 'Invoke-Command') {
        $params = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
        if ($params -notcontains 'Session') { $problems.Add("line $($c.Extent.StartLineNumber): Invoke-Command must use -Session (the one session to the target)") }
        if ($params -contains 'ComputerName') { $problems.Add("line $($c.Extent.StartLineNumber): Invoke-Command must not name other computers") }
    }
}

$members = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or $n -is [System.Management.Automation.Language.TypeExpressionAst] }, $true)
foreach ($m in $members) {
    foreach ($f in $forbiddenMembers) {
        if ($m.Extent.Text -match [regex]::Escape($f)) { $problems.Add("line $($m.Extent.StartLineNumber): forbidden member or type '$f'") }
    }
    if ($m -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $m.Extent.Text -match 'scriptblock\]\s*::\s*Create') {
        $problems.Add("line $($m.Extent.StartLineNumber): ScriptBlock.Create builds code from strings")
    }
}

# Required safety elements, searched in non-comment tokens only.
$code = (@($tokens | Where-Object { $_.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment } | ForEach-Object { $_.Text }) -join ' ')
$required = @('SupportsShouldProcess', 'WhatIfPreference', 'LabTarget', 'Read-Host', '-Cleanup', 'Get-WinEvent', 'Test-AllowListed',
    'Stop-Refused', 'exit 1', 'CreateNew', 'GetUnresolvedProviderPathFromPSPath', 'NoMatchingEventsFound')
foreach ($r in $required) { if ($code.IndexOf($r, [StringComparison]::Ordinal) -lt 0) { $problems.Add("missing required safety element '$r'") } }

# The parameters the safety gates hang on, read from the param block (not from text).
$paramNames = @{}
if ($ast.ParamBlock) {
    foreach ($pa in $ast.ParamBlock.Parameters) { $paramNames[$pa.Name.VariablePath.UserPath] = $pa }
}
foreach ($need in 'Target', 'Campaign', 'Credential', 'LabTargetsFile') {
    if (-not $paramNames.ContainsKey($need)) { $problems.Add("missing parameter -$need") }
}
foreach ($mand in 'Target', 'Campaign') {
    if ($paramNames.ContainsKey($mand)) {
        $isMand = $false
        foreach ($attr in $paramNames[$mand].Attributes) {
            if ($attr.TypeName.Name -eq 'Parameter') {
                foreach ($na in $attr.NamedArguments) { if ($na.ArgumentName -eq 'Mandatory' -and $na.Argument.Extent.Text -match 'true') { $isMand = $true } }
            }
        }
        if (-not $isMand) { $problems.Add("parameter -$mand must be Mandatory") }
    }
}
# -Credential is the WinRM credential. It is required for every real run: the script refuses (exit 1) when it is
# missing, after the -WhatIf branch (which contacts nothing) and before the session is opened.
if ($paramNames.ContainsKey('Credential')) {
    if ($paramNames['Credential'].StaticType -ne [System.Management.Automation.PSCredential]) { $problems.Add('parameter -Credential must be a PSCredential') }
    $credIf = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -match '^\s*-not\s+\$Credential\s*$' }, $true)
    if ($null -eq $credIf -or $credIf.Extent.Text -notmatch 'Stop-Refused') { $problems.Add('missing the refusal when -Credential is not supplied') }
    else {
        $sess = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-PSSession' }, $true)
        if ($null -eq $sess -or $credIf.Extent.StartOffset -gt $sess.Extent.StartOffset) { $problems.Add('the -Credential check must come before New-PSSession') }
    }
}
# Allow-list and registry marker must be checked before the session is opened / the prompt is shown.
$firstSession = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-PSSession' }, $true)
$allowCall = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Test-AllowListed' }, $true)
if ($null -eq $allowCall -or ($firstSession -and $allowCall.Extent.StartOffset -gt $firstSession.Extent.StartOffset)) { $problems.Add('the allow-list check (Test-AllowListed) must run before New-PSSession') }
$confirm = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Read-Host' }, $true)
if ($null -eq $confirm) { $problems.Add('missing the typed confirmation (Read-Host)') }
elseif ($code -notmatch '-cne\s+\$Target') { $problems.Add('the typed confirmation must compare exactly (-cne $Target)') }

# The refusal helper must exit non-zero.
$stop = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Stop-Refused' }, $true)
if ($null -eq $stop -or $stop.Extent.Text -notmatch 'exit\s+1') { $problems.Add('Stop-Refused must exit with code 1') }

if ($PassThru) { return , $problems.ToArray() }
if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    exit 1
}
Write-Host "Lab runner static check passed ($($commands.Count) commands inspected)."
