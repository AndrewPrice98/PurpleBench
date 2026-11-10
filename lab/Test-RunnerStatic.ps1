<#
.SYNOPSIS
    Static safety check of the lab runner. Parses the script with the PowerShell parser (never runs it)
    and fails on parse errors, forbidden commands or dynamic code execution.
#>
[CmdletBinding()]
param(
    [string]$Path
)

$ErrorActionPreference = 'Stop'
if (-not $Path) {
    $root = $PSScriptRoot
    if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
    $Path = Join-Path $root 'Invoke-PurpleBenchRun.ps1'
}
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Path).Path, [ref]$tokens, [ref]$errors)

$problems = New-Object System.Collections.Generic.List[string]
foreach ($e in $errors) { $problems.Add("parse error at line $($e.Extent.StartLineNumber): $($e.Message)") }

$forbiddenCommands = @(
    'Invoke-Expression', 'iex', 'Invoke-WebRequest', 'iwr', 'Invoke-RestMethod', 'irm', 'curl', 'wget',
    'Start-BitsTransfer', 'Install-Module', 'Install-Package', 'Save-Module', 'Save-Package', 'Install-Script',
    'Enable-PSRemoting', 'Set-Item', 'Set-WSManInstance', 'Add-MpPreference', 'Set-MpPreference'
)
$forbiddenMembers = @('DownloadString', 'DownloadFile', 'DownloadData', 'DownloadStringAsync', 'OpenRead', 'WebClient')

$commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
foreach ($c in $commands) {
    $name = $c.GetCommandName()
    if ($null -eq $name) {
        $problems.Add("line $($c.Extent.StartLineNumber): command name is not a literal ('$($c.Extent.Text)'); dynamic invocation is forbidden")
        continue
    }
    if ($forbiddenCommands -contains $name) { $problems.Add("line $($c.Extent.StartLineNumber): forbidden command '$name'") }
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

$required = @('SupportsShouldProcess', 'WhatIfPreference', 'LabTarget', 'Read-Host', '-Cleanup', 'Get-WinEvent')
$text = Get-Content -LiteralPath $Path -Raw
foreach ($r in $required) { if ($text.IndexOf($r, [StringComparison]::Ordinal) -lt 0) { $problems.Add("missing required safety element '$r'") } }

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    exit 1
}
Write-Host "Lab runner static check passed ($($commands.Count) commands inspected)."
