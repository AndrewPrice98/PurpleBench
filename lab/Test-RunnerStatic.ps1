<#
.SYNOPSIS
    Static safety check of the lab runner: an ALLOW-LIST check on the PowerShell syntax tree. It parses the script with
    the PowerShell parser (never runs it) and fails on anything the runner is not meant to do.

.DESCRIPTION
    A deny-list is always incomplete, so this check works the other way round:
      * every command must have a literal bare-word name that is on an explicit allow-list (one list for the local
        script, a tighter one for the script blocks that are sent to the target); native executables, aliases,
        paths, quoted or computed names, the call operator (&) and dot-sourcing all fail;
      * .NET calls must be on a short allow-list (static calls by type and member, instance calls by member name);
        New-Object only for allow-listed types;
      * -EncodedCommand (any abbreviation) fails on any command, Set-Alias/New-Alias fail, and so does everything
        else that is not listed;
      * Invoke-Command may only use -Session, -ScriptBlock and -ArgumentList, with a script block held in a variable
        that is assigned once;
      * the safety gates are checked structurally (an if statement that calls Stop-Refused, in the right order), not
        by looking for words.
    A deny-list of well-known bad commands is kept only to give clearer messages.

    This is defence in depth, not a sandbox: it reads the script's text structure and cannot prove what a script does
    at run time. The runner is meant to be read by its operator before it is used.
.NOTES
    -ScriptText and -PassThru exist for Test-RunnerStatic.SelfTest.ps1 (nothing is written to disk).
#>
[CmdletBinding()]
param(
    [string]$Path,
    [string]$ScriptText,
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
function Add-Problem($node, [string]$text) { $problems.Add("line $($node.Extent.StartLineNumber): $text") }
foreach ($e in $errors) { $problems.Add("parse error at line $($e.Extent.StartLineNumber): $($e.Message)") }

# ---- the allow-lists -------------------------------------------------------------------------------------------
# Commands the local part of the runner uses (derived from the runner; keep it tight).
$localCommands = @(
    'Set-StrictMode', 'Test-Path', 'Split-Path', 'Join-Path', 'Get-Content', 'ConvertFrom-Json', 'ConvertTo-Json',
    'Get-Date', 'Get-Location', 'Write-Host', 'Write-Warning', 'Read-Host', 'Start-Sleep', 'Where-Object',
    'Select-Object', 'New-Object', 'New-PSSession', 'Invoke-Command', 'Remove-PSSession',
    # the runner's own functions (their definitions are checked too, and no other function may be defined)
    'Stop-Refused', 'Test-AllowListed', 'ConvertTo-IsoUtc', 'Get-RoundtripDate'
)
$ownFunctions = @('Stop-Refused', 'Test-AllowListed', 'ConvertTo-IsoUtc', 'Get-RoundtripDate')
# Commands inside the script blocks that run on the target.
$remoteCommands = @(
    'Get-ItemProperty', 'Get-WinEvent', 'Get-Module', 'Import-Module', 'Invoke-AtomicTest', 'Out-String',
    'ForEach-Object', 'New-Object'
)
$allowedNewObject = @('System.Collections.Generic.List[string]', 'System.Collections.Generic.List[object]',
    'System.Text.UTF8Encoding', 'System.IO.FileStream')
$allowedInvokeAtomicParams = @('TestGuids', 'PathToAtomicsFolder', 'CheckPrereqs', 'Cleanup', 'Confirm', 'ErrorAction', 'ErrorVariable')
$allowedInvokeCommandParams = @('Session', 'ScriptBlock', 'ArgumentList')
# .NET: static calls and properties by Type::Member, instance calls by member name.
$allowedStatic = @('DateTime::Parse', 'DateTime::UtcNow', 'string::IsNullOrWhiteSpace',
    'System.Globalization.CultureInfo::InvariantCulture', 'System.Globalization.DateTimeStyles::RoundtripKind',
    'System.IO.FileMode::CreateNew', 'System.IO.FileAccess::Write', 'System.IO.FileShare::None')
$allowedInstanceCalls = @('ToString', 'ToXml', 'GetUnresolvedProviderPathFromPSPath', 'Add', 'ToArray', 'Dispose', 'Write',
    'ToLowerInvariant', 'ShouldProcess', 'Substring', 'ToUniversalTime', 'ToLocalTime', 'Trim', 'AddSeconds', 'GetBytes')
# Member names that fail anywhere (kept for the clearer message; anything not listed above fails anyway).
$deniedMembers = @('InvokeScript', 'InvokeCommand', 'NewScriptBlock', 'ExpandString', 'Load', 'LoadFrom', 'LoadFile',
    'LoadWithPartialName', 'DownloadString', 'DownloadFile', 'DownloadData', 'DownloadStringAsync', 'UploadString',
    'UploadFile', 'UploadData', 'OpenRead', 'Create', 'Invoke', 'GetType', 'CreateInstance')
# Deny-list, for the clearer message only.
$denyCommands = @('Invoke-Expression', 'iex', 'Invoke-WebRequest', 'iwr', 'Invoke-RestMethod', 'irm', 'curl', 'wget',
    'Start-BitsTransfer', 'Install-Module', 'Install-Package', 'Save-Module', 'Save-Package', 'Install-Script',
    'Enable-PSRemoting', 'Set-Item', 'Set-WSManInstance', 'Add-MpPreference', 'Set-MpPreference', 'Start-Process',
    'start', 'saps', 'Add-Type', 'Invoke-Item', 'Set-ExecutionPolicy', 'Enter-PSSession', 'Invoke-WmiMethod',
    'Invoke-CimMethod', 'Register-ScheduledTask', 'New-Service', 'Set-Service', 'Stop-Service', 'Format-Volume',
    'Clear-EventLog', 'Remove-EventLog', 'Clear-Disk', 'Initialize-Disk', 'Remove-Partition', 'Stop-Computer',
    'Restart-Computer', 'Remove-Item', 'Set-ItemProperty', 'New-ItemProperty', 'Disable-NetFirewallProfile',
    'Set-Alias', 'New-Alias', 'sal', 'nal', 'Set-Variable')
$denyNative = @('powershell', 'powershell.exe', 'pwsh', 'pwsh.exe', 'cmd', 'cmd.exe', 'certutil', 'bitsadmin', 'mshta',
    'rundll32', 'regsvr32', 'reg', 'sc', 'netsh', 'schtasks', 'wevtutil', 'vssadmin', 'bcdedit', 'diskpart', 'cipher',
    'format', 'wmic', 'net', 'net1')
$encodedParam = '^(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)$'

# ---- helpers ---------------------------------------------------------------------------------------------------
function Test-Inside($node, $ranges) {
    foreach ($r in $ranges) { if ($node.Extent.StartOffset -ge $r[0] -and $node.Extent.EndOffset -le $r[1]) { return $true } }
    return $false
}
function Get-CommandCalls($within, [string]$name) {
    @($within.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $name }, $true))
}
function In-List([string[]]$list, [string]$value) { return [bool]($list | Where-Object { $_ -ieq $value }) }

$commandAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))

# ---- Invoke-Command: -Session, -ScriptBlock (a variable assigned once), -ArgumentList only ----------------------------
$remoteVars = @{}
foreach ($c in @($commandAsts | Where-Object { $_.GetCommandName() -eq 'Invoke-Command' })) {
    $els = @($c.CommandElements | Select-Object -Skip 1)
    $seen = @{}
    for ($i = 0; $i -lt $els.Count; $i++) {
        $el = $els[$i]
        if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { Add-Problem $c 'Invoke-Command: an argument that is not the value of -Session, -ScriptBlock or -ArgumentList'; continue }
        $canon = $allowedInvokeCommandParams | Where-Object { $_ -ieq $el.ParameterName }
        if (-not $canon) { Add-Problem $c "Invoke-Command: parameter -$($el.ParameterName) is not allowed (only -Session, -ScriptBlock and -ArgumentList, spelled in full; no -FilePath, no -ComputerName)"; continue }
        $seen[$canon] = $true
        if ($canon -eq 'ScriptBlock') {
            $val = $null
            if ($el.Argument) { $val = $el.Argument } elseif ($i + 1 -lt $els.Count) { $val = $els[$i + 1]; $i++ }
            if ($val -is [System.Management.Automation.Language.VariableExpressionAst]) { $remoteVars[$val.VariablePath.UserPath] = $true }
            else { Add-Problem $c 'Invoke-Command: -ScriptBlock must be a variable that holds a script block assigned once in the script' }
        } elseif ($canon -eq 'Session') {
            if (-not $el.Argument) { $i++ }
        } else {  # ArgumentList takes the elements up to the next parameter
            while ($i + 1 -lt $els.Count -and $els[$i + 1] -isnot [System.Management.Automation.Language.CommandParameterAst]) { $i++ }
        }
    }
    if (-not $seen['Session'] -or -not $seen['ScriptBlock']) { Add-Problem $c 'Invoke-Command must use -Session and -ScriptBlock' }
}
$assignments = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))
$remoteRanges = New-Object System.Collections.Generic.List[object]
$remoteByVar = @{}
foreach ($v in $remoteVars.Keys) {
    $mine = @($assignments | Where-Object { $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Left.VariablePath.UserPath -ieq $v })
    $sb = $null
    if ($mine.Count -eq 1 -and $mine[0].Right -is [System.Management.Automation.Language.CommandExpressionAst] -and
        $mine[0].Right.Expression -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $sb = $mine[0].Right.Expression }
    if ($null -eq $sb) { $problems.Add("script block variable `$$v must be assigned exactly once, directly from a { script block } literal") }
    else { $remoteRanges.Add(@($sb.Extent.StartOffset, $sb.Extent.EndOffset)); $remoteByVar[$v] = $sb }
}

# ---- every command: literal bare-word name on the allow-list --------------------------------------------------------
foreach ($c in $commandAsts) {
    $name = $c.GetCommandName()
    if ($null -eq $name) { Add-Problem $c "command name is not a literal ('$($c.Extent.Text.Split([char]10)[0])'); dynamic invocation is forbidden"; continue }
    $first = $c.CommandElements[0]
    if ($c.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown) { Add-Problem $c "the call operator and dot-sourcing are forbidden ('$name')"; continue }
    if ($first -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $first.StringConstantType -ne [System.Management.Automation.Language.StringConstantType]::BareWord) { Add-Problem $c "command name '$name' must be a bare word, not a quoted string"; continue }
    $remote = Test-Inside $c $remoteRanges
    $list = $localCommands
    if ($remote) { $list = $remoteCommands }
    if (-not (In-List $list $name)) {
        if (In-List $denyCommands $name) { Add-Problem $c "forbidden command '$name' (not on the allow-list)" }
        elseif (In-List $denyNative $name) { Add-Problem $c "forbidden native command '$name' (not on the allow-list)" }
        elseif ($name -match '[\\/:]|\.(exe|com|bat|cmd|ps1|psm1|dll|vbs|js)$') { Add-Problem $c "'$name' looks like a path or a native executable; only allow-listed cmdlets may be called" }
        else {
            $where = ''
            if ($remote) { $where = ' for script blocks sent to the target' }
            Add-Problem $c "command '$name' is not on the allow-list$where"
        }
        continue
    }
    foreach ($el in $c.CommandElements) {
        if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
        if ($el.ParameterName -match $encodedParam) { Add-Problem $c "parameter -$($el.ParameterName) (an abbreviation of -EncodedCommand) is forbidden on every command" }
    }
    $pnames = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
    if ($name -ieq 'Invoke-AtomicTest') {
        foreach ($p in $pnames) { if (-not (In-List $allowedInvokeAtomicParams $p)) { Add-Problem $c "Invoke-AtomicTest: parameter -$p is not allowed (never -GetPrereqs, which downloads)" } }
    }
    if ($name -ieq 'Import-Module') {
        $okName = $false
        $els = @($c.CommandElements)
        for ($i = 1; $i -lt $els.Count; $i++) {
            if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst]) {
                if ($els[$i].ParameterName -ieq 'Name' -and $i + 1 -lt $els.Count -and $els[$i + 1] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $els[$i + 1].Value -ieq 'Invoke-AtomicRedTeam') { $okName = $true; $i++ }
                elseif ($els[$i].ParameterName -ieq 'ErrorAction') { $i++ }
                else { Add-Problem $c "Import-Module: parameter -$($els[$i].ParameterName) is not allowed" }
            } else { Add-Problem $c "Import-Module: only -Name 'Invoke-AtomicRedTeam' (a module name, never a path) is allowed" }
        }
        if (-not $okName) { Add-Problem $c "Import-Module may only import 'Invoke-AtomicRedTeam' by name" }
    }
    if ($name -ieq 'New-Object') {
        $typeEl = $c.CommandElements | Select-Object -Skip 1 | Select-Object -First 1
        $typeText = $null
        if ($typeEl -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $typeText = $typeEl.Value } elseif ($typeEl) { $typeText = $typeEl.Extent.Text }
        if (-not (In-List $allowedNewObject $typeText)) { Add-Problem $c "New-Object type '$typeText' is not on the allow-list" }
    }
}

# ---- .NET members --------------------------------------------------------------------------------------------------
foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)) {
    $member = $null
    if ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $member = $m.Member.Value }
    if ($null -eq $member) { Add-Problem $m 'member name is not a literal (dynamic member access is forbidden)'; continue }
    if (In-List $deniedMembers $member) { Add-Problem $m "forbidden member '$member'"; continue }
    $isCall = $m -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
    if ($m.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
        $tn = $m.Expression.TypeName.FullName
        if (-not (In-List $allowedStatic "${tn}::$member")) { Add-Problem $m "static .NET member [$tn]::$member is not on the allow-list" }
    } elseif ($isCall) {
        if (-not (In-List $allowedInstanceCalls $member)) { Add-Problem $m "method .$member() is not on the allow-list" }
    }
}
foreach ($v in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -ieq 'ExecutionContext' }, $true)) {
    # allowed only as $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(...)
    $p1 = $v.Parent
    $p2 = $null; if ($p1) { $p2 = $p1.Parent }
    $p3 = $null; if ($p2) { $p3 = $p2.Parent }
    $ok = ($p1 -is [System.Management.Automation.Language.MemberExpressionAst] -and $p1.Member.Value -ieq 'SessionState' -and
        $p2 -is [System.Management.Automation.Language.MemberExpressionAst] -and $p2.Member.Value -ieq 'Path' -and
        $p3 -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $p3.Member.Value -ieq 'GetUnresolvedProviderPathFromPSPath')
    if (-not $ok) { Add-Problem $v '$ExecutionContext may only be used as $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(...)' }
}

# ---- other syntax that is not needed ------------------------------------------------------------------------------
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if (-not (In-List $ownFunctions $f.Name)) { Add-Problem $f "function '$($f.Name)' is not one of the runner's own functions" }
}
foreach ($u in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.UsingStatementAst] }, $true)) { Add-Problem $u '"using" statements are forbidden' }
foreach ($r in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst] }, $true)) { Add-Problem $r 'redirection to a file is forbidden (the run file is written through the checked FileStream only)' }

# ---- the session is opened to the named target only -------------------------------------------------------------------
$sessionCalls = @(Get-CommandCalls $ast 'New-PSSession')
if ($sessionCalls.Count -ne 1) { $problems.Add('the script must open exactly one session (New-PSSession)') }
foreach ($sc in $sessionCalls) {
    $sargs = @($sc.CommandElements | Select-Object -Skip 1)
    if ($sargs.Count -ne 1 -or $sargs[0] -isnot [System.Management.Automation.Language.VariableExpressionAst] -or -not $sargs[0].Splatted -or $sargs[0].VariablePath.UserPath -ne 'sessionArgs') {
        Add-Problem $sc 'New-PSSession must be called as New-PSSession @sessionArgs only'
    }
}
$sessArgsAssign = @($assignments | Where-Object { $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Left.VariablePath.UserPath -eq 'sessionArgs' })
if ($sessArgsAssign.Count -ne 1) { $problems.Add('$sessionArgs must be assigned exactly once') }
else {
    $ht = $sessArgsAssign[0].Right.Expression
    $cn = $null
    if ($ht -is [System.Management.Automation.Language.HashtableAst]) {
        foreach ($kv in $ht.KeyValuePairs) { if ($kv.Item1.Extent.Text -ieq 'ComputerName') { $cn = $kv.Item2.Extent.Text } }
    }
    if ($cn -ne '$Target') { $problems.Add('$sessionArgs must set ComputerName = $Target (the one allow-listed target)') }
}
foreach ($a in $assignments) {
    if ($a.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and $a.Left.Expression.Extent.Text -eq '$sessionArgs' -and $a.Left.Member.Extent.Text -ne 'UseSSL') {
        Add-Problem $a "`$sessionArgs.$($a.Left.Member.Extent.Text) must not be changed"
    }
}

# ---- parameters the gates hang on (from the param block) -----------------------------------------------------------
$paramNames = @{}
if ($ast.ParamBlock) { foreach ($pa in $ast.ParamBlock.Parameters) { $paramNames[$pa.Name.VariablePath.UserPath] = $pa } }
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
if ($paramNames.ContainsKey('Credential') -and $paramNames['Credential'].StaticType -ne [System.Management.Automation.PSCredential]) { $problems.Add('parameter -Credential must be a PSCredential') }
$hasShouldProcess = $false
if ($ast.ParamBlock) {
    foreach ($attr in $ast.ParamBlock.Attributes) {
        if ($attr.TypeName.Name -eq 'CmdletBinding') { foreach ($na in $attr.NamedArguments) { if ($na.ArgumentName -eq 'SupportsShouldProcess' -and $na.Argument.Extent.Text -match 'true') { $hasShouldProcess = $true } } }
    }
}
if (-not $hasShouldProcess) { $problems.Add('[CmdletBinding(SupportsShouldProcess)] is required (it provides -WhatIf)') }

# ---- the gates, structurally ----------------------------------------------------------------------------------------
$ifs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] }, $true))
function Get-GateIf([scriptblock]$condition) {
    # The condition of an if statement that matches, with a clause body that calls Stop-Refused.
    foreach ($if in $ifs) {
        foreach ($cl in $if.Clauses) {
            if ((& $condition $cl.Item1) -and (Get-CommandCalls $cl.Item2 'Stop-Refused').Count -gt 0) { return $cl.Item1 }
        }
    }
    return $null
}
function Has-Text($expr, [string]$pattern) { return ($expr.Extent.Text -match $pattern) }
$firstSession = [int]::MaxValue
if ($sessionCalls.Count -gt 0) { $firstSession = $sessionCalls[0].Extent.StartOffset }

# 1. allow-list: if (-not (Test-AllowListed ...)) { Stop-Refused } before any session
$gAllow = Get-GateIf { param($x) (Has-Text $x '^\s*-not\s*\(\s*Test-AllowListed\b') -and (Has-Text $x '-Name\s+\$Target\b') }
if ($null -eq $gAllow) { $problems.Add('missing the allow-list gate: if (-not (Test-AllowListed -Name $Target ...)) { Stop-Refused ... }') }
elseif ($gAllow.Extent.StartOffset -gt $firstSession) { $problems.Add('the allow-list gate must come before New-PSSession') }
$fnAllow = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-AllowListed' }, $true)
if ($null -eq $fnAllow) { $problems.Add('missing function Test-AllowListed') }
elseif ($fnAllow.Extent.Text -match '(?i)\s-(like|match|clike|cmatch|notlike|notmatch)\b') { $problems.Add('Test-AllowListed must compare names exactly, not with -like or -match') }
# 2. -WhatIf is handled before any credential check, never needs a credential and ends the script
$whatIf = $ifs | Where-Object { $_.Clauses[0].Item1.Extent.Text.Trim() -eq '$WhatIfPreference' } | Select-Object -First 1
if ($null -eq $whatIf) { $problems.Add('missing the -WhatIf branch (if ($WhatIfPreference) { ... return })') }
else {
    $wBody = $whatIf.Clauses[0].Item2
    $returns = @($wBody.FindAll({ param($n) $n -is [System.Management.Automation.Language.ReturnStatementAst] -or $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
    if ($returns.Count -eq 0) { Add-Problem $whatIf 'the -WhatIf branch must end the script (return)' }
    if ($wBody.Extent.Text -match '(?i)\$Credential\b|New-PSSession|Invoke-Command|Read-Host|FileStream') { Add-Problem $whatIf 'the -WhatIf branch must not use a credential, open a session, prompt or write a file' }
}
# 3. -Credential is refused when missing, after -WhatIf and before the session
$gCred = Get-GateIf { param($x) (Has-Text $x '^\s*-not\s+\$Credential\s*$') }
if ($null -eq $gCred) { $problems.Add('missing the refusal when -Credential is not supplied: if (-not $Credential) { Stop-Refused ... }') }
else {
    if ($gCred.Extent.StartOffset -gt $firstSession) { $problems.Add('the -Credential check must come before New-PSSession') }
    if ($whatIf -and $gCred.Extent.StartOffset -lt $whatIf.Extent.StartOffset) { $problems.Add('the -WhatIf branch must come before the -Credential check so that -WhatIf works without a credential') }
}
# 4. the registry marker is checked, with a refusal, after the first (read-only) remote call and before anything else remote
$icCalls = @(Get-CommandCalls $ast 'Invoke-Command' | Sort-Object { $_.Extent.StartOffset })
function Get-BlockVar($call) {
    $els = @($call.CommandElements)
    for ($i = 1; $i -lt $els.Count - 1; $i++) {
        if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$i].ParameterName -ieq 'ScriptBlock' -and $els[$i + 1] -is [System.Management.Automation.Language.VariableExpressionAst]) { return $els[$i + 1].VariablePath.UserPath }
    }
    return $null
}
$markerCall = $icCalls | Where-Object { (Get-BlockVar $_) -eq 'markerBlock' } | Select-Object -First 1
if ($null -eq $markerCall) { $problems.Add('missing the remote marker check (Invoke-Command -Session $session -ScriptBlock $markerBlock)') }
else {
    if ($icCalls[0].Extent.StartOffset -ne $markerCall.Extent.StartOffset) { Add-Problem $icCalls[0] 'the first remote call must be the marker check' }
    $mb = $remoteByVar['markerBlock']
    if ($null -eq $mb -or $mb.Extent.Text -notmatch 'HKLM:\\SOFTWARE\\PurpleBench' -or $mb.Extent.Text -notmatch "'LabTarget'") { $problems.Add('the marker block must read HKLM:\SOFTWARE\PurpleBench LabTarget') }
}
$gMarker = Get-GateIf { param($x) (Has-Text $x '\$info\.Marker\s+-isnot\s+\[int\]') -and (Has-Text $x '\$info\.Marker\s+-ne\s+1\b') }
if ($null -eq $gMarker) { $problems.Add('missing the marker gate: if (($info.Marker -isnot [int]) -or ($info.Marker -ne 1)) { Stop-Refused ... }') }
elseif ($markerCall -and $gMarker.Extent.StartOffset -lt $markerCall.Extent.StartOffset) { $problems.Add('the marker gate must come after the marker check call') }
# 5. typed confirmation: the Read-Host answer is compared with -cne $Target in an if that calls Stop-Refused
$readHost = @(Get-CommandCalls $ast 'Read-Host')
$typedVar = $null
if ($readHost.Count -ne 1) { $problems.Add('the script must prompt exactly once with Read-Host (the typed confirmation)') }
else {
    $asg = $readHost[0]
    while ($asg -and $asg -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { $asg = $asg.Parent }
    if ($asg -and $asg.Left -is [System.Management.Automation.Language.VariableExpressionAst]) { $typedVar = $asg.Left.VariablePath.UserPath }
    if ($null -eq $typedVar) { $problems.Add('the Read-Host answer must be assigned to a variable') }
}
$gTyped = $null
if ($typedVar) {
    $typedPattern = '^\s*\$' + [regex]::Escape($typedVar) + '\s+-cne\s+\$Target\s*$'
    $gTyped = Get-GateIf { param($x) (Has-Text $x $typedPattern) }
    if ($null -eq $gTyped) { $problems.Add('missing the typed-confirmation gate: if ($typed -cne $Target) { Stop-Refused ... } (exact, case-sensitive)') }
}
# 6. order: allow-list < whatif < credential < session < marker call < marker gate < typed gate < every state-changing remote call
if ($gMarker -and $gTyped -and $gTyped.Extent.StartOffset -lt $gMarker.Extent.StartOffset) { $problems.Add('the typed confirmation must come after the marker gate') }
foreach ($ic in $icCalls) {
    $bv = Get-BlockVar $ic
    if (-not (@('markerBlock', 'utcNowBlock', 'runBlock', 'cleanupBlock', 'collectBlock') -contains $bv)) { Add-Problem $ic "remote script block `$$bv is not one of the runner's known blocks" }
    if ($gTyped -and (@('runBlock', 'cleanupBlock', 'collectBlock') -contains $bv) -and $ic.Extent.StartOffset -lt $gTyped.Extent.StartOffset) {
        Add-Problem $ic "remote call with `$$bv before the typed confirmation"
    }
}
# the refusal helper must exit non-zero
$stop = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Stop-Refused' }, $true)
if ($null -eq $stop) { $problems.Add('missing function Stop-Refused') }
else {
    $ex = @($stop.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
    if (@($ex | Where-Object { $_.Pipeline -and $_.Pipeline.Extent.Text.Trim() -eq '1' }).Count -eq 0) { $problems.Add('Stop-Refused must exit with code 1') }
}
# the run file is created exclusively (never overwrites); collection tells "no events" from an error
$code = (@($tokens | Where-Object { $_.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment } | ForEach-Object { $_.Text }) -join ' ')
foreach ($r in @('CreateNew', 'GetUnresolvedProviderPathFromPSPath', '-Cleanup', 'NoMatchingEventsFound')) {
    if ($code.IndexOf($r, [StringComparison]::Ordinal) -lt 0) { $problems.Add("missing required element '$r'") }
}

if ($PassThru) { return , $problems.ToArray() }
if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    exit 1
}
Write-Host "Lab runner static check passed ($($commandAsts.Count) commands inspected, allow-list)."
