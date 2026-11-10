<#
.SYNOPSIS
    Test helper: extracts the Test-AllowListed function from the lab runner with the PowerShell parser and
    calls it alone. Prints True, False or "REFUSED: ...". Never runs the runner itself.
#>
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$Script
)
$ErrorActionPreference = 'Stop'
if (-not $Script) {
    $root = $PSScriptRoot
    if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
    $Script = Join-Path $root 'Invoke-PurpleBenchRun.ps1'
}
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Script).Path, [ref]$tokens, [ref]$errors)
$fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-AllowListed' }, $true)
if ($null -eq $fn) { Write-Output 'NO-FUNCTION'; exit 2 }
# The runner's Stop-Refused exits the process; here it reports instead.
function Stop-Refused { param([string]$Reason) throw "REFUSED: $Reason" }
. ([scriptblock]::Create($fn.Extent.Text))
try { Write-Output ([string](Test-AllowListed -Name $Name -Path $Path)) }
catch { Write-Output $_.Exception.Message }
