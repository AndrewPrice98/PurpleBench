# Test fixture for Test-RunnerStatic.SelfTest.ps1. The static check must FAIL on this file.
# It is parsed and never run; the forbidden call is harmless (it evaluates the current date).
param()
Invoke-Expression -Command 'Get-Date'
