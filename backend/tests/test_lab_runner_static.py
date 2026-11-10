"""Static safety checks of the lab runner script. The script is read as text and never executed."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[2] / "lab"
SCRIPT = LAB / "Invoke-PurpleBenchRun.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")


def _code() -> str:
    """The script without comments and the help block (so words in prose do not satisfy a check)."""
    no_block = re.sub(r"<#.*?#>", "", TEXT, flags=re.S)
    return "\n".join(re.sub(r"(?<!['\"`])#.*$", "", ln) for ln in no_block.splitlines())


CODE = _code()


def test_parameters_exist():
    for p in ("$Target", "$Campaign", "$Credential", "$OutFile", "$LabTargetsFile"):
        assert p in CODE
    assert "SupportsShouldProcess" in CODE  # provides -WhatIf


def test_allow_list_check_precedes_any_connection():
    assert "Test-AllowListed" in CODE
    assert CODE.index("Test-AllowListed -Name $Target") < CODE.index("New-PSSession")
    assert "is not in the allow-list" in CODE
    # exact comparison, never wildcard matching, for the allow-list
    body = CODE[CODE.index("function Test-AllowListed"):CODE.index("function Test-AllowListed") + 900]
    assert "-eq $Name" in body and "-like" not in body and "-match" not in body


def test_registry_marker_checked_on_target():
    assert r"HKLM:\SOFTWARE\PurpleBench" in CODE and "LabTarget" in CODE
    assert re.search(r"\$info\.Marker\s+-ne\s+1", CODE)
    assert CODE.index("$info.Marker") < CODE.index("Read-Host") < CODE.index("$runBlock -ArgumentList")


def test_confirmation_prompt_requires_typing_target_name():
    assert "DESTRUCTIVE ACTION" in CODE
    assert re.search(r"Read-Host .*Type the target name", CODE)
    assert re.search(r"\$typed\s+-cne\s+\$Target", CODE)  # exact, case-sensitive
    assert "snapshot" in CODE.lower()


def test_whatif_executes_nothing():
    i = CODE.index("if ($WhatIfPreference)")
    block = CODE[i:CODE.index("return", i) + 6]
    for forbidden in ("New-PSSession", "Invoke-Command", "$runBlock", "WriteAllText", "Read-Host"):
        assert forbidden not in block
    assert i < CODE.index("New-PSSession")


def test_cleanup_after_each_test_in_finally():
    assert "-Cleanup" in CODE
    fin = CODE[CODE.index("finally {"):]
    assert "$cleanupBlock" in fin
    assert CODE.index("$collectBlock -ArgumentList") < CODE.index("$cleanupBlock -ArgumentList")


def test_test_execution_and_event_collection():
    assert "Invoke-AtomicTest $TechniqueId -TestGuids $TestGuid" in CODE
    assert "Get-WinEvent -FilterHashtable" in CODE
    assert "Microsoft-Windows-Sysmon/Operational" in CODE and "'Security'" in CODE
    assert "$PreSeconds = 5" in CODE and "$PostSeconds = 120" in CODE
    assert "purplebench-run" in CODE and "'lab'" in CODE


def test_campaign_values_are_validated_and_passed_as_arguments_not_code():
    assert "$TechniquePattern" in CODE and "$GuidPattern" in CODE
    assert "-ArgumentList $tech, $guid" in CODE


FORBIDDEN = [
    r"Invoke-Expression", r"\biex\b", r"Invoke-WebRequest", r"\biwr\b", r"Invoke-RestMethod", r"\birm\b",
    r"DownloadString", r"DownloadFile", r"DownloadData", r"Start-BitsTransfer", r"Net\.WebClient", r"\bcurl\b",
    r"\bwget\b", r"Install-Module", r"Install-Package", r"Save-Module", r"-GetPrereqs", r"scriptblock\]::Create",
    r"Add-Type", r"Enable-PSRemoting", r"Set-MpPreference", r"Add-MpPreference", r"Set-ExecutionPolicy",
    r"\bnc\b", r"Start-Process", r"Invoke-Item",
]


@pytest.mark.parametrize("pattern", FORBIDDEN)
def test_forbidden_constructs_absent(pattern):
    assert not re.search(pattern, TEXT, flags=re.I), pattern


def test_only_one_session_to_the_named_target():
    assert len(re.findall(r"New-PSSession", CODE)) == 1
    assert "ComputerName = $Target" in CODE
    for m in re.finditer(r"Invoke-Command[^\n]*", CODE):
        assert "-Session $session" in m.group(0), m.group(0)
        assert "-ComputerName" not in m.group(0)
    assert "Enter-PSSession" not in CODE


def test_no_dynamic_invocation():
    assert not re.search(r"^\s*[&.]\s+[$(]", CODE, flags=re.M)


def test_example_allow_list_is_a_placeholder():
    import json

    data = json.loads((LAB / "lab-targets.example.json").read_text(encoding="utf-8"))
    assert data["targets"] == ["LAB-WS01"]
    assert not (LAB / "lab-targets.json").exists() or "lab-targets.json" in Path(LAB.parent / ".gitignore").read_text()


@pytest.mark.skipif(shutil.which("powershell") is None and shutil.which("pwsh") is None, reason="needs PowerShell")
def test_ast_checker_passes_real_script_and_fails_a_bad_one(tmp_path):
    ps = shutil.which("pwsh") or shutil.which("powershell")
    checker = LAB / "Test-RunnerStatic.ps1"
    ok = subprocess.run([ps, "-NoProfile", "-File", str(checker)], capture_output=True, text=True, timeout=120)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    bad = bad_dir / "bad.ps1"
    bad.write_text("param()\nInvoke-Expression $x\nInvoke-Command -ComputerName other -ScriptBlock { 1 }\n", encoding="utf-8")
    res = subprocess.run([ps, "-NoProfile", "-File", str(checker), "-Path", str(bad)],
                         capture_output=True, text=True, timeout=120)
    assert res.returncode != 0
