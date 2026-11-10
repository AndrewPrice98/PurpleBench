"""Event builders for the Sigma tests."""
from __future__ import annotations

from typing import Any

from purplebench.sigma import mapping

# The EventData names a Sysmon 13 process-creation event carries (as in the recorded telemetry).
PROC_FIELDS = ("RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion", "Description", "Product",
               "Company", "OriginalFileName", "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId",
               "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage",
               "ParentCommandLine")


def event(event_id: int, rid: int = 1, ts: str = "2021-01-01T00:00:00.000000Z", channel: str = mapping.SYSMON,
          host: str = "host1", **fields: Any) -> dict[str, Any]:
    return {"ts": ts, "channel": channel, "event_id": event_id, "host": host, "record_id": rid,
            "fields": {k: str(v) for k, v in fields.items()}}


def proc(rid: int = 1, ts: str = "2021-01-01T00:00:00.000000Z", **fields: Any) -> dict[str, Any]:
    """A complete Sysmon event 1; unspecified fields hold neutral values."""
    base = {k: "-" for k in PROC_FIELDS}
    base.update({"Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe",
                 "ParentImage": "C:\\Windows\\explorer.exe", "User": "CORP\\alice", "OriginalFileName": "NOTEPAD.EXE",
                 "IntegrityLevel": "Medium", "ProcessId": "100", "ParentProcessId": "50"})
    base.update(fields)
    return event(1, rid, ts, **base)
