"""Sigma ``logsource`` -> telemetry source mapping, and rule field -> event field mapping.

A rule's logsource resolves to one or more :class:`Source` objects. Each source names a Windows
event channel, the event ids it covers (``None`` = every event id of the channel) and how the rule's
field names are read from an event of that source.

The category and service tables follow the Sigma taxonomy appendix (Sigma specification 2.1.0,
``sigma-appendix-taxonomy.md``, "Windows Folder"). Field names follow Sysmon, as the taxonomy does,
so Sysmon sources read fields unchanged. Security event 4688 is a second source for
``process_creation`` with an explicit field map (``Image`` <- ``NewProcessName`` and so on); fields
4688 does not carry (``OriginalFileName``, ``Hashes``, ``ParentCommandLine`` ...) are absent there and
show up as telemetry gaps, never as silent non-matches.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"
SYSTEM = "System"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_CORE = "PowerShellCore/Operational"
POWERSHELL_CLASSIC = "Windows PowerShell"

# Taxonomy appendix, "Windows Folder / Category": Sysmon category -> event ids.
SYSMON_CATEGORIES: dict[str, tuple[int, ...]] = {
    "process_creation": (1,),
    "file_change": (2,),
    "network_connection": (3,),
    "sysmon_status": (4, 16),
    "process_termination": (5,),
    "driver_load": (6,),
    "image_load": (7,),
    "create_remote_thread": (8,),
    "raw_access_thread": (9,),
    "process_access": (10,),
    "file_event": (11,),
    "registry_event": (12, 13, 14),
    "registry_add": (12,),
    "registry_delete": (12,),
    "registry_set": (13,),
    "registry_rename": (14,),
    "create_stream_hash": (15,),
    "pipe_created": (17, 18),
    "wmi_event": (19, 20, 21),
    "dns_query": (22,),
    "file_delete": (23,),
    "clipboard_capture": (24,),
    "process_tampering": (25,),
    "file_delete_detected": (26,),
    "file_block_executable": (27,),
    "file_block_shredding": (28,),
    "file_executable_detected": (29,),
    "sysmon_error": (255,),
}

# Same table, PowerShell categories: category -> ((channel, event ids), ...).
OTHER_CATEGORIES: dict[str, tuple[tuple[str, tuple[int, ...]], ...]] = {
    "ps_classic_start": ((POWERSHELL_CLASSIC, (400,)),),
    "ps_classic_provider_start": ((POWERSHELL_CLASSIC, (600,)),),
    "ps_classic_script": ((POWERSHELL_CLASSIC, (800,)),),
    "ps_module": ((POWERSHELL, (4103,)), (POWERSHELL_CORE, (4103,))),
    "ps_script": ((POWERSHELL, (4104,)), (POWERSHELL_CORE, (4104,))),
}

# Categories the taxonomy defines through an ETW provider rather than an event log channel.
ETW_CATEGORIES = frozenset({"file_access", "file_rename"})

# Taxonomy appendix, "Windows Folder / Service": service -> channels.
SERVICES: dict[str, tuple[str, ...]] = {
    "application": ("Application",),
    "application-experience": ("Microsoft-Windows-Application-Experience/Program-Telemetry",
                               "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant"),
    "applocker": ("Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL",
                  "Microsoft-Windows-AppLocker/Packaged app-Deployment",
                  "Microsoft-Windows-AppLocker/Packaged app-Execution"),
    "appmodel-runtime": ("Microsoft-Windows-AppModel-Runtime/Admin",),
    "appxdeployment-server": ("Microsoft-Windows-AppXDeploymentServer/Operational",),
    "appxpackaging-om": ("Microsoft-Windows-AppxPackaging/Operational",),
    "bitlocker": ("Microsoft-Windows-BitLocker/BitLocker Management",),
    "bits-client": ("Microsoft-Windows-Bits-Client/Operational",),
    "capi2": ("Microsoft-Windows-CAPI2/Operational",),
    "certificateservicesclient-lifecycle-system": (
        "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",),
    "codeintegrity-operational": ("Microsoft-Windows-CodeIntegrity/Operational",),
    "dhcp": ("Microsoft-Windows-DHCP-Server/Operational",),
    "diagnosis-scripted": ("Microsoft-Windows-Diagnosis-Scripted/Operational",),
    "dns-client": ("Microsoft-Windows-DNS Client Events/Operational",),
    "dns-server": ("DNS Server",),
    "dns-server-analytic": ("Microsoft-Windows-DNS-Server/Analytical",),
    "dns-server-audit": ("Microsoft-Windows-DNS-Server/Audit",),
    "driver-framework": ("Microsoft-Windows-DriverFrameworks-UserMode/Operational",),
    "firewall-as": ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",),
    "hyper-v-worker": ("Microsoft-Windows-Hyper-V-Worker",),
    "iis-configuration": ("Microsoft-IIS-Configuration/Operational",),
    "kernel-event-tracing": ("Microsoft-Windows-Kernel-EventTracing",),
    "kernel-shimengine": ("Microsoft-Windows-Kernel-ShimEngine/Operational",
                          "Microsoft-Windows-Kernel-ShimEngine/Diagnostic"),
    "ldap": ("Microsoft-Windows-LDAP-Client/Debug",),
    "lsa-server": ("Microsoft-Windows-LSA/Operational",),
    "msexchange-management": ("MSExchange Management",),
    "ntfs": ("Microsoft-Windows-Ntfs/Operational",),
    "ntlm": ("Microsoft-Windows-NTLM/Operational",),
    "openssh": ("OpenSSH/Operational",),
    "powershell": (POWERSHELL,),
    "powershell-classic": (POWERSHELL_CLASSIC,),
    "printservice-admin": ("Microsoft-Windows-PrintService/Admin",),
    "printservice-operational": ("Microsoft-Windows-PrintService/Operational",),
    "security": (SECURITY,),
    "security-mitigations": ("Microsoft-Windows-Security-Mitigations/Kernel Mode",
                             "Microsoft-Windows-Security-Mitigations/User Mode"),
    "sense": ("Microsoft-Windows-SENSE/Operational",),
    "servicebus-client": ("Microsoft-ServiceBus-Client/Operational", "Microsoft-ServiceBus-Client/Admin"),
    "shell-core": ("Microsoft-Windows-Shell-Core/Operational",),
    "smbclient-security": ("Microsoft-Windows-SmbClient/Security",),
    "sysmon": (SYSMON,),
    "system": (SYSTEM,),
    "taskscheduler": ("Microsoft-Windows-TaskScheduler/Operational",),
    "terminalservices-localsessionmanager": ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",),
    "vhdmp": ("Microsoft-Windows-VHDMP/Operational",),
    "windefend": ("Microsoft-Windows-Windows Defender/Operational",),
    "wmi": ("Microsoft-Windows-WMI-Activity/Operational",),
}


@dataclass(frozen=True)
class FieldRead:
    """How one rule field is read from an event's EventData.

    ``requires`` is the EventData name whose presence the value depends on; a telemetry source whose
    events never carry it cannot supply the rule field (a telemetry gap).
    """

    requires: str
    convert: Callable[[str], str | None] | None = None

    def __call__(self, fields: dict[str, str]) -> str | None:
        v = fields.get(self.requires)
        if v is None or self.convert is None:
            return v
        return self.convert(v)


# Mandatory label SIDs (Security 4688 ``MandatoryLabel``) -> Sysmon ``IntegrityLevel`` names.
_INTEGRITY = {
    "S-1-16-0": "Untrusted", "S-1-16-4096": "Low", "S-1-16-8192": "Medium", "S-1-16-8448": "MediumPlus",
    "S-1-16-12288": "High", "S-1-16-16384": "System", "S-1-16-20480": "Protected",
}


def _hex_to_dec(value: str) -> str:
    v = value.strip()
    try:
        return str(int(v, 16)) if v.lower().startswith("0x") else v
    except ValueError:
        return v


class _SecurityUser(FieldRead):
    """``DOMAIN\\user`` like Sysmon's ``User``, from 4688 ``SubjectDomainName`` + ``SubjectUserName``."""

    def __call__(self, fields: dict[str, str]) -> str | None:
        user = fields.get("SubjectUserName")
        if user is None:
            return None
        domain = fields.get("SubjectDomainName")
        return f"{domain}\\{user}" if domain else user


# Security 4688 (process creation) -> Sigma/Sysmon process_creation field names.
# NewProcessId and ProcessId are hex in 4688 and decimal in Sysmon, so they are converted; the 4688
# ``ProcessId`` is the creator (parent) process. ``User`` is the subject (creator) account rendered
# ``DOMAIN\user`` like Sysmon (on Windows 10+ the new process's own account is in TargetUserName).
SECURITY_4688_FIELDS: dict[str, FieldRead] = {
    "Image": FieldRead("NewProcessName"),
    "CommandLine": FieldRead("CommandLine"),
    "ParentImage": FieldRead("ParentProcessName"),
    "User": _SecurityUser("SubjectUserName"),
    "ProcessId": FieldRead("NewProcessId", _hex_to_dec),
    "ParentProcessId": FieldRead("ProcessId", _hex_to_dec),
    "IntegrityLevel": FieldRead("MandatoryLabel", lambda v: _INTEGRITY.get(v.strip().upper(), v)),
    "LogonId": FieldRead("SubjectLogonId"),
}


def _hash_part(algo: str) -> FieldRead:
    """Sigma's ``md5``/``sha1``/``sha256``/``Imphash`` read out of Sysmon's ``Hashes`` (``SHA1=..,MD5=..``)."""
    key = algo.upper() + "="

    def convert(hashes: str) -> str | None:
        for part in hashes.split(","):
            p = part.strip()
            if p.upper().startswith(key):
                return p[len(key):]
        return None
    return FieldRead("Hashes", convert)


SYSMON_DERIVED: dict[str, FieldRead] = {
    "md5": _hash_part("md5"), "sha1": _hash_part("sha1"), "sha256": _hash_part("sha256"),
    "Imphash": _hash_part("imphash"), "imphash": _hash_part("imphash"),
}

# Fields every source answers from the event envelope rather than EventData.
ENVELOPE_FIELDS = frozenset({"EventID", "Channel", "Computer"})


@dataclass(frozen=True)
class Source:
    """One place a rule's events come from."""

    channel: str
    event_ids: tuple[int, ...] | None  # None = every event id of the channel
    label: str
    field_map: dict[str, FieldRead] = field(default_factory=dict, compare=False, hash=False)
    passthrough: bool = True  # rule fields missing from field_map are read under the same name

    def reader(self, rule_field: str) -> FieldRead | None:
        """How to read ``rule_field`` from this source's events (``None``: the source cannot carry it)."""
        if rule_field in self.field_map:
            return self.field_map[rule_field]
        if self.passthrough:
            return FieldRead(rule_field)
        return None


class LogsourceError(ValueError):
    """The logsource has no mapping to an event channel (the rule is reported as unsupported)."""


def _ids(ids: tuple[int, ...]) -> str:
    return "/".join(str(i) for i in ids)


def resolve_logsource(logsource: Any) -> list[Source]:
    """Map a Sigma ``logsource`` to the sources its events come from.

    Raises :class:`LogsourceError` with the reason when the logsource is outside the mapping.
    """
    if not isinstance(logsource, dict):
        raise LogsourceError("logsource is not a map")
    for key in ("product", "category", "service"):
        value = logsource.get(key)
        if value is not None and not isinstance(value, str):
            raise LogsourceError(f"logsource {key} must be a string, not a {type(value).__name__}")
    product = logsource.get("product")
    category = logsource.get("category")
    service = logsource.get("service")
    if product != "windows":
        raise LogsourceError(f"logsource product {product!r} is not mapped (only 'windows' is)")
    if category is not None and service is not None:
        raise LogsourceError(f"logsource with both category {category!r} and service {service!r} is not mapped")
    if category is not None:
        if category in SYSMON_CATEGORIES:
            ids = SYSMON_CATEGORIES[category]
            out = [Source(SYSMON, ids, f"Sysmon event {_ids(ids)}", field_map=SYSMON_DERIVED)]
            if category == "process_creation":
                out.append(Source(SECURITY, (4688,), "Security event 4688", field_map=SECURITY_4688_FIELDS,
                                  passthrough=False))
            return out
        if category in OTHER_CATEGORIES:
            return [Source(ch, ids, f"{ch} event {_ids(ids)}") for ch, ids in OTHER_CATEGORIES[category]]
        if category in ETW_CATEGORIES:
            raise LogsourceError(f"logsource category {category!r} comes from an ETW provider, not an event log")
        raise LogsourceError(f"logsource category {category!r} is not mapped")
    if service is not None:
        if service in SERVICES:
            return [Source(ch, None, f"logsource service '{service}'", field_map=SYSMON_DERIVED if ch == SYSMON else {})
                    for ch in SERVICES[service]]
        raise LogsourceError(f"logsource service {service!r} is not mapped")
    raise LogsourceError("logsource has neither category nor service")


def read_field(source: Source, event: dict[str, Any], rule_field: str) -> str | None:
    """Value of ``rule_field`` in ``event`` as seen through ``source`` (``None`` = absent)."""
    if rule_field == "EventID":
        return str(event["event_id"])
    if rule_field == "Channel":
        return event["channel"]
    if rule_field == "Computer":
        return event["host"]
    reader = source.reader(rule_field)
    return None if reader is None else reader(event["fields"])


def field_available(source: Source, rule_field: str, present: frozenset[str] | set[str]) -> bool:
    """Whether events of ``source`` whose EventData keys are ``present`` can carry ``rule_field``."""
    if rule_field in ENVELOPE_FIELDS:
        return True
    reader = source.reader(rule_field)
    return reader is not None and reader.requires in present
