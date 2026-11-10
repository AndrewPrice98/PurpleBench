import re

from purplebench import library
from purplebench.telemetry import read_jsonl_gz

GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def test_library_size_and_tactic_coverage():
    techs = library.list_techniques()
    assert 20 <= len(techs) <= 30
    assert len(library.covered_tactics()) >= 8
    assert len({t.attack_id for t in techs}) == len(techs)


def test_uses_attack_v20_ids_and_tactics():
    ids = {t.attack_id for t in library.list_techniques()}
    # Revoked in ATT&CK v19/v20: replaced by T1685 and T1685.005.
    assert "T1562.001" not in ids and "T1070.001" not in ids
    assert {"T1685", "T1685.005"} <= ids
    assert "defense-evasion" not in library.TACTICS
    assert {"stealth", "defense-impairment"} <= set(library.TACTICS)
    for t in library.list_techniques():
        assert t.tactics and all(x in library.TACTICS for x in t.tactics)
    assert library.library_meta()["attack"]["version"] == "20"


def test_dataset_id_alias():
    t = library.get_technique("T1562.001")
    assert t is not None and t.attack_id == "T1685" and t.dataset_id == "T1562.001"
    assert library.get_technique("T1685") is t
    assert library.get_technique("T1070.001").attack_id == "T1685.005"
    assert library.get_technique("T9999") is None


def test_atomic_metadata_is_complete():
    n_atomic = 0
    for t in library.list_techniques():
        if t.atomic is None:
            assert t.execution_kind == library.EXECUTION_RECORDED
            assert t.link == "recorded"
            assert t.dataset["description"]
            continue
        n_atomic += 1
        a = t.atomic
        assert t.execution_kind == library.EXECUTION_ATOMIC
        assert GUID.match(a.guid), a.guid
        assert a.name and a.executor
        assert "windows" in a.supported_platforms
        assert a.source_url.startswith("https://github.com/redcanaryco/atomic-red-team/blob/")
    assert n_atomic >= 20


def test_known_guids_match_the_selected_tests():
    expected = {
        "T1685.005": ("Clear Logs", "e6abb60e-26b8-41da-8aae-0c35174b0967"),
        "T1490": ("Windows - Delete Volume Shadow Copies", "43819286-91a9-4369-90ed-d31fb4da2c01"),
        "T1047": ("WMI Execute Local Process", "b3bdfc91-b33e-4c6d-a5c8-d64bee0276b3"),
    }
    for tid, (name, guid) in expected.items():
        a = library.get_technique(tid).atomic
        assert (a.name, a.guid) == (name, guid)


def test_non_atomic_executions_are_not_labelled_as_atomic_tests():
    recorded = {t.attack_id for t in library.list_techniques() if t.atomic is None}
    assert {"T1558.003", "T1550.002", "T1560.001"} <= recorded


def test_command_resolved_substitutes_defaults_only_for_display():
    a = library.get_technique("T1047").atomic
    assert "#{process_to_execute}" in a.command
    assert a.command_resolved == "wmic process call create notepad.exe"
    assert "#{" not in library.get_technique("T1685.005").atomic.command_resolved


def test_telemetry_files_exist_and_load():
    for t in library.list_techniques():
        events = list(read_jsonl_gz(library.DATA_DIR / "telemetry" / t.telemetry))
        assert events, t.attack_id
        assert set(events[0]) == {"ts", "channel", "event_id", "host", "record_id", "fields"}
