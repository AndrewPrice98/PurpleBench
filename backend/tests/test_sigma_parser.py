"""Sigma parser: round trips, modifiers, condition grammar, wildcard escaping, regex guard and
unsupported features."""
from pathlib import Path

import pytest
import yaml
from sigma_helpers import evaluate_on, proc

from purplebench import sigma
from purplebench.sigma import parser as P

RULES = Path(__file__).resolve().parent.parent / "rules"


def rule(detection: dict, logsource: dict | None = None, **extra) -> sigma.Rule:
    doc = {"title": "t", "id": "r1", "logsource": logsource or {"product": "windows", "category": "process_creation"},
           "detection": detection, **extra}
    return sigma.parse_rule(doc)


def fires(detection: dict, *events) -> bool:
    r = rule(detection)
    assert r.status == "ok", r.reason
    return evaluate_on(r, list(events)).status == sigma.MATCH


def match_value(key: str, value, field_value: str | None) -> bool:
    """Does ``{key: value}`` match a process event whose field holds ``field_value`` (None = absent)?"""
    name = key.split("|")[0]
    ev = proc()
    if field_value is None:
        ev["fields"].pop(name, None)
    else:
        ev["fields"][name] = field_value
    r = rule({"sel": {key: value}, "condition": "sel"})
    assert r.status == "ok", r.reason
    # the field occurs in the telemetry (so this is a match question, not a telemetry gap)
    profile = sigma.TelemetryProfile.from_events([proc(**{name: "x"})])
    res = sigma.evaluate(r, [ev], profile=profile)
    assert res.status in (sigma.MATCH, sigma.NO_MATCH), res.detail
    return res.status == sigma.MATCH


# -------------------------------------------------------------------------------------------- round trips

def all_rule_files():
    return sorted(RULES.glob("*/*.yml"))


@pytest.mark.parametrize("path", all_rule_files(), ids=lambda p: p.name)
def test_parser_round_trip(path):
    """Loading, dumping the YAML document and loading again yields the same rule and condition."""
    first = sigma.load_rule(path)
    doc = yaml.safe_load(path.read_text("utf-8"))
    second = sigma.parse_rule_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), first.path)
    assert first == second
    assert first.status == second.status and first.reason == second.reason
    if first.status == "ok":
        assert first.detection.condition == second.detection.condition
        assert set(first.detection.searches) == set(second.detection.searches)
        assert first.fields == second.fields
    # metadata kept verbatim (DRL 1.1: author, id and licence travel with the rule)
    assert first.id == str(doc["id"]) and first.title == doc["title"]
    assert first.author == doc.get("author") and first.license == doc.get("license")
    assert first.level == doc.get("level")


def test_rule_metadata_fields():
    r = sigma.load_rule(RULES / "sigmahq" / "proc_creation_win_schtasks_creation.yml")
    assert r.status == "ok" and r.reason is None
    assert r.id == "92626ddd-662c-49e3-ac59-f6535f12d189"
    assert r.origin == "sigmahq" and r.level and r.author and r.references and r.date
    assert r.techniques == ("T1053.005",)
    assert "attack.t1053.005" in r.tags
    assert r.logsource == {"product": "windows", "category": "process_creation"}


def test_old_attack_ids_are_renumbered_through_the_library_alias_table():
    r = rule({"sel": {"Image": "x"}, "condition": "sel"},
             tags=["attack.defense-evasion", "attack.t1562.001", "attack.t1070.001", "attack.t1059.001"])
    assert r.techniques == ("T1685", "T1685.005", "T1059.001")


def test_load_rules_selection_by_list():
    d = RULES / "sigmahq"
    picked = sigma.load_rules(d, include=["proc_creation_win_schtasks_creation", "e1a8b1b0-0000-0000-0000-000000000000"
                                          if False else "proc_creation_win_net_user_add"])
    assert [Path(r.path).stem for r in picked] == ["proc_creation_win_net_user_add", "proc_creation_win_schtasks_creation"]
    with pytest.raises(ValueError, match="unknown rules: nope"):
        sigma.load_rules(d, include=["nope"])
    by_id = sigma.load_rules(d, include=["92626ddd-662c-49e3-ac59-f6535f12d189"])
    assert len(by_id) == 1


# -------------------------------------------------------------------------------------------- modifiers

@pytest.mark.parametrize("key,value,field_value,expected", [
    # plain equality is case-insensitive and whole-value
    ("Image", "C:\\Windows\\System32\\CMD.exe", "c:\\windows\\system32\\cmd.exe", True),
    ("Image", "cmd.exe", "c:\\windows\\system32\\cmd.exe", False),
    # contains / startswith / endswith
    ("CommandLine|contains", "/CREATE", "schtasks /create /tn x", True),
    ("CommandLine|contains", "/delete", "schtasks /create /tn x", False),
    ("Image|startswith", "C:\\Windows\\", "c:\\windows\\x.exe", True),
    ("Image|startswith", "\\Windows\\", "c:\\windows\\x.exe", False),
    ("Image|endswith", "\\X.EXE", "c:\\windows\\x.exe", True),
    ("Image|endswith", "\\x.ex", "c:\\windows\\x.exe", False),
    # list = OR
    ("Image|endswith", ["\\a.exe", "\\x.exe"], "c:\\windows\\x.exe", True),
    ("Image|endswith", ["\\a.exe", "\\b.exe"], "c:\\windows\\x.exe", False),
    # all = AND
    ("CommandLine|contains|all", ["user", "/add"], "net user bob /add", True),
    ("CommandLine|contains|all", ["user", "/add"], "net user bob", False),
    # cased
    ("CommandLine|contains|cased", "Invoke", "x Invoke y", True),
    ("CommandLine|contains|cased", "Invoke", "x invoke y", False),
    ("CommandLine|cased", "Exact", "exact", False),
    # exists
    ("ParentUser|exists", True, "CORP\\bob", True),
    ("ParentUser|exists", True, None, False),
    ("ParentUser|exists", False, None, True),
    ("ParentUser|exists", True, "", True),  # presence only, the value may be empty
    # windash: '-' and '/' and the en dash, em dash and horizontal bar stand for each other
    ("CommandLine|windash|contains", " -enc ", "powershell /enc AAAA", True),
    ("CommandLine|windash|contains", " -enc ", "powershell \u2013enc AAAA", True),  # en dash
    ("CommandLine|windash|contains", " /enc ", "powershell \u2015enc AAAA", True),  # horizontal bar
    ("CommandLine|windash|contains", " -enc ", "powershell \u2014enc AAAA", True),  # em dash
    ("CommandLine|windash|contains", " -enc ", "powershell +enc AAAA", False),
    ("CommandLine|contains", " -enc ", "powershell /enc AAAA", False),  # without windash
    # re: case-sensitive search, with i / m / s sub-modifiers
    ("CommandLine|re", r"\s/c\s", "cmd.exe /c whoami", True),
    ("CommandLine|re", r"\s/C\s", "cmd.exe /c whoami", False),
    ("CommandLine|re|i", r"\s/C\s", "cmd.exe /c whoami", True),
    ("CommandLine|re", r"^second$", "first\nsecond", False),
    ("CommandLine|re|m", r"^second$", "first\nsecond", True),
    ("CommandLine|re", r"first.second", "first\nsecond", False),
    ("CommandLine|re|s", r"first.second", "first\nsecond", True),
    # null: absent or empty
    ("ParentUser", None, None, True),
    ("ParentUser", None, "", True),
    ("ParentUser", None, "CORP\\bob", False),
    # empty string: present and empty only
    ("CommandLine", "", "", True),
    ("CommandLine", "", "x", False),
    # numbers compare numerically
    ("ProcessId", 100, "100", True),
    ("ProcessId", 100, "0100", True),
    ("ProcessId", 100, "1000", False),
    ("ProcessId|startswith", 10, "1000", True),
    # booleans compare as true/false text
    ("Initiated", True, "true", True),
    ("Initiated", True, "False", False),
    # an absent field never matches a value
    ("ParentUser|contains", "bob", None, False),
])
def test_each_modifier(key, value, field_value, expected):
    assert match_value(key, value, field_value) is expected


def test_list_of_maps_is_or_and_map_is_and():
    det = {"sel": [{"Image|endswith": "\\a.exe", "CommandLine|contains": "zzz"}, {"Image|endswith": "\\b.exe"}],
           "condition": "sel"}
    assert fires(det, proc(Image="C:\\b.exe"))
    assert fires(det, proc(Image="C:\\a.exe", CommandLine="a zzz"))
    assert not fires(det, proc(Image="C:\\a.exe", CommandLine="a"))


# -------------------------------------------------------------------------------------------- conditions

def test_condition_precedence():
    t, f = proc(CommandLine="t"), None  # sel_t matches, sel_f does not
    base = {"sel_t": {"CommandLine": "t"}, "sel_f": {"CommandLine": "nope"}, "sel_t2": {"Image|endswith": "notepad.exe"}}

    def run(cond):
        return fires({**base, "condition": cond}, t)
    assert f is None
    # and binds tighter than or
    assert run("sel_t or sel_f and sel_f")          # t or (f and f)
    assert not run("(sel_t or sel_f) and sel_f")    # brackets override
    # not binds tighter than and / or
    assert not run("not sel_t and sel_t2")          # (not t) and t
    assert run("not sel_f and sel_t")
    assert run("not (sel_f and sel_t)")
    assert not run("not sel_f and sel_f or sel_f")  # ((not f) and f) or f
    # x of binds tighter than not
    assert not run("not 1 of sel_t*")
    assert run("not all of sel_*")                  # not (t and f and t)
    assert run("1 of sel_* and not sel_f")
    # them, all of them, case-insensitive operators
    assert run("1 of them") and not run("all of them")
    assert run("sel_t AND NOT sel_f")


def test_them_excludes_underscore_identifiers_and_lists_are_or():
    ev = proc(CommandLine="t")
    det = {"sel": {"CommandLine": "t"}, "_helper": {"CommandLine": "nope"}, "condition": "all of them"}
    assert fires(det, ev)
    assert fires({"sel": {"CommandLine": "nope"}, "other": {"CommandLine": "t"},
                  "condition": ["sel", "other"]}, ev)


def test_condition_ast():
    r = rule({"a": {"Image": "x"}, "b1": {"Image": "y"}, "b2": {"Image": "z"},
              "condition": "a and not 1 of b* or all of them"})
    assert r.detection.condition == ("or", [("and", [("id", "a"), ("not", ("of", "1", ["b1", "b2"]))]),
                                            ("of", "all", ["a", "b1", "b2"])])


# -------------------------------------------------------------------------------------------- wildcards

@pytest.mark.parametrize("pattern,value,expected", [
    ("C:\\Windows\\\\*.exe", "C:\\Windows\\notepad.exe", True),   # \W literal backslash, \\* backslash + wildcard
    ("C:\\Windows\\\\*.exe", "C:\\Windows\\sub\\a.exe", True),     # * spans anything
    ("C:\\Windows\\*.exe", "C:\\Windows\\notepad.exe", False),     # \* is a literal star
    ("C:\\Windows\\*.exe", "C:\\Windows*.exe", True),
    ("prog?.exe", "progA.exe", True),
    ("prog?.exe", "progAB.exe", False),
    ("prog\\?.exe", "prog?.exe", True),                            # \? is a literal ?
    ("prog\\?.exe", "progA.exe", False),
    ("a\\*b", "a*b", True),                                         # \* is a literal *
    ("a\\*b", "axxb", False),
    ("a\\\\*", "a\\anything", True),                                # \\* = backslash then wildcard
    ("a\\\\*", "a\\", True),
    ("a\\\\*", "ab", False),
    ("a\\\\\\*", "a\\*", True),                                     # \\\* = backslash then literal *
    ("a\\\\\\*", "a\\x", False),
    ("a\\\\\\\\b", "a\\\\b", True),                                 # \\\\ = two backslashes
    ("a\\\\\\\\b", "a\\b", False),
    ("ends\\", "ends\\", True),                                     # trailing backslash is literal
    ("*evil*", "one\nevil\nline", True),                            # * crosses newlines
    ("EVIL*", "evil.exe", True),                                    # wildcards keep case-insensitivity
])
def test_wildcard_escaping(pattern, value, expected):
    assert match_value("CommandLine", pattern, value) is expected


def test_wildcard_tokens():
    assert P.wildcard_tokens("a\\*b*c?\\\\") == [("lit", "a*b"), ("any", "*"), ("lit", "c"), ("one", "?"),
                                                    ("lit", "\\")]


# -------------------------------------------------------------------------------------------- regex guard

@pytest.mark.parametrize("pattern,why", [
    ("(a+)+$", "nested quantifier"),
    ("(a|aa)*b", "nested quantifier"),
    ("(\\w+\\s?)*x", "nested quantifier"),
    ("((ab)*c)+", "nested quantifier"),
    ("(x)\\1", "backreference"),
    ("(?P<n>x)(?P=n)", "backreference"),
    ("a" * (P.MAX_REGEX_LENGTH + 1), "longer than"),
    ("(unclosed", "does not compile"),
])
def test_regex_guard_rejects(pattern, why):
    r = rule({"sel": {"CommandLine|re": pattern}, "condition": "sel"})
    assert r.status == "unsupported" and why in r.reason and "sel.CommandLine|re" in r.reason


@pytest.mark.parametrize("pattern", [
    "(\\d{1,3}\\.){3}\\d{1,3}", "^(cmd|powershell)\\.exe$", "(?i)\\.(exe|dll)$", "[(*+]+x", "\\(a+\\)+",
    "(a)?b", "(ab)+c",
])
def test_regex_guard_accepts(pattern):
    assert rule({"sel": {"CommandLine|re": pattern}, "condition": "sel"}).status == "ok"


def test_regex_input_is_capped():
    tail = "x" * P.MAX_REGEX_INPUT + "NEEDLE"
    assert not match_value("CommandLine|re", "NEEDLE", tail)
    assert match_value("CommandLine|re", "NEEDLE", "NEEDLE" + tail)
    assert match_value("CommandLine|contains", "NEEDLE", tail)  # only |re is capped


def test_redos_pattern_is_rejected_quickly():
    import time
    t = time.perf_counter()
    r = rule({"sel": {"CommandLine|re": "^(a+)+$"}, "condition": "sel"})
    assert r.status == "unsupported"
    assert time.perf_counter() - t < 1


# -------------------------------------------------------------------------------------------- unsupported

UNSUPPORTED = [
    ({"sel": {"CommandLine|base64offset|contains": "IEX"}, "condition": "sel"}, "modifier 'base64offset' is not supported"),
    ({"sel": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "sel"}, "modifier 'cidr' is not supported"),
    ({"sel": {"CommandLine|utf16le|base64": "x"}, "condition": "sel"}, "modifier 'utf16le' is not supported"),
    ({"sel": {"Image|expand": "%Servers%"}, "condition": "sel"}, "modifier 'expand' is not supported"),
    ({"sel": {"Image|fieldref": "ParentImage"}, "condition": "sel"}, "modifier 'fieldref' is not supported"),
    ({"sel": {"ProcessId|gt": 4}, "condition": "sel"}, "modifier 'gt' is not supported"),
    ({"sel": {"Image|neq": "x"}, "condition": "sel"}, "modifier 'neq' is not supported"),
    ({"sel": {"Image|frobnicate": "x"}, "condition": "sel"}, "unknown modifier 'frobnicate'"),
    ({"sel": {"Image|contains|startswith": "x"}, "condition": "sel"}, "cannot be combined"),
    ({"sel": {"Image": "x"}, "condition": "sel | count() > 5"}, "aggregation"),
    ({"sel": {"Image": "x"}, "condition": "sel | count(Image) by Computer > 5"}, "aggregation"),
    ({"sel": {"Image": "x"}, "other": {"Image": "y"}, "condition": "sel near other"}, "unexpected token 'near'"),
    ({"sel": {"Image": "x"}, "timeframe": "5m", "condition": "sel"}, "timeframe"),
    ({"keywords": ["evil", "worse"], "condition": "keywords"}, "keyword (full-text) search"),
    ({"kw": {"|all": ["a", "b"]}, "condition": "kw"}, "keyword (full-text) search"),
    ({"sel": {"Image": "x"}, "condition": "2 of sel*"}, "'2 of' is not supported"),
    ({"sel": {"Image": "x"}, "condition": "sel and missing"}, "undefined search identifier 'missing'"),
    ({"sel": {"Image": "x"}, "condition": "1 of nothing*"}, "matches no search identifier"),
    ({"sel": {"Image": ["x", None]}, "condition": "sel"}, "null inside a value list"),
    ({"sel": {"Image|all": "x"}, "condition": "sel"}, "'all' on a single value"),
    ({"sel": {"Image|contains": None}, "condition": "sel"}, "null cannot be combined"),
]


@pytest.mark.parametrize("detection,reason", UNSUPPORTED, ids=[r for _, r in UNSUPPORTED])
def test_unsupported_feature_reported(detection, reason):
    r = rule(detection)
    assert r.status == "unsupported"
    assert reason in r.reason
    # never silently evaluated as a non-match
    res = evaluate_on(r, [proc(Image="x", CommandLine="IEX evil")])
    assert res.status == sigma.UNSUPPORTED and res.detail == r.reason and res.matched_events == ()


@pytest.mark.parametrize("doc,reason", [
    ({"title": "c", "correlation": {"type": "event_count", "rules": ["a"]}}, "correlation rule"),
    ({"title": "f", "filter": {"rules": ["a"], "selection": {"User": "x"}, "condition": "selection"},
      "logsource": {"product": "windows"}}, "filter (meta) rule"),
    ({"title": "g", "action": "global", "logsource": {"product": "windows"}, "detection": {}}, "rule collection"),
    ({"title": "l", "logsource": {"product": "linux", "category": "process_creation"},
      "detection": {"sel": {"Image": "x"}, "condition": "sel"}}, "product 'linux' is not mapped"),
    ({"title": "e", "logsource": {"product": "windows", "category": "file_access"},
      "detection": {"sel": {"Image": "x"}, "condition": "sel"}}, "ETW provider"),
    ({"title": "u", "logsource": {"product": "windows", "category": "made_up"},
      "detection": {"sel": {"Image": "x"}, "condition": "sel"}}, "category 'made_up' is not mapped"),
    ({"title": "n", "logsource": {"product": "windows", "category": "process_creation"}}, "no 'detection'"),
])
def test_unsupported_rule_kinds_reported(doc, reason):
    r = sigma.parse_rule(doc)
    assert r.status == "unsupported" and reason in r.reason
    assert evaluate_on(r, [proc()]).status == sigma.UNSUPPORTED


def test_unsupported_yaml_shapes(tmp_path):
    multi = tmp_path / "multi.yml"
    multi.write_text("title: a\nlogsource: {product: windows}\n---\ntitle: b\n", encoding="utf-8")
    assert "multi-document" in sigma.load_rule(multi).reason
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [unclosed\n", encoding="utf-8")
    assert sigma.load_rule(bad).reason.startswith("YAML does not parse")
    big = tmp_path / "big.yml"
    big.write_text("title: x\n#" + "a" * P.MAX_RULE_BYTES, encoding="utf-8")
    assert "larger than" in sigma.load_rule(big).reason
    tags = tmp_path / "tags.yml"
    tags.write_text("!!python/object:os.system 'x'\n", encoding="utf-8")  # safe_load refuses arbitrary tags
    assert sigma.load_rule(tags).status == "unsupported"


def test_real_sigmahq_rules_outside_the_subset_are_reported():
    d = RULES / "sigmahq"
    expected = {
        "proc_creation_win_powershell_base64_iex.yml": "modifier 'base64offset' is not supported",
        "proc_creation_win_powershell_base64_frombase64string.yml": "modifier 'base64offset' is not supported",
        "proc_creation_win_powershell_defender_disable_feature.yml": "modifier 'base64offset' is not supported",
        "net_connection_win_rundll32_net_connections.yml": "modifier 'cidr' is not supported",
    }
    for name, reason in expected.items():
        r = sigma.load_rule(d / name)
        assert r.status == "unsupported" and reason in r.reason, name
    others = [r for r in sigma.load_rules(d) if r.status != "ok" and Path(r.path).name not in expected]
    assert others == []
