"""Evaluate compiled Sigma rules against normalised events.

``evaluate(rule, events)`` is pure and deterministic. Its status is one of:

- ``match``: at least one event satisfies the rule (record ids in time order);
- ``no_match``: the rule could have matched this telemetry and nothing did;
- ``telemetry_gap``: no source of the rule can be evaluated, because its channel or event id is
  absent from the telemetry, or because fields the rule needs never occur in it (the detail names
  them). A gap is never reported as ``no_match``;
- ``unsupported``: the rule uses a feature outside the supported subset (the detail is the reason).

Whether a channel, event id or field "occurs" is decided by a :class:`TelemetryProfile`. By default
it is built from the events passed in; to judge one execution window against everything a mode can
record, pass the profile of the whole corpus (``recorded_profile()`` for recorded mode).

A missing field only makes a source a gap when the rule cannot match without it: the condition is
evaluated three-valued (search identifiers that need an absent field are false, the others unknown),
so ``selection and not filter`` with an absent filter field is still evaluable.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .. import library
from ..telemetry import event_sort_key, read_jsonl_gz
from . import mapping
from .parser import Rule, SearchId, eval_condition, kleene

MATCH, NO_MATCH, GAP, UNSUPPORTED = "match", "no_match", "telemetry_gap", "unsupported"


@dataclass(frozen=True)
class TelemetryProfile:
    """Which (channel, event id) pairs occur, and which EventData field names each carries."""

    fields: dict[tuple[str, int], frozenset[str]]

    @classmethod
    def from_events(cls, events: Iterable[dict[str, Any]]) -> TelemetryProfile:
        acc: dict[tuple[str, int], set[str]] = defaultdict(set)
        for ev in events:
            acc[(ev["channel"], ev["event_id"])].update(ev["fields"])
        return cls({k: frozenset(v) for k, v in acc.items()})

    def merge(self, other: TelemetryProfile) -> TelemetryProfile:
        keys = set(self.fields) | set(other.fields)
        return TelemetryProfile({k: self.fields.get(k, frozenset()) | other.fields.get(k, frozenset()) for k in keys})

    @property
    def channels(self) -> set[str]:
        return {c for c, _ in self.fields}

    def event_ids(self, channel: str) -> list[int]:
        return sorted(e for c, e in self.fields if c == channel)


class EventIndex:
    """Events grouped by (channel, event id), each group in ``(ts, host, record_id)`` order."""

    def __init__(self, events: Iterable[dict[str, Any]]) -> None:
        groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for ev in events:
            groups[(ev["channel"], ev["event_id"])].append(ev)
        for g in groups.values():
            g.sort(key=event_sort_key)
        self.groups = dict(groups)
        self.profile = TelemetryProfile({k: frozenset(f for ev in g for f in ev["fields"]) for k, g in groups.items()})

    def __len__(self) -> int:
        return sum(len(g) for g in self.groups.values())


@dataclass(frozen=True)
class EventRef:
    ts: str
    host: str
    record_id: int
    channel: str
    event_id: int


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    status: str  # match | no_match | telemetry_gap | unsupported
    matched_events: tuple[int, ...]  # record ids, in time order
    first_ts: str | None
    detail: str
    matches: tuple[EventRef, ...] = ()
    gaps: tuple[str, ...] = ()  # sources that could not be evaluated, with the reason


def _search_value(search: SearchId, source: mapping.Source, event: dict[str, Any]) -> bool:
    for alt in search.alternatives:
        if all(t.test(mapping.read_field(source, event, t.field)) for t in alt):
            return True
    return False


def _search_gap_value(search: SearchId, source: mapping.Source, present: frozenset[str]) -> bool | None:
    """Three-valued value of a search identifier when only field presence is known."""
    alts: list[bool | None] = []
    for alt in search.alternatives:
        vals: list[bool | None] = []
        for t in alt:
            if mapping.field_available(source, t.field, present):
                vals.append(None)
            else:
                vals.append(t.test(None))
        alts.append(False if False in vals else (True if all(v is True for v in vals) else None))
    return True if True in alts else (False if all(v is False for v in alts) else None)


def _missing_fields(rule: Rule, source: mapping.Source, present: frozenset[str]) -> list[str]:
    return sorted(f for f in rule.fields if not mapping.field_available(source, f, present))


def _short(channel: str) -> str:
    return "Sysmon" if channel == mapping.SYSMON else channel


def evaluate(rule: Rule, events: Iterable[dict[str, Any]] | EventIndex,
             profile: TelemetryProfile | None = None) -> RuleResult:
    """Evaluate ``rule`` over ``events`` (a list of normalised events or an :class:`EventIndex`)."""
    if rule.status != "ok" or rule.detection is None:
        return RuleResult(rule.id, UNSUPPORTED, (), None, rule.reason or "unsupported")
    index = events if isinstance(events, EventIndex) else EventIndex(events)
    prof = profile if profile is not None else index.profile
    det = rule.detection
    gaps: list[str] = []
    runnable: list[tuple[mapping.Source, int]] = []
    for source in rule.sources:
        if source.channel not in prof.channels:
            gaps.append(f"channel {source.channel!r} is not in the telemetry (needed for {source.label})")
            continue
        ids = list(source.event_ids) if source.event_ids is not None else prof.event_ids(source.channel)
        for eid in ids:
            key = (source.channel, eid)
            if key not in prof.fields:
                gaps.append(f"{source.label}: no {_short(source.channel)} event {eid} in the telemetry")
                continue
            present = prof.fields[key]
            missing = _missing_fields(rule, source, present)
            if missing:
                cache: dict[str, bool | None] = {}

                def val(name: str, _s=source, _p=present, _c=cache) -> bool | None:
                    if name not in _c:
                        _c[name] = _search_gap_value(det.searches[name], _s, _p)
                    return _c[name]
                if kleene(det.condition, val) is False:
                    gaps.append(f"{source.label}: {_short(source.channel)} event {eid} never has field(s) "
                                f"{', '.join(missing)}")
                    continue
            runnable.append((source, eid))
    if not runnable:
        return RuleResult(rule.id, GAP, (), None, "; ".join(gaps) or "no source to evaluate", gaps=tuple(gaps))

    hits: dict[tuple[str, str, int, str, int], dict[str, Any]] = {}
    for source, eid in runnable:
        for ev in index.groups.get((source.channel, eid), ()):
            memo: dict[str, bool] = {}

            def value(name: str, _ev=ev, _s=source, _m=memo) -> bool:
                if name not in _m:
                    _m[name] = _search_value(det.searches[name], _s, _ev)
                return _m[name]
            if eval_condition(det.condition, value):
                hits[(ev["ts"], ev["host"], ev["record_id"], ev["channel"], ev["event_id"])] = ev
    refs = tuple(EventRef(*k) for k in sorted(hits))
    note = f" (not evaluated: {'; '.join(gaps)})" if gaps else ""
    evaluated = ", ".join(sorted({f"{_short(s.channel)} event {e}" for s, e in runnable}))
    if refs:
        return RuleResult(rule.id, MATCH, tuple(r.record_id for r in refs), refs[0].ts,
                          f"{len(refs)} matching event(s) in {evaluated}{note}", refs, tuple(gaps))
    return RuleResult(rule.id, NO_MATCH, (), None, f"no matching event in {evaluated}{note}", (), tuple(gaps))


def evaluate_all(rules: Iterable[Rule], events: Iterable[dict[str, Any]] | EventIndex,
                 profile: TelemetryProfile | None = None) -> list[RuleResult]:
    index = events if isinstance(events, EventIndex) else EventIndex(events)
    return [evaluate(r, index, profile) for r in rules]


@lru_cache(maxsize=2)
def _recorded_profile(tele_dir: str) -> TelemetryProfile:
    acc: dict[tuple[str, int], set[str]] = defaultdict(set)
    for path in sorted(Path(tele_dir).rglob("*.jsonl.gz")):
        for ev in read_jsonl_gz(path):
            acc[(ev["channel"], ev["event_id"])].update(ev["fields"])
    return TelemetryProfile({k: frozenset(v) for k, v in acc.items()})


def recorded_profile(data_dir: Path | str | None = None) -> TelemetryProfile:
    """Profile of all committed recorded telemetry (what recorded mode can ever show a rule)."""
    root = Path(data_dir) if data_dir else library.DATA_DIR
    return _recorded_profile(str((root / "telemetry").resolve()))
