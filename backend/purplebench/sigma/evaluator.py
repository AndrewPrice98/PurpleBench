"""Evaluate compiled Sigma rules against normalised events.

``evaluate(rule, events, profile)`` is pure and deterministic. Its status is one of:

- ``match``: at least one event satisfies the rule (record ids in time order);
- ``no_match``: the rule could have matched this telemetry and nothing did;
- ``telemetry_gap``: no source of the rule can be evaluated, because its channel or the event ids
  it asks for are absent from the telemetry, or because fields the rule needs never occur in it
  (the detail names them). A gap is never reported as ``no_match``;
- ``unsupported``: the rule uses a feature outside the supported subset (the detail is the reason),
  or it could not be evaluated at all.

Whether a channel, event id or field "occurs" is decided by the :class:`TelemetryProfile` the caller
passes. There is deliberately no default: to judge one execution window against everything a mode
can record, pass the profile of the whole corpus (``recorded_profile()`` for recorded mode); a
per-window profile would call "no Sysmon event 8 in this window" a telemetry gap.

Gap analysis is three-valued. For each candidate (channel, event id) of a rule source:

1. ``EventID`` and ``Channel`` tests are decided literally for that candidate; everything else is
   unknown. If the condition is then definitely false, the candidate is irrelevant to the rule (for
   example event 4768 for a rule on ``EventID: 4769``) and is skipped, not reported.
2. Search identifiers that need a field absent from the candidate are false. If the condition is then
   definitely false, the candidate is a gap ("never has field(s) ..."); a missing field used only in
   a filter (``selection and not filter``) is not a gap.

If no candidate of any source remains, the rule is a ``telemetry_gap``.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .. import library
from ..telemetry import event_sort_key, read_jsonl_gz
from . import mapping
from .parser import (
    Rule,
    SearchId,
    eval_condition,
    kleene,
    start_regex_timeout_count,
    stop_regex_timeout_count,
)

MATCH, NO_MATCH, GAP, UNSUPPORTED = "match", "no_match", "telemetry_gap", "unsupported"

log = logging.getLogger(__name__)


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
    """Events grouped by (channel, event id), each group in ``(ts, host, record_id)`` order.

    ``profile`` describes only these events; pass it to :func:`evaluate` explicitly when that is the
    intended reference.
    """

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
    regex_timeouts: int = 0  # |re matches abandoned at the time limit (each counted as no match)


def _search_value(search: SearchId, source: mapping.Source, event: dict[str, Any]) -> bool:
    for alt in search.alternatives:
        if all(t.test(mapping.read_field(source, event, t.field)) for t in alt):
            return True
    return False


def _and3(vals: list[bool | None]) -> bool | None:
    return False if False in vals else (True if all(v is True for v in vals) else None)


def _search_gap_value(search: SearchId, source: mapping.Source, channel: str, eid: int,
                      present: frozenset[str] | None) -> bool | None:
    """Three-valued value of a search identifier for one (channel, event id) candidate.

    ``EventID`` and ``Channel`` are decided literally. Other fields are unknown, except, when
    ``present`` is given, fields the candidate never carries, which take their absent-field value.
    """
    alts: list[bool | None] = []
    for alt in search.alternatives:
        vals: list[bool | None] = []
        for t in alt:
            if t.field == "EventID":
                vals.append(t.test(str(eid)))
            elif t.field == "Channel":
                vals.append(t.test(channel))
            elif present is None or mapping.field_available(source, t.field, present):
                vals.append(None)
            else:
                vals.append(t.test(None))
        alts.append(_and3(vals))
    return True if True in alts else (False if all(v is False for v in alts) else None)


def _condition3(rule: Rule, source: mapping.Source, channel: str, eid: int,
                present: frozenset[str] | None) -> bool | None:
    det = rule.detection
    cache: dict[str, bool | None] = {}

    def val(name: str) -> bool | None:
        if name not in cache:
            cache[name] = _search_gap_value(det.searches[name], source, channel, eid, present)
        return cache[name]
    return kleene(det.condition, val)


def _missing_fields(rule: Rule, source: mapping.Source, present: frozenset[str]) -> list[str]:
    return sorted(f for f in rule.fields if not mapping.field_available(source, f, present))


def _short(channel: str) -> str:
    return "Sysmon" if channel == mapping.SYSMON else channel


def _wanted_event_ids(rule: Rule) -> list[str]:
    """The ``EventID`` values the rule's detection names (for messages)."""
    out: list[str] = []
    for search in rule.detection.searches.values():
        for alt in search.alternatives:
            for t in alt:
                if t.field == "EventID":
                    out.extend(str(v) for v in t.raw if str(v) not in out)
    return out


def _plan(rule: Rule, prof: TelemetryProfile) -> tuple[list[tuple[mapping.Source, int]], list[str]]:
    """Which (source, event id) pairs can be evaluated, and why the others cannot."""
    gaps: list[str] = []
    runnable: list[tuple[mapping.Source, int]] = []
    for source in rule.sources:
        ch = source.channel
        if ch not in prof.channels:
            gaps.append(f"channel {ch!r} is not in the telemetry (needed for {source.label})")
            continue
        candidates = list(source.event_ids) if source.event_ids is not None else prof.event_ids(ch)
        relevant = [e for e in candidates if _condition3(rule, source, ch, e, None) is not False]
        if not relevant:
            ids = _wanted_event_ids(rule) or [str(e) for e in candidates]
            gaps.append(f"no {_short(ch)} event {'/'.join(ids)} in the telemetry (needed for {source.label})")
            continue
        src_gaps: list[str] = []
        src_runnable: list[tuple[mapping.Source, int]] = []
        for eid in relevant:
            if (ch, eid) not in prof.fields:
                src_gaps.append(f"{source.label}: no {_short(ch)} event {eid} in the telemetry")
                continue
            present = prof.fields[(ch, eid)]
            missing = _missing_fields(rule, source, present)
            if missing and _condition3(rule, source, ch, eid, present) is False:
                src_gaps.append(f"{source.label}: {_short(ch)} event {eid} never has field(s) {', '.join(missing)}")
                continue
            src_runnable.append((source, eid))
        runnable.extend(src_runnable)
        # A channel-wide source (a logsource service) is judged as a whole: other event ids of the
        # channel lacking the rule's fields are not gaps when some event id can be evaluated.
        if source.event_ids is not None or not src_runnable:
            gaps.extend(src_gaps)
    return runnable, gaps


def evaluate(rule: Rule, events: Iterable[dict[str, Any]] | EventIndex, profile: TelemetryProfile) -> RuleResult:
    """Evaluate ``rule`` over ``events`` (normalised events or an :class:`EventIndex`).

    ``profile`` is the telemetry the gap decision is made against (required, see the module docstring).
    """
    if not isinstance(profile, TelemetryProfile):
        raise TypeError("evaluate() needs a TelemetryProfile (for example recorded_profile())")
    if rule.status != "ok" or rule.detection is None:
        return RuleResult(rule.id, UNSUPPORTED, (), None, rule.reason or "unsupported")
    index = events if isinstance(events, EventIndex) else EventIndex(events)
    det = rule.detection
    runnable, gaps = _plan(rule, profile)
    if not runnable:
        return RuleResult(rule.id, GAP, (), None, "; ".join(gaps) or "no source to evaluate", gaps=tuple(gaps))

    counter, token = start_regex_timeout_count()
    try:
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
    finally:
        stop_regex_timeout_count(token)
    timeouts = counter.count
    refs = tuple(EventRef(*k) for k in sorted(hits))
    note = f" (not evaluated: {'; '.join(gaps)})" if gaps else ""
    if timeouts:
        note += f"; {timeouts} |re match(es) timed out and were treated as no match"
        log.warning("rule %s: %d |re match(es) timed out", rule.id, timeouts)
    evaluated = ", ".join(sorted({f"{_short(s.channel)} event {e}" for s, e in runnable}))
    if refs:
        return RuleResult(rule.id, MATCH, tuple(r.record_id for r in refs), refs[0].ts,
                          f"{len(refs)} matching event(s) in {evaluated}{note}", refs, tuple(gaps), timeouts)
    return RuleResult(rule.id, NO_MATCH, (), None, f"no matching event in {evaluated}{note}", (), tuple(gaps),
                      timeouts)


def evaluate_all(rules: Iterable[Rule], events: Iterable[dict[str, Any]] | EventIndex,
                 profile: TelemetryProfile) -> list[RuleResult]:
    """Evaluate every rule; a rule that fails unexpectedly is reported, never aborts the others."""
    index = events if isinstance(events, EventIndex) else EventIndex(events)
    out: list[RuleResult] = []
    for r in rules:
        try:
            out.append(evaluate(r, index, profile))
        except Exception as exc:  # noqa: BLE001 - one broken rule must not hide the rest
            log.exception("rule %s could not be evaluated", r.id)
            out.append(RuleResult(r.id, UNSUPPORTED, (), None, f"rule could not be evaluated: {type(exc).__name__}"))
    return out


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
