"""Score test executions against a rule set.

Everything here is pure and deterministic: the same rules, events and settings give the same
:class:`RunScore`, byte for byte. Nothing is executed; rules are evaluated over recorded events only.

Status of one execution (``technique`` is the tested ATT&CK v20 id; rule tags are mapped through the
library alias table when a rule is loaded, so ``attack.t1562.001`` already reads ``T1685``):

``detected``
    at least one rule tagged with exactly the tested technique id fired in the execution window and is
    not noisy.
``partial``
    something fired, but no rule that earns credit for this technique did. In order of preference the
    reason is *parent-technique rule* (the test is a sub-technique and only a rule tagged with its
    parent, e.g. T1569 for T1569.002, fired), *detected via related technique <id>* (rules tagged with
    other techniques fired; a rule for a more specific sub-technique of a tested parent counts here
    too), or *noisy rule* (only rules over the noise threshold fired).
``missed``
    nothing fired in the window although the rules tagged for the technique could have matched
    (or no rule is tagged for it at all). "Missed" only ever means "no rule in this rule set fired on
    this telemetry".
``telemetry_gap``
    nothing fired and every evaluable rule tagged for the technique is a ``telemetry_gap`` (its channel,
    event id or fields never occur in the recorded telemetry). The rule may be fine; the telemetry
    cannot show it.
``untested``
    the execution has no usable recording (for example the dataset holds no execution of the
    technique). Untested executions are excluded from coverage denominators.

Time to detect (TTD) is the first matching event's timestamp minus the execution start (the anchor:
the first event of the executed command, not the window start, which is 30 s earlier). It is clamped at
0. Clock skew of up to ``skew_seconds`` (default 5) is tolerated: a match up to that long before the
anchor counts and gives TTD 0. Matches earlier than that, or later than ``window_seconds`` (default
120) after the anchor, are outside the execution window: they never earn credit or set the TTD, and
are only counted in ``out_of_window``.

Noise is the number of events a rule matches in the benign baseline. A rule with more hits than
``noise_threshold`` (default 0) is noisy: it never earns ``detected`` credit and is reported with its
count.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import catalog, library
from .sigma import GAP, MATCH, UNSUPPORTED, EventIndex, Rule, RuleResult, TelemetryProfile, evaluate
from .telemetry import parse_ts, read_jsonl_gz

DETECTED, PARTIAL, MISSED, TELEMETRY_GAP, UNTESTED = "detected", "partial", "missed", "telemetry_gap", "untested"
STATUSES = (DETECTED, PARTIAL, MISSED, TELEMETRY_GAP, UNTESTED)

EXACT, PARENT, RELATED = "exact", "parent", "related"

DEFAULT_NOISE_THRESHOLD = 0
DEFAULT_SKEW_SECONDS = 5.0
DEFAULT_WINDOW_SECONDS = 120.0

UNTESTED_NO_EXECUTION = "recorded dataset contains no execution"


@dataclass(frozen=True)
class Execution:
    """One executed test and the telemetry recorded for it."""

    technique: str  # v20 ATT&CK id
    name: str
    tactics: tuple[str, ...]
    events: Sequence[dict[str, Any]] = field(default=(), repr=False)
    anchor_ts: str | None = None  # execution start (normalised timestamp)
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    untested_reason: str | None = None
    atomic_test: str | None = None


@dataclass(frozen=True)
class RuleHit:
    """A rule that fired in an execution window."""

    rule_id: str
    title: str
    techniques: tuple[str, ...]
    relation: str  # exact | parent | related
    noisy: bool
    noise_hits: int
    events: int  # matching events inside the window
    first_ts: str
    ttd_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__, techniques=list(self.techniques))


@dataclass(frozen=True)
class ExecutionScore:
    technique: str
    name: str
    tactics: tuple[str, ...]
    status: str
    reason: str
    atomic_test: str | None
    anchor_ts: str | None
    hits: tuple[RuleHit, ...]  # every rule that fired in the window, best first
    ttd_seconds: float | None  # of the rules behind the status
    out_of_window: int  # rule matches discarded because they fall outside the execution window
    tagged_rules: int  # rules tagged for exactly this technique
    gap_details: tuple[str, ...] = ()

    @property
    def fired_rules(self) -> list[str]:
        return [h.rule_id for h in self.hits]

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["tactics"] = list(self.tactics)
        d["hits"] = [h.to_dict() for h in self.hits]
        d["gap_details"] = list(self.gap_details)
        return d


@dataclass(frozen=True)
class RuleNoise:
    rule_id: str
    title: str
    techniques: tuple[str, ...]
    status: str  # baseline evaluation status
    hits: int
    noisy: bool

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__, techniques=list(self.techniques))


@dataclass(frozen=True)
class RunScore:
    executions: tuple[ExecutionScore, ...]
    rule_noise: tuple[RuleNoise, ...]
    noise_threshold: int
    skew_seconds: float
    window_seconds: float

    @property
    def noisy_rules(self) -> list[RuleNoise]:
        return [r for r in self.rule_noise if r.noisy]

    def counts(self) -> dict[str, int]:
        return {s: sum(1 for e in self.executions if e.status == s) for s in STATUSES}

    def to_dict(self) -> dict[str, Any]:
        return {
            "executions": [e.to_dict() for e in self.executions],
            "rule_noise": [r.to_dict() for r in self.rule_noise],
            "noise_threshold": self.noise_threshold, "skew_seconds": self.skew_seconds,
            "window_seconds": self.window_seconds, "counts": self.counts(),
        }


def _seconds(a: str, b: str) -> float:
    """``a - b`` in seconds for two normalised timestamps."""
    return (parse_ts(a) - parse_ts(b)).total_seconds()


def _relation(tested: str, rule_techniques: Iterable[str]) -> str:
    techs = set(rule_techniques)
    if tested in techs:
        return EXACT
    if "." in tested and tested.split(".")[0] in techs:
        return PARENT
    return RELATED


def baseline_noise(rules: Sequence[Rule], baseline: Iterable[dict[str, Any]], profile: TelemetryProfile,
                   noise_threshold: int = DEFAULT_NOISE_THRESHOLD) -> dict[str, RuleNoise]:
    """Hits of every rule on the benign baseline."""
    index = EventIndex(baseline)
    out: dict[str, RuleNoise] = {}
    for r in sorted(rules, key=lambda x: x.id):
        res = evaluate(r, index, profile)
        hits = len(res.matched_events) if res.status == MATCH else 0
        out[r.id] = RuleNoise(r.id, r.title, r.techniques, res.status, hits, hits > noise_threshold)
    return out


def _in_window(res: RuleResult, anchor: str, skew: float, window: float) -> tuple[list[str], int]:
    """Timestamps of the rule's matches inside the execution window, and the number outside it."""
    inside, outside = [], 0
    for ref in res.matches:
        d = _seconds(ref.ts, anchor)
        if -skew <= d <= window:
            inside.append(ref.ts)
        else:
            outside += 1
    return sorted(inside), outside


def _names(hits: Sequence[RuleHit]) -> str:
    return "; ".join(f"{h.title} [{h.rule_id}]" for h in hits)


def _score_execution(ex: Execution, rules: Sequence[Rule], noise: dict[str, RuleNoise], profile: TelemetryProfile,
                     skew: float, window: float) -> ExecutionScore:
    base = {"technique": ex.technique, "name": ex.name, "tactics": ex.tactics, "atomic_test": ex.atomic_test,
            "anchor_ts": ex.anchor_ts}
    if ex.untested_reason or ex.anchor_ts is None:
        return ExecutionScore(status=UNTESTED, reason=ex.untested_reason or "no execution start time recorded",
                              hits=(), ttd_seconds=None, out_of_window=0, tagged_rules=0, **base)
    window = ex.window_seconds or window
    index = EventIndex(ex.events)
    hits: list[RuleHit] = []
    outside = 0
    tagged: list[tuple[Rule, RuleResult]] = []
    for r in sorted(rules, key=lambda x: x.id):
        res = evaluate(r, index, profile)
        if ex.technique in r.techniques:
            tagged.append((r, res))
        if res.status != MATCH:
            continue
        inside, out = _in_window(res, ex.anchor_ts, skew, window)
        outside += out
        if not inside:
            continue
        n = noise.get(r.id)
        first = inside[0]
        hits.append(RuleHit(
            rule_id=r.id, title=r.title, techniques=r.techniques, relation=_relation(ex.technique, r.techniques),
            noisy=bool(n and n.noisy), noise_hits=n.hits if n else 0, events=len(inside), first_ts=first,
            ttd_seconds=max(0.0, _seconds(first, ex.anchor_ts)),
        ))
    rank = {EXACT: 0, PARENT: 1, RELATED: 2}
    hits.sort(key=lambda h: (h.noisy, rank[h.relation], h.first_ts, h.rule_id))

    clean = [h for h in hits if not h.noisy]
    exact = [h for h in clean if h.relation == EXACT]
    parent = [h for h in clean if h.relation == PARENT]
    related = [h for h in clean if h.relation == RELATED]
    noisy = [h for h in hits if h.noisy]

    def ttd(hs: Sequence[RuleHit]) -> float:
        return min(h.ttd_seconds for h in hs)

    common = {"hits": tuple(hits), "out_of_window": outside, "tagged_rules": len(tagged), **base}
    if exact:
        return ExecutionScore(status=DETECTED, reason=f"detected by {_names(exact)}", ttd_seconds=ttd(exact), **common)
    if parent:
        return ExecutionScore(status=PARTIAL, reason=f"parent-technique rule: {_names(parent)}",
                              ttd_seconds=ttd(parent), **common)
    if related:
        ids = sorted({t for h in related for t in h.techniques})
        return ExecutionScore(status=PARTIAL, reason=f"detected via related technique {', '.join(ids)}: "
                              f"{_names(related)}", ttd_seconds=ttd(related), **common)
    if noisy:
        return ExecutionScore(status=PARTIAL, reason="noisy rule: " + "; ".join(
            f"{h.title} [{h.rule_id}] ({h.noise_hits} baseline hits)" for h in noisy),
            ttd_seconds=ttd(noisy), **common)

    # Nothing fired in the window.
    evaluable = [(r, res) for r, res in tagged if res.status != UNSUPPORTED]
    note = f" ({outside} match(es) outside the execution window ignored)" if outside else ""
    if evaluable and all(res.status == GAP for _, res in evaluable):
        details = tuple(sorted(f"{r.id}: {res.detail}" for r, res in evaluable))
        return ExecutionScore(status=TELEMETRY_GAP, reason="rules tagged for this technique cannot match this "
                              "telemetry: " + "; ".join(details), ttd_seconds=None, gap_details=details, **common)
    if not tagged:
        return ExecutionScore(status=MISSED, reason="no rule in the rule set is tagged for this technique" + note,
                              ttd_seconds=None, **common)
    if not evaluable:
        return ExecutionScore(status=MISSED, reason="the rules tagged for this technique use unsupported Sigma "
                              "features and could not be evaluated" + note, ttd_seconds=None, **common)
    return ExecutionScore(status=MISSED, reason=f"{len(evaluable)} rule(s) tagged for this technique were evaluated; "
                          f"none fired{note}", ttd_seconds=None, **common)


def score_run(rules: Sequence[Rule], executions: Sequence[Execution], baseline: Iterable[dict[str, Any]],
              profile: TelemetryProfile, noise_threshold: int = DEFAULT_NOISE_THRESHOLD, *,
              skew_seconds: float = DEFAULT_SKEW_SECONDS, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> RunScore:
    """Score every execution against ``rules``.

    ``profile`` is required by the evaluator (use ``recorded_profile()`` in recorded mode, never one
    built from a single window). ``baseline`` is the benign event stream used to count rule noise.
    """
    if noise_threshold < 0 or skew_seconds < 0 or window_seconds <= 0:
        raise ValueError("noise_threshold and skew_seconds must be >= 0 and window_seconds > 0")
    rules = list(rules)
    noise = baseline_noise(rules, baseline, profile, noise_threshold)
    scored = tuple(_score_execution(ex, rules, noise, profile, skew_seconds, window_seconds) for ex in executions)
    return RunScore(executions=scored, rule_noise=tuple(noise.values()), noise_threshold=noise_threshold,
                    skew_seconds=skew_seconds, window_seconds=window_seconds)


# --- recorded mode ----------------------------------------------------------------------------

def recorded_executions(data_dir: Path | str | None = None) -> list[Execution]:
    """The recorded executions of the technique library, in library order, with their telemetry.

    The execution start is the first anchor event of the manifest window (the executed command), not
    the window start. A ``whole-file-head`` window has no anchor: that dataset holds no execution.
    """
    root = Path(data_dir) if data_dir else library.DATA_DIR
    manifest = catalog.load_manifest(root)
    files = {f["path"]: f for f in manifest["files"] if f["kind"] == "test"}
    out: list[Execution] = []
    for t in library.list_techniques(root / "library.json"):
        w = files[t.telemetry]["window"]
        events = list(read_jsonl_gz(root / "telemetry" / t.telemetry))
        anchor = w.get("anchor_first") if w["method"] == "process-creation-anchor" else None
        post = float(w.get("post_seconds") or DEFAULT_WINDOW_SECONDS)
        out.append(Execution(
            technique=t.attack_id, name=t.name, tactics=t.tactics, events=events, anchor_ts=anchor,
            window_seconds=post, untested_reason=None if anchor else UNTESTED_NO_EXECUTION,
            atomic_test=t.atomic.name if t.atomic else None,
        ))
    return out


def recorded_baseline(data_dir: Path | str | None = None) -> list[dict[str, Any]]:
    root = Path(data_dir) if data_dir else library.DATA_DIR
    return list(read_jsonl_gz(root / "telemetry" / "baseline.jsonl.gz"))
