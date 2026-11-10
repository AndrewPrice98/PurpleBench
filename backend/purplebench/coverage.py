"""Coverage per technique and per tactic, and the gap list, derived from a :class:`RunScore`.

- A technique's status is the best status of its executions, in the order detected > partial > missed >
  telemetry_gap. ``untested`` only when every execution of it is untested.
- Per-tactic and overall scores are ``detected / tested``; ``untested`` techniques are excluded from
  every denominator. ATT&CK techniques may belong to several tactics, so a technique counts once in
  each tactic it belongs to (and once in the overall score). ``partial_score`` additionally credits
  partials at half weight, to show progress without hiding that partial is not detected.
- Gaps: one record per missed or telemetry-gap execution, with notes from ``data/gap_hints.yml``
  (keyed by v20 technique id). A technique with no hint gets a generic note rather than none.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import library
from .scoring import DETECTED, MISSED, PARTIAL, STATUSES, TELEMETRY_GAP, UNTESTED, DID_NOT_RUN, NOT_TESTED, ExecutionScore, RunScore

_BEST = (DETECTED, PARTIAL, MISSED, TELEMETRY_GAP, DID_NOT_RUN, UNTESTED)
GENERIC_HINT = {
    "telemetry_needed": "No curated hint for this technique: check that process creation with command lines "
                        "(Sysmon 1 / Security 4688) and the events specific to the technique are collected.",
    "rule_idea": "No curated hint for this technique.",
}


def _pct(num: float, den: float) -> float | None:
    return round(100.0 * num / den, 1) if den else None


@dataclass(frozen=True)
class TechniqueCoverage:
    technique: str
    name: str
    tactics: tuple[str, ...]
    status: str
    reason: str
    executions: int
    ttd_seconds: float | None
    rules: tuple[str, ...]  # rules that matched in the best execution (any relation, noisy ones included)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__, tactics=list(self.tactics), rules=list(self.rules))


@dataclass(frozen=True)
class TacticCoverage:
    tactic: str
    name: str
    counts: dict[str, int]
    tested: int
    score: float | None  # detected / tested, percent

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class Coverage:
    techniques: tuple[TechniqueCoverage, ...]
    tactics: tuple[TacticCoverage, ...]
    counts: dict[str, int]
    tested: int
    score: float | None  # detected / tested, percent
    partial_score: float | None  # (detected + 0.5 * partial) / tested, percent
    noisy_rules: tuple[dict[str, Any], ...] = field(default=())

    def to_dict(self) -> dict[str, Any]:
        return {
            "techniques": [t.to_dict() for t in self.techniques], "tactics": [t.to_dict() for t in self.tactics],
            "counts": self.counts, "tested": self.tested, "score": self.score, "partial_score": self.partial_score,
            "noisy_rules": list(self.noisy_rules),
        }


def _best(execs: list[ExecutionScore]) -> ExecutionScore:
    def key(e: ExecutionScore) -> tuple[int, float]:
        return _BEST.index(e.status), e.ttd_seconds if e.ttd_seconds is not None else 1e9
    return min(execs, key=key)


def _counts(statuses: list[str]) -> dict[str, int]:
    return {s: statuses.count(s) for s in STATUSES}


def compute_coverage(run: RunScore) -> Coverage:
    by_tech: dict[str, list[ExecutionScore]] = {}
    for e in run.executions:
        by_tech.setdefault(e.technique, []).append(e)
    techs = []
    for tid, execs in by_tech.items():
        b = _best(execs)
        techs.append(TechniqueCoverage(
            technique=tid, name=b.name, tactics=b.tactics, status=b.status, reason=b.reason, executions=len(execs),
            ttd_seconds=b.ttd_seconds, rules=tuple(h.rule_id for h in b.hits),
        ))
    order = list(library.TACTICS)
    techs.sort(key=lambda t: (min((order.index(x) for x in t.tactics if x in order), default=99), t.technique))

    tactics = []
    for tac in order:
        members = [t for t in techs if tac in t.tactics]
        if not members:
            continue
        counts = _counts([t.status for t in members])
        tested = sum(counts[s] for s in STATUSES if s not in NOT_TESTED)
        tactics.append(TacticCoverage(tac, library.TACTICS[tac], counts, tested, _pct(counts[DETECTED], tested)))
    counts = _counts([t.status for t in techs])
    tested = sum(counts[s] for s in STATUSES if s not in NOT_TESTED)
    return Coverage(
        techniques=tuple(techs), tactics=tuple(tactics), counts=counts, tested=tested,
        score=_pct(counts[DETECTED], tested),
        partial_score=_pct(2 * counts[DETECTED] + counts[PARTIAL], 2 * tested),
        noisy_rules=tuple({"rule_id": r.rule_id, "title": r.title, "hits": r.hits, "threshold": run.noise_threshold}
                          for r in sorted(run.noisy_rules, key=lambda r: (-r.hits, r.rule_id))),
    )


# --- gaps -------------------------------------------------------------------------------------

def load_gap_hints(path: Path | str | None = None) -> dict[str, dict[str, str]]:
    p = Path(path) if path else library.DATA_DIR / "gap_hints.yml"
    with open(p, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return {str(k): {"telemetry_needed": str(v["telemetry_needed"]), "rule_idea": str(v["rule_idea"])}
            for k, v in data.items()}


@dataclass(frozen=True)
class Gap:
    technique: str
    name: str
    tactics: tuple[str, ...]
    kind: str  # missed | telemetry_gap
    reason: str
    telemetry_needed: str
    rule_idea: str
    hinted: bool

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__, tactics=list(self.tactics))


def compute_gaps(run: RunScore, hints: dict[str, dict[str, str]] | None = None) -> list[Gap]:
    """One gap per missed / telemetry-gap execution, in run order."""
    hints = load_gap_hints() if hints is None else hints
    out = []
    for e in run.executions:
        if e.status not in (MISSED, TELEMETRY_GAP):
            continue
        h = hints.get(e.technique)
        use = h or GENERIC_HINT
        out.append(Gap(e.technique, e.name, e.tactics, e.status, e.reason, use["telemetry_needed"],
                       use["rule_idea"], h is not None))
    return out
