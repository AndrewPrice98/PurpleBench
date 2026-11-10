"""ATT&CK Navigator layer export (layer format 4.5, ATT&CK Enterprise v20).

Format reference: https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
(see DECISIONS.md section 5). Required: top level ``name`` and ``domain``; ``versions.layer`` ("4.5") and
``versions.navigator``; each technique needs ``techniqueID``. :func:`validate_layer` checks the fields
PurpleBench writes against that format.

Colours: detected blue, partial violet, missed red, telemetry gap grey, untested dark grey. Each
technique carries a comment and ``metadata``. A technique that belongs to several tactics is written
once without ``tactic``, which Navigator shows in every tactic it belongs to.
"""

from __future__ import annotations

import re
from typing import Any

from .coverage import Coverage
from .scoring import DETECTED, MISSED, PARTIAL, TELEMETRY_GAP, UNTESTED, DID_NOT_RUN

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.3.2"
ATTACK_VERSION = "20"
DOMAIN = "enterprise-attack"

COLORS = {DETECTED: "#3b82f6", PARTIAL: "#a78bfa", MISSED: "#ef4444", TELEMETRY_GAP: "#9ca3af", UNTESTED: "#4b5563", DID_NOT_RUN: "#6b7280"}
SCORES = {DETECTED: 100, PARTIAL: 50, MISSED: 0, TELEMETRY_GAP: 0}
LABELS = {DETECTED: "Detected", PARTIAL: "Partial", MISSED: "Missed", TELEMETRY_GAP: "Telemetry gap",
          UNTESTED: "Untested", DID_NOT_RUN: "Did not run"}

_TID = re.compile(r"^T\d{4}(\.\d{3})?$")
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def rule_labels() -> dict[str, str]:
    """``"title (author)"`` of every bundled rule by id (SigmaHQ's Detection Rule License 1.1 requires the
    author wherever a rule is shown)."""
    from . import rulesets

    attr = rulesets.rule_attribution()
    out = {}
    for r in rulesets.load_all_rules().values():
        out[r.id] = f"{r.title} ({attr.get(r.id, {}).get('author') or r.author or 'unknown author'})"
    return out


def build_layer(cov: Coverage, name: str = "PurpleBench coverage", description: str = "",
                labels: dict[str, str] | None = None) -> dict[str, Any]:
    labels = rule_labels() if labels is None else labels
    techniques = []
    for t in cov.techniques:
        comment = f"{LABELS[t.status]}: {t.reason}"
        if t.ttd_seconds is not None:
            comment += f" (time to detect {t.ttd_seconds:.1f} s)"
        meta = [{"name": "status", "value": t.status}]
        if t.rules:
            meta.append({"name": "rules that matched (any relation)",
                         "value": "; ".join(labels.get(r, r) for r in t.rules)})
        if t.ttd_seconds is not None:
            meta.append({"name": "time to detect (s)", "value": f"{t.ttd_seconds:.1f}"})
        entry: dict[str, Any] = {"techniqueID": t.technique, "color": COLORS[t.status], "comment": comment,
                                 "enabled": True, "metadata": meta}
        if t.status in SCORES:
            entry["score"] = SCORES[t.status]
        techniques.append(entry)
    desc = description or ("Detection coverage of a Sigma rule set over recorded Atomic Red Team telemetry. "
                           "'Missed' means no rule in this rule set fired on this telemetry.")
    return {
        "name": name,
        "versions": {"attack": ATTACK_VERSION, "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": DOMAIN,
        "description": desc,
        "techniques": techniques,
        "legendItems": [{"label": LABELS[s], "color": COLORS[s]}
                        for s in (DETECTED, PARTIAL, MISSED, TELEMETRY_GAP, UNTESTED, DID_NOT_RUN)],
        "gradient": {"colors": [COLORS[MISSED], COLORS[PARTIAL], COLORS[DETECTED]], "minValue": 0, "maxValue": 100},
    }


def validate_layer(layer: Any) -> list[str]:
    """Problems found checking ``layer`` against the layer format 4.5 fields PurpleBench uses."""
    errs: list[str] = []
    if not isinstance(layer, dict):
        return ["layer is not an object"]
    if not isinstance(layer.get("name"), str) or not layer["name"]:
        errs.append("name is required (string)")
    if layer.get("domain") not in ("enterprise-attack", "mobile-attack", "ics-attack"):
        errs.append("domain is required (enterprise-attack, mobile-attack or ics-attack)")
    v = layer.get("versions")
    if not isinstance(v, dict):
        errs.append("versions is required")
    else:
        if v.get("layer") != "4.5":
            errs.append('versions.layer must be "4.5"')
        if not isinstance(v.get("navigator"), str):
            errs.append("versions.navigator is required (string)")
        if "attack" in v and not isinstance(v["attack"], str):
            errs.append("versions.attack must be a string")
    if "description" in layer and not isinstance(layer["description"], str):
        errs.append("description must be a string")
    techs = layer.get("techniques", [])
    if not isinstance(techs, list):
        return [*errs, "techniques must be an array"]
    seen = set()
    for i, t in enumerate(techs):
        p = f"techniques[{i}]"
        if not isinstance(t, dict):
            errs.append(f"{p} is not an object")
            continue
        tid = t.get("techniqueID")
        if not isinstance(tid, str) or not _TID.match(tid):
            errs.append(f"{p}.techniqueID must look like T1234 or T1234.567")
        elif (tid, t.get("tactic")) in seen:
            errs.append(f"{p}: duplicate entry for {tid}")
        else:
            seen.add((tid, t.get("tactic")))
        if "tactic" in t and not (isinstance(t["tactic"], str) and re.match(r"^[a-z-]+$", t["tactic"])):
            errs.append(f"{p}.tactic must be a tactic shortname")
        if "score" in t and (isinstance(t["score"], bool) or not isinstance(t["score"], int | float)):
            errs.append(f"{p}.score must be a number")
        if "color" in t and not (isinstance(t["color"], str) and _COLOR.match(t["color"])):
            errs.append(f"{p}.color must be a #rrggbb hex colour")
        if "comment" in t and not isinstance(t["comment"], str):
            errs.append(f"{p}.comment must be a string")
        if "enabled" in t and not isinstance(t["enabled"], bool):
            errs.append(f"{p}.enabled must be a boolean")
        for j, m in enumerate(t.get("metadata", [])):
            if not (isinstance(m, dict) and isinstance(m.get("name"), str) and isinstance(m.get("value"), str)):
                errs.append(f"{p}.metadata[{j}] needs string name and value")
    for j, li in enumerate(layer.get("legendItems", [])):
        if not (isinstance(li, dict) and isinstance(li.get("label"), str) and _COLOR.match(str(li.get("color")))):
            errs.append(f"legendItems[{j}] needs a label and a #rrggbb color")
    g = layer.get("gradient")
    if g is not None and not (
        isinstance(g, dict) and isinstance(g.get("colors"), list) and g["colors"]
        and all(_COLOR.match(str(c)) for c in g["colors"])
        and isinstance(g.get("minValue"), int | float) and isinstance(g.get("maxValue"), int | float)
    ):
        errs.append("gradient needs colors, minValue and maxValue")
    return errs
