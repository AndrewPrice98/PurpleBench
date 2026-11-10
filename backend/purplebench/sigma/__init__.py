"""Sigma rules: parsing of the supported subset, logsource/field mapping and evaluation.

Unsupported features are reported per rule with the exact reason, never silently skipped. See
``docs/SIGMA_SUPPORT.md``.
"""

from .evaluator import (
    GAP,
    MATCH,
    NO_MATCH,
    UNSUPPORTED,
    EventIndex,
    EventRef,
    RuleResult,
    TelemetryProfile,
    evaluate,
    evaluate_all,
    recorded_profile,
)
from .parser import Rule, Unsupported, load_rule, load_rules, parse_rule, parse_rule_text

__all__ = [
    "GAP", "MATCH", "NO_MATCH", "UNSUPPORTED", "EventIndex", "EventRef", "Rule", "RuleResult", "TelemetryProfile",
    "Unsupported", "evaluate", "evaluate_all", "load_rule", "load_rules", "parse_rule", "parse_rule_text",
    "recorded_profile",
]
