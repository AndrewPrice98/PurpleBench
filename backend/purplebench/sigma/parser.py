"""Sigma rule parsing and compilation for PurpleBench's supported subset (Sigma specification 2.1.0).

``load_rule(path)`` always returns a :class:`Rule`. A rule that uses anything outside the subset
documented in ``docs/SIGMA_SUPPORT.md`` loads with ``status == "unsupported"`` and the exact reason;
it is never compiled into something that silently fails to match.

Matching semantics implemented here (spec references are to the rules specification and the
modifiers appendix, version 2.1.0):

- string values are compared case-insensitively unless ``|cased`` is given;
- ``*`` matches any run of characters and ``?`` one character; ``\\`` escapes ``*``, ``?`` and ``\\``,
  and a backslash before any other character is a literal backslash;
- a list of values is OR, ``|all`` makes it AND; maps are AND, lists of maps are OR;
- ``|windash`` lets each of ``-``, ``/``, en dash, em dash and horizontal bar stand for any of them;
- ``|re`` is a Python regular expression searched anywhere in the value, case-sensitive unless
  ``|re|i``; ``|re|m`` and ``|re|s`` set multi-line and dot-all. Patterns are guarded (see
  :func:`check_regex`);
- ``null`` matches an absent or empty field; ``|exists`` tests presence only;
- integers compare numerically when the event value is an integer.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import mapping

MAX_RULE_BYTES = 256 * 1024
MAX_REGEX_LENGTH = 1024          # characters in one |re pattern
MAX_REGEX_INPUT = 32_768         # characters of a field value a |re pattern is applied to
SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "all", "cased", "exists", "windash", "re"})
REGEX_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
KNOWN_UNSUPPORTED_MODIFIERS = frozenset({
    "base64", "base64offset", "utf16", "utf16le", "utf16be", "wide", "cidr", "expand", "fieldref",
    "lt", "lte", "gt", "gte", "neq", "minute", "hour", "day", "week", "month", "year",
})
WINDASH_CHARS = "-/\u2013\u2014\u2015"  # hyphen, slash, en dash, em dash, horizontal bar
_WINDASH_CLASS = "[" + re.escape(WINDASH_CHARS) + "]"
_MATCH_TYPES = ("contains", "startswith", "endswith", "re", "exists")

# Rule metadata kept on load (the licence and author fields are kept verbatim, DRL 1.1).
META_FIELDS = ("title", "id", "status", "description", "author", "date", "modified", "references", "tags",
               "logsource", "detection", "falsepositives", "level", "license")


class Unsupported(Exception):
    """A rule feature outside the supported subset, or a rule that is invalid per the specification."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------------------------------
# value matching
# --------------------------------------------------------------------------------------------------

Pred = Callable[[str], bool]


def wildcard_tokens(value: str) -> list[tuple[str, str]]:
    """Split a Sigma string into ``("lit", text)``, ``("any", "*")`` and ``("one", "?")`` tokens.

    Escapes follow the specification: ``\\*``, ``\\?`` and ``\\\\`` are the literal characters; a
    backslash before anything else (or at the end) is a literal backslash.
    """
    out: list[tuple[str, str]] = []
    lit: list[str] = []
    i, n = 0, len(value)
    while i < n:
        c = value[i]
        if c == "\\":
            nxt = value[i + 1] if i + 1 < n else ""
            if nxt in ("*", "?", "\\"):
                lit.append(nxt)
                i += 2
                continue
            lit.append("\\")
        elif c in "*?":
            if lit:
                out.append(("lit", "".join(lit)))
                lit = []
            out.append(("any", "*") if c == "*" else ("one", "?"))
        else:
            lit.append(c)
        i += 1
    if lit:
        out.append(("lit", "".join(lit)))
    return out


def _lit_regex(text: str, windash: bool) -> str:
    if not windash:
        return re.escape(text)
    return "".join(_WINDASH_CLASS if ch in WINDASH_CHARS else re.escape(ch) for ch in text)


def string_predicate(value: str, mode: str, *, cased: bool = False, windash: bool = False) -> Pred:
    """Predicate for one Sigma string value. ``mode`` is ``equals``/``contains``/``startswith``/``endswith``."""
    tokens = wildcard_tokens(value)
    plain = all(kind == "lit" for kind, _ in tokens) and not (windash and any(c in WINDASH_CHARS for c in value))
    if plain:
        needle = "".join(t for _, t in tokens)
        if not cased:
            needle = needle.lower()
        if mode == "equals":
            return (lambda v: v == needle) if cased else (lambda v: v.lower() == needle)
        if mode == "contains":
            return (lambda v: needle in v) if cased else (lambda v: needle in v.lower())
        if mode == "startswith":
            return (lambda v: v.startswith(needle)) if cased else (lambda v: v.lower().startswith(needle))
        return (lambda v: v.endswith(needle)) if cased else (lambda v: v.lower().endswith(needle))
    parts = []
    for kind, text in tokens:
        parts.append(".*" if kind == "any" else "." if kind == "one" else _lit_regex(text, windash))
    body = "".join(parts)
    if mode in ("contains", "endswith"):
        body = ".*" + body
    if mode in ("contains", "startswith"):
        body = body + ".*"
    rx = re.compile(body, re.DOTALL | (0 if cased else re.IGNORECASE))
    return lambda v: rx.fullmatch(v) is not None


_BACKREF = re.compile(r"\\[1-9]|\(\?P=")


def check_regex(pattern: str) -> None:
    """Reject ``|re`` patterns that risk catastrophic backtracking (raises :class:`Unsupported`).

    Python's ``re`` has no match timeout, so the guard is static: a length cap, no backreferences,
    and no group repeated without bound (``*``, ``+``, ``{n,}``) whose body itself contains a
    quantifier or an alternation (``(a+)+``, ``(a|aa)*``, ``(\\w+\\s?)*``: the shapes behind
    exponential backtracking). Bounded repetition such as ``(\\d{1,3}\\.){3}`` is allowed. Values
    longer than :data:`MAX_REGEX_INPUT` characters are matched on their first
    :data:`MAX_REGEX_INPUT` characters (Windows caps a command line at 32,767).
    """
    if len(pattern) > MAX_REGEX_LENGTH:
        raise Unsupported(f"|re pattern longer than {MAX_REGEX_LENGTH} characters (regex guard)")
    if _BACKREF.search(pattern):
        raise Unsupported("|re pattern uses a backreference (regex guard)")
    # Walk the pattern, tracking for each open group whether its body holds a quantifier or '|'.
    stack: list[bool] = []
    i, n = 0, len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            continue
        if c == "(":
            stack.append(False)
        elif c == ")":
            risky = stack.pop() if stack else False
            rest = pattern[i + 1:]
            m = re.match(r"[*+]|\{\d+,\}", rest)
            bounded = re.match(r"\?|\{\d*(,\d*)?\}", rest)
            if m and risky:
                raise Unsupported(f"|re pattern has a nested quantifier near {pattern[max(0, i - 20):i + 1 + len(m.group(0))]!r} (regex guard)")
            if stack and (risky or m or bounded):
                stack[-1] = True
        elif c in "*+|" or (c == "{" and re.match(r"\{\d*(,\d*)?\}", pattern[i:])):
            if stack:
                stack[-1] = True
        i += 1
    try:
        re.compile(pattern)
    except re.error as exc:
        raise Unsupported(f"|re pattern does not compile: {exc}") from None


def regex_predicate(pattern: str, flags: str) -> Pred:
    check_regex(pattern)
    f = 0
    for ch in flags:
        f |= REGEX_FLAGS[ch]
    rx = re.compile(pattern, f)
    return lambda v: rx.search(v[:MAX_REGEX_INPUT]) is not None


def _int_predicate(n: int) -> Pred:
    text = str(n)

    def pred(v: str) -> bool:
        s = v.strip()
        try:
            return int(s, 10) == n
        except ValueError:
            return s.lower() == text
    return pred


# --------------------------------------------------------------------------------------------------
# detection structure
# --------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class FieldTest:
    """One ``field|modifiers: value(s)`` item of a search identifier map."""

    key: str
    field: str
    modifiers: tuple[str, ...]
    kind: str  # "values" | "exists" | "null"
    preds: tuple[Pred, ...] = field(default=(), compare=False, repr=False)
    match_all: bool = False
    exists: bool = True

    def test(self, value: str | None) -> bool:
        if self.kind == "exists":
            return (value is not None) == self.exists
        if self.kind == "null":
            return value is None or value == ""
        if value is None:
            return False
        if self.match_all:
            return all(p(value) for p in self.preds)
        return any(p(value) for p in self.preds)


@dataclass(frozen=True)
class SearchId:
    """A search identifier: a list of alternatives (OR), each an AND of field tests."""

    name: str
    alternatives: tuple[tuple[FieldTest, ...], ...]

    @property
    def fields(self) -> set[str]:
        return {t.field for alt in self.alternatives for t in alt}


def _parse_key(key: Any, where: str) -> tuple[str, tuple[str, ...]]:
    if not isinstance(key, str):
        raise Unsupported(f"{where}: field name {key!r} is not a string")
    parts = key.split("|")
    fname, mods = parts[0], tuple(parts[1:])
    if not fname:
        raise Unsupported(f"{where}: keyword (full-text) search with {key!r} is not supported")
    return fname, mods


def _check_modifiers(mods: tuple[str, ...], where: str) -> tuple[str, str, bool, bool, bool]:
    """Validate a modifier chain. Returns (match type, regex flags, all, cased, windash)."""
    match_type = "equals"
    flags = ""
    seen: set[str] = set()
    for m in mods:
        if m in seen:
            raise Unsupported(f"{where}: modifier '{m}' repeated")
        seen.add(m)
        if m in REGEX_FLAGS and "re" in seen:
            flags += m
            continue
        if m in KNOWN_UNSUPPORTED_MODIFIERS:
            raise Unsupported(f"{where}: modifier '{m}' is not supported")
        if m not in SUPPORTED_MODIFIERS:
            raise Unsupported(f"{where}: unknown modifier '{m}'")
        if m in _MATCH_TYPES:
            if match_type != "equals":
                raise Unsupported(f"{where}: modifiers '{match_type}' and '{m}' cannot be combined")
            match_type = m
    windash = "windash" in seen
    if windash and match_type in ("re", "exists"):
        raise Unsupported(f"{where}: 'windash' cannot be combined with '{match_type}'")
    if match_type == "exists" and seen - {"exists"}:
        raise Unsupported(f"{where}: 'exists' cannot be combined with other modifiers")
    return match_type, flags, "all" in seen, "cased" in seen, windash


def _value_pred(value: Any, match_type: str, flags: str, cased: bool, windash: bool, where: str) -> Pred:
    if isinstance(value, bool):
        if match_type == "re":
            raise Unsupported(f"{where}: |re needs a string pattern")
        return string_predicate("true" if value else "false", match_type, cased=cased)
    if isinstance(value, int):
        if match_type == "re":
            raise Unsupported(f"{where}: |re needs a string pattern")
        if match_type == "equals" and not windash:
            return _int_predicate(value)
        return string_predicate(str(value), match_type, cased=cased, windash=windash)
    if isinstance(value, float):
        return string_predicate(repr(value), match_type, cased=cased, windash=windash)
    if isinstance(value, str):
        if match_type == "re":
            try:
                return regex_predicate(value, flags)
            except Unsupported as exc:
                raise Unsupported(f"{where}: {exc.reason}") from None
        return string_predicate(value, match_type, cased=cased, windash=windash)
    raise Unsupported(f"{where}: value of type {type(value).__name__} is not supported")


def compile_field(key: Any, value: Any, where: str) -> FieldTest:
    fname, mods = _parse_key(key, where)
    w = f"{where}.{key}"
    match_type, flags, match_all, cased, windash = _check_modifiers(mods, w)
    if match_type == "exists":
        if not isinstance(value, bool):
            raise Unsupported(f"{w}: |exists needs true or false")
        return FieldTest(key, fname, mods, "exists", exists=value)
    if value is None:
        if mods:
            raise Unsupported(f"{w}: null cannot be combined with modifiers")
        return FieldTest(key, fname, mods, "null")
    values = value if isinstance(value, list) else [value]
    if not values:
        raise Unsupported(f"{w}: empty value list")
    if any(v is None for v in values):
        raise Unsupported(f"{w}: null inside a value list is invalid (specification: null is its own selection)")
    if any(isinstance(v, (list, dict)) for v in values):
        raise Unsupported(f"{w}: nested lists or maps as values are not supported")
    if match_all and len(values) < 2:
        raise Unsupported(f"{w}: 'all' on a single value is invalid per the specification")
    preds = tuple(_value_pred(v, match_type, flags, cased, windash, w) for v in values)
    return FieldTest(key, fname, mods, "values", preds, match_all=match_all)


def compile_search(name: str, body: Any) -> SearchId:
    where = name
    if isinstance(body, dict):
        if not body:
            raise Unsupported(f"{where}: empty search identifier")
        return SearchId(name, (tuple(compile_field(k, v, where) for k, v in body.items()),))
    if isinstance(body, list):
        if not body:
            raise Unsupported(f"{where}: empty search identifier")
        if all(isinstance(x, dict) for x in body):
            alts = []
            for i, m in enumerate(body):
                if not m:
                    raise Unsupported(f"{where}[{i}]: empty map")
                alts.append(tuple(compile_field(k, v, f"{where}[{i}]") for k, v in m.items()))
            return SearchId(name, tuple(alts))
        if all(isinstance(x, (str, int)) and not isinstance(x, bool) for x in body):
            raise Unsupported(f"{where}: keyword (full-text) search identifiers are not supported")
        raise Unsupported(f"{where}: a list mixing maps and plain values is not supported")
    raise Unsupported(f"{where}: search identifier must be a map or a list of maps")


# --------------------------------------------------------------------------------------------------
# condition grammar
# --------------------------------------------------------------------------------------------------

# AST nodes: ("id", name) | ("not", node) | ("and", [nodes]) | ("or", [nodes]) | ("of", "1"|"all", [names])
Node = tuple

_TOKEN = re.compile(r"\s*(?:(\()|(\))|([A-Za-z0-9_*]+)|(\|)|(\S))")


def _tokenize(text: str) -> list[str]:
    toks: list[str] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            break  # only trailing whitespace remains
        pos = m.end()
        if m.group(4):
            raise Unsupported("condition uses '|' (aggregation, deprecated in Sigma 2; use correlation rules)")
        if m.group(5):
            raise Unsupported(f"condition has an unexpected character {m.group(5)!r}")
        toks.append(m.group(1) or m.group(2) or m.group(3))
    return toks


class _ConditionParser:
    def __init__(self, text: str, names: list[str]) -> None:
        self.toks = _tokenize(text)
        self.i = 0
        self.names = names

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        t = self.peek()
        if t is None:
            raise Unsupported("condition ends unexpectedly")
        self.i += 1
        return t

    def parse(self) -> Node:
        if not self.toks:
            raise Unsupported("condition is empty")
        node = self.expr()
        if self.peek() is not None:
            raise Unsupported(f"condition has unexpected token {self.peek()!r}")
        return node

    def expr(self) -> Node:
        items = [self.and_expr()]
        while (t := self.peek()) is not None and t.lower() == "or":
            self.take()
            items.append(self.and_expr())
        return items[0] if len(items) == 1 else ("or", items)

    def and_expr(self) -> Node:
        items = [self.not_expr()]
        while (t := self.peek()) is not None and t.lower() == "and":
            self.take()
            items.append(self.not_expr())
        return items[0] if len(items) == 1 else ("and", items)

    def not_expr(self) -> Node:
        t = self.peek()
        if t is not None and t.lower() == "not":
            self.take()
            return ("not", self.not_expr())
        return self.atom()

    def atom(self) -> Node:
        t = self.take()
        low = t.lower()
        if t == "(":
            node = self.expr()
            if self.take() != ")":
                raise Unsupported("condition has unbalanced parentheses")
            return node
        if t == ")":
            raise Unsupported("condition has unbalanced parentheses")
        nxt = self.peek()
        if nxt is not None and nxt.lower() == "of":
            if low not in ("1", "all"):
                raise Unsupported(f"condition '{t} of' is not supported (only '1 of' and 'all of')")
            self.take()
            target = self.take()
            if target in ("(", ")"):
                raise Unsupported("condition 'of' needs a search identifier pattern or 'them'")
            if target.lower() == "them":
                names = [n for n in self.names if not n.startswith("_")]
            else:
                rx = re.compile("^" + ".*".join(re.escape(p) for p in target.split("*")) + "$")
                names = [n for n in self.names if rx.match(n)]
            if not names:
                raise Unsupported(f"condition pattern {target!r} matches no search identifier")
            return ("of", "1" if low == "1" else "all", names)
        if low in ("and", "or", "not", "of", "them"):
            raise Unsupported(f"condition has misplaced {t!r}")
        if low == "near":
            raise Unsupported("condition uses 'near' (not supported)")
        if "*" in t:
            raise Unsupported(f"condition uses pattern {t!r} outside '1 of'/'all of'")
        if t not in self.names:
            raise Unsupported(f"condition references undefined search identifier {t!r}")
        return ("id", t)


def parse_condition(condition: Any, names: list[str]) -> Node:
    """Parse ``condition`` (a string, or a list of strings linked with OR) into an AST."""
    if isinstance(condition, list):
        if not condition or not all(isinstance(c, str) for c in condition):
            raise Unsupported("condition list must hold strings")
        nodes = [_ConditionParser(c, names).parse() for c in condition]
        return nodes[0] if len(nodes) == 1 else ("or", nodes)
    if not isinstance(condition, str):
        raise Unsupported("condition must be a string")
    return _ConditionParser(condition, names).parse()


def eval_condition(node: Node, value: Callable[[str], bool]) -> bool:
    kind = node[0]
    if kind == "id":
        return value(node[1])
    if kind == "not":
        return not eval_condition(node[1], value)
    if kind == "and":
        return all(eval_condition(n, value) for n in node[1])
    if kind == "or":
        return any(eval_condition(n, value) for n in node[1])
    if node[1] == "1":
        return any(value(n) for n in node[2])
    return all(value(n) for n in node[2])


def kleene(node: Node, value: Callable[[str], bool | None]) -> bool | None:
    """Three-valued (True/False/unknown=None) evaluation, used to decide telemetry gaps."""
    kind = node[0]
    if kind == "id":
        return value(node[1])
    if kind == "not":
        v = kleene(node[1], value)
        return None if v is None else not v
    if kind == "of":
        vals = [value(n) for n in node[2]]
        kind = "or" if node[1] == "1" else "and"
    else:
        vals = [kleene(n, value) for n in node[1]]
    if kind == "and":
        return False if False in vals else (True if all(v is True for v in vals) else None)
    return True if True in vals else (False if all(v is False for v in vals) else None)


@dataclass(frozen=True)
class Detection:
    searches: dict[str, SearchId]
    condition: Node

    @property
    def fields(self) -> set[str]:
        return {f for s in self.searches.values() for f in s.fields}


def compile_detection(detection: Any) -> Detection:
    if not isinstance(detection, dict):
        raise Unsupported("detection is not a map")
    if "condition" not in detection:
        raise Unsupported("detection has no condition")
    if "timeframe" in detection:
        raise Unsupported("detection uses 'timeframe' (aggregation/correlation, not supported)")
    searches: dict[str, SearchId] = {}
    for name, body in detection.items():
        if name == "condition":
            continue
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_]+", name):
            raise Unsupported(f"search identifier name {name!r} is not supported")
        searches[name] = compile_search(name, body)
    if not searches:
        raise Unsupported("detection has no search identifiers")
    return Detection(searches, parse_condition(detection["condition"], list(searches)))


# --------------------------------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------------------------------

_ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@lru_cache(maxsize=1)
def _aliases() -> dict[str, str]:
    from .. import library  # local import: library reads data files

    try:
        return library.technique_aliases()
    except (OSError, ValueError, KeyError):
        return {}


def techniques_from_tags(tags: Any) -> tuple[str, ...]:
    """ATT&CK technique ids from ``attack.tNNNN[.NNN]`` tags, renumbered through the library alias table
    (SigmaHQ tags predate ATT&CK v19, e.g. ``attack.t1562.001`` -> ``T1685``)."""
    out: list[str] = []
    for tag in tags or []:
        m = _ATTACK_TAG.match(str(tag))
        if m:
            tid = m.group(1).upper()
            tid = _aliases().get(tid, tid)
            if tid not in out:
                out.append(tid)
    return tuple(out)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    level: str | None
    tags: tuple[str, ...]
    techniques: tuple[str, ...]
    logsource: dict[str, Any]
    status: str  # "ok" | "unsupported"
    reason: str | None
    author: str | None = None
    license: str | None = None
    sigma_status: str | None = None
    description: str | None = None
    references: tuple[str, ...] = ()
    falsepositives: tuple[str, ...] = ()
    date: str | None = None
    modified: str | None = None
    path: str | None = None
    origin: str | None = None  # rule set folder name, e.g. "sigmahq" or "custom"
    detection: Detection | None = field(default=None, compare=False, repr=False)
    sources: tuple[mapping.Source, ...] = field(default=(), compare=False, repr=False)

    @property
    def fields(self) -> set[str]:
        return self.detection.fields if self.detection else set()


def _str_or_none(v: Any) -> str | None:
    return None if v is None else str(v)


def _str_tuple(v: Any) -> tuple[str, ...]:
    if v is None:
        return ()
    if isinstance(v, list):
        return tuple(str(x) for x in v)
    return (str(v),)


def parse_rule(doc: Any, path: str | None = None) -> Rule:
    """Build a :class:`Rule` from a parsed YAML document."""
    origin = Path(path).parent.name if path else None
    if not isinstance(doc, dict):
        return Rule(id=Path(path).stem if path else "", title=Path(path).name if path else "", level=None, tags=(),
                    techniques=(), logsource={}, status="unsupported", reason="rule file is not a YAML map",
                    path=path, origin=origin)
    tags = _str_tuple(doc.get("tags"))
    base = dict(
        id=str(doc.get("id") or (Path(path).stem if path else "")),
        title=str(doc.get("title") or (Path(path).name if path else "")),
        level=_str_or_none(doc.get("level")), tags=tags, techniques=techniques_from_tags(tags),
        logsource=doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {},
        author=_str_or_none(doc.get("author")), license=_str_or_none(doc.get("license")),
        sigma_status=_str_or_none(doc.get("status")), description=_str_or_none(doc.get("description")),
        references=_str_tuple(doc.get("references")), falsepositives=_str_tuple(doc.get("falsepositives")),
        date=_str_or_none(doc.get("date")), modified=_str_or_none(doc.get("modified")),
        path=path, origin=origin,
    )
    try:
        if "correlation" in doc:
            raise Unsupported("Sigma correlation rule (separate specification, not supported)")
        if "filter" in doc and "detection" not in doc:
            raise Unsupported("Sigma filter (meta) rule (separate specification, not supported)")
        if "action" in doc:
            raise Unsupported(f"Sigma 1.x rule collection document (action: {doc.get('action')!r}) is not supported")
        for req in ("title", "logsource", "detection"):
            if req not in doc:
                raise Unsupported(f"invalid rule: no '{req}'")
        try:
            sources = tuple(mapping.resolve_logsource(doc["logsource"]))
        except mapping.LogsourceError as exc:
            raise Unsupported(str(exc)) from None
        detection = compile_detection(doc["detection"])
    except Unsupported as exc:
        return Rule(**base, status="unsupported", reason=exc.reason)
    return Rule(**base, status="ok", reason=None, detection=detection, sources=sources)


def _unsupported(path: str | None, reason: str, doc: Any = None) -> Rule:
    rule = parse_rule(doc if isinstance(doc, dict) else None, path)
    return replace(rule, status="unsupported", reason=reason, detection=None, sources=())


def parse_rule_text(text: str, path: str | None = None) -> Rule:
    """Parse rule YAML text (one document) into a :class:`Rule`."""
    if len(text.encode("utf-8")) > MAX_RULE_BYTES:
        return _unsupported(path, f"rule file larger than {MAX_RULE_BYTES} bytes")
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        return _unsupported(path, f"YAML does not parse: {type(exc).__name__}")
    if not docs:
        return _unsupported(path, "empty rule file")
    if len(docs) > 1:
        return _unsupported(path, "multi-document YAML (Sigma 1.x rule collection) is not supported", docs[0])
    return parse_rule(docs[0], path)


def load_rule(path: Path | str) -> Rule:
    """Load one Sigma rule file. Never raises for rule content; unsupported rules carry the reason."""
    p = Path(path)
    data = p.read_bytes()
    if len(data) > MAX_RULE_BYTES:
        return _unsupported(p.as_posix(), f"rule file larger than {MAX_RULE_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _unsupported(p.as_posix(), "rule file is not UTF-8")
    return parse_rule_text(text, p.as_posix())


def load_rules(directory: Path | str, include: list[str] | None = None) -> list[Rule]:
    """Load the ``*.yml`` rules in ``directory`` (sorted by file name).

    ``include`` restricts the set to rules whose id or file stem is listed (rule-set versions are
    defined this way); an entry that names no rule raises ``ValueError``.
    """
    d = Path(directory)
    rules = [load_rule(p) for p in sorted(d.glob("*.yml"))]
    if include is None:
        return rules
    wanted = set(include)
    out = [r for r in rules if r.id in wanted or (r.path and Path(r.path).stem in wanted)]
    found = {r.id for r in out} | {Path(r.path).stem for r in out if r.path}
    missing = sorted(wanted - found)
    if missing:
        raise ValueError(f"rule selection names unknown rules: {', '.join(missing)}")
    return out
