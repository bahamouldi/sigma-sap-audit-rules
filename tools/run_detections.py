#!/usr/bin/env python3
"""Minimal Sigma rule runner for the SAP Security Audit Log ruleset.

Runs the rules in sigma/rules/sap/ against a JSONL file of normalised audit events and
prints the findings.

WHY A LOCAL RUNNER
    `sigma-cli` was not usable in the target environment (it hangs at startup on this
    machine), and depending on it would make the ruleset impossible to demonstrate
    offline. This runner implements the subset of the Sigma specification the rules in
    this repository actually use, and nothing more. It is deliberately small and
    readable rather than a general-purpose engine.

SUPPORTED SIGMA SUBSET
    logsource.category / logsource.product   - advisory only, not used for matching
    detection.<name>                          - a selection is a mapping of conditions
      field: value                            equality (str, int, bool)
      field: [a, b, c]                        equality against any of the values
      field: value*   field: *value   field: *value*   glob matching
      field|contains: v   |startswith: v   |endswith: v   |re: v (regex)
      - bare string list                      every keyword must be present somewhere
    condition                                - selection names joined by " and ", " or ",
                                               "not", parentheses, and
                                               "count() by <field> > <n>"

NOT SUPPORTED (and not used by these rules)
    - aggregation modifiers (first, last, distinct)
    - near / re modifiers on values
    - timeframe windows
    - field existence operators other than plain equality

Usage:
    python3 tools/run_detections.py --rules sigma/rules/sap --logs events.jsonl
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# A selection is a list of predicates; an event matches when all of them hold.
Predicate = dict[str, Any]


@dataclass
class Rule:
    path: Path
    title: str
    uid: str
    level: str
    tags: list[str]
    detection: dict[str, Any]
    logsource: dict[str, Any]
    raw: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- loading


def load_rules(directory: Path) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(directory.rglob("*.yml")):
        import yaml

        with path.open(encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not doc or "detection" not in doc:
            continue
        tags = doc.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        detection = doc["detection"]
        rules.append(
            Rule(
                path=path,
                title=doc.get("title", path.stem),
                uid=str(doc.get("id", "")),
                # Per the Sigma specification, level and falsepositives live inside the
                # detection block. Fall back to the top level for tolerance.
                level=str(detection.get("level", doc.get("level", "informational"))),
                tags=[str(t) for t in tags],
                detection=detection,
                logsource=doc.get("logsource") or {},
                raw=doc,
            )
        )
    return rules


# ----------------------------------------------------------------------- match engine


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _match_one(event: dict, predicate: Predicate) -> bool:
    """Evaluate a single {field: spec} predicate against one event."""
    for field_name, spec in predicate.items():
        for op, modifier in (("|contains", "contains"), ("|startswith", "startswith"), ("|endswith", "endswith"), ("|re", "re")):
            if field_name.endswith(op):
                real_field = field_name[: -len(op)]
                if real_field not in event:
                    return False
                actual = str(event[real_field] or "")
                expected = str(spec)
                if modifier == "contains" and expected not in actual:
                    return False
                if modifier == "startswith" and not actual.startswith(expected):
                    return False
                if modifier == "endswith" and not actual.endswith(expected):
                    return False
                if modifier == "re" and not re.search(expected, actual):
                    return False
                break
        else:
            if field_name not in event:
                return False
            actual = event[field_name]
            if isinstance(spec, str) and any(ch in spec for ch in "*?"):
                if not fnmatch.fnmatch(str(actual or ""), spec):
                    return False
            elif actual not in _as_list(spec):
                return False
    return True


def _keywords_in_event(keyword: str, event: dict) -> bool:
    needle = keyword.lower()
    for value in event.values():
        if value is not None and needle in str(value).lower():
            return True
    return False


def match_selection(events: list[dict], selection: Any) -> list[dict]:
    """Return the subset of events matching a Sigma selection."""
    predicates: list[Predicate] = []
    keywords: list[str] = []

    if isinstance(selection, list):
        # A bare list of strings is a keyword list: every keyword must be present.
        keywords = [str(k) for k in selection]
    else:
        predicates.append(selection)

    out = []
    for event in events:
        if all(_match_one(event, p) for p in predicates) and all(
            _keywords_in_event(k, event) for k in keywords
        ):
            out.append(event)
    return out


# ---------------------------------------------------------------- condition parsing

_COUNT_RE = re.compile(r"count\(\)\s*by\s+([\w.]+)\s*>\s*(\d+)")


def _split_or(expression: str) -> list[str]:
    """Split a condition on top-level 'or' / 'and' / 'not', dropping the operators.

    Returns the operand list only: ['selection or additional'] -> ['selection', 'additional'].
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for token in re.split(r"(\s+or\s+|\s+and\s+|\s+not\s+|\(|\))", expression):
        if token == "(":
            depth += 1
            current.append(token)
        elif token == ")":
            depth -= 1
            current.append(token)
        elif depth == 0 and token.strip().lower() in ("or", "and", "not", ""):
            if token.strip() == "" and not current:
                continue
            joined = "".join(current).strip()
            if joined:
                parts.append(joined)
            current = []
        else:
            current.append(token)
    joined = "".join(current).strip()
    if joined:
        parts.append(joined)
    return parts


def evaluate_condition(rule: Rule, events: list[dict]) -> list[dict]:
    condition = str(rule.detection.get("condition", "selection")).strip()

    count_match = _COUNT_RE.search(condition)
    if count_match:
        field_name, threshold = count_match.group(1), int(count_match.group(2))
        base = _evaluate_name(rule, events, "selection")
        buckets: dict[Any, list[dict]] = defaultdict(list)
        for event in base:
            buckets[event.get(field_name)].append(event)
        hit: list[dict] = []
        for group in buckets.values():
            if len(group) > threshold:
                hit.extend(group)
        return hit

    return _evaluate_expression(rule, events, condition)


def _evaluate_name(rule: Rule, events: list[dict], name: str) -> list[dict]:
    if name not in rule.detection:
        raise KeyError(f"{rule.path.name}: selection '{name}' referenced but not defined")
    return match_selection(events, rule.detection[name])


def _evaluate_expression(rule: Rule, events: list[dict], expression: str) -> list[dict]:
    expression = expression.strip()
    if expression.startswith("not "):
        excluded = set(id(e) for e in _evaluate_expression(rule, events, expression[4:]))
        return [e for e in events if id(e) not in excluded]
    if expression.startswith("(") and expression.endswith(")"):
        return _evaluate_expression(rule, events, expression[1:-1])

    or_parts = _split_or(expression)
    if len(or_parts) > 1:
        out: list[dict] = []
        seen = set()
        for part in or_parts:
            part = part.strip()
            if part.lower() in ("or", ""):
                continue
            for event in _evaluate_expression(rule, events, part):
                if id(event) not in seen:
                    seen.add(id(event))
                    out.append(event)
        return out

    and_parts = [p for p in _split_or(expression) if p.strip().lower() not in ("and", "")]
    if len(and_parts) > 1:
        result = events
        for part in and_parts:
            selected = set(id(e) for e in _evaluate_expression(rule, events, part.strip()))
            result = [e for e in result if id(e) in selected]
        return result

    return _evaluate_name(rule, events, expression)


# -------------------------------------------------------------------------- reporting


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rules", type=Path, default=Path("sigma/rules/sap"))
    ap.add_argument("--logs", type=Path, required=True, help="JSONL file of audit events")
    ap.add_argument("--min-level", default=None, choices=["low", "medium", "high", "critical"])
    args = ap.parse_args(argv)

    events = [json.loads(line) for line in args.logs.read_text(encoding="utf-8").splitlines() if line.strip()]
    rules = load_rules(args.rules)

    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = order.get(args.min_level, 0)

    print(f"{len(events)} events | {len(rules)} rules | ruleset {args.rules}")
    print("=" * 78)

    total = 0
    for rule in rules:
        if order.get(rule.level, 0) < threshold:
            continue
        try:
            hits = evaluate_condition(rule, events)
        except Exception as exc:  # noqa: BLE001 - report and continue, this is a CLI tool
            print(f"[ERROR] {rule.path.name}: {exc}")
            continue
        if not hits:
            print(f"[  --  ] {rule.level.upper():8} {rule.title}  (0 match)")
            continue
        total += len(hits)
        users = sorted({str(h.get("user")) for h in hits})
        hosts = sorted({str(h.get("client_host")) for h in hits})
        print(f"[ HIT  ] {rule.level.upper():8} {rule.title}  ({len(hits)} match)")
        print(f"          id      : {rule.uid}")
        print(f"          users   : {', '.join(users)}")
        print(f"          hosts   : {', '.join(hosts)}")
        print(f"          tags    : {', '.join(rule.tags)}")
        for hit in hits[:3]:
            print(f"          e.g.    : {hit['timestamp']}  {hit['event_type']}  "
                  f"user={hit.get('user')} host={hit.get('client_host')} tcode={hit.get('tcode')}")
        print()

    print("=" * 78)
    print(f"{total} events matched across {len(rules)} rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())