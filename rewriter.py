"""Conservative atomic-group rewrites (stdlib only, needs Python >= 3.11).

Each rule returns a candidate pattern or None if inapplicable. A candidate
is accepted ONLY by the conjunction (SPEC accept-rule):
  1. benign verdicts byte-identical (harness.benign_check on both), AND
  2. growth class drops to linear (harness.measure + classify on pumps).

Rules never promise semantic equivalence in general; the measurements do.
"""

import re


def rule_nested_plus(pattern):
    """(X+)+ -> (X++): possessive inner kills the ambiguity that feeds
    catastrophic backtracking. Example: (a+)+$ -> (a++)$"""
    new, n = re.subn(r"\(([^()]+)\+\)\+", r"(\1++)", pattern)
    return new if n else None


def rule_atomic_star(pattern):
    """(...) * LITERAL -> (?>...) * LITERAL: commit to the greedy first path,
    fail fast instead of backtracking. Narrow shape only: one star-group
    followed by a single trailing literal char.
    Example: '(...)*' -> '(?>...)*'"""
    i = pattern.rfind(")*")
    if i <= 0:
        return None
    # head = everything before the LAST '(' that opens the star group
    open_idx = pattern.rfind("(", 0, i)
    if open_idx < 0:
        return None
    head, inner, tail = pattern[:open_idx], pattern[open_idx + 1 : i], pattern[i + 2 :]
    if not inner or "(" in inner or ")" in inner:
        return None
    if len(tail) != 1 or tail.isalnum():
        return None
    return f"{head}(?>{inner})*{tail}"


RULES = (rule_nested_plus, rule_atomic_star)


def rewrite_candidates(pattern):
    """All distinct candidates from every applicable rule."""
    out = []
    for rule in RULES:
        try:
            cand = rule(pattern)
        except re.error:
            continue
        if cand and cand != pattern and cand not in out:
            out.append(cand)
    return out
