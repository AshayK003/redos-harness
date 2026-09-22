"""The one runnable check (SPEC): evil flagged + fixed, safe stays clean,
rewrites never alter benign verdicts."""

from harness import benign_check, classify, measure
from rewriter import rewrite_candidates

EVIL = r"(a+)+$"
SAFE = r"a+$"
SIZES = [10, 20, 40, 80, 160]
ACCEPTS = ["aaaa"]
REJECTS = ["aaab"]


def texts(core="a", suffix="b"):
    return [core * n + suffix for n in SIZES]


def growth(pattern):
    return classify(measure(pattern, "match", texts()))


def test_evil_flagged():
    assert growth(EVIL) == "exponential (timeout)"


def test_evil_fixed_by_rewrite():
    cands = rewrite_candidates(EVIL)
    assert cands, "no rewrite candidate for evil pattern"
    fixed = [
        c
        for c in cands
        if benign_check(c, "match", ACCEPTS, REJECTS)[0]
        and benign_check(EVIL, "match", ACCEPTS, REJECTS)[0]
        and classify(measure(c, "match", texts())) == "linear"
    ]
    assert fixed, f"no candidate fixed it: {cands}"


def test_safe_stays_clean():
    assert growth(SAFE) == "linear"
    assert benign_check(SAFE, "match", ACCEPTS, REJECTS)[0]


def test_rewrite_preserves_benigns():
    for c in rewrite_candidates(EVIL):
        ok, detail = benign_check(c, "match", ACCEPTS, REJECTS)
        assert ok, f"{c}: {detail}"
