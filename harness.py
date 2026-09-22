"""ReDoS timing harness (stdlib only).

Measure a pattern's worst-case growth on pump strings and classify it:
linear / polynomial / exponential. Timeout is recorded as data, never
swallowed. Timing runs in worker *processes* (threads can't be killed
under the GIL when `re` backtracks catastrophically).
"""

import multiprocessing as mp
import re
import statistics
import time

TIMEOUT_S = 15


def time_once(pattern, method, text):
    """Single timing in this process. Returns seconds."""
    rx = re.compile(pattern)
    t0 = time.perf_counter()
    try:
        if method == "match":
            rx.match(text)
        elif method == "fullmatch":
            rx.fullmatch(text)
        elif method == "search":
            rx.search(text)
        else:
            raise ValueError(f"unknown method: {method}")
    except Exception:
        pass
    return time.perf_counter() - t0


def _worker(args):
    pattern, method, text = args
    return time_once(pattern, method, text)


def measure(pattern, method, texts, timeout=TIMEOUT_S):
    """Time pattern against each text. Returns [seconds | None(timeout)]."""
    out = []
    with mp.Pool(1) as pool:
        for t in texts:
            ar = pool.apply_async(_worker, ((pattern, method, t),))
            try:
                out.append(ar.get(timeout=timeout))
            except mp.TimeoutError:
                out += [None] * (len(texts) - len(out))
                break
    return out


def classify(times):
    """Growth class from per-doubling times. Timeout past the first length
    counts as exponential: a real attacker only needs the small input."""
    if any(t is None for t in times[1:]):
        return "exponential (timeout)"
    pairs = [(a, b) for a, b in zip(times, times[1:]) if a and a > 0 and b is not None]
    if not pairs:
        return "unknown"
    median_ratio = statistics.median(b / a for a, b in pairs)
    if median_ratio >= 6:
        return "exponential"
    if median_ratio >= 2.7:
        return "polynomial"
    return "linear"


def benign_check(pattern, method, accepts, rejects):
    """True iff every accept matches and every reject doesn't.

    Returns (ok, detail-string). Semantics compared as match/no-match only.
    """
    rx = re.compile(pattern)
    fn = {"match": rx.match, "fullmatch": rx.fullmatch, "search": rx.search}[method]
    for s in accepts:
        if not fn(s):
            return False, f"accept missed: {s!r}"
    for s in rejects:
        if fn(s):
            return False, f"reject matched: {s!r}"
    return True, "ok"
