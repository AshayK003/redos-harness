"""One-command benchmark: growth class per corpus entry + rewrite verdicts.

Usage: python report.py   (reads corpus.json, prints before/after table)
Every number regenerable; timeouts are table entries, not errors.
"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from harness import benign_check, classify, fit_slope, measure  # noqa: E402
from rewriter import rewrite_candidates  # noqa: E402

TIMEOUT_S = 15


def _tornado_time(s):
    """Module top level so multiprocessing spawn can pickle it."""
    t0 = time.perf_counter()
    tornado_old(s)
    return time.perf_counter() - t0


def tornado_old(s):
    import re

    OctalPatt = re.compile(r"\\[0-3][0-7][0-7]")
    QuotePatt = re.compile(r"[\\].")
    i, n, res = 0, len(s), []
    while 0 <= i < n:
        o_match = OctalPatt.search(s, i)
        q_match = QuotePatt.search(s, i)
        if not o_match and not q_match:
            res.append(s[i:])
            break
        j = k = -1
        if o_match:
            j = o_match.start(0)
        if q_match:
            k = q_match.start(0)
        if q_match and (not o_match or k < j):
            res.append(s[i:k])
            res.append(s[k + 1])
            i = k + 2
        else:
            res.append(s[i:j])
            res.append(chr(int(s[j + 1 : j + 4], 8)))
            i = j + 4
    return "".join(res)


# entry id -> (method, [pump texts smallest-first], accepts, rejects)
def pumps(entry):
    eid = entry["id"]
    if eid == "black-tabs":
        ns = [250, 500, 1000, 2000, 4000]
        return "match", ["\t" * n for n in ns], ["\tx"], ["   "], ns
    if eid == "pydantic-email":
        ns = [1500, 3000, 6000, 12000, 24000]
        return "fullmatch", [" " * n + "<" + "y" * n for n in ns], ["name <a@b.com>"], ["not-an-email"], ns
    if eid == "sqlparse-string":
        ns = [15, 30, 60, 120, 240]
        return "match", ["'" + "\\" * n for n in ns], ["'hello'", "'it''s'", "'\\\\'", "'\\''"], ["hello", "'unterminated"], ns
    if eid == "tarfile-pax":
        ns = [1000, 2000, 4000, 8000, 16000]
        return "match", [b"9" * n for n in ns], [b"13 foo="], [b"   "], ns
    if eid == "tarfile-hdrcharset":
        ns = [2500, 5000, 10000, 20000, 40000]
        return "search", [b"1" * n for n in ns], [b"12 hdrcharset=BINARY\n"], [b"no digits here!"], ns
    raise ValueError(eid)


def fmt(times):
    return "[" + ", ".join("TIMEOUT" if t is None else f"{t * 1000:.1f}ms" for t in times) + "]"


def main():
    corpus = json.load(open(os.path.join(HERE, "corpus.json")))["entries"]
    print(f"{'entry':<20} {'before':<12} {'candidate':<38} {'after':<12} verdict")
    print("-" * 110)
    for entry in corpus:
        eid = entry["id"]
        if entry.get("kind") == "driver":
            ns = [5000, 10000, 20000, 40000, 80000]
            import multiprocessing as mp

            texts = ['a="b=' + "\\\\" * n + '"' for n in ns]
            out = []
            with mp.Pool(1) as pool:
                for t in texts:
                    ar = pool.apply_async(_tornado_time, (t,))
                    try:
                        out.append(ar.get(timeout=TIMEOUT_S))
                    except mp.TimeoutError:
                        out += [None] * (len(texts) - len(out))
                        break
            dslope = fit_slope(out, ns)
            print(f"{eid:<20} {classify(out, ns):<12} {'(driver: restructure, no pattern rule)':<38} {'-':<12} measured; fix=upstream sub-pass")
            print(f"  times: {fmt(out)} slope={dslope:.2f}" if dslope is not None else f"  times: {fmt(out)}")
            continue
        method, texts, accepts, rejects, ns = pumps(entry)
        pat = entry["pattern"]  # JSON escaping already yields the exact source pattern
        before = measure(pat, method, texts)
        bclass = classify(before, ns)
        bslope = fit_slope(before, ns)
        ok, _ = benign_check(pat, method, accepts, rejects)
        verdict, after, cand_shown = "UNFIXED", None, "-"
        if bclass == "linear":
            verdict = "CLEAN (control)"
        for cand in rewrite_candidates(pat):
            cok, _ = benign_check(cand, method, accepts, rejects)
            if not cok:
                continue
            at = measure(cand, method, texts)
            if classify(at, ns) == "linear":
                verdict, after, cand_shown = "FIXED", at, cand
                break
        print(f"{eid:<20} {bclass:<12} {cand_shown:<38} {(classify(after, ns) if after else '-').center(12)} {verdict}{' (benign base broken!)' if not ok else ''}")
        slope_txt = f" slope={bslope:.2f}" if bslope is not None else ""
        print(f"  times: {fmt(before)}{slope_txt}")
        if after:
            print(f"  fixed: {fmt(after)}")


if __name__ == "__main__":
    main()
