# ReDoS Safe-Regex Harness (Python)

**Author:** [Ashay Kushwaha](https://github.com/AshayK003) ([CypherLabs](https://github.com/AshayK003))
**Report:** [internals/report.pdf](internals/report.pdf)

> **Status: measured on CPython 3.12.10 (Windows), `python report.py`
> regenerates every number.** Article follows numbers, never precedes them.

---

## Gap

CPython is the only major regex engine with **no ReDoS defense**
(SoK ReDoS, ASIACCS'25: Rust/Go safe, JS/Ruby/Java/C# partial, Python
"Not Safe"). Static checkers flag patterns without measuring real cost —
no single tool catches every evil pattern (Rogers 2025, 9 tools, 12
patterns). Dynamic fuzzers target JS/Java engines or cost 1000s of
CPU-hours. **No fast stdlib Python harness measures real `re` timing and
ships verified fixes.** This repo is that harness.

## What it will do

Time 5 CVE-grounded patterns on pump strings, fit linear/polynomial/
exponential growth, auto-rewrite with Python 3.11+ atomic groups and
possessive quantifiers, and re-time to **prove** each fix — accepting a
rewrite only if benign behavior is byte-identical and worst-case latency
collapses to ~linear.

## Results (`python report.py`, 15s per-case timeout)

| Entry (CVE) | Before | After | Verdict |
|---|---|---|---|
| black tabs (2024-21503) | exponential: 59ms → 389ms → 3.3s → TIMEOUT ×2 | — | UNFIXED: no sound atomic rewrite exists; upstream removed the regex |
| pydantic email (2024-3772) | polynomial: 21ms → 88ms → 369ms → 1.6s → 6.1s (~4.2×/doubling) | — | UNFIXED: atomic rewrite breaks valid matches; upstream capped length at 2048. Published Snyk PoC (`'<' + ' ' * 3000`) measures 0.0ms — does not reproduce; our spaces-first pump does |
| sqlparse string (2023-30608) | exponential: 0.2ms → 254ms → TIMEOUT ×3 | `'(?>''\|\\\\\|\\'\|[^'])*'` → all ≤0.1ms, linear | **FIXED**, benigns byte-identical |
| tornado unquote (2024-52804) | exponential: 334ms → 1.3s → 5.0s → TIMEOUT ×2 | — | driver-level quadratic (repeated `.search`); fix is restructure to single `.sub()` pass, as upstream did |
| tarfile pax (2024-6232) | linear: ≤0.3ms | — | CLEAN control: suspect-shaped, correctly not flagged |
| tarfile hdrcharset (2024-6232) | polynomial: 26ms → 101ms → 362ms → 1.6s → 6.1s | possessive variant tried: constant-only win, class unchanged (search position-scan dominates) | UNFIXED: needs parser restructure, as upstream did |

Accept-rule for every fix: benign accept/reject verdicts byte-identical AND
growth class drops to linear, both re-measured — never inferred.

## References

- SoK ReDoS: https://arxiv.org/abs/2406.11618 (artifact: PurdueDualityLab/SoKReDoS-ASIACCS25)
- ReDoSHunter (USENIX Sec'21): https://www.usenix.org/system/files/sec21-li-yeting.pdf
- REGULATOR (USENIX Sec'22): https://www.usenix.org/system/files/usenixsecurity22-mclaughlin.pdf
- Python 3.11 atomic groups: https://docs.python.org/3.11/library/re.html / bpo-433030
- Tool comparison: https://joshua.hu/comparing-redos-detection-tools

## Limitations (honest, updated as numbers land)

- Python ≥3.11 required (atomic-group syntax doesn't exist below).
- `ast`-free dynamic timing only; adversarial pump strings are synthetic, not traffic replays.
- Corpus v1 = 5 CVE patterns; generality claims wait for a bigger corpus.
