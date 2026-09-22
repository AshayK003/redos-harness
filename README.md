# ReDoS Safe-Regex Harness (Python)

**Author:** [Ashay Kushwaha](https://github.com/AshayK003) ([CypherLabs](https://github.com/AshayK003))

> **Status: corpus freeze in progress — no numbers yet.** Nothing below is
> claimed until one command reproduces it. Article follows numbers, never
> precedes them.

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
