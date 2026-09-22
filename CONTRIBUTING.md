# Contributing

## One command reproduces everything

```bash
python -m pytest tests -q   # suite green on CPython >= 3.11
python report.py            # regenerates every README number (15s per-case timeout)
```

## Corpus policy (frozen v1)

`corpus.json` v1 (6 entries / 5 CVEs) is **frozen**. Every entry was
reproduced on CPython 3.12 before freezing. Additions bump the version and
re-run everything — no entry without a measured pump and benign
accept/reject strings.

## Rewrite rules

New rules go in `rewriter.py` and pass the accept-rule conjunction:
benign verdicts byte-identical AND growth class drops to linear, both
re-measured. A rule that only wins constants (see tarfile-hdrcharset note
in `corpus.json`) gets deleted, not merged.

## Open issues (stretch, in order)

1. **Parser-replacement table** — benchmark email-validator / urllib.parse
   drop-ins with measured false-accept/reject + worst-case latency.
2. Pump knee-tuning per entry (no verdict impact; polish).
3. Tornado/black benign-set expansion from advisory tests.
4. New rewrite rules behind the accept-rule gate.
