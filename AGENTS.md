# Agent notes

## Benchmark discipline

Always validate against MaliciousSkillBench before changing detection behavior.
Record the baseline first, then change, then rerun and compare.

```bash
CGO_ENABLED=0 go build -trimpath -o decloak ./cmd/decloak
uv run scripts/bench_msb.py --bin ./decloak --part validation
uv run scripts/bench_msb.py --bin ./decloak --part validation --policy --breakdown
```

- Report recall and FPR at HIGH+ (LOW+ when relevant). The validation split is
  the tuning surface.
- Never tune on the `test` split. Run it only for final reporting.
- The default split is `source_disjoint`; the pinned dataset is cached under
  `.bench/msb/`.
- The judge (`decloak-judge`) does not change static detection, but rule changes
  still require the baseline above. Measure judge recall on validation with:

  ```bash
  uv run scripts/bench_msb.py --bin ./decloak --part validation --policy \
    --judge-bin ./decloak-judge --judge-only --judge-provider opencode
  ```

- The judge defaults to `--provider opencode` in the benchmark script and uses
  `deepseek-v4.1-flash-free` unless `--judge-model` is given. Set
  `OPENCODE_API_KEY` before running. Verdicts are cached under
  `~/.cache/decloak/judge`; pass `--no-cache` to force fresh calls.


## Baseline (source_disjoint / validation, 2026-11-18)

- default rules: HIGH+ **23.9% recall / 0.0% FPR**; LOW+ 32.0% / 1.8%.
- `--policy`: HIGH+ **36.3% recall / 1.2% FPR**; LOW+ 44.4% / 3.6%.

Re-record this after any detection change, and update the README numbers if they
shift. Test split numbers are reporting-only: default 3.9%/2.6%, `--policy`
36.7%/3.3% (HIGH+).
