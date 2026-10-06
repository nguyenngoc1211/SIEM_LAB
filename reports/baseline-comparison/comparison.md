# Baseline mapper comparison

- Generated at: `2026-10-06T14:14:04.124272+00:00`
- Primary paired metric: `primary_hit`
- Dataset: `1.0.0` (90 alerts)
- Alerts SHA-256: `68ebdf83997bd8033c02808688e3fdf752d4214edf483452788f6350e5bf481e`

## Overall metrics

| Strategy | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit | Wrong primary | Coverage | Abstain | Median latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bm25_only | 90 | 34.4% | 34.4% | 67.8% | 37.2% | 60.0% | 100.0% | 0.0% | 1.24 |
| bm25_only_threshold | 90 | 34.4% | 34.4% | 67.8% | 37.2% | 60.0% | 100.0% | 0.0% | 1.334 |
| deepseek_only | 90 | 58.9% | 58.9% | 94.4% | 63.3% | 27.8% | 95.6% | 4.4% | 6532.487 |
| hybrid_current | 90 | 47.8% | 47.8% | 81.1% | 53.3% | 18.9% | 77.8% | 22.2% | 2227.967 |

## Per-group breakdown

| Strategy | Group | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit |
|---|---|---:|---:|---:|---:|---:|
| bm25_only | A1 | 15 | 33.3% | 33.3% | 40.0% | 33.3% |
| bm25_only | A2 | 75 | 34.7% | 34.7% | 73.3% | 38.0% |
| bm25_only_threshold | A1 | 15 | 33.3% | 33.3% | 40.0% | 33.3% |
| bm25_only_threshold | A2 | 75 | 34.7% | 34.7% | 73.3% | 38.0% |
| deepseek_only | A1 | 15 | 33.3% | 33.3% | 86.7% | 33.3% |
| deepseek_only | A2 | 75 | 64.0% | 64.0% | 96.0% | 69.3% |
| hybrid_current | A1 | 15 | 33.3% | 33.3% | 80.0% | 33.3% |
| hybrid_current | A2 | 75 | 50.7% | 50.7% | 81.3% | 57.3% |

## Paired McNemar tests (primary hit)

| Comparison | Only first | Only second | p-value |
|---|---:|---:|---:|
| bm25_only__vs__bm25_only_threshold | 0 | 0 | 1.0 |
| bm25_only__vs__deepseek_only | 8 | 30 | 0.000472 |
| bm25_only__vs__hybrid_current | 2 | 14 | 0.004181 |
| bm25_only_threshold__vs__deepseek_only | 8 | 30 | 0.000472 |
| bm25_only_threshold__vs__hybrid_current | 2 | 14 | 0.004181 |
| deepseek_only__vs__hybrid_current | 21 | 11 | 0.110184 |

## Notes

- `exact_top1` requires the single expected technique to be the primary mapping.
- `primary_hit` accepts any expected technique as primary.
- `partial_credit` gives 1.0 for an exact hit and 0.5 for a parent/child relation.
- `hybrid_current` is read from archived reports and is a reference, not a re-run.
- Status values `skipped` and `error` mean the strategy did not produce a mapping.
