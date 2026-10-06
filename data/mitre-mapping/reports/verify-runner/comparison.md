# Baseline mapper comparison

- Generated at: `2026-10-05T13:59:54.975540+00:00`
- Primary paired metric: `primary_hit`
- Dataset: `1.0.0` (90 alerts)
- Alerts SHA-256: `68ebdf83997bd8033c02808688e3fdf752d4214edf483452788f6350e5bf481e`

## Overall metrics

| Strategy | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit | Wrong primary | Coverage | Abstain | Median latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bm25_only | 90 | 0.0% | 0.0% | 0.0% | 0.0% | 1.1% | 1.1% | 98.9% | 2.339 |
| bm25_only_threshold | 90 | 0.0% | 0.0% | 0.0% | 0.0% | 1.1% | 1.1% | 98.9% | 3.461 |
| hybrid_current | 90 | 47.8% | 47.8% | 81.1% | 53.3% | 18.9% | 77.8% | 22.2% | 2227.967 |

## Per-group breakdown

| Strategy | Group | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit |
|---|---|---:|---:|---:|---:|---:|
| bm25_only | A1 | 15 | 0.0% | 0.0% | 0.0% | 0.0% |
| bm25_only | A2 | 75 | 0.0% | 0.0% | 0.0% | 0.0% |
| bm25_only_threshold | A1 | 15 | 0.0% | 0.0% | 0.0% | 0.0% |
| bm25_only_threshold | A2 | 75 | 0.0% | 0.0% | 0.0% | 0.0% |
| hybrid_current | A1 | 15 | 33.3% | 33.3% | 80.0% | 33.3% |
| hybrid_current | A2 | 75 | 50.7% | 50.7% | 81.3% | 57.3% |

## Paired McNemar tests (primary hit)

| Comparison | Only first | Only second | p-value |
|---|---:|---:|---:|
| bm25_only__vs__bm25_only_threshold | 0 | 0 | 1.0 |
| bm25_only__vs__hybrid_current | 0 | 43 | 0.0 |
| bm25_only_threshold__vs__hybrid_current | 0 | 43 | 0.0 |

## Warnings

- `bm25_only`: 89/90 runs did not produce a mapping. Status counts: `{'mapped': 1, 'not_run': 89}`.
- `bm25_only_threshold`: 89/90 runs did not produce a mapping. Status counts: `{'mapped': 1, 'not_run': 89}`.

## Notes

- `exact_top1` requires the single expected technique to be the primary mapping.
- `primary_hit` accepts any expected technique as primary.
- `partial_credit` gives 1.0 for an exact hit and 0.5 for a parent/child relation.
- `hybrid_current` is read from archived reports and is a reference, not a re-run.
- Status values `skipped` and `error` mean the strategy did not produce a mapping.
