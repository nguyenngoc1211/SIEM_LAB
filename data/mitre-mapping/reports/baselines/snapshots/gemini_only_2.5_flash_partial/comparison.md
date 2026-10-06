# Baseline mapper comparison

- Generated at: `2026-10-05T13:41:33.762583+00:00`
- Primary paired metric: `primary_hit`
- Dataset: `1.0.0` (23 alerts)
- Alerts SHA-256: `68ebdf83997bd8033c02808688e3fdf752d4214edf483452788f6350e5bf481e`

## Overall metrics

| Strategy | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit | Wrong primary | Coverage | Abstain | Median latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bm25_only | 23 | 26.1% | 26.1% | 60.9% | 26.1% | 73.9% | 100.0% | 0.0% | 1.206 |
| bm25_only_threshold | 23 | 26.1% | 26.1% | 60.9% | 26.1% | 73.9% | 100.0% | 0.0% | 1.233 |
| gemini_only | 23 | 78.3% | 78.3% | 91.3% | 78.3% | 21.7% | 100.0% | 0.0% | 16031.407 |
| gemini_only_pro31 | 23 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | n/a |
| hybrid_current | 23 | 39.1% | 39.1% | 69.6% | 39.1% | 21.7% | 60.9% | 39.1% | 1945.971 |

## Per-group breakdown

| Strategy | Group | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit |
|---|---|---:|---:|---:|---:|---:|
| bm25_only | A1 | 15 | 33.3% | 33.3% | 40.0% | 33.3% |
| bm25_only | A2 | 8 | 12.5% | 12.5% | 100.0% | 12.5% |
| bm25_only_threshold | A1 | 15 | 33.3% | 33.3% | 40.0% | 33.3% |
| bm25_only_threshold | A2 | 8 | 12.5% | 12.5% | 100.0% | 12.5% |
| gemini_only | A1 | 15 | 66.7% | 66.7% | 86.7% | 66.7% |
| gemini_only | A2 | 8 | 100.0% | 100.0% | 100.0% | 100.0% |
| gemini_only_pro31 | A1 | 15 | 0.0% | 0.0% | 0.0% | 0.0% |
| gemini_only_pro31 | A2 | 8 | 0.0% | 0.0% | 0.0% | 0.0% |
| hybrid_current | A1 | 15 | 33.3% | 33.3% | 80.0% | 33.3% |
| hybrid_current | A2 | 8 | 50.0% | 50.0% | 50.0% | 50.0% |

## Paired McNemar tests (primary hit)

| Comparison | Only first | Only second | p-value |
|---|---:|---:|---:|
| bm25_only__vs__bm25_only_threshold | 0 | 0 | 1.0 |
| bm25_only__vs__gemini_only | 1 | 13 | 0.001831 |
| bm25_only__vs__gemini_only_pro31 | 6 | 0 | 0.03125 |
| bm25_only__vs__hybrid_current | 0 | 3 | 0.25 |
| bm25_only_threshold__vs__gemini_only | 1 | 13 | 0.001831 |
| bm25_only_threshold__vs__gemini_only_pro31 | 6 | 0 | 0.03125 |
| bm25_only_threshold__vs__hybrid_current | 0 | 3 | 0.25 |
| gemini_only__vs__gemini_only_pro31 | 18 | 0 | 8e-06 |
| gemini_only__vs__hybrid_current | 10 | 1 | 0.011719 |
| gemini_only_pro31__vs__hybrid_current | 0 | 9 | 0.003906 |

## Warnings

- `gemini_only_pro31`: 23/23 runs did not produce a mapping. Status counts: `{'error': 1, 'not_run': 22}`.

## Notes

- `exact_top1` requires the single expected technique to be the primary mapping.
- `primary_hit` accepts any expected technique as primary.
- `partial_credit` gives 1.0 for an exact hit and 0.5 for a parent/child relation.
- `hybrid_current` is read from archived reports and is a reference, not a re-run.
- Status values `skipped` and `error` mean the strategy did not produce a mapping.
