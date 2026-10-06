# Baseline mapper comparison

- Generated at: `2026-10-05T13:17:06.404428+00:00`
- Primary paired metric: `primary_hit`
- Dataset: `1.0.0` (90 alerts)
- Alerts SHA-256: `68ebdf83997bd8033c02808688e3fdf752d4214edf483452788f6350e5bf481e`

## Overall metrics

| Strategy | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit | Wrong primary | Coverage | Abstain | Median latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gemini_only | 90 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | n/a |

## Per-group breakdown

| Strategy | Group | N | Exact top-1 | Primary hit | Top-3 hit | Partial credit |
|---|---|---:|---:|---:|---:|---:|
| gemini_only | A1 | 15 | 0.0% | 0.0% | 0.0% | 0.0% |
| gemini_only | A2 | 75 | 0.0% | 0.0% | 0.0% | 0.0% |

## Paired McNemar tests (primary hit)

| Comparison | Only first | Only second | p-value |
|---|---:|---:|---:|

## Warnings

- `gemini_only`: 90/90 runs did not produce a mapping. Status counts: `{'error': 1, 'not_run': 89}`.

## Notes

- `exact_top1` requires the single expected technique to be the primary mapping.
- `primary_hit` accepts any expected technique as primary.
- `partial_credit` gives 1.0 for an exact hit and 0.5 for a parent/child relation.
- `hybrid_current` is read from archived reports and is a reference, not a re-run.
- Status values `skipped` and `error` mean the strategy did not produce a mapping.
