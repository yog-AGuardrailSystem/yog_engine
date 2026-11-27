# OpenFGA Equivalence & Stress Benchmarks

Generated 2026-11-27T07:45:51+00:00.

## OpenFGA (`common` corpus, local tuple-graph evaluator)

Total checked: **900**, mismatches: **0**.

| Size | Checked | Mismatches |
| --- | ---: | ---: |
| small | 300 | 0 |
| medium | 300 | 0 |
| large | 300 | 0 |

## Concurrent Throughput (`ReferencePDP`)

| Threads | Calls | Throughput (ops/s) | p50 (µs) | p95 (µs) | p99 (µs) | Errors |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 500 | 19226.9 | 37.7 | 81.5 | 305.8 | 0 |
| 2 | 1000 | 21275.5 | 37.0 | 78.5 | 140.9 | 0 |
| 4 | 2000 | 20505.2 | 37.5 | 92.1 | 196.4 | 0 |
| 8 | 4000 | 20017.1 | 37.3 | 87.3 | 194.1 | 0 |

## Memory Ceiling (2,000 facts)

- Decision: `ALLOW`
- Peak traced Python heap: **2792.8 KiB**
- `yogc validate` passed: `True`
