# Local YOG benchmark results

Generated: 2026-11-12T13:59:52.979196+00:00
Host: Windows-11-10.0.26200-SP0 / Python 3.14.7

These are local measurements of this build. They are not a comparison
with Cedar, OPA or Casbin; see `docs/BENCHMARKS.md` for the methodology
and for why adapter results are reported separately.

## small

7 predicates, 132 clauses, 66 constants.

### Compile and load

| metric | mean | p50 | p95 | p99 | throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| compile (engine) | 0.666 ms | 0.607 ms | 1.094 ms | 1.261 ms | 1325.0/s |

### Engine check (compile once, time `yog_check`)

| request | decision | mean | p50 | p95 | p99 | throughput |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| admin allow | ALLOW | 4.51 µs | 4.00 µs | 7.50 µs | 10.50 µs | 209267/s |
| team join allow | ALLOW | 6.96 µs | 6.60 µs | 9.80 µs | 13.40 µs | 138448/s |
| guest default deny | DENY | 15.74 µs | 15.00 µs | 22.20 µs | 29.20 µs | 62443/s |
| low clearance deny | DENY | 15.48 µs | 15.00 µs | 15.60 µs | 28.30 µs | 63523/s |

### End-to-end (`yogc` process)

| mode | mean | p50 | p95 | p99 | throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| one `yogc check` | 32.177 ms | 31.382 ms | 37.171 ms | 45.246 ms | 31.1/s |
| `yogc batch` (2000 requests) | 32.4 µs/request | — | — | — | 30836/s |

Batch decision mismatches: 0.

### Memory (resident set, approximate)

| phase | RSS |
| --- | ---: |
| before compile | 3964 KiB |
| after checks | 4408 KiB |

## medium

7 predicates, 1058 clauses, 432 constants.

### Compile and load

| metric | mean | p50 | p95 | p99 | throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| compile (engine) | 7.695 ms | 7.597 ms | 8.476 ms | 9.315 ms | 120.0/s |

### Engine check (compile once, time `yog_check`)

| request | decision | mean | p50 | p95 | p99 | throughput |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| admin allow | ALLOW | 4.30 µs | 4.10 µs | 4.60 µs | 4.70 µs | 219626/s |
| team join allow | ALLOW | 25.20 µs | 24.50 µs | 25.00 µs | 46.10 µs | 39277/s |
| guest default deny | DENY | 96.61 µs | 94.90 µs | 103.70 µs | 135.80 µs | 10323/s |
| low clearance deny | DENY | 99.62 µs | 95.40 µs | 108.10 µs | 203.10 µs | 10010/s |

### End-to-end (`yogc` process)

| mode | mean | p50 | p95 | p99 | throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| one `yogc check` | 40.040 ms | 39.145 ms | 48.460 ms | 61.166 ms | 25.0/s |
| `yogc batch` (1000 requests) | 101.5 µs/request | — | — | — | 9853/s |

Batch decision mismatches: 0.

### Memory (resident set, approximate)

| phase | RSS |
| --- | ---: |
| before compile | 3996 KiB |
| after checks | 4912 KiB |

## large

7 predicates, 8260 clauses, 3112 constants.

### Compile and load

| metric | mean | p50 | p95 | p99 | throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| compile (engine) | 223.904 ms | 223.344 ms | 235.185 ms | 235.185 ms | 4.4/s |

### Engine check (compile once, time `yog_check`)

| request | decision | mean | p50 | p95 | p99 | throughput |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| admin allow | ALLOW | 4.57 µs | 4.50 µs | 4.60 µs | 4.80 µs | 207503/s |
| team join allow | ALLOW | 211.07 µs | 209.10 µs | 221.80 µs | 249.70 µs | 4732/s |
| guest default deny | DENY | 885.21 µs | 872.30 µs | 954.30 µs | 1103.00 µs | 1129/s |
| low clearance deny | DENY | 883.52 µs | 869.60 µs | 950.90 µs | 1158.10 µs | 1132/s |

### End-to-end (`yogc` process)

| mode | mean | p50 | p95 | p99 | throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| one `yogc check` | 263.864 ms | 261.657 ms | 289.419 ms | 289.419 ms | 3.8/s |
| `yogc batch` (200 requests) | 1870.4 µs/request | — | — | — | 535/s |

Batch decision mismatches: 0.

### Memory (resident set, approximate)

| phase | RSS |
| --- | ---: |
| before compile | 4184 KiB |
| after checks | 9328 KiB |
