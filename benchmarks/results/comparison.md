# Fair cross-engine comparison

Generated: 2026-11-15T05:50:08.563141+00:00
Commit: `3b58cf95c62194ec5180916abfa0e77d665e8278`

Each boundary compares engines that run in the **same language runtime**,
in process. Cells are p50 microseconds with a 95% percentile bootstrap
interval over independent run medians. Every engine returned the expected
decision for every request; a mismatch would have aborted the run.

Corpus profile: `common`. Config: 10 runs x 500 calls after 50 warm-up calls per request.
CPU: pinned to CPU 0 (mask 0x1); children inherit.

## Boundary: `python-in-process`

YOG-Python (ctypes) and Casbin both run in CPython. Native runtime: same.

### small

| request | yog-python | casbin |
| --- | ---: | ---: |
| admin allow | 8.7 [8.7, 8.7] | 132.7 [131.7, 140.0] |
| team join allow | 10.5 [10.4, 10.5] | 152.6 [150.7, 158.8] |
| guest default deny | 12.5 [12.5, 12.6] | 206.6 [196.8, 216.6] |
| unmapped deny | 12.5 [12.5, 12.6] | 197.7 [196.3, 201.1] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-python | 138.3 [133.8, 193.8] |
| casbin | 1,968.0 [1,947.0, 2,037.4] |

### medium

| request | yog-python | casbin |
| --- | ---: | ---: |
| admin allow | 8.7 [8.7, 8.7] | 129.7 [129.4, 130.0] |
| team join allow | 21.2 [21.2, 21.2] | 151.3 [151.2, 152.8] |
| guest default deny | 41.6 [41.6, 41.7] | 378.4 [377.0, 385.6] |
| unmapped deny | 41.7 [41.7, 41.8] | 187.2 [185.0, 198.3] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-python | 1,822.5 [1,739.3, 3,079.6] |
| casbin | 4,826.9 [4,365.5, 9,731.9] |

### large

| request | yog-python | casbin |
| --- | ---: | ---: |
| admin allow | 8.7 [8.7, 8.7] | 132.4 [130.7, 135.8] |
| team join allow | 133.6 [133.4, 133.9] | 150.9 [150.6, 151.6] |
| guest default deny | 364.2 [360.7, 370.9] | 1,350.8 [1,316.5, 1,420.6] |
| unmapped deny | 358.9 [357.4, 366.5] | 1,373.3 [1,327.5, 1,471.6] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-python | 59,105.5 [58,363.2, 62,128.1] |
| casbin | 71,049.8 [68,688.1, 75,001.4] |

## Boundary: `rust-in-process`

YOG-Rust (safe wrapper) and the Cedar Rust SDK both run in a Rust process. Native runtime: same.

### small

| request | yog-rust | cedar-rust |
| --- | ---: | ---: |
| admin allow | 1.8 [1.8, 1.8] | 10.9 [10.5, 11.1] |
| team join allow | 3.5 [3.5, 3.5] | 10.2 [9.9, 10.4] |
| guest default deny | 5.4 [5.4, 5.5] | 8.7 [8.7, 9.0] |
| unmapped deny | 5.4 [5.4, 5.4] | 8.7 [8.7, 8.8] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-rust | 229.6 [225.5, 243.6] |
| cedar-rust | 5,139.9 [4,988.1, 8,075.9] |

### medium

| request | yog-rust | cedar-rust |
| --- | ---: | ---: |
| admin allow | 1.6 [1.6, 1.7] | 10.6 [10.6, 10.9] |
| team join allow | 13.8 [13.7, 13.8] | 10.0 [10.0, 10.2] |
| guest default deny | 34.2 [33.9, 34.2] | 8.8 [8.7, 8.9] |
| unmapped deny | 34.1 [33.9, 34.2] | 8.7 [8.7, 8.9] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-rust | 2,081.1 [2,030.5, 2,303.6] |
| cedar-rust | 14,235.1 [14,067.5, 15,779.9] |

### large

| request | yog-rust | cedar-rust |
| --- | ---: | ---: |
| admin allow | 1.8 [1.8, 1.9] | 10.5 [10.4, 11.1] |
| team join allow | 121.8 [121.4, 123.5] | 10.4 [10.0, 10.6] |
| guest default deny | 345.4 [344.7, 347.7] | 8.8 [8.8, 9.4] |
| unmapped deny | 344.8 [343.1, 348.9] | 8.8 [8.7, 8.9] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-rust | 54,917.7 [54,748.9, 56,856.7] |
| cedar-rust | 73,761.8 [71,899.0, 84,171.9] |

## Boundary: `go-in-process`

YOG-Go calls the C ABI via syscall/cgo; OPA is the Go SDK. Both run in a Go process, but only the YOG side pays an FFI boundary. Read the two as bounds, not as a pure engine comparison.

### small

| request | yog-go | opa-go |
| --- | ---: | ---: |
| admin allow | 2.1 [2.1, 2.1] | 58.0 [57.0, 61.6] |
| team join allow | 3.7 [3.7, 3.8] | 47.6 [46.9, 52.2] |
| guest default deny | 5.7 [5.6, 5.7] | 46.1 [45.1, 47.8] |
| unmapped deny | 5.6 [5.6, 5.6] | 40.0 [38.4, 42.0] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-go | 242.9 [240.9, 283.6] |
| opa-go | 1,976.5 [1,933.9, 2,053.7] |

### medium

| request | yog-go | opa-go |
| --- | ---: | ---: |
| admin allow | 1.9 [1.9, 1.9] | 177.3 [156.2, 188.4] |
| team join allow | 14.2 [14.1, 14.2] | 164.6 [162.6, 178.4] |
| guest default deny | 34.5 [34.4, 34.6] | 154.8 [152.2, 160.5] |
| unmapped deny | 34.5 [34.3, 34.6] | 156.3 [143.8, 160.6] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-go | 2,046.6 [2,022.1, 2,107.4] |
| opa-go | 2,069.2 [1,902.4, 2,231.4] |

### large

| request | yog-go | opa-go |
| --- | ---: | ---: |
| admin allow | 2.0 [2.0, 2.0] | 1,467.7 [1,449.5, 1,546.0] |
| team join allow | 123.5 [123.1, 124.5] | 1,472.5 [1,450.5, 1,511.8] |
| guest default deny | 347.2 [346.4, 348.8] | 1,464.1 [1,448.2, 1,480.3] |
| unmapped deny | 348.0 [346.9, 353.0] | 1,463.3 [1,457.5, 1,474.9] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-go | 55,061.9 [54,438.3, 55,963.3] |
| opa-go | 1,894.3 [1,851.8, 1,963.6] |

## Boundary: `c-reference`

YOG's native C harness. This is the engine's best case and is cross-language against every other row; it is context, not fairness evidence.

### small

| request | yog-c |
| --- | ---: |
| admin allow | 1.4 [1.4, 1.4] |
| team join allow | 3.1 [3.0, 3.1] |
| guest default deny | 4.9 [4.9, 4.9] |
| unmapped deny | 4.9 [4.9, 5.0] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-c | 124.8 [124.5, 126.3] |

### medium

| request | yog-c |
| --- | ---: |
| admin allow | 1.3 [1.3, 1.3] |
| team join allow | 13.3 [13.2, 13.4] |
| guest default deny | 33.7 [33.4, 33.7] |
| unmapped deny | 33.6 [33.4, 33.8] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-c | 2,266.7 [2,155.9, 2,868.4] |

### large

| request | yog-c |
| --- | ---: |
| admin allow | 1.3 [1.3, 1.3] |
| team join allow | 121.8 [121.1, 124.0] |
| guest default deny | 341.6 [340.8, 344.9] |
| unmapped deny | 346.9 [343.5, 349.1] |

Load time (compile / parse / prepare), p50 µs [95% CI]:

| engine | load |
| --- | ---: |
| yog-c | 61,543.4 [59,307.0, 62,990.6] |

## How to read this

- Same-runtime pairs are the evidence. The `c-reference` boundary is the
  C engine's best case and is not a fairness claim.
- The `go-in-process` pair is asymmetric: YOG crosses an FFI boundary and
  OPA does not. Treat the two numbers as bounds on the engine difference.
- The corpus is the feature-matched `common` profile. Casbin cannot express
  the numeric clearance clause; `equivalence.md` records the measured cost
  of that gap on the `full` profile.
- Agreeing on this corpus is evidence, not proof of language equivalence.

## Versions and environment

| item | value |
| --- | --- |
| Python | 3.14.7 |
| Platform | Windows-11-10.0.26200-SP0 |
| Machine | AMD64 |
| yog | source 3b58cf9 (shared library + bindings) |
| casbin | casbin 1.43.0 |
| opa | Version: 1.22.4 |
| cedar | cedar-policy 4.14.1 (Rust SDK) |
