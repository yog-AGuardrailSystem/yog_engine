# Cross-engine benchmark comparison

Generated: 2026-11-14T19:46:21.331491+00:00
Commit: `c4ce48e6bdd9fb2c88331a83c6f0d8b2f76aafb8`

Read this table by boundary. **cli-process** numbers include process
startup and policy load; **library** numbers are in-process decisions.
They are not interchangeable, and no result here is a general claim
that one engine is faster than another.

## Boundary: `cli-process`

Each sample spawns a process: policy compile/load, startup, decision and output are all included.

### small

| request | yog | opa | cedar |
| --- | ---: | ---: | ---: |
| admin allow | 31,865 / 35,484 / 52,629 | 101,698 / 138,745 / 168,791 | 127,715 / 148,894 / 155,666 |
| team join allow | 33,058 / 39,623 / 41,052 | 100,692 / 118,795 / 237,440 | 128,959 / 179,361 / 260,218 |
| guest default deny | 32,429 / 36,976 / 37,826 | 112,637 / 136,427 / 158,107 | 128,238 / 143,371 / 214,748 |
| low clearance deny | 32,576 / 37,040 / 39,842 | 112,957 / 170,336 / 231,109 | 129,782 / 165,810 / 250,097 |

Cells are p50 / p95 / p99 in microseconds. All reported decisions matched the corpus.
N = 30 samples per request per run, 2 runs; the cell is the median of runs. p99 is nearest-rank, so it equals the maximum when N < 100.

### medium

| request | yog | opa | cedar |
| --- | ---: | ---: | ---: |
| admin allow | 39,758 / 51,347 / 51,347 | 108,349 / 135,885 / 135,885 | 603,186 / 734,029 / 734,029 |
| team join allow | 41,569 / 53,953 / 53,953 | 101,988 / 187,931 / 187,931 | 594,456 / 798,046 / 798,046 |
| guest default deny | 40,422 / 51,914 / 51,914 | 108,800 / 125,060 / 125,060 | 588,102 / 641,028 / 641,028 |
| low clearance deny | 40,507 / 55,720 / 55,720 | 96,881 / 116,173 / 116,173 | 602,437 / 660,918 / 660,918 |

Cells are p50 / p95 / p99 in microseconds. All reported decisions matched the corpus.
N = 20 samples per request per run, 2 runs; the cell is the median of runs. p99 is nearest-rank, so it equals the maximum when N < 100.

### large

| request | yog | opa | cedar |
| --- | ---: | ---: | ---: |
| admin allow | 146,710 / 181,222 / 181,222 | 114,425 / 125,014 / 125,014 | 4,350,820 / 5,214,717 / 5,214,717 |
| team join allow | 149,792 / 179,862 / 179,862 | 110,677 / 119,691 / 119,691 | 4,455,915 / 4,727,852 / 4,727,852 |
| guest default deny | 151,022 / 167,376 / 167,376 | 107,662 / 118,212 / 118,212 | 4,241,234 / 4,698,914 / 4,698,914 |
| low clearance deny | 146,686 / 174,876 / 174,876 | 104,216 / 113,700 / 113,700 | 4,392,226 / 4,695,562 / 4,695,562 |

Cells are p50 / p95 / p99 in microseconds. All reported decisions matched the corpus.
N = 10 samples per request per run, 2 runs; the cell is the median of runs. p99 is nearest-rank, so it equals the maximum when N < 100.

## Boundary: `library`

In-process decisions. YOG is C and Casbin is Python, so this is a cross-language comparison and is not directly comparable with the CLI boundary.

### small

| request | yog | casbin |
| --- | ---: | ---: |
| admin allow | 1 / 1 / 2 | 164 / 404 / 3,059 |
| team join allow | 3 / 3 / 3 | 185 / 455 / 1,606 |
| guest default deny | 8 / 14 / 17 | 230 / 635 / 2,995 |
| low clearance deny | 8 / 14 / 20 | 234 / 582 / 2,341 |

Cells are p50 / p95 / p99 in microseconds. All reported decisions matched the corpus.
YOG: 5000 samples. Casbin: 200 samples x 2 runs. YOG library build: release.

### medium

| request | yog | casbin |
| --- | ---: | ---: |
| admin allow | 1 / 2 / 2 | 196 / 493 / 2,371 |
| team join allow | 14 / 22 / 30 | 225 / 415 / 1,492 |
| guest default deny | 57 / 101 / 130 | 587 / 965 / 1,559 |
| low clearance deny | 57 / 97 / 125 | 418 / 724 / 1,277 |

Cells are p50 / p95 / p99 in microseconds. All reported decisions matched the corpus.
YOG: 2000 samples. Casbin: 100 samples x 2 runs. YOG library build: release.

### large

| request | yog | casbin |
| --- | ---: | ---: |
| admin allow | 1 / 1 / 2 | 152 / 256 / 1,306 |
| team join allow | 140 / 280 / 313 | 162 / 303 / 407 |
| guest default deny | 559 / 682 / 1,823 | 1,398 / 1,968 / 3,099 |
| low clearance deny | 559 / 995 / 2,489 | 1,411 / 2,128 / 5,901 |

Cells are p50 / p95 / p99 in microseconds. All reported decisions matched the corpus.
YOG: 500 samples. Casbin: 30 samples x 2 runs. YOG library build: release.

## Versions and environment

| item | value |
| --- | --- |
| Python | 3.14.7 |
| Platform | Windows-11-10.0.26200-SP0 |
| yogc | `yog/build-release/yogc.exe` |
| yog | source c4ce48e (release) |
| opa | Version: 1.22.4 |
| cedar | cedar-policy-cli 4.14.1 |
| casbin | 1.43.0 |

## What is not measured

- Request rates under concurrent load; every sample is sequential.
- Peak RSS for the OPA and Cedar child processes.
- Casbin's numeric clearance clause, which its standard model cannot
  express; the adapter records `numeric_clause: false`.
