# Semantic equivalence over the full workload

Generated: 2026-11-16T17:27:23.563045+00:00

Expected decisions come from `benchmarks/oracle.py`, an independent
implementation of the corpus semantics. Every engine runs in-process and
sees the same requests.

| Profile | Size | Engine | Checked | Mismatches | Agreement | Note |
| --- | --- | --- | ---: | ---: | ---: | --- |
| common | small | yog-python | 300 | 0 | 100.00% |  |
| common | small | yog-rust | 300 | 0 | 100.00% |  |
| common | small | yog-go | 300 | 0 | 100.00% |  |
| common | small | casbin | 300 | 0 | 100.00% |  |
| common | small | opa-go | 300 | 0 | 100.00% |  |
| common | small | cedar-rust | 300 | 0 | 100.00% |  |
| common | small | cedar-rust-alt | 300 | 0 | 100.00% |  |
| common | medium | yog-python | 300 | 0 | 100.00% |  |
| common | medium | yog-rust | 300 | 0 | 100.00% |  |
| common | medium | yog-go | 300 | 0 | 100.00% |  |
| common | medium | casbin | 300 | 0 | 100.00% |  |
| common | medium | opa-go | 300 | 0 | 100.00% |  |
| common | medium | cedar-rust | 300 | 0 | 100.00% |  |
| common | medium | cedar-rust-alt | 300 | 0 | 100.00% |  |
| common | large | yog-python | 300 | 0 | 100.00% |  |
| common | large | yog-rust | 300 | 0 | 100.00% |  |
| common | large | yog-go | 300 | 0 | 100.00% |  |
| common | large | casbin | 300 | 0 | 100.00% |  |
| common | large | opa-go | 300 | 0 | 100.00% |  |
| common | large | cedar-rust | 300 | 0 | 100.00% |  |
| common | large | cedar-rust-alt | 300 | 0 | 100.00% |  |
| full | small | yog-python | 300 | 0 | 100.00% |  |
| full | small | yog-rust | 300 | 0 | 100.00% |  |
| full | small | yog-go | 300 | 0 | 100.00% |  |
| full | small | casbin | 300 | 46 | 84.67% | expected: no numeric clause |
| full | small | opa-go | 300 | 0 | 100.00% |  |
| full | small | cedar-rust | 300 | 0 | 100.00% |  |
| full | small | cedar-rust-alt | 300 | 0 | 100.00% |  |
| full | medium | yog-python | 300 | 0 | 100.00% |  |
| full | medium | yog-rust | 300 | 0 | 100.00% |  |
| full | medium | yog-go | 300 | 0 | 100.00% |  |
| full | medium | casbin | 300 | 41 | 86.33% | expected: no numeric clause |
| full | medium | opa-go | 300 | 0 | 100.00% |  |
| full | medium | cedar-rust | 300 | 0 | 100.00% |  |
| full | medium | cedar-rust-alt | 300 | 0 | 100.00% |  |
| full | large | yog-python | 300 | 0 | 100.00% |  |
| full | large | yog-rust | 300 | 0 | 100.00% |  |
| full | large | yog-go | 300 | 0 | 100.00% |  |
| full | large | casbin | 300 | 60 | 80.00% | expected: no numeric clause |
| full | large | opa-go | 300 | 0 | 100.00% |  |
| full | large | cedar-rust | 300 | 0 | 100.00% |  |
| full | large | cedar-rust-alt | 300 | 0 | 100.00% |  |

**Total decisions compared:** 12,600  
**Unexpected mismatches:** 0  
**Expected feature-gap mismatches (Casbin, full profile):** 147

The `common` profile is feature-matched: all engines agree on every
request. On the `full` profile Casbin disagrees exactly on requests whose
outcome depends on the numeric `clearance >= classification` clause,
which its standard model cannot express. That is the measured cost of the
feature gap, and the reason the fair comparison uses `common`.

Agreement is evidence about this corpus, not a proof of language
equivalence. Cedar and OPA translations are also checked with their
official validators in `benchmarks/validate_translations.py`.
