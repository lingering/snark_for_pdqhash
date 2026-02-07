# Regime A microbenchmark results

Environment: `cargo bench --bench regime_a_microbenchmark` (Criterion).

## Timing summary

| DB size (`n`) | `ttp_setup` | `client_submit` | `server_verify` |
|---:|---:|---:|---:|
| 32  | 5.48–5.54 µs | 51.62–52.25 µs | 52.78–53.39 µs |
| 128 | 23.53–23.94 µs | 205.24–207.20 µs | 202.77–204.13 µs |
| 512 | 93.02–94.08 µs | 855.07–869.47 µs | 846.60–859.11 µs |

These values are copied from the Criterion console output generated in this repository.
