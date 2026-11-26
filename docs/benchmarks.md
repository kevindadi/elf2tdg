# Benchmark and regression harness

`elf2tdg-bench` runs the normal analysis library over a declarative suite of
ELF/profile cases and produces a JSON report plus a Markdown summary. It is
intended for three jobs:

1. detect regressions in cycle results, model selection and fallbacks;
2. compare longest-path and IPET on the same inputs;
3. collect externally produced reference cycles, including OTAWA results,
   without embedding them in the analyzer or inventing values.

The harness does **not** invoke OTAWA. A reference block records a value that a
user or CI job obtained separately. Until those values are filled in, the suite
is a local regression and precision report, not an OTAWA validation claim.

## Running

```sh
cargo run --bin elf2tdg-bench -- \
  --suite benchmarks/suite.toml \
  --json target/benchmarks/report.json \
  --markdown target/benchmarks/report.md
```

The Markdown report is also printed to stdout. Useful options:

- `--filter TEXT` runs only cases whose ID contains `TEXT`;
- `--fail-on-error` exits nonzero when any analysis fails, which is suitable
  for CI once the chosen cases are expected to succeed.

## Suite format

```toml
schema_version = 1
description = "Local embedded ELF regression suite"

[[case]]
id = "cortex-m0-isr"
elf = "../examples/cortex-m0-isr/artifacts/cortex-m0-isr.elf"
profile = "profiles/cortex-m0-benchmark.toml"
analyses = ["longest-path", "ipet"]
# cpu = "cortex-m0"              # optional explicit CPU override
# frequency_hz = 48_000_000     # optional CLI-equivalent frequency
# flowfacts = ["loops.ff"]      # optional F4/FFX files
# require_safe = false          # optional safe-gate run
```

Paths are resolved relative to the suite file. If `analyses` is omitted, both
`longest-path` and `ipet` are run. Case IDs must be unique.

Optional external reference for one backend:

```toml
[case.reference]
backend = "ipet"
source = "otawa"
root = "main"          # optional; default is the maximum finite root
cycles = 12345.0       # value measured/produced by the external tool
```

`root` matches either a root name from the CFG or a function ID such as
`fn:0x8000138`. If omitted, the harness selects the root with the largest
finite cycle value. The report records:

- `reference_cycles`, `measured_cycles`;
- `delta_cycles = measured - reference`;
- `ratio = measured / reference`;
- a note when the requested root or a finite result was not found.

A reference for a backend that is not run is rejected by suite validation.

## JSON report

Top-level fields:

- `schema_version`: benchmark report schema, currently `1`;
- `suite`, `description`;
- `cases[]`: input paths and one entry per analysis;
- `summary`: counts, wall time and reference coverage.

Each analysis entry records:

- `backend`, `status` (`ok`, `ok-without-wcet` or `error`);
- `elapsed_ms`: wall-clock analysis time;
- `wcet`: model, solver, function status counts, all root results and the
  maximum finite root;
- `timing`: timing model, determinism and frequency;
- `models`: IPET function count, solver/status counts and the selected
  cache/pipeline/branch/BTB/RAS and CFG-partitioning model variants;
- `diagnostics`: number of CFG diagnostics;
- `safe_ok` when `require_safe` was requested;
- `reference` when a matching external reference was configured.

Cycle fields are deterministic for the same binary, input, profile and flow
facts. `elapsed_ms` is wall-clock time and naturally varies with the machine
and load.

## Current corpus

`benchmarks/suite.toml` contains:

| Case | ELF | Profile | Purpose |
|---|---|---|---|
| `cortex-m0-isr` | `examples/cortex-m0-isr` | `benchmarks/profiles/cortex-m0-benchmark.toml` | deterministic M0 longest-path/IPET comparison |
| `cortex-m0-fixture` | `tests/fixtures/cortex_m0/firmware.elf` | same | small regression fixture |
| `rust-concurrency-full-stack` | `examples/rust-concurrency` | `examples/profiles/cortex-m4-full-stack.toml` | IPET with cache/pipeline state products, branch fallbacks and state-aware region summaries |

The benchmark profiles are deliberately separate from board-validation
profiles. They are not evidence that a real board matches the timing values.

## Interpreting results

- `longest-path` is an unrolled CFG longest-path estimate; `ipet` enforces
  flow facts and callee summaries. A lower IPET objective is expected when
  path correlations or flow facts remove impossible combinations, but a large
  difference should be investigated before treating either as a WCET bound.
- `state-product`, `block-bounds`, `edge-context` and
  `interprocedural-state-product` entries expose where a model completed or
  fell back.
- `partition:sese-branch-regions` means IPET summarized eligible state-free
  branch-entry SESE regions before solving. The cycle objective should be
  identical to the monolithic model for the same eligible function; report a
  mismatch as a partitioning regression.
- `partition:sese-state-product-regions` means IPET summarized eligible
  branch-entry regions on an active cache/pipeline/branch/BTB/RAS state
  product. Nested regions are summarized innermost first, with costs and block
  counts folded into the enclosing summary. The summary preserves entry and
  exit states and is a safe upper bound, but an entry state that reaches
  several exit states may be relaxed, so it can exceed monolithic
  state-product IPET. Compare it against the same build without partitioning,
  not against the state-free baseline. Regions containing loop headers or
  latches, or ending at a loop header, stay monolithic.
- Recovered call sites without a containing block no longer disable either
  partition model. They stay function-level, are not assigned to a region, and
  keep the result partial; fixed call-block summaries are allowed.
- Supported branch/call facts and infeasible-path constraints no longer disable
  partitioning, but regions that touch a referenced block stay monolithic and
  the final model enforces the fact. Exact state-free partitioning also accepts
  ordered automata, including cross-function conflicts, keeping automaton reset
  loops (also loop-scoped cross-function resets), all call-group boundaries and
  caller-side pattern elements monolithic, and running the automaton or
  cross-function product on the reduced CFG. State-product
  partitioning stays monolithic for ordered and cross-function automata;
  unresolved control-flow gaps stay monolithic.
- `partial`, `unbounded` and `unknown` function counts are more important than
  a single objective value. A benchmark with any partial/unbounded root is not
  a safe WCET result.
- `--require-safe` results are part of the benchmark when requested. Cases
  with statistical pipeline/branch models or incomplete flow facts are
  expected to fail that gate.
- Do not compare wall-clock times across machines as a precision metric; use
  cycle results for analysis changes and solve time only within one machine.

## OTAWA comparison workflow

1. Build or obtain the OTAWA result for the same ELF, entry/root, hardware
   model and loop/flow facts.
2. Convert the OTAWA WCET for the selected root to cycles using the same core
   frequency, or supply the cycle value directly.
3. Add a `[case.reference]` block with `source = "otawa"`, the matching
   backend, root and cycles.
4. Run the suite and archive the JSON report next to the OTAWA invocation and
   configuration.

The harness cannot establish equivalence of hardware models by itself. Record
the OTAWA architecture description/profile, solver settings and flow facts
alongside the reference value.

## Next steps

- populate OTAWA references for the local corpus and a public embedded
  benchmark set;
- add benchmark cases with complete safe-mode flow facts;
- add large-function cases that exercise CFG partitioning and its limits;
- use `--fail-on-error`/cycle baselines in CI once expected results stabilize.
