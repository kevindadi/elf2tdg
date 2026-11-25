# Human-readable CFG and WCET report

`--format text` renders the same selected program CFG as the JSON, DOT and
Mermaid exporters, but in a form intended to be read and diffed directly:

```sh
cargo run -p elf2tdg -- firmware.elf --view cfg --format text \
    --function main --output main-report.txt
```

With a board profile that enables WCET analysis, the report also carries the
per-function and per-root worst-case cycles:

```sh
cargo run -p elf2tdg -- firmware.elf --view cfg --format text \
    --board-profile examples/profiles/cortex-m7-wcet.toml \
    --function sensor_task --output sensor-task.txt
```

## Sections

The report is deterministic and uses plain text only.

1. **Image** — path, architecture, entry point, ELF type, symbol/debug flags
   and the CFG schema version.
2. **Program** — selected/total function, block, edge, call, root, concurrency,
   lock and diagnostic counts.
3. **Execution roots** — startup, main, ISR, task, callback and pointer roots,
   including vector/IRQ numbers and confidence.
4. **Timing** — the instruction timing model, determinism, cost-table version,
   frequency domains and model caveats.
5. **Analysis models** — instruction/data cache (including line-split
   first-miss regions), branch prediction, data-memory latency, the pipeline
   model and its fallback edge stalls, and multicore interference summaries
   when enabled.
6. **WCET** — model name, loop-bound configuration, resolved branch/call flow
   facts, result counts, per-root cycles/nanoseconds and the analysis caveats.
7. **Layered system model** — when a WCET profile is active: task/place/
   transition counts, state-equation ILP solver/status/objective, firing
   counts, horizon/period/activation bounds, resource budgets, priorities,
   lock hold times, fork/join links, per-task response bounds/deadline misses,
   priority-ceiling blocking and inversion records, discrete-time-expanded
   feasibility status, task costs and the model assumptions.
8. **Interprocedural call graph** — caller, callee, call site, flags and
   bounded candidate sets.
9. **Concurrency annotations** — spawn/join/await/callback/scope sites.
10. **Lock events** — acquire/try-acquire/release events with API provenance.
11. **Diagnostics** — scoped to the selected functions, with omitted image-wide
    diagnostics counted.
12. **Function sections** — metadata, WCET result, then every basic block with
    instructions, calls, typed edges and per-block analysis annotations.

## Example

```text
function main
-------------

id               fn:0x8000138
address          0x8000138 (14 bytes)
section          .text
source           main.c:26:16
language         c
kind             normal
noreturn         control-flow
entry            bb:0x8000138
blocks           3
edges            3
call sites       2
wcet             partial, 42.0 cycle(s), 250.0 ns (incomplete-call-or-control-flow-model)
wcet path        bb:0x8000138 -> bb:0x800013e

  block bb:0x8000138  0x8000138  6B  cycles 4..8  terminator=call
    instructions:
      0x8000138  2B  push {r4, lr}  [main.c:26:16]
      0x800013a  4B  bl #0x8000120  [call]  [main.c:27:5]
    calls:
      @0x800013a -> sensor_task  [direct]
    edges:
      -> bb:0x800013e call-return  @0x800013a
```

`--no-cfg-instructions` keeps block, edge, call and WCET information but
replaces the instruction listing with a count. The JSON output remains the
lossless machine-readable form; see [cfg-format.md](cfg-format.md).

## WCET semantics

The `wcet` section reports the selected backend:

- `cfg-longest-path` (default): CFG longest path with bounded loop visits.
- `cfg-ipet` (`--path-analysis ipet`): IPET integer-linear program solved with
  the pure-Rust `microlp` backend. The report prints the solver status, objective,
  cache model (`state-product`, `ccg`, `conflict-graph`, `line-split` or
  `block-bounds`) when a cache profile is active, CCG and aggregate
  conflict-graph summaries when those constraints apply, branch model
  (`state-product`, `interprocedural-state-product` or `block-bounds`) when a
  branch-prediction profile is active, pipeline model (`state-product` or `edge-context`) when a pipeline
  profile is active, and positive block execution counts for each function.
  The cache model section also lists each first-miss loop and its line
  addresses. The flow-facts section
  lists each explicit loop bound with its source (board profile or F4/FFX file)
  and any caller context; contextual branch/call facts use the same
  `[context: ...]` suffix. Infeasible-path conflict records show whether the
  constraint was applied, its aggregate/automaton enforcement mode, scope, and
  any reason it was ignored. Cross-function records also print the selected
  callee and call-site address.

Both are static estimates, not hardware proofs: loop bounds must be configured,
recursive call-graph SCCs are unbounded, cache models are per-function with
cold entry and call-return invalidation, CCG flow, line splitting and aggregate
conflict bounds over-approximate cache evictions, IPET pipeline costs
propagate reachable inter-block pipeline state and fall back to a first-order
edge context when the state table is unavailable, branch-prediction IPET
starts from the configured predictor state and (for bimodal) can carry state
and branch cost through direct calls while first-execution/global history is
not modeled, data-memory results remain block-local, and interrupts, DMA, bus contention and
concurrency are not modeled. A
function marked `partial` has unresolved inputs; `unbounded` means no finite
estimate was produced. A partial IPET objective is not a safe upper bound.
Irreducible cycles are reported as `unbounded` rather than producing an
unsound model.

When a WCET profile is active, the report also includes the layered system
model, its state-equation ILP solution and work-conserving or fixed-priority
per-task response bounds. Configured priority-ceiling locking adds per-task
blocking times and direct priority-inversion lines. The
`analyzed-core-activation-bounds` relaxation is a coarse total-work bound;
`system_model.response` carries the separate per-task bound. See
[layered-model.md](layered-model.md).
