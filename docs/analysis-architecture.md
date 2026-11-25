# Analysis architecture and precision roadmap

This document records the intended analysis architecture. It separates what is
implemented today from the planned multicore and precision work;
`--list-passes` is the authoritative status report for a build/profile. The
OTAWA capability roadmap and confirmed scope exclusions are in
[otawa-parity.md](otawa-parity.md).

## Goals

- Target multicore AArch64 and RISC-V images.
- Produce **certifiable safe upper bounds** when the selected models and flow
  facts support that claim; never silently turn an incomplete model into a
  bound.
- Keep analyses modular and removable at compile time.
- Emit human-readable CFG/WCET text in addition to machine-readable JSON.

## Pass model

The build uses a compile-time pass catalog, not a runtime dynamic-library ABI.
Each pass declares:

- a stable ID (`domain.role`, for example `wcet.longest-path`);
- its kind (`frontend`, `timing`, `analysis`, `path-analysis`, `report`);
- consumed and produced fact IDs;
- a soundness claim (`model-only`, `model-dependent`, `safe-upper-bound`,
  `estimate`, `planned`).

The catalog lives in `crates/elf2tdg/src/passes.rs` and is exposed by:

```sh
elf2tdg --list-passes
elf2tdg --list-passes --board-profile board.toml
```

The analyzer still invokes the current analyses directly. The catalog is the
scheduler contract for the next refactor: passes will read/write typed facts
through a `PassContext`, and the registry will topologically order them. The
public pass IDs and the JSON schema remain stable across that migration.

### Why compile-time

Rust trait objects do not have a stable cross-`cdylib` ABI. Compile-time
registration with Cargo features is type-safe, testable and sufficient for
built-in analyses. If third-party runtime plugins are needed later, the
recommended boundary is an out-of-process JSON/IPC or WASM provider, not a raw
Rust `dylib` interface.

## Precision ladder

| Level | Capability | Status |
|---|---|---|
| P0 | CFG recovery, roots, runtime rules, longest-path WCET | implemented |
| P1 | Flow facts and IPET/ILP backend | implemented: profile bounds, F4 `.ff`/FFX import, conservative counted-loop inference, context-sensitive caller-chain analysis, FFX branch/call facts, unordered/structurally-forced/cross-iteration/cross-function ordered infeasible-path conflicts in IPET (cross-iteration and cross-function use product automata; cross-function inlines one direct call group), per-function IPET, pure-Rust `microlp`; call-site-sensitive contexts, richer FFX constructs and conflict scalability are next |
| P2 | Cache, pipeline and branch constraints in IPET | first versions implemented: per-block LRU I/D-cache models with line-split logical blocks and a per-function cache-state product, a full instruction-cache CCG flow model, per-line first-miss and aggregate conflict bounds for fallback, concrete branch-predictor state products with per-edge misprediction costs, optional unknown first-execution history, global-history, gshare, local-history, configurable two-level pattern tables, a global/local tournament predictor, set-associative BTB miss models and bounded return-address stacks, interprocedural branch summaries that carry predictor state and branch costs through direct calls, and multiple-issue Cortex-M4 plus generic/bounded AArch64/RISC-V resource/dependency pipeline models with full inter-block state tables in the IPET state product with first-order edge stalls as fallback; other tournament component pairs are next |
| P3 | Call-site-sensitive context summaries, bounded recursion, SMT infeasible paths | planned; caller-function context summaries are implemented in P1 |
| P4 | Interrupt/CRPD and multicore shared-resource interference | first versions implemented: `[multicore]` per-access/per-fetch budget, a layered task/place/transition model, its state-equation ILP relaxation, `[system]` activation/periodic/resource/lock/link constraints, work-conserving and fixed-priority per-task response bounds, priority-ceiling blocking and priority-inversion analysis, and a first discrete-time-expanded deadline-feasibility model; timed-state response analysis, priority inheritance/chained blocking, automatic link derivation, arbitration schedules, shared caches, CRPD and interrupt effects are next |
| P5 | Probabilistic/measurement-based or ML-assisted modes | out of scope until P1-P4 are sound |

The IPET first version is available with:

```sh
elf2tdg firmware.elf --board-profile board.toml \
  --path-analysis ipet --view cfg --format text --function main
```

It builds a per-function integer program with flow conservation, natural-loop
bounds and callee summaries, solves it with `microlp`, and records the positive
block execution counts. The remaining P1 work is:

1. Additional FFX constructs, richer cross-function conflict forms (multiple
   groups, loop-scoped groups, call-address selection) and inference beyond
   canonical counted loops.
2. A convenience API for programmatic flow facts beyond files and `[wcet]`.
3. Larger benchmarks comparing IPET and longest-path precision and solve time.
4. Making IPET the default only after the bounded-results contract is validated.

The irreducible-cycle guard is deliberate: if removing all natural-loop
backedges still leaves a cycle, the function is reported `unbounded` rather than
emitting an unsound finite number.

## Soundness contract

Every pass result must carry:

- the model/solver version and configuration hash;
- the soundness claim and the assumptions it depends on;
- unsupported or unresolved inputs;
- a status (`bounded`, `partial`, `unbounded`, `unknown`).

`partial` results are never presented as safe bounds. IPET output is a safe
upper bound only when the flow facts, block costs and microarchitecture models
are all conservative. Unresolved calls, missing callee summaries, unresolved
control flow, missing block timing and non-terminating loops that were bound by
assumption all mark a result `partial`. Irreducible cycles are reported
`unbounded` because no configured loop bound covers them. The text report
prints these statuses and caveats; later passes must preserve them. The
`--require-safe` CLI gate requires the IPET backend, a timing model classified
as `deterministic` or `bounded` (not `statistical`), call-invalidated cache
state, complete cache/memory address coverage, and a `bounded` result for every
execution root; otherwise the run fails before emitting a CFG.

## Multicore direction

The current `[multicore]` access-budget model is a conservative, auditable first
step: it charges explicit per-access/per-fetch budgets and records every
charged event. The layered `system_model` then converts per-root WCET results
into tasks, Petri-net-shaped places/transitions and solves the state-equation
ILP relaxation for a coarse analyzed-core bound. The bound is intentionally
only a total-work relaxation; it is not exact reachability or a timed model. It
is not the final interference model. The next step is a resource-aware
interference pass with explicit models:

- shared bus/memory arbitration (TDMA, round-robin, priority);
- cache sharing, cache coloring and CRPD;
- bank/channel contention;
- interrupt and preemption effects.

These facts should feed the same IPET constraints as the single-core analyses,
so a system-level bound is composed from sound per-resource bounds rather than
from summed local estimates.

## Current limits

- Context-sensitive flow facts use caller-chain function versions: F4 `in ...`
  chains and FFX `<call>` nesting select per-context loop bounds and, in IPET,
  per-context branch/call constraints. Context identity is the caller function,
  not the individual call site. An FFX context whose caller-to-callee edge has
  multiple call sites is ignored with a warning rather than broadened.
  Function-level WCET is the maximum over analyzed contexts. Context
  enumeration is bounded; overflow falls back to a conservative
  context-insensitive model and marks results `partial`.
- IPET enforces unordered infeasible-path conflicts when all elements share one
  function and are outside natural loops (`sum <= n-1` per invocation) or touch
  one common non-nested loop (`sum <= (n-1) * loop iterations`). Ordered
  conflicts reduce to the same constraints only when reachability forces the
  declared order: function-scope acyclic order, or per-iteration loop-body
  order with loop backedges removed. Structurally impossible sequences add no
  constraint. Other ordered conflicts use a product IPET with a progress
  automaton: function scope spans an invocation, loop scope resets on entry,
  and iteration scope resets on entry/backedge. Cross-function ordered
  conflicts with one direct `<call>` group inline the selected callee; group
  elements must match within one invocation, and the callee summary remains the
  cost bound. The product is capped; cap overflow makes the function `unknown`.
  Specific-iteration, multi-group, nested-group and ambiguous-call-site
  conflicts are ignored with warnings. `longest-path` records but does not
  enforce conflicts. Conditional call sites remain unsupported for call-count
  facts.
- Cache analysis is per-function with cold entry and call-return invalidation.
  IPET selects a cache-state product when the instruction/data-cache analysis
  completes and `invalidate_on_call` is true; the product substitutes modeled
  misses for the per-block worst-case penalty. When the product is unavailable
  (ordered/cross-function automata or product overflow), a full instruction
  cache conflict graph models per-set access flows when the function has no
  call-return edges or unresolved control flow. Source/sink flow is one, node
  throughput is the IPET block execution count times line accesses, and only
  immediate same-line incoming flow is counted as a hit. When CCG is
  unavailable for those functions, data cache, or model limits, line splitting
  models each basic block's cache cost per logical
  line block and allows at most one miss per persistent line per loop entry.
  Per-line first-miss is proved from
  the concrete cache-state graph: a line qualifies when it is never evicted
  after being loaded within the loop. This is more precise than a whole-set
  working-set check, because a line can persist even when the loop's total set
  working set exceeds the associativity. IPET also adds conflict-graph bounds
  per loop and set:
  `line-misses <= entries + accesses to other lines in the same set`. This
  bound is independent of the concrete state categories and remains valid when
  the cache analysis falls back. Non-LRU replacement and cache state shared
  with callees remain unimplemented; unresolved data addresses, loops with
  call-return edges, multi-entry loops, no eligible loop or model-size
  overflow keep per-block bounds. Data-cache state integration also requires
  zero unresolved memory accesses, and with `write_allocate = false` lines
  with any store are excluded from the first-miss claim. Data-memory results
  remain per-block and not path-sensitive.
- Branch-prediction state IPET starts each function from the configured
  predictor state and follows concrete predictor transitions, charging the
  actual outcome on each edge. For the bimodal model it computes branch-only
  callee summaries from the caller's concrete predictor state, keeps the
  maximum branch cost for each feasible exit state, and continues the caller
  product from that state; nested direct calls are summarized recursively.
  The caller uses a branch-excluded base callee cost, so only branch state and
  branch cost cross the call. Unsupported branches, analysis fallback,
  indirect/unresolved/recursive calls, contextual facts, ordered/cross-function
  integration and summary caps keep the per-function or per-block misprediction
  bounds. With `first_execution = "unknown"`, each unexecuted pattern-table
  entry considers all four two-bit counters and keeps the worst outcome.
  `global-history` and `gshare` track a global history register and shared
  pattern table; `local-history` tracks a per-branch history register;
  `two-level` combines a global/local level-1 history with a global/per-address
  table; `tournament` selects between global-history and local-history
  components with choice counters. Other component pairs are not modeled. The
  BTB models intra-function taken branch/jump targets with LRU replacement;
  call/return and indirect-call targets are outside the model. The RAS models
  per-function call-return push/pop and return misses; recursive nesting and
  cross-function stack occupancy are outside the model.
- The board-profile pipeline model (Cortex-M4 and AArch64/RISC-V) remains
  statistical. IPET precomputes a per-function table of pipeline entry states
  reachable from function entry and charges the state-dependent block cost in
  its state product, including loop-carried resource/register state. Call-return
  edges reset the modeled state; a state-cap overflow, ordered/cross-function
  automata and `longest-path` fall back to block-local costs or first-order
  edge-context stalls. Memory dependencies, speculative/out-of-order execution,
  cross-block co-issue and cross-function pipeline state are not propagated,
  and `--require-safe` rejects the statistical pipeline model. Multiple issue
  slots, per-resource unit counts and optional register-file read/write port
  budgets are modeled within each block and carried through the pipeline state
  product. Oversized register-file accesses take exclusive issue cycles;
  writeback-cycle contention and banked register files are not modeled.
  Enabling `[pipeline]` on a bounded AArch64/RISC-V model therefore makes the
  whole timing model statistical.
- Multicore interference is an explicit access/fetch budget; arbitration
  schedules, shared caches, DMA, CRPD and concurrency are not modeled.
- The layered system model solves the state-equation relaxation and computes
  work-conserving or fixed-priority busy-window response bounds, plus optional
  priority-ceiling blocking and direct priority inversions. It does not model
  exact reachability, priority inheritance/chained blocking or timed-state
  order; spawn/join annotations are recorded separately from explicit link
  constraints.
- Cortex-M7, generic RISC-V, generic AArch64 and x86-64 models are statistical.
  Opt-in bounded abstract AArch64/RISC-V models (`aarch64-bounded`,
  `riscv32-bounded`, `riscv64-bounded`) are available, but they require a board
  profile with memory regions for `--require-safe` and still exclude multicore
  interference.
- The default backend remains `longest-path` until IPET has broader benchmark
  validation.
