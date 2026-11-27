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
| P1 | Flow facts and IPET/ILP backend | implemented: profile bounds, F4 `.ff`/FFX import, conservative counted-loop inference, context-sensitive caller-chain and call-site analysis, FFX branch/call facts, unordered/structurally-forced/cross-iteration/cross-function ordered infeasible-path conflicts in IPET (ordered loop and cross-function conflicts use product automata; cross-function inlines one or more direct call groups and both forms support loop-scoped sequences with entry, per-iteration backedge, numeric-iteration or last-iteration reset, including nested and mixed loop/non-loop contexts, while unordered same-function presence indicators cover mixed loop/non-loop, nested-loop and disjoint-loop elements), per-function IPET, pure-Rust `microlp`; richer FFX constructs and conflict scalability are next |
| P2 | Cache, pipeline and branch constraints in IPET | first versions implemented: per-block LRU I/D-cache models with line-split logical blocks and a per-function cache-state product, a full instruction-cache CCG flow model, per-line first-miss and aggregate conflict bounds for fallback, concrete branch-predictor state products with per-edge misprediction costs, optional unknown first-execution history, global-history, gshare, local-history, configurable two-level pattern tables, a global/local tournament predictor, set-associative BTB miss models and bounded return-address stacks, interprocedural branch summaries that carry predictor state and branch costs through direct calls, and multiple-issue Cortex-M4 plus generic/bounded AArch64/RISC-V resource/dependency pipeline models with full inter-block state tables in the IPET state product with first-order edge stalls as fallback; other tournament component pairs are next |
| P3 | Call-site-sensitive context summaries, bounded recursion, SMT infeasible paths | first version implemented in P1: FFX `address`/`site` frames distinguish call sites and select per-site callee/partition versions; bounded recursion and SMT infeasible paths are planned |
| P4 | Interrupt/CRPD and multicore shared-resource interference | first versions implemented: `[multicore]` per-access/per-fetch budget, a layered task/place/transition model, its state-equation ILP relaxation, `[system]` activation/periodic/resource/lock/link constraints, work-conserving and fixed-priority per-task response bounds, priority-ceiling blocking and priority-inversion analysis, and a first discrete-time-expanded deadline-feasibility model; timed-state response analysis, priority inheritance/chained blocking, automatic link derivation, arbitration schedules, shared caches, CRPD and interrupt effects are next |
| P5 | Probabilistic/measurement-based or ML-assisted modes | out of scope until P1-P4 are sound |

The IPET first version is available with:

```sh
elf2tdg firmware.elf --board-profile board.toml \
  --path-analysis ipet --view cfg --format text --function main
```

It builds a per-function integer program with flow conservation, natural-loop
bounds and callee summaries, solves it with `microlp`, and records the positive
block execution counts. State-free functions with statically modeled call
blocks first summarize branch-entry SESE regions bottom-up; fixed
per-call-block callee costs are included in both local and final models.
Supported branch/call facts and infeasible-path constraints are enforced by the
final model, and regions that touch any referenced block stay monolithic.
Ordered automata, including cross-function conflicts, are supported by the
exact partitioner: loop-reset blocks (including loop-scoped and
specific-iteration resets), cross-function call boundaries and
caller-side pattern elements stay monolithic, and the final automaton or
cross-function product enforces the order. State-product partitioning keeps ordered and cross-function automata
monolithic. Each function version is
analyzed
in its caller-frame context, so call-site-specific FFX facts produce separate
partitioned versions and call costs. Each region is replaced by an exact
per-entry cost block and block counts are expanded into the original CFG.
A region whose entry is the function entry replaces it with a new entry block.
When cache, pipeline, branch-prediction, BTB or RAS state products are active,
the same partitioner selects a laminar (nested or disjoint) family of
branch-entry regions that contain no loop header or latch and do not end at a
loop header. It summarizes regions innermost first: each reachable entry
product state gets its worst-cost local path to each reachable exit product
state, the interior product nodes are replaced with state-preserving summary
edges, and nested costs and block counts are folded into enclosing summaries.
A single entry state that reaches several exit states is relaxed to use each
exit independently, so the state-aware path is a safe upper bound but can
exceed the monolithic state-product objective. The first partitioner is capped
at 4096 blocks, 512 regions and a bounded scan-work budget; state summaries
additionally cap entry/exit states and local product nodes. Unsupported shapes
use monolithic IPET. The remaining P1 work is:

1. Additional FFX constructs, nested cross-function group forms, and inference
   beyond canonical counted loops.
2. A convenience API for programmatic flow facts beyond files and `[wcet]`.
3. Larger benchmarks comparing IPET and longest-path precision and solve time.
   `elf2tdg-bench` now provides a reproducible local suite with cycle results,
   model/fallback summaries and external-reference slots; OTAWA reference
   population, larger public benchmark sets and richer partition shapes
   remain.
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

- IPET CFG partitioning covers branch-entry SESE regions in functions with
  statically modeled calls. Supported branch/call facts and infeasible-path
  constraints are enforced by the final model; any region touching a referenced
  block stays monolithic. Exact state-free partitioning supports ordered and
  cross-function automata, keeping automaton reset-loop blocks (including
  loop-scoped and specific-iteration resets), call boundaries
  and caller-side pattern elements monolithic, and running the automaton or
  cross-function product after summarization. State-product partitioning keeps
  ordered and cross-function automata monolithic.
  Recovered call sites without a containing block do not block partitioning,
  but remain function-level, are not assigned to regions and keep the function
  `partial`. State-free regions use exact per-entry summaries and homogeneous
  scaling. With cache/pipeline/branch/BTB/RAS state products,
  a laminar family of regions without loop headers/latches or loop-header
  exits is summarized innermost first per entry and exit product state; nested
  costs and block counts are folded into enclosing summaries. The final IPET
  may combine exit states more freely than a concrete execution, so this mode
  is a safe upper bound but not an exact match for monolithic state-product
  IPET. It is capped at 4096 blocks, 512 regions and a bounded scan-work
  budget, plus 128 entry states, 256 exit states and 20,000 local product
  nodes per state-aware region. Other functions or regions use monolithic
  IPET, and block counts inside a state-summarized region are diagnostic.
- Context-sensitive flow facts use caller-frame versions. F4 `in ...` frames
  are function-level and apply to every call from that caller. FFX `<call>`
  frames are call-site scoped: an explicit `address`/`site` selects the call
  instruction, otherwise a unique caller-to-callee edge is used. Multiple
  sites without an address are ignored with a warning. Call-site-specific
  versions feed callee summaries and partitioned IPET costs independently per
  call site; function-level WCET is the maximum over analyzed contexts.
  Context enumeration is bounded; overflow falls back to a conservative
  context-insensitive model and marks results `partial`.
- IPET enforces unordered infeasible-path conflicts when all elements share one
  function and are outside natural loops (`sum <= n-1` per invocation) or touch
  one common non-nested loop (`sum <= (n-1) * loop iterations`). Same-function
  conflicts without an iteration context that mix loop and non-loop elements,
  span nested loops, or touch disjoint loops use binary presence indicators at
  invocation scope, with big-M bounds from the containing loop bounds and
  `sum(presence) <= n-1`, so a repeated loop element is not mistaken for
  multiple present elements. Ordered
  conflicts reduce to the same constraints only when reachability forces the
  declared order: function-scope acyclic order, or per-iteration loop-body
  order with loop backedges removed. Structurally impossible sequences add no
  constraint. Other ordered conflicts use a product IPET with a progress
  automaton: function scope spans an invocation, loop scope resets on entry,
  and iteration scope resets on entry/backedge. Cross-function ordered
  conflicts with one or more direct `<call>` groups inline the selected callees;
  each group's elements must match within one invocation, the callee summary
  remains the cost bound, and a multi-group automaton preserves group order.
  A loop-scoped cross-function conflict keeps its caller-side elements and call
  boundaries inside the declaring function's natural loop and resets its
  sequence on loop entry, or on every backedge for iteration scope. Nested
  `<loop>` contexts select the innermost declared loop containing every caller
  event and lift to an enclosing declared loop when elements span child loops;
  an iteration context pins its declaring loop. If no declared loop contains
  all caller events but some touch a declared loop, an ordered conflict without
  an iteration context is enforced at function scope. Numeric, last and
  all-iteration mixed conflicts keep the selected loop and allow outside events
  before/after it. A numeric
  iteration scope selects one 1-based iteration; `-1` selects the last
  iteration and defers a completed sequence until a loop exit rejects it. A
  target above the configured per-entry loop bound is exactly vacuous, and
  numbers above 256 are ignored conservatively. Numeric iteration scopes apply
  to same-function and cross-function ordered conflicts; nested groups and
  ambiguous call sites are ignored with warnings. Product states that cannot
  reach a function exit are pruned, so dead circulations cannot inflate the
  objective. The product is capped; cap overflow makes the function `unknown`.
  `longest-path` records but does not
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
  slots, per-resource unit counts, optional register-file read/write port
  budgets, data forwarding and block-local store-to-load forwarding are
  modeled within each block and carried through the pipeline state product.
  Oversized register-file accesses take exclusive issue cycles; forwarding uses
  bypass latencies but block completion remains full latency and forwarding
  does not cross blocks. Writeback-cycle contention, banked register files,
  forwarding-network arbitration, store-buffer drain/age and cache/data-memory
  penalty suppression are not modeled. Enabling `[pipeline]` on a bounded
  AArch64/RISC-V model therefore makes the whole timing model statistical.
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
