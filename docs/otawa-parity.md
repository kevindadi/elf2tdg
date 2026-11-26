# OTAWA parity roadmap

This document fixes the scope for matching OTAWA's analysis capabilities while
keeping the elf2tdg system model and its future Petri-net/multicore scheduling
layer.

## Parity target

The target is equivalent **analysis capability on AArch64, RISC-V and
Thumb**, expressed through elf2tdg's own typed schema and pass architecture:

1. architecture/resource/timing description with safe defaults;
2. binary CFG, call graph and data-flow/abstract-interpretation infrastructure;
3. automatic loop bounds, non-loop flow facts, context-sensitive facts and
   infeasible-path constraints;
4. instruction/data cache analysis, including persistence and cache constraints
   in IPET;
5. general pipeline/resource-dependency analysis and branch prediction, with
   pipeline constraints in IPET;
6. scalable IPET/ILP with cache/pipeline/flow constraints and CFG partitioning;
7. validation and benchmarks against OTAWA and reference WCET results.

## Confirmed exclusions

The following OTAWA implementation mechanisms or non-target capabilities are
deliberately not implemented:

- **XML/SimNML/GLISS2/ADL architecture descriptions and generated ISS.**
  Capstone already provides decoding. A second ISA description plus a generated
  instruction-set simulator would duplicate the front-end, add a large
  maintenance surface, and contribute nothing to a static safe upper bound.
  The replacement is a typed TOML hardware profile with safe defaults and a
  generated complete template.
- **C++ plugin ABI, OWL scripting and lp_solve coupling.**
  Rust has no stable cross-`cdylib` ABI. Analyses stay compile-time passes over
  typed facts, and `microlp` remains the first solver. An external solver can
  be added later through an explicit file exchange, not an OTAWA-compatible
  plugin ABI.
- **Full timing/pipeline support for non-target ISAs** such as PowerPC or
  TriCore. The product target is AArch64/RISC-V/Thumb; x86-64 retains only the
  incidental ELF/CFG decode path.
- **OTAWA CLI/API/XML compatibility.** elf2tdg keeps its own JSON/text schema
  and F4/FFX import. It does not emulate OTAWA commands, OWL files or XML
  architecture descriptions.
- **Host language/runtime analysis** (Rust std, C++ standard library, pthread,
  OpenMP and other host runtimes) remains outside the global no_std profile
  established for the project.

## Hardware configuration contract

- Hardware configuration is typed TOML/JSON, never XML.
- `--print-default-profile --cpu <model>` emits a complete, safe-default
  template with every currently supported hardware attribute.
- The minimum valid profile is `cpu = "..."`:
  - `schema_version` defaults to `2`;
  - `id` defaults to `board:default`;
  - `arch` is inferred from `cpu`.
- Omitted optional sections disable that model. Board-specific clock, memory,
  cache, pipeline, branch-prediction and multicore values are never guessed
  from a CPU name; they must come from verified board data.
- As parity features are added, the template and its tests must be extended in
  the same change.

## Phases

| Phase | Scope | Status |
|---|---|---|
| A | Typed hardware profile, safe defaults, complete template, resolved values | first version implemented |
| B | Data-flow/abstract interpretation, automatic loop bounds, non-loop flow facts, context-sensitive facts, infeasible paths | in progress: counted-loop inference, FFX branch/call facts, caller-function and call-site-sensitive context versions, unordered/structurally-forced/cross-iteration/cross-function ordered conflict constraints implemented (cross-function covers one or more direct call groups per conflict, including loop-scoped sequences with entry or per-iteration backedge reset, plus numeric 1-based and last-iteration scopes, nested loop contexts and mixed loop/non-loop ordering with function, numeric/last or all-iteration scope for same-function and cross-function conflicts, plus invocation-scope presence indicators for same-function unordered mixed loop/non-loop conflicts); conflict scalability remains planned |
| C | Cache persistence/line splitting, general pipeline/resource model, branch prediction, constraints in IPET | in progress: per-block LRU instruction/data-cache models with line-split logical blocks, a per-function cache-state product, a full instruction-cache CCG flow model, per-line first-miss and aggregate conflict bounds, concrete branch-predictor state products with per-edge misprediction costs, optional unknown first-execution history, global-history, gshare, local-history, configurable two-level pattern tables, a global/local tournament predictor, set-associative BTB miss models and bounded return-address stacks, interprocedural branch summaries that carry predictor state and branch costs through direct calls, and multiple-issue Cortex-M4 plus AArch64/RISC-V resource/dependency pipeline models with register-file port constraints, data forwarding, block-local store-to-load forwarding and full inter-block state tables in the IPET state product with first-order edge stalls as fallback implemented; other tournament component pairs planned |
| D | IPET scalability, CFG partitioning, call-site-sensitive context summaries, benchmarks against OTAWA | in progress: IPET solves SESE branch regions, including function-entry regions and statically modeled calls, bottom-up with exact per-entry summaries and expands block counts; with active cache/pipeline/branch/BTB/RAS state products it summarizes a laminar family of regions without loop headers/latches innermost first per entry/exit product state, folds nested costs/counts into enclosing summaries and keeps those states explicit, producing a safe upper bound that can exceed monolithic state-product IPET; recovered call sites without a containing block do not block partitioning but stay function-level and partial; supported branch/call facts and infeasible-path constraints are enforced by the partition parent; exact state-free partitioning also supports ordered and cross-function automata by keeping automaton reset-loop blocks, all call-group boundaries and caller-side pattern elements monolithic and running the automaton or cross-function product on the reduced CFG, while regions touching fact blocks and state-product ordered/cross-function automata stay monolithic; a reproducible benchmark/regression harness compares longest-path and IPET on the local ELF corpus, records model selections/fallbacks and accepts external reference cycles (for example OTAWA) without fabricating values; call-site-sensitive context versions select per-site callee summaries and partitioned costs; OTAWA reference population, large-function cases and richer partition shapes remain planned |

The layered system model remains available throughout; parity work must not
regress its response, blocking, timed-feasibility or future Petri-net hooks.
