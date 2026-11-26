# F4 and FFX flow facts

Loop bounds are supplied by the board profile's `[wcet]` section, by external
flow-fact files, or by conservative counted-loop inference enabled by default.
FFX files can also supply non-loop branch and call facts:

```sh
elf2tdg firmware.elf --board-profile board.toml \
  --flowfacts loops.ff --flowfacts extra.ffx \
  --path-analysis ipet --format text --function main
```

`--flowfacts` may be repeated and requires a board profile with `[wcet]`.
The two backends share the same resolved facts:

- `longest-path` uses the bounds when unrolling natural loops.
- `ipet` turns them into ILP loop constraints.

## Merge and precedence

1. `default_loop_bound` is a fallback for loops without an explicit bound.
2. Explicit profile `[[wcet.loop_bounds]]` entries are explicit bounds.
3. Imported F4/FFX bounds are merged with existing explicit bounds.
4. If two explicit bounds disagree for the same loop header and caller
   context, the larger bound is kept and a warning is recorded in the WCET
   caveats.
5. An imported bound overrides the profile's default bound (it is explicit).
6. With `auto_loop_bounds = true` (the default), a recognized counted-loop
   bound is added only when no larger explicit/default bound exists. If the
   inferred value is larger than an explicit or default bound, the larger
   inferred value is kept conservatively and a warning is recorded. Set
   `auto_loop_bounds = false` to disable inference.

### Context-sensitive facts

F4 `in ...` paths and FFX `<call>` nesting select a caller context. Contexts are
normalized to the same order: **immediate caller first**, excluding the function
that contains the fact. A fact applies when its caller chain is a prefix of the
analyzed call chain.

- `in "sensor_task"` applies when `sensor_task` calls the function directly,
  regardless of who called `sensor_task`.
- `in "sensor_task" / "main"` additionally requires that `main` called
  `sensor_task`.
- A fact without a context remains global.

For example, this FFX fact applies to `delay` when called by `main`:

```xml
<function name="main">
  <call name="delay">
    <loop address="0x0800_00d8" maxcount="2"/>
  </call>
</function>
```

The same fact in F4 form is:

```text
loop 0x080000d8 2 in "main";
```

When `main` calls `delay` from more than one site, FFX can select the exact
call instruction with an `address` (or `site`) attribute:

```xml
<function name="main">
  <call name="delay" address="0x0800_0140">
    <loop address="0x0800_00d8" maxcount="2"/>
  </call>
  <call name="delay" address="0x0800_0160">
    <loop address="0x0800_00d8" maxcount="5"/>
  </call>
</function>
```

The two call sites become separate `delay` versions. Without an address, a
unique `main` -> `delay` call edge is used automatically; an ambiguous edge is
ignored with a warning instead of applying one bound to every site.

Context-sensitive loop bounds are analyzed per caller chain by both backends.
IPET also applies contextual branch/call facts. Function-level WCET is the
maximum over all analyzed contexts, while a root result uses the root's own
(empty) caller chain. Context-aware callee summaries are selected per call site,
so an expensive context does not inflate an unrelated caller path.

Within one context, the most specific matching caller chain wins and takes
precedence over a global, default or inferred loop bound. Conflicting facts for
the same chain keep the larger loop bound (or the tighter branch/call count) and
emit a caveat. When context analysis is not used (no contextual
facts, or a context limit was exceeded), the fallback folds all contextual loop
bounds in with their maximum and requires a global or default bound for safety.
Contextual non-loop facts are enforced by IPET only; `longest-path` records them
but ignores them.

Context enumeration is bounded to depth 16, 64 contexts per function and 4096
contexts per program. Exceeding a limit falls back to a context-insensitive
model: contextual loop bounds are merged conservatively, contextual branch/call
facts are not applied, and finite results computed in that fallback are marked
`partial` (so `--require-safe` rejects them).

Context identity is a chain of **caller frames**. Each frame has a caller
function and an optional call-site address:

- F4 `in ...` frames are function-level (`site = null`). A F4 fact applies to
  every call from that caller, so two calls from the same caller share the
  frame and the fact applies to both.
- FFX nested `<call>` frames are call-site scoped. The address comes from the
  `<call address="...">`/`site="..."` attribute, or from the unique
  caller-to-callee edge when no address is declared. If a caller has multiple
  matching sites and no address, the fact is ignored with a warning rather
  than broadened unsafely.

A F4 function-level frame matches any site-specific analyzed frame for the same
caller. A call-site-specific fact is more specific than a function-level fact
with the same chain length and wins for that site. Conflicting facts at the
same specificity keep the larger loop bound or tighter non-loop count. A fact
whose caller chain matches no analyzed execution has no effect. Recursive
call-graph SCCs remain `unbounded`, so contexts are not expanded through them.
Function-level WCET is the maximum over analyzed contexts; call-site-specific
facts therefore affect callee summaries and the enclosing caller's call costs,
including partitioned IPET results.

## F4 `.ff`

Supported loop forms:

```text
checksum "firmware.elf" 0x12345678;

loop 0x08000100 10;
loop 0x08000100 max 10 total 15;

loop "main" + 0x24 max 10 total 15;
loop "main.c":29 max 10 total 15;

loop "main.c":29 max 10 total 15 in "g1" / "main";
```

- The first form is a direct loop-header address.
- `"function" + offset` resolves the header as `function.address + offset`.
- `"file":line` resolves a natural-loop header whose header instruction has
  that source location. File matching accepts the full path, a suffix, or the
  same basename.
- `max` is the per-entry loop bound used by the analysis. If only `total` is
  present, it is used as the per-entry bound with a warning.
- `in "step1" / "step2" / ...` is a caller chain, immediate caller first.
  `step1` is the function calling the loop, `step2` is its caller, and so on.
  Each step may be a function name or a `0x` function address, matching F4.
- `checksum` is parsed but not verified; a warning is recorded.
- `nocall` and unknown directives are ignored with warnings; calls remain in
  the analysis.

## FFX `.ffx`

Supported shape:

```xml
<flowfacts>
  <function name="main">
    <loop source="main.c" line="29" maxcount="10" totalcount="15"/>
    <loop offset="0x24" max="10">
      <loop offset="0x30" max="4"/>
    </loop>
  </function>
</flowfacts>
```

- `<function name="...">` scopes loop targets to a function.
- `<call name="...">` nesting selects a caller context. The enclosing
  `<function>` names and nested call names form the call path; the normalized
  context excludes the function containing the fact.
- `<loop offset="...">` resolves against the current function entry.
- `<loop address="...">` uses a direct loop-header address.
- `<loop source="..." line="...">` resolves through DWARF source locations.
- `maxcount`/`max` is the per-entry bound. If only `totalcount`/`total` is
  present, it is used as the bound with a warning.
- Unknown elements are ignored with warnings; malformed XML is fatal.
- Nested `<loop>` elements are imported as separate facts.

## Non-loop FFX facts

FFX `<conditional>` and `<call>` elements provide non-loop facts. A
conditional fact identifies a conditional branch by `address`, `offset` +
enclosing function, or `source`/`line`:

```xml
<conditional>
  <condition address="0x0800_00e4"/>
  <case cond="1" executed="false"/>       <!-- taken edge never executes -->
  <case cond="0" executed="true"/>        <!-- no numeric count inferred -->
</conditional>

<conditional executed="false" address="0x0800_0110"/>  <!-- block never executes -->
```

A call fact uses `numcall` (total calls to the function) or
`executed="false"`:

```xml
<call name="delay" address="0x0800_0140" numcall="1"/>
<call name="monitor" executed="false"/>   <!-- every resolved call site is zero -->
```

Semantics and limits:

- Branch facts constrain the taken or fallthrough CFG edge in IPET; a
  `both`/`executed=false` conditional constrains the conditional block to zero.
  IT-predicated branch blocks are rejected because the source-level condition
  may not correspond to a CFG edge under predication.
- Call facts constrain the containing block when the block has one unconditional
  call site with a single resolved, non-heuristic target and no predication.
  Conditional calls (including A32 `BLcc`/`BLXcc`), multi-target/unresolved
  calls, IT-predicated calls and blocks with multiple call sites are skipped
  with a warning because a block-count constraint would not be implied by the
  call fact.
- A callee-wide `numcall` is applied as a per-call-site upper bound. It is a
  relaxation of the global total, and therefore remains a conservative upper
  bound.
- Numeric branch counts (`maxcount`/`totalcount` on a case) are not supported
  yet; only `executed=false` is applied, with a warning for the numeric form.
  Iteration- and scenario-specific elements are ignored entirely because the
  current analysis is not iteration- or scenario-sensitive.
- Context-specific branch/call facts are applied only in matching caller
  contexts by IPET. A fact whose caller chain matches no analyzed context has no
  effect.
- Non-loop facts are enforced by IPET only. `longest-path` records them but is
  left as a conservative overestimate and emits a caveat.
- IPET may still partition a function containing supported branch/call facts or
  infeasible-path constraints. Regions that touch a fact-referenced block stay
  monolithic, and the final parent model enforces the fact. Exact state-free
  partitioning also supports non-cross-function ordered automata: automaton
  reset-loop blocks stay monolithic, and the final automaton product enforces
  the order. State-product partitioning keeps ordered automata monolithic;
  cross-function constraints keep the whole function monolithic.
- F4 non-loop directives are not implemented; unknown F4 directives are
  reported and ignored. Use FFX for branch/call facts.

## Infeasible-path conflicts

FFX `<conflict>` elements declare a set of edges or blocks that cannot all
appear in one execution sub-trace:

```xml
<function name="sensor_task">
  <conflict>
    <edge src="0x0800_0120" dst="0x0800_0128"/>
    <block address="0x0800_012a"/>
  </conflict>
</function>
```

- `<edge src="..." dst="..."/>` identifies a CFG edge by source and target
  addresses. `<block address="..."/>` identifies a basic block; block locations
  also accept `offset`, or `source`/`line`.
- A conflict must be declared inside a `<function>` or `<call>` scope. It is
  interpreted per function invocation; top-level conflicts are ignored because
  their whole-program scope cannot be guaranteed per invocation.
- Conflicts are also recognized through the OTAWA `<not-all seq="true">`
  form. Both that form and `<conflict ordered="yes">` are ordered conflicts and
  are enforced by IPET in three ways:
  - **Structural reduction.** Function-scope conflicts whose elements are
    outside loops are checked by CFG reachability between consecutive elements.
    If every pair is reachable in the declared order, any trace containing all
    elements must use that order, so the unordered `sum <= n - 1` constraint
    applies exactly. `<iteration number="*">` conflicts use the per-iteration
    CFG with loop backedges removed and, when the order is forced, the loop
    aggregate constraint.
  - **Automaton product.** Other ordered conflicts use a product IPET with a
    sequence-progress automaton. Function scope tracks progress over the whole
    invocation, loop scope resets on entry and spans all iterations, and
    `<iteration number="*">` scope resets on entry and every backedge. This
    models cross-iteration ordering exactly without unrolling loop iterations.
    The product is capped (100,000 states / 200,000 transitions); exceeding the
    cap makes the function `unknown` rather than returning an unsound bound.
  - **Cross-function product.** An ordered conflict may contain one direct
    `<call name="...">` group:

    ```xml
    <function name="main">
      <conflict ordered="yes">
        <block address="0x0800_0138"/>       <!-- caller-side -->
        <call name="delay">
          <block address="0x0800_00d8"/>     <!-- callee-side -->
          <edge src="0x0800_00e4" dst="0x0800_00e6"/>
        </call>
      </conflict>
    </function>
    ```

    Top-level elements must resolve in the declaring function; group elements
    must resolve in the callee. The group is selected by the callee's function
    name; call-address, offset or source/line attributes are not accepted on a
    conflict call group. The group is one sequence item and must match in a
    **single invocation** of the selected call. If the call site is in a
    loop, callee progress resets on every invocation, while caller-side progress
    persists across the function invocation. The call must be a unique,
    unconditional, directly resolved call site of the declaring function, in a
    reachable block with exactly one call-return edge. The enforcing product
    IPET inlines the callee at that call site. Callee blocks carry no direct
    cost: the caller call block keeps the callee summary cost, so this prunes
    caller-side paths and call executions but does not re-derive the callee's
    internal worst-case cost. The same state/transition caps apply, and cap
    overflow makes the function `unknown`. A callee whose inlined CFG or loop
    bounds cannot be built also makes the caller `unknown` rather than silently
    dropping the constraint.
  If the sequence is structurally impossible, the fact is vacuously satisfied:
  no constraint or automaton is needed and the record explains why. Ordered
  conflicts that repeat an element, name a backedge element in an iteration
  scope, contain more than one call group, nest a call inside a call group, or
  select an ambiguous call site are ignored conservatively.
- Caller contexts follow the same rules as other FFX facts. Loop contexts are
  accepted for same-function conflicts: a `<loop ...>` may omit its bound and
  acts as a context only; a missing bound produces a warning and falls back to
  the profile/default or inference. `<iteration number="*">` conflicts are
  supported. Conflicts for a specific iteration number are ignored with
  warnings. A cross-function conflict with an enclosing `<loop>` or
  `<iteration>` context is ignored because per-iteration call-group reset
  semantics are not implemented. Unordered conflicts spanning nested loops are
  ignored; ordered conflicts use the automaton product.
- For same-function conflicts, all elements must resolve inside one function.
  For a conflict declared inside a `<loop>` or `<iteration>` context, every
  edge endpoint and block must be inside that loop; entry/exit edges are
  rejected with a warning. Two structural forms are enforced by IPET:
  - all elements are outside every natural loop: `sum(executions) <= n - 1`
    per function invocation;
  - all elements touch one common natural loop and none lies in a nested loop:
    `sum(executions) <= (n - 1) * loop_header_executions`. This is a
    conservative per-iteration relaxation and also covers whole-loop conflicts.
- Mixed loop/non-loop sets, nested-loop elements and unsupported cross-function
  shapes are ignored with warnings. Unordered cross-function conflicts are not
  supported. Unsupported or unresolvable conflicts only lose precision and
  never tighten the bound incorrectly.
- Infeasible-path constraints are enforced by IPET only. `longest-path`
  records them but remains a conservative overestimate and emits a caveat.
  A conflict that contradicts the CFG or other facts can make the IPET model
  infeasible; the affected function is then `unknown`, not a claimed bound.
- F4 has no infeasible-path directive in this implementation.

## Resolution failures

An imported fact that cannot be resolved is a fatal configuration error:

- no function matches the name, or the name is ambiguous;
- the function + offset is not a CFG basic block;
- the source file/line matches no natural-loop header;
- the source file/line matches more than one loop;
- a branch/call fact has no resolvable location, or matches multiple sites;
- a callee-only call fact names a function with no matching call sites;
- a context name does not resolve to a unique function;
- a callee-wide call fact declares a scope that does not contain its call site;
- a cross-function conflict call group names a function that does not resolve.

An FFX caller context that names an ambiguous multi-site edge without an
address is not a fatal error: the fact is ignored with a warning. Adding an
explicit `<call address="...">` resolves it. An address that is not a
caller-to-callee call site is also ignored with a warning. A context edge with
no call site produces a warning and has no effect. Conflict element-level resolution
failures and unsupported conflict shapes are also non-fatal: the conflict is
recorded as ignored and the analysis remains conservative. This includes a
cross-function group with no unique unconditional call site, no unique
call-return edge, more than one group, a nested call group, or a merged
unordered form. An unresolvable conflict enclosing function name or
loop-context target is fatal, consistent with the other flow-fact targets.

Ambiguity is not silently resolved because a wrong flow fact is a soundness
problem for WCET analysis. Conditional calls and multi-call blocks are the
exception: their facts are ignored with a warning because the block-level
constraint is not implied.

## Recorded metadata

Imported facts are recorded in `wcet.flow_facts`:

```json
{
  "source": "board-profile [wcet] + loops.ff",
  "default_loop_bound": 4,
  "bound_nonterminating_loops": true,
  "loops": [
    { "header": "0x800013e", "bound": 7, "source": "loops.ff" },
    {
      "header": "0x80000d8",
      "bound": 2,
      "context": ["main"],
      "source": "context.ffx"
    }
  ],
  "branches": [
    {
      "function": "fn:0x80000d8",
      "site": "0x80000e4",
      "outcome": "taken",
      "max_count": 0,
      "context": ["sensor_task"],
      "source": "branch.ffx"
    }
  ],
  "calls": [
    {
      "function": "fn:0x8000138",
      "site": "0x8000140",
      "max_count": 1,
      "context": ["Reset_Handler"],
      "source": "call.ffx"
    }
  ],
  "conflicts": [
    {
      "function": "fn:0x8000120",
      "ordered": false,
      "applied": true,
      "mode": "aggregate",
      "scope": "function",
      "elements": [
        { "kind": "block", "source": "bb:0x8000120" },
        { "kind": "edge", "source": "bb:0x8000124",
          "target": "bb:0x8000128", "site": "0x8000126" }
      ],
      "source": "conflicts.ffx"
    },
    {
      "function": "fn:0x8000138",
      "ordered": true,
      "applied": true,
      "mode": "automaton",
      "scope": "cross-function",
      "call": {
        "callee": "fn:0x80000d8",
        "block": "bb:0x800013e",
        "site": "0x8000140",
        "continuation": "bb:0x8000144"
      },
      "elements": [
        { "kind": "block", "function": "fn:0x8000138",
          "source": "bb:0x8000138" },
        { "kind": "block", "function": "fn:0x80000d8",
          "source": "bb:0x80000d8" }
      ],
      "source": "cross.ffx"
    }
  ]
}
```

Per-loop `source` values and non-empty contexts are also shown in the text
report. For a cross-function constraint the report also prints the selected
callee and call-site address. Warnings from import, merge and context handling
are appended to `wcet.caveats`.
