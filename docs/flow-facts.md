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
4. If two explicit bounds disagree for the same loop header, the larger bound
   is kept and a warning is recorded in the WCET caveats.
5. An imported bound overrides the profile's default bound (it is explicit).
6. With `auto_loop_bounds = true` (the default), a recognized counted-loop
   bound is added only when no larger explicit/default bound exists. If the
   inferred value is larger than an explicit or default bound, the larger
   inferred value is kept conservatively and a warning is recorded. Set
   `auto_loop_bounds = false` to disable inference.

Context-specific facts (F4 `in ...` paths or FFX `<call>` nesting) are applied
context-insensitively because the current WCET analysis is per-function. This
keeps the larger bound across contexts and emits a warning.

## F4 `.ff`

Supported loop forms:

```text
checksum "firmware.elf" 0x12345678;

loop 0x08000100 10;
loop 0x08000100 max 10 total 15;

loop "main" + 0x24 max 10 total 15;
loop "main.c":29 max 10 total 15;

loop "main.c":29 max 10 total 15 in "f" / "g1" / "main";
```

- The first form is a direct loop-header address.
- `"function" + offset` resolves the header as `function.address + offset`.
- `"file":line` resolves a natural-loop header whose header instruction has
  that source location. File matching accepts the full path, a suffix, or the
  same basename.
- `max` is the per-entry loop bound used by the analysis. If only `total` is
  present, it is used as the per-entry bound with a warning.
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
- `<call name="...">` nesting is retained as evidence, but facts are applied
  context-insensitively with a warning.
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
  current analysis is not context/iteration-sensitive.
- Context-specific branch/call facts are **ignored** with a warning because the
  current analysis is context-insensitive. Applying a context-specific fact
  globally could understate WCET.
- Non-loop facts are enforced by IPET only. `longest-path` records them but is
  left as a conservative overestimate and emits a caveat.
- F4 non-loop directives are not implemented; unknown F4 directives are
  reported and ignored. Use FFX for branch/call facts.

## Resolution failures

An imported fact that cannot be resolved is a fatal configuration error:

- no function matches the name, or the name is ambiguous;
- the function + offset is not a CFG basic block;
- the source file/line matches no natural-loop header;
- the source file/line matches more than one loop;
- a branch/call fact has no resolvable location, or matches multiple sites;
- a callee-only call fact names a function with no matching call sites.

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
    { "header": "0x800013e", "bound": 7, "source": "loops.ff" }
  ],
  "branches": [
    {
      "function": "fn:0x80000d8",
      "site": "0x80000e4",
      "outcome": "taken",
      "max_count": 0,
      "source": "branch.ffx"
    }
  ],
  "calls": [
    {
      "function": "fn:0x8000138",
      "site": "0x8000140",
      "max_count": 1,
      "source": "call.ffx"
    }
  ]
}
```

Per-loop `source` values are also shown in the text report. Warnings from
import, merge and context handling are appended to `wcet.caveats`.
