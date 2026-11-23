# F4 and FFX flow facts

Loop bounds are supplied by the board profile's `[wcet]` section or by
external flow-fact files:

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

## Resolution failures

An imported fact that cannot be resolved is a fatal configuration error:

- no function matches the name, or the name is ambiguous;
- the function + offset is not a CFG basic block;
- the source file/line matches no natural-loop header;
- the source file/line matches more than one loop.

Ambiguity is not silently resolved because a wrong loop bound is a soundness
problem for WCET analysis.

## Recorded metadata

Imported facts are recorded in `wcet.flow_facts`:

```json
{
  "source": "board-profile [wcet] + loops.ff",
  "default_loop_bound": 4,
  "bound_nonterminating_loops": true,
  "loops": [
    { "header": "0x800013e", "bound": 7, "source": "loops.ff" }
  ]
}
```

Per-loop `source` values are also shown in the text report. Warnings from
import, merge and context handling are appended to `wcet.caveats`.
