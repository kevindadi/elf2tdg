# TDG diagram legend

This is the visual vocabulary used by `elf2tdg --format dot` and
`--format mermaid`. The JSON output is canonical; diagrams are projections.
Both renderers use the same relation labels, though Graphviz carries the full
color styling and Mermaid is limited to shapes and line styles.

## Nodes

| Shape / style | Color | Meaning |
|---|---|---|
| rounded box | white | ordinary function |
| rounded box | light green | entry function (`FunctionKind::Entry`) |
| rounded box | pale yellow | interrupt handler function (`FunctionKind::Isr`) |
| rounded box | lavender | kernel function (`FunctionKind::Kernel`) |
| rounded box, dashed border | lavender | synthesized logical task entry, zero size, `ext["elf2tdg.logical_task"] = true` |
| rounded box, dashed gray border | light gray | external dynamic import (`malloc`, `free`, ...); address is a GOT slot pseudo-address |
| box | blue | `startup` context |
| box | light blue | `main` context |
| box | purple | `thread` or `scoped-thread` context |
| box | lavender | `async-task` or `executor` context |
| box | orange | `isr` context |
| box | pale yellow | `timer-callback` context |
| box | gray | `system-workqueue` or `kernel-thread` context |
| box, dashed border | context color | synthesized logical task context, or orphan context created from a spawn API symbol |
| dashed green ellipse | green | structured-concurrency scope |
| orange diamond | orange | Cortex-M vector / IRQ source |
| pale-yellow note | yellow | lock/semaphore acquire or release event |
| gray note | gray | opaque target with unresolved candidates |

Contexts also carry their kind as a second label line. A context points at its
entry function with a dotted blue `entry` edge. Context parent relationships are
present in JSON but not drawn separately; a spawn edge and context labels make
the same relationship visible without duplicating arrows.

## Edges

| Label | Style | Meaning |
|---|---|---|
| `call` | solid gray | direct call |
| `tail` | dashed gray | tail call |
| `spawn (OsThread)` etc. | red, bold | creates a context |
| `spawn?` / opaque note | red, dashed through target | spawn target unresolved; candidates in JSON |
| `Join` / `Detach` / `Abort` | blue, bold | waits for or terminates a context |
| `Await`, `Poll`, ... | purple, bold | async await relation |
| `callback <api>` | teal, dashed | callback/timer/workqueue registration |
| `ISR` / `IRQ n` | orange, dashed | vector activates an ISR context |
| `preempts` | orange, dotted | derived preemption relation |
| `lock` | yellow, dotted | function → lock/semaphore event |
| `entry` | blue, dotted | context entry function |
| `in` / `member` | green, dotted | scope entering context / owned spawn relation |

### Confidence encoding

For `spawn`, `join`, and `await`:

- **bold solid** — high or medium confidence;
- **bold dashed with a `?` suffix** — low or unknown confidence;
- an **opaque note** — target unresolved; its label lists the candidate count.

Contexts synthesized during analysis (logical tasks or orphan spawn contexts)
use a dashed border in DOT. Every inferred relation also carries the exact
`confidence` value and, for unresolved targets, the candidate list in JSON.

## Projections

`--projection full` (default) draws every function and call edge plus all
concurrency-control relations. Use it for small images such as the Cortex-M0
example.

`--projection concurrency` omits ordinary call edges and draws only:

- contexts and their entry functions;
- functions that originate a spawn/join/await/callback or lock relation;
- lock events, scopes, ISR vectors, opaque targets, and derived preemption
  edges.

This keeps optimized Rust binaries readable. `--legend` appends the key shown
above to the DOT or Mermaid output.

## Examples

- [`examples/rust-concurrency/`](../examples/rust-concurrency/README.md) —
  no-std Embassy task spawns, async-task contexts, and DWARF inline recovery
  with the recommended `analysis` profile.
- [`examples/cortex-m0-isr/`](../examples/cortex-m0-isr/README.md) — reset/main
  contexts, vector 53 / IRQ 37, call graph, and Cortex-M0 cycle estimates.

## Reading caveats

- Function labels are truncated to 72 characters with `...`.
- Crate-hash segments such as `std[f9fb83b88fa27b65]::` are removed in diagrams
  for readability; JSON symbol names retain the original spelling.
- Cycle labels on functions are **static block sums**, not path times or WCET
  bounds.
- Mermaid carries relation labels and basic line styles; use DOT/SVG when the
  full color legend matters.
