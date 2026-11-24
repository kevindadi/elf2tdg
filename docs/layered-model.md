# Layered system model

The WCET results described elsewhere are **local** results: one execution root,
one function CFG and one configured core. The layered model is the first
composition step above that local layer. It is deliberately explicit and
conservative, and it is exported in CFG JSON as `system_model`.

```text
Layer 1  root/local WCET        cfg-longest-path or cfg-ipet per execution root
Layer 2  layered system model  tasks, places, transitions, dependencies
Layer 3  state-equation ILP    current coarse reachability relaxation
Layer 4  future timed PN       exact reachability / response-time analysis
```

The current implementation builds Layer 2 and solves its state-equation ILP
relaxation with the pure-Rust `microlp` backend. It does not solve exact
reachability or a timed Petri net yet.

## What is modeled

When a board profile enables `[wcet]`, every execution root in `wcet.roots`
becomes a candidate task:

- `task`, `isr` and `callback` roots are included in the concurrent task set;
- `startup` and `main` boot roots are excluded from the concurrent bound and
  remain available as ordinary local CFG/WCET analyses;
- if no concurrent roots exist, all roots are used as a fallback and a caveat
  is recorded.

Each task carries its local status, cycles and nanoseconds. Tasks get stable
local IDs (`t0`, `t1`, ...); the root function ID, root kind and task name are
preserved.

The model also contains:

- one `core:<core_id>` place with a single token, representing the analyzed
  core;
- one `ready:<task>` and one `done:<task>` place per task;
- one `execute:<task>` transition per task, consuming `ready` and `core` and
  producing `done` and `core`;
- spawn/join/await/callback/scope dependencies from the CFG concurrency
  annotations.

## Activation and resource budgets

The optional `[system]` board-profile section supplies per-task activation
bounds and cumulative resource budgets:

```toml
[system]

[[system.tasks]]
target = "sensor_task"       # function name, symbol, task name or 0x address
activations = 3              # default: 1
resources = { bus = 1 }      # units consumed per activation

[[system.resources]]
name = "bus"
capacity = 4                 # units available in this bound window
```

`target` is resolved against the recovered concurrent execution roots. A target
may be the full function/task name, its last `::` segment, a symbol, or a `0x`
address. Unknown or ambiguous targets are configuration errors rather than
silently ignored bounds. Boot roots are not part of the concurrent task set, so
they cannot be target tasks.

Each task gets `ready` tokens equal to its activation bound and a matching
`done` capacity. The final markings stay within `[0, activations]`; the
objective maximizes firing, so each transition fires as many times as the
bounds and budgets allow, up to `activations`. A resource adds a
`budget:<name>` place with `capacity` tokens; each task activation consumes its
declared units from that place and never returns them in this layer. The state
equation therefore enforces the cumulative constraint:

```text
sum(units(task, resource) * fires(task)) <= capacity(resource)
```

Resources are **cumulative per-window budgets**, not lock or bus-hold models.
They constrain total modeled usage and can reduce firing counts; the ILP
maximizes total work, so a task with a positive activation bound may receive
fewer (even zero) modeled firings when another task consumes the budget. They
do not add resource waiting time or arbitration delay.

## Current bound

The bound scope is `analyzed-core-activation-bounds`. The model is an integer
program:

```text
variables   x_t = firing count of transition t, integer, 0 <= x_t <= activations
objective   maximize sum(cost_t * x_t)
constraint  M_final = M_initial + C * x
constraint  ready/done/budget final markings within [0, capacity]
constraint  exact final marking for the core place
```

The state equation is only a necessary condition for Petri-net reachability.
Solving it may accept firing-count combinations that no concrete schedule can
realize, so the optimum is a conservative upper bound. Without `[system]`, each
task has activation bound 1, every `execute` transition fires once and the
objective equals the total local work.

The aggregate status is:

- `bounded` only when every modeled task is bounded;
- `partial` when any task is partial (a finite number is still reported, but it
  is not a safe upper bound);
- `unbounded` when any task is unbounded;
- `unknown` when no finite result is available.

Local task costs already include configured cache, pipeline, data-memory and
`[multicore]` block penalties. The layered bound does not add those penalties
again.

## What the bound does not cover

- Per-task response time or scheduling order.
- Periodic release times, jitter, deadlines or a hyperperiod; activation
  bounds are static per-window counts.
- Lock/semaphore hold semantics, waiting and priority inversion. Resources are
  cumulative budgets only.
- Preemption, interrupt nesting and interrupt latency.
- Other cores' actual workloads, bus arbitration or shared caches. Other cores
  are represented only by the explicit `[multicore]` access budget.
- Spawn/join/await/callback dependencies as Petri-net arcs or ordering
  constraints. They are currently metadata.

`--require-safe` continues to certify the local per-root WCET layer. The
layered model is a composition IR, not an additional certification gate yet.

## JSON shape

```json
{
  "system_model": {
    "model": "layered-petri-state-equation",
    "cores": 2,
    "core_id": 0,
    "boot_roots": 2,
    "tasks": [
      {
        "id": "t0",
        "function": "fn:0x800085c",
        "kind": "task",
        "name": "sensor_task",
        "status": "bounded",
        "cycles": 87.0,
        "activation_bound": 3
      }
    ],
    "places": [
      { "id": "core:0", "kind": "core", "tokens": 1, "capacity": 1 },
      { "id": "budget:bus", "kind": "budget", "tokens": 4, "capacity": 4 },
      { "id": "ready:t0", "kind": "ready", "tokens": 3, "capacity": 3 },
      { "id": "done:t0", "kind": "done", "tokens": 0, "capacity": 3 }
    ],
    "transitions": [
      {
        "id": "execute:t0",
        "kind": "execute",
        "task": "t0",
        "cost_cycles": 87.0,
        "activations": 3,
        "inputs": ["ready:t0", "core:0", "budget:bus"],
        "outputs": ["done:t0", "core:0"]
      }
    ],
    "dependencies": [
      {
        "kind": "spawn",
        "from": "fn:0x800082a",
        "to": "fn:0x800085c",
        "site": "0x8000868",
        "runtime": "rust-embassy",
        "api": "embassy::Spawner::spawn",
        "confidence": "medium"
      }
    ],
    "petri": {
      "solver": "microlp",
      "relaxation": "state-equation",
      "status": "optimal",
      "objective": 87.0,
      "firing": [
        { "transition": "execute:t0", "fires": 3 }
      ]
    },
    "bound": {
      "scope": "analyzed-core-activation-bounds",
      "status": "partial",
      "cycles": 261.0,
      "tasks": 1,
      "max_activations": 3,
      "assumptions": ["..."]
    },
    "caveats": ["..."]
  }
}
```

## Next layer

The state-equation solver and static activation/resource budgets are in place.
The next steps tighten them:

1. add periodic release times, jitter or a hyperperiod to the task places;
2. encode spawn/join dependencies as fork/join arcs and ordering constraints;
3. add lock/bus hold semantics and arbitration-aware resource places;
4. add bounded reachability or timed-Petri-net analysis for per-task response
   time;
5. add the system bound to the safe gate only after the model and solver are
   validated.
