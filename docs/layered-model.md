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

## Current bound

The bound scope is `analyzed-core-single-activation`:

```text
bound.cycles = sum(task.local_cycles)   for one activation of every task
bound.time_ns = sum(task.local_time_ns)
```

The model is an integer program:

```text
variables   x_t = firing count of transition t, integer, 0 <= x_t <= activations
objective   maximize sum(cost_t * x_t)
constraint  M_final = M_initial + C * x
constraint  exact final marking for ready/done/core places
```

The state equation is only a necessary condition for Petri-net reachability.
Solving it may accept firing-count combinations that no concrete schedule can
realize, so the optimum is a conservative upper bound. With the current one
activation per task and one analyzed core, every `execute` transition fires
once and the objective equals the total local work.

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
- Periodic/repeated activation counts.
- Lock/semaphore waiting and priority inversion.
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
        "activation_bound": 1
      }
    ],
    "places": [
      { "id": "core:0", "kind": "core", "tokens": 1, "capacity": 1 },
      { "id": "ready:t0", "kind": "ready", "tokens": 1, "capacity": 1 },
      { "id": "done:t0", "kind": "done", "tokens": 0, "capacity": 1 }
    ],
    "transitions": [
      {
        "id": "execute:t0",
        "kind": "execute",
        "task": "t0",
        "cost_cycles": 87.0,
        "activations": 1,
        "inputs": ["ready:t0", "core:0"],
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
        { "transition": "execute:t0", "fires": 1 }
      ]
    },
    "bound": {
      "scope": "analyzed-core-single-activation",
      "status": "bounded",
      "cycles": 87.0,
      "tasks": 1,
      "assumptions": ["..."]
    },
    "caveats": ["..."]
  }
}
```

## Next layer

The state-equation solver is in place. The next steps tighten it:

1. add bounded activation counts or a hyperperiod to the task places;
2. encode spawn/join dependencies as fork/join arcs and ordering constraints;
3. encode locks, buses and memory banks as resource places;
4. add bounded reachability or timed-Petri-net analysis for per-task response
   time;
5. add the system bound to the safe gate only after the model and solver are
   validated.
