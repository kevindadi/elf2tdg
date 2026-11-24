# Layered system model

The WCET results described elsewhere are **local** results: one execution root,
one function CFG and one configured core. The layered model is the first
composition step above that local layer. It is deliberately explicit and
conservative, and it is exported in CFG JSON as `system_model`.

```text
Layer 1  root/local WCET        cfg-longest-path or cfg-ipet per execution root
Layer 2  layered system model  tasks, places, transitions, dependencies, bound
Layer 3  future Petri-net ILP  state-equation or timed-PN resource analysis
```

The current implementation stops at Layer 2. It records the Petri-net-shaped
structure and computes a coarse closed-form bound, but it does not yet solve a
state-equation or timed Petri net.

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

This is the closed-form solution of the current Petri-net relaxation: every
transition fires at most once, all tasks serialize on one analyzed core, and no
ordering constraints from spawn/join are applied. It is intentionally coarse.

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
    "model": "layered-petri-single-activation",
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

The next step is to solve the exported Petri-net structure rather than its
closed form:

1. add bounded activation counts or a hyperperiod to the task places;
2. encode dependencies as fork/join places and arcs;
3. encode locks, buses and memory banks as resource places;
4. maximize weighted firing counts under the state equation (a sound
   over-approximation of reachability) or use a timed Petri net for per-task
   response time;
5. add a system-bound status to the safe gate only after the model and solver
   are validated.
