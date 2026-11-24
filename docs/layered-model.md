# Layered system model

The WCET results described elsewhere are **local** results: one execution root,
one function CFG and one configured core. The layered model is the first
composition step above that local layer. It is deliberately explicit and
conservative, and it is exported in CFG JSON as `system_model`.

```text
Layer 1  root/local WCET        cfg-longest-path or cfg-ipet per execution root
Layer 2  layered system model  tasks, places, transitions, dependencies
Layer 3  state-equation ILP    coarse reachability relaxation
Layer 4  response bounds       work-conserving busy-period RTA
Layer 5  discrete-time PN      slot-based deadline feasibility
Layer 6  future timed PN       exact reachability / tighter response analysis
```

The current implementation builds Layers 2-5 with the pure-Rust `microlp`
backend. It does not solve exact reachability or a full timed state-class
response analysis yet.

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

For periodic tasks, set `horizon_ns` on `[system]` and `period_ns` on the task:

```toml
[system]
horizon_ns = 5_000_000

[[system.tasks]]
target = "sensor_task"
period_ns = 1_000_000
release_offset_ns = 0
release_jitter_ns = 0
```

The activation bound is derived as:

```text
earliest = max(0, release_offset_ns - release_jitter_ns)
releases = floor((horizon_ns - earliest) / period_ns) + 1
```

If both `period_ns` and an explicit `activations` are present, the smaller
bound is kept. This constrains the number of releases in the window; it does
not enforce release instants, deadlines or order.

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

## Timed feasibility

Setting `[system].slot_ns` enables a discrete-time-expanded Petri-net model.
It uses `horizon_ns`, each task's release count, optional `deadline_ns` and
local `time_ns`:

- local WCET is rounded up to whole `slot_ns` slots;
- execution is preemptible only at slot boundaries;
- each activation needs that many execution slots before its deadline;
- the analyzed core can execute at most one slot at a time;
- releases at or after `horizon_ns` are excluded.

The result is a feasibility status (`feasible`, `infeasible`, `unsupported` or
`no-local-time`), not a worst-case response-time bound. The model is
model-dependent: slot rounding and slot-boundary preemption can both miss or
reject real schedules. Fork/join links and cumulative resource budgets are not
part of the timed feasibility model yet.

## Per-task response bounds

The system model also derives a work-conserving busy-period response bound for
each task:

```text
R_i = C_i + sum(j != i) N_j(R_i) * C_j + M_i(R_i) * C_i
```

For a periodic task `k`, both terms count one carry-in activation plus every
release that can fall inside a window of length `R`:

```text
N_k(R) = floor((R + J_k) / T_k) + 1
M_i(R) = N_i(R) for a periodic target
```

`J_k` is the configured release jitter and `T_k` the period. The carry-in
accounts for work released just before the window; the `+1` is needed because
an arbitrary work-conserving scheduler may not have completed that activation.
The target's own term covers queued earlier activations and, conservatively,
releases that occur while the analyzed activation is still pending.

For a non-periodic task, the activation bound is a total activation budget:
`N_j = B_j` for another task and `M_i = B_i - 1` for the target.

Periodic activation bounds derived from `horizon_ns` are **per-horizon** counts,
not lifetime totals. They are therefore not used to cap releases when the busy
window extends past the horizon; `floor((R + J)/T) + 1` is evaluated directly
for the full window. This is essential for a safe bound: capping at a horizon
count would undercount interference in a response window longer than the
horizon. An explicit periodic `activations` bound is likewise ignored here;
not capping it only makes the response more conservative.

The fixed point is computed with a bounded, monotone iteration that stops as
soon as `f(R) <= R`; such a post-fixed point is already a safe upper bound, so
no floating-point tolerance is used that could understate it. Exceeding
`1e15 ns` reports `unbounded`. Reaching the iteration limit without a
post-fixed point reports `unknown`; the partial bound is never presented as a
conclusion. A configured `deadline_ns` produces a `deadline_missed` flag when
the finite bound exceeds it.

Assumptions:

- one analyzed core;
- work-conserving scheduling with arbitrary preemption order;
- periodic releases follow the configured period and jitter;
- non-periodic activation bounds are true total bounds;
- jobs may queue, so same-task self-interference is included;
- no priority model, blocking, fork/join ordering, locks, resources,
  interrupts, other cores, caches, CRPD or preemption overhead;
- partial local WCET inputs make the response result `partial`.

This is a safe upper bound only under those assumptions; it is deliberately
conservative, independent of a particular priority assignment, and can reject
a feasible system. A priority-aware response analysis is the next tightening
step.

## Fork/join links

Explicit fork/join count constraints are configured under `[system.links]`:

```toml
[[system.links]]
from = "app_main"
to = "sensor_task"
kind = "fork"
count = 2

[[system.links]]
from = "app_main"
to = "sensor_task"
kind = "join"
count = 1
```

Semantics:

```text
fork: fires(to)   <= count * fires(from)
join: fires(from) <= count * fires(to)
```

A fork link means each source activation enables at most `count` target
activations. A join link means each target activation can satisfy at most
`count` source joins. `from` and `to` must resolve to distinct concurrent
tasks; self-links, zero counts and duplicate `(from, to, kind)` links are
errors.

Links constrain firing counts only. They do not establish temporal order,
release-to-join matching or deadline semantics. CFG concurrency annotations
are still recorded as `dependencies` metadata; auto-deriving links from every
annotation is not done because a spawn site inside a loop would need a proven
per-activation execution bound.

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

- The state-equation total-work bound does not itself provide per-task
  response time; use the separate work-conserving response section.
- Release instants, deadlines or ordering. Activation bounds are static
  per-window counts; release jitter only shifts the first-release count
  conservatively.
- Lock/semaphore hold semantics, waiting and priority inversion. Resources are
  cumulative budgets only.
- Preemption, interrupt nesting and interrupt latency.
- Other cores' actual workloads, bus arbitration or shared caches. Other cores
  are represented only by the explicit `[multicore]` access budget.
- Automatic link derivation from CFG concurrency annotations and temporal
  ordering. Explicit `[system.links]` count constraints are supported; the
  discovered annotations remain metadata.

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
    "links": [
      {
        "kind": "fork",
        "from": "t0",
        "to": "t1",
        "from_function": "fn:0x800082a",
        "to_function": "fn:0x800085c",
        "count": 2
      }
    ],
    "response": {
      "model": "work-conserving-busy-period",
      "tasks": [
        {
          "task": "t1",
          "function": "fn:0x800085c",
          "status": "bounded",
          "time_ns": 6375.0,
          "deadline_ns": 2000000,
          "deadline_missed": false
        }
      ],
      "caveats": ["..."]
    },
    "timed": {
      "model": "discrete-time-expanded-petri",
      "slot_ns": 100000,
      "horizon_slots": 50,
      "status": "feasible",
      "activations": 8,
      "execution_slots": 8,
      "variables": 392,
      "caveats": ["..."]
    },
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

1. replace the work-conserving busy-period bound with priority-aware or timed
   state-class response analysis and tighter blocking models;
2. derive fork/join links from concurrency annotations when per-activation
   execution bounds are proven, and add temporal ordering;
3. include fork/join links and resource budgets in the timed model;
4. add lock/bus hold semantics and arbitration-aware resource places;
5. add the system bounds to the safe gate only after the model and solver are
   validated.
