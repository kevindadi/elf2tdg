# Layered system model

The WCET results described elsewhere are **local** results: one execution root,
one function CFG and one configured core. The layered model is the first
composition step above that local layer. It is deliberately explicit and
conservative, and it is exported in CFG JSON as `system_model`.

```text
Layer 1  root/local WCET        cfg-longest-path or cfg-ipet per execution root
Layer 2  layered system model  tasks, places, transitions, dependencies
Layer 3  state-equation ILP    coarse reachability relaxation
Layer 4  response bounds       work-conserving or fixed-priority busy-window RTA
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

The system model derives a busy-window response upper bound for each task. Two
interference models are available:

- `work-conserving-busy-period` — used when priorities are not configured;
  every other task may delay the target under an arbitrary work-conserving
  scheduler;
- `fixed-priority-busy-period` — used when every contributing task has a
  priority; only tasks with a priority greater than or equal to the target's
  can interfere. Larger numeric priority values run first.

Configure priorities under `[system.tasks]`:

```toml
[[system.tasks]]
target = "sensor_task"
priority = 3
```

The selected model is reported as `system_model.response.model`. If only some
contributing tasks have priorities, the analysis falls back to the
work-conserving model and records a caveat; it never mixes the two models
silently. Equal-priority tasks are conservatively treated as interference
because the same-priority tie-break order is not modeled.

Both models evaluate:

```text
R_i = B_i + C_i + sum(j != i) N_j(R_i) * C_j + M_i(R_i) * C_i
```

`B_i` is the configured blocking bound and is zero without a blocking model.
The sum runs over the tasks selected by the interference model. For a periodic
task `k`, both terms count one carry-in activation plus every release that can
fall inside a window of length `R`:

```text
N_k(R) = floor((R + J_k) / T_k) + 1
M_i(R) = N_i(R) for a periodic target
```

`J_k` is the configured release jitter and `T_k` the period. The carry-in
accounts for work released just before the window; the `+1` is needed because
the scheduler may not have completed that activation. The target's own term
covers queued earlier activations and, conservatively, releases that occur
while the analyzed activation is still pending.

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
the finite bound exceeds it. A task's status reflects only the inputs that can
interfere with it under the selected model; a partial lower-priority task does
not make a fixed-priority result partial.

Assumptions:

- one analyzed core;
- work-conserving scheduling with arbitrary preemption order, or preemptive
  fixed-priority scheduling where larger priority values run first;
- fixed-priority results include equal-priority tasks as interference and
  exclude lower-priority tasks;
- periodic releases follow the configured period and jitter;
- non-periodic activation bounds are true total bounds;
- jobs may queue, so same-task self-interference is included;
- without a blocking model, no blocking, priority inversion or inheritance,
  fork/join ordering, locks, resources, interrupts, other cores, caches, CRPD
  or preemption overhead;
- partial local WCET inputs make the response result `partial`.

Both results are safe upper bounds only under their stated assumptions and are
deliberately conservative. A fixed-priority result is valid only when the
target scheduler is actually preemptive fixed-priority. A configured blocking
model adds the assumptions in the next section.

## Blocking and priority inversion

`blocking_model = "priority-ceiling"` enables a blocking layer for
fixed-priority systems. Locks and per-task hold times are explicit:

```toml
[system]
blocking_model = "priority-ceiling"

[[system.locks]]
name = "uart"

[[system.tasks]]
target = "sensor_task"
priority = 3
locks = { uart = 200 }

[[system.tasks]]
target = "monitor_task"
priority = 2
locks = { uart = 900 }
```

The ceiling of a lock is the maximum priority of the modeled tasks that use
it. Under the immediate priority ceiling protocol, a task activation can be
blocked by at most one lower-priority critical section whose lock ceiling is at
least the target's priority:

```text
B_i = max { hold(j, r) | priority(j) < priority(i),
                         ceiling(r) >= priority(i) }
```

`B_i` is added once to the response fixed point. It is conservative for a task
that does not itself lock a resource, because a ceiling-boosted lower-priority
holder can still delay it. The blocking report also lists every direct priority
inversion on a shared lock: higher-priority blocked task, lower-priority
blocking task, and the blocker's hold time.

Blocking analysis requires every contributing task to have a distinct priority
and every lock user to be in the modeled task set. Each `hold_ns` must
upper-bound one contiguous acquisition, including any nested critical sections.
Priority inheritance, chained/multiple blocking, spinlocks, non-preemptive
sections, interrupt masking and unmodeled lock users are not modeled. The
blocking bound is valid only if the target RTOS implements the immediate
priority ceiling protocol as configured; using it for a plain mutex or priority
inheritance system would be unsound.

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
  response time; use the separate response-bound section.
- Release instants, deadlines or ordering. Activation bounds are static
  per-window counts; release jitter only shifts the first-release count
  conservatively.
- Lock/semaphore hold semantics, waiting and priority inversion are not part
  of the state-equation bound. The separate response layer supports configured
  priority-ceiling blocking; `[system.resources]` here remain cumulative
  budgets only.
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
        "priority": 3,
        "locks": { "uart": 200 },
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
    "blocking": {
      "model": "priority-ceiling",
      "tasks": [
        {
          "task": "t1",
          "status": "bounded",
          "time_ns": 900.0,
          "blocker": "t2",
          "lock": "uart"
        }
      ],
      "inversions": [
        {
          "lock": "uart",
          "blocked": "t1",
          "blocker": "t2",
          "blocked_priority": 3,
          "blocker_priority": 2,
          "hold_ns": 900
        }
      ],
      "caveats": ["..."]
    },
    "response": {
      "model": "fixed-priority-busy-period",
      "tasks": [
        {
          "task": "t1",
          "function": "fn:0x800085c",
          "status": "bounded",
          "time_ns": 1507.2,
          "blocking_ns": 900.0,
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

1. add timed state-class response analysis and explicit deadline-overrun and
   same-task backlog terms;
2. derive fork/join links from concurrency annotations when per-activation
   execution bounds are proven, and add temporal ordering;
3. include fork/join links and resource budgets in the timed model;
4. add priority-inheritance, chained-blocking, spinlock and bus-hold semantics,
   plus arbitration-aware resource places;
5. add the system bounds to the safe gate only after the model and solver are
   validated.
