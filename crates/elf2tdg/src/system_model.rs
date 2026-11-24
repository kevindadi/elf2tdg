//! Layered system model for multicore composition.
//!
//! The local WCET layer is computed per execution root by the CFG/IPET
//! analyses. This module builds the next layer: a small Petri-net-shaped
//! workload model whose transitions carry the local root costs. It solves the
//! state-equation ILP relaxation of that net and records the full
//! task/place/transition/dependency structure for a later timed-Petri-net
//! solver.

use std::collections::BTreeMap;

use good_lp::{
    Expression, ProblemVariables, Solution, SolutionStatus, SolverModel, Variable, constraint,
};

use crate::board_profile::{BoardProfile, SystemBlockingModel, SystemLinkKind, SystemProfile};
use crate::cfg::{
    CfgConcurrencyKind, CfgSystemBlockingInfo, CfgSystemBlockingTask, CfgSystemBound,
    CfgSystemDependency, CfgSystemFiring, CfgSystemInversion, CfgSystemLink, CfgSystemModelInfo,
    CfgSystemPetriSolution, CfgSystemPlace, CfgSystemResponseInfo, CfgSystemResponseTask,
    CfgSystemTask, CfgSystemTimedInfo, CfgSystemTransition, CfgWcetRoot, CfgWcetStatus, ProgramCfg,
};
use crate::rules::normalize_crate_hashes;
use crate::wcet::frequency_hz;

const MAX_TIMED_ACTIVATIONS: u32 = 10_000;
const MAX_TIMED_VARIABLES: u64 = 200_000;

#[derive(Clone, Copy, Debug)]
struct LinkConstraint {
    from_index: usize,
    to_index: usize,
    kind: SystemLinkKind,
    count: u32,
}

#[derive(Clone, Debug)]
struct TaskConfig {
    priority: Option<u32>,
    activations: u32,
    period_ns: Option<u64>,
    release_offset_ns: Option<u64>,
    release_jitter_ns: Option<u64>,
    deadline_ns: Option<u64>,
    resources: BTreeMap<String, u32>,
    locks: BTreeMap<String, u64>,
}

/// Builds the layered system model from the completed per-root WCET layer.
///
/// Returns `Ok(None)` when no `[wcet]` analysis was configured. Profile task
/// selectors are resolved against the recovered execution roots; an unknown or
/// ambiguous selector is a configuration error.
///
/// # Errors
///
/// Returns an error when a `[system]` task target cannot be resolved to exactly
/// one execution root, or when a configured resource has no matching place.
#[allow(clippy::too_many_lines)]
pub(crate) fn analyze(
    program: &ProgramCfg,
    board: Option<&BoardProfile>,
) -> Result<Option<CfgSystemModelInfo>, String> {
    let Some(wcet) = program.wcet.as_ref() else {
        return Ok(None);
    };
    let system = board.and_then(BoardProfile::system);
    let cores = program
        .multicore
        .as_ref()
        .map_or(1, |info| info.cores.max(1));
    let core_id = program.multicore.as_ref().map_or(0, |info| info.core_id);
    let core_place = format!("core:{core_id}");

    let concurrent: Vec<&CfgWcetRoot> = wcet
        .roots
        .iter()
        .filter(|root| {
            !matches!(
                root.kind,
                crate::cfg::CfgRootKind::Startup | crate::cfg::CfgRootKind::Main
            )
        })
        .collect();
    let boot_roots = wcet
        .roots
        .iter()
        .filter(|root| {
            matches!(
                root.kind,
                crate::cfg::CfgRootKind::Startup | crate::cfg::CfgRootKind::Main
            )
        })
        .count();
    let fallback_to_boot_roots = concurrent.is_empty() && !wcet.roots.is_empty();
    let roots: Vec<&CfgWcetRoot> = if fallback_to_boot_roots {
        wcet.roots.iter().collect()
    } else {
        concurrent
    };
    let horizon_ns = system.and_then(crate::board_profile::SystemProfile::horizon_ns);
    let mut configs: Vec<TaskConfig> = roots
        .iter()
        .map(|_| TaskConfig {
            priority: None,
            activations: 1,
            period_ns: None,
            release_offset_ns: None,
            release_jitter_ns: None,
            deadline_ns: None,
            resources: BTreeMap::new(),
            locks: BTreeMap::new(),
        })
        .collect();
    let mut matched = vec![false; roots.len()];
    if let Some(system) = system {
        for entry in system.tasks() {
            let index = resolve_task(program, &roots, entry.target())?;
            if matched[index] {
                return Err(format!(
                    "board profile system target {:?} resolves to an execution root already configured",
                    entry.target()
                ));
            }
            matched[index] = true;
            configs[index].priority = entry.priority();
            let period = entry.period_ns();
            let derived = match period {
                Some(period) => {
                    let horizon = horizon_ns.ok_or_else(|| {
                        format!(
                            "board profile system task {:?} has period_ns but no horizon_ns",
                            entry.target()
                        )
                    })?;
                    Some(periodic_releases(
                        horizon,
                        entry.release_offset_ns().unwrap_or(0),
                        entry.release_jitter_ns().unwrap_or(0),
                        period,
                    ))
                }
                None => None,
            };
            configs[index].activations = match (entry.activations(), derived) {
                (Some(explicit), Some(derived)) => explicit.min(derived),
                (Some(explicit), None) => explicit,
                (None, Some(derived)) => derived,
                (None, None) => 1,
            };
            configs[index].period_ns = period;
            configs[index].release_offset_ns =
                period.map(|_| entry.release_offset_ns().unwrap_or(0));
            configs[index].release_jitter_ns =
                period.map(|_| entry.release_jitter_ns().unwrap_or(0));
            configs[index].deadline_ns = entry.deadline_ns();
            configs[index].resources.clone_from(entry.resources());
            configs[index].locks.clone_from(entry.locks());
        }
    }

    let mut links = Vec::new();
    let mut link_constraints = Vec::new();
    if let Some(system) = system {
        for link in system.links() {
            let from_index = resolve_task(program, &roots, link.from())?;
            let to_index = resolve_task(program, &roots, link.to())?;
            if from_index == to_index {
                return Err(format!(
                    "board profile system link {:?} -> {:?} refers to the same task",
                    link.from(),
                    link.to()
                ));
            }
            links.push(CfgSystemLink {
                kind: link.kind().name().to_owned(),
                from: format!("t{from_index}"),
                to: format!("t{to_index}"),
                from_function: roots[from_index].function.clone(),
                to_function: roots[to_index].function.clone(),
                count: link.count(),
            });
            link_constraints.push(LinkConstraint {
                from_index,
                to_index,
                kind: link.kind(),
                count: link.count(),
            });
        }
    }

    let mut places = vec![CfgSystemPlace {
        id: core_place.clone(),
        kind: "core".to_owned(),
        tokens: 1,
        capacity: 1,
    }];
    let mut resource_places: BTreeMap<String, String> = BTreeMap::new();
    if let Some(system) = system {
        for resource in system.resources() {
            let id = format!("budget:{}", resource.name());
            places.push(CfgSystemPlace {
                id: id.clone(),
                kind: "budget".to_owned(),
                tokens: resource.capacity(),
                capacity: resource.capacity(),
            });
            resource_places.insert(resource.name().to_owned(), id);
        }
    }
    let mut tasks = Vec::with_capacity(roots.len());
    let mut transitions = Vec::with_capacity(wcet.roots.len());
    let mut all_cycles = true;
    let mut all_time = true;
    let mut cycles = 0.0;
    let mut time_ns = 0.0;

    for (index, root) in roots.iter().enumerate() {
        let task_id = format!("t{index}");
        let ready_place = format!("ready:{task_id}");
        let done_place = format!("done:{task_id}");
        let config = &configs[index];
        let task = system_task(&task_id, root, config);
        if let Some(value) = task.cycles {
            cycles += value;
        } else {
            all_cycles = false;
        }
        if let Some(value) = task.time_ns {
            time_ns += value;
        } else {
            all_time = false;
        }

        let activation_bound = task.activation_bound;
        places.push(CfgSystemPlace {
            id: ready_place.clone(),
            kind: "ready".to_owned(),
            tokens: activation_bound,
            capacity: activation_bound,
        });
        places.push(CfgSystemPlace {
            id: done_place.clone(),
            kind: "done".to_owned(),
            tokens: 0,
            capacity: activation_bound,
        });
        let mut inputs = vec![ready_place, core_place.clone()];
        for (name, units) in &config.resources {
            let Some(resource) = resource_places.get(name) else {
                return Err(format!(
                    "board profile system task {:?} references resource {name:?} without a place",
                    root.name.as_deref().unwrap_or(root.function.as_str())
                ));
            };
            for _ in 0..*units {
                inputs.push(resource.clone());
            }
        }
        transitions.push(CfgSystemTransition {
            id: format!("execute:{task_id}"),
            kind: "execute".to_owned(),
            task: task_id.clone(),
            cost_cycles: task.cycles,
            activations: activation_bound,
            inputs,
            outputs: vec![done_place, core_place.clone()],
        });
        tasks.push(task);
    }

    let max_activations = configs
        .iter()
        .map(|config| config.activations)
        .max()
        .unwrap_or(1);
    let aggregate = aggregate_status(&tasks);
    let blocking = blocking_analysis(&tasks, system)?;
    let response = response_times(&tasks, blocking.as_ref());
    let timed = solve_timed_model(&tasks, system);
    let petri = solve_state_equation(&places, &transitions, &link_constraints);
    let (bound_status, bound_cycles, bound_time_ns) = bound_from_solution(
        aggregate,
        petri.as_ref(),
        all_cycles.then_some(cycles),
        all_time.then_some(time_ns),
        frequency_hz(program),
    );
    let mut caveats = vec![
        "The layered bound is a coarse total-work bound over the configured activation bounds, not a per-task response-time bound."
            .to_owned(),
        "The state equation M_final = M0 + C*x is a necessary-condition relaxation of Petri-net reachability; infeasible interleavings may remain, so the result is conservative."
            .to_owned(),
        "Spawn/join/await/callback annotations remain metadata; only explicit [system.links] fork/join count constraints are encoded, and temporal ordering is not modeled."
            .to_owned(),
        "Lock/semaphore waiting, release instants, deadlines, preemption and scheduling order are not modeled in the state-equation layer; the optional timed model uses slot-level release/deadline windows."
            .to_owned(),
        "Activation bounds are upper bounds; ready/done markings stay within [0, capacity], the core marking is exact, and firing counts are solved by the pure-Rust microlp backend."
            .to_owned(),
    ];
    if let Some(system) = system {
        caveats.push(format!(
            "Task activation bounds and cumulative resource budgets come from [system] ({} task(s), {} resource(s)).",
            system.tasks().len(),
            system.resources().len()
        ));
        caveats.push(
            "Resource places are cumulative per-window budgets; lock hold semantics are modeled separately only when blocking_model is configured, and arbitration and resource waiting time are not modeled."
                .to_owned(),
        );
        if !system.resources().is_empty() {
            caveats.push(
                "A cumulative budget may reduce modeled firing counts; a task with a positive activation bound can receive fewer (even zero) firings when another task consumes the budget."
                    .to_owned(),
            );
        }
        if system.tasks().iter().any(|task| task.period_ns().is_some()) {
            caveats.push(
                "Periodic releases are approximated by a release count over horizon_ns in the state-equation layer; the timed model uses release/deadline windows."
                    .to_owned(),
            );
        }
        if !system.links().is_empty() {
            caveats.push(
                "Fork/join links constrain firing counts only; temporal ordering and deadline semantics are not modeled."
                    .to_owned(),
            );
        }
    }
    if fallback_to_boot_roots {
        caveats.push(
            "No task/ISR/callback roots were available; startup/main roots are used as the fallback task set."
                .to_owned(),
        );
    } else if boot_roots > 0 {
        caveats.push(
            "Startup/main boot roots are excluded from the concurrent task bound; they remain available as local CFG/WCET analyses."
                .to_owned(),
        );
    }
    if cores > 1 {
        caveats.push(
            "Only the analyzed core is modeled; other cores contribute through the configured [multicore] access budget."
                .to_owned(),
        );
    }
    if matches!(
        aggregate,
        CfgWcetStatus::Partial | CfgWcetStatus::Unbounded | CfgWcetStatus::Unknown
    ) {
        caveats.push(
            "At least one execution root is not bounded; the aggregate number is not a safe upper bound."
                .to_owned(),
        );
    }
    if let Some(petri) = &petri
        && petri.status != "optimal"
    {
        caveats.push(format!(
            "The state-equation ILP did not produce an optimal solution ({}); no solver-backed bound is reported.",
            petri.status
        ));
    }

    Ok(Some(CfgSystemModelInfo {
        model: "layered-petri-state-equation".to_owned(),
        cores,
        core_id,
        horizon_ns,
        tasks,
        boot_roots: u32::try_from(if fallback_to_boot_roots { 0 } else { boot_roots })
            .unwrap_or(u32::MAX),
        places,
        transitions,
        dependencies: dependencies(program),
        links,
        petri,
        timed,
        blocking,
        response,
        bound: CfgSystemBound {
            scope: "analyzed-core-activation-bounds".to_owned(),
            status: bound_status,
            cycles: bound_cycles,
            time_ns: bound_time_ns,
            tasks: u32::try_from(roots.len()).unwrap_or(u32::MAX),
            max_activations,
            assumptions: vec![
                "Each modeled execution root runs at most its activation bound in the bound window."
                    .to_owned(),
                "All modeled roots execute on the analyzed core; other cores are represented only by the configured [multicore] budget."
                    .to_owned(),
                "Local root costs already include configured cache, pipeline, data-memory and multicore block costs; this layer does not add them again."
                    .to_owned(),
                "The state equation is a reachability relaxation; the solver may accept firing-count combinations that no concrete schedule can realize."
                    .to_owned(),
                "Fork/join link counts are maximum relation counts per source activation, not temporal ordering constraints."
                    .to_owned(),
                "The state-equation bound does not model release instants, deadlines, preemption, scheduling order or lock waits; see the timed feasibility model when enabled."
                    .to_owned(),
            ],
        },
        caveats,
    }))
}

#[allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn solve_state_equation(
    places: &[CfgSystemPlace],
    transitions: &[CfgSystemTransition],
    links: &[LinkConstraint],
) -> Option<CfgSystemPetriSolution> {
    if transitions.is_empty()
        || transitions
            .iter()
            .any(|transition| transition.cost_cycles.is_none())
    {
        return None;
    }
    let mut vars = ProblemVariables::new();
    let firing: Vec<Variable> = transitions
        .iter()
        .map(|transition| {
            vars.add(
                good_lp::variable()
                    .integer()
                    .min(0.0)
                    .max(f64::from(transition.activations)),
            )
        })
        .collect();
    let mut objective = Expression::from(0.0);
    for (transition, variable) in transitions.iter().zip(&firing) {
        objective += Expression::from(*variable) * transition.cost_cycles.unwrap_or(0.0);
    }

    let mut constraints = Vec::new();
    for link in links {
        let (Some(&from), Some(&to)) = (firing.get(link.from_index), firing.get(link.to_index))
        else {
            return None;
        };
        let from = Expression::from(from);
        let to = Expression::from(to);
        let count = f64::from(link.count);
        match link.kind {
            SystemLinkKind::Fork => {
                constraints.push(constraint::leq(to, from * count));
            }
            SystemLinkKind::Join => {
                constraints.push(constraint::leq(from, to * count));
            }
        }
    }
    for place in places {
        let initial = f64::from(place.tokens);
        let mut delta = Expression::from(0.0);
        for (transition, variable) in transitions.iter().zip(&firing) {
            let inputs = transition
                .inputs
                .iter()
                .filter(|id| *id == &place.id)
                .count();
            let outputs = transition
                .outputs
                .iter()
                .filter(|id| *id == &place.id)
                .count();
            let coefficient = i32::try_from(outputs).unwrap_or(i32::MAX)
                - i32::try_from(inputs).unwrap_or(i32::MAX);
            if coefficient != 0 {
                delta += Expression::from(*variable) * f64::from(coefficient);
            }
        }
        match place.kind.as_str() {
            // Activation bounds are upper bounds: a task may fire fewer times
            // when a shared budget or another constraint prevents the maximum.
            "ready" | "done" | "budget" => {
                constraints.push(constraint::geq(delta.clone(), -initial));
                constraints.push(constraint::leq(delta, f64::from(place.capacity) - initial));
            }
            _ => constraints.push(constraint::eq(delta, 0.0)),
        }
    }

    let mut model = vars.maximise(objective.clone()).using(good_lp::microlp);
    for item in constraints {
        model = model.with(item);
    }
    let solution = match model.solve() {
        Ok(solution) => solution,
        Err(good_lp::ResolutionError::Unbounded) => {
            return Some(CfgSystemPetriSolution {
                solver: "microlp".to_owned(),
                relaxation: "state-equation".to_owned(),
                status: "unbounded".to_owned(),
                objective: None,
                firing: Vec::new(),
            });
        }
        Err(good_lp::ResolutionError::Infeasible) => {
            return Some(CfgSystemPetriSolution {
                solver: "microlp".to_owned(),
                relaxation: "state-equation".to_owned(),
                status: "infeasible".to_owned(),
                objective: None,
                firing: Vec::new(),
            });
        }
        Err(error) => {
            return Some(CfgSystemPetriSolution {
                solver: "microlp".to_owned(),
                relaxation: "state-equation".to_owned(),
                status: format!("solver-error: {error}"),
                objective: None,
                firing: Vec::new(),
            });
        }
    };

    let status = match solution.status() {
        SolutionStatus::Optimal => "optimal",
        SolutionStatus::TimeLimit => "time-limit",
        SolutionStatus::GapLimit => "gap-limit",
    };
    let mut counted = Vec::new();
    let mut integral = true;
    for (transition, variable) in transitions.iter().zip(&firing) {
        let value = solution.value(*variable);
        let rounded = value.round();
        if (value - rounded).abs() > 1e-4 {
            integral = false;
        }
        if rounded > 0.0 {
            counted.push(CfgSystemFiring {
                transition: transition.id.clone(),
                fires: u32::try_from(rounded.max(0.0) as u64).unwrap_or(u32::MAX),
            });
        }
    }
    let objective = solution.eval(&objective);
    Some(CfgSystemPetriSolution {
        solver: "microlp".to_owned(),
        relaxation: "state-equation".to_owned(),
        status: if integral {
            status.to_owned()
        } else {
            "fractional".to_owned()
        },
        objective: (objective.is_finite() && objective >= 0.0).then_some(objective),
        firing: counted,
    })
}

#[allow(clippy::cast_precision_loss)]
fn bound_from_solution(
    aggregate: CfgWcetStatus,
    petri: Option<&CfgSystemPetriSolution>,
    fallback_cycles: Option<f64>,
    fallback_time: Option<f64>,
    frequency_hz: Option<u64>,
) -> (CfgWcetStatus, Option<f64>, Option<f64>) {
    let Some(petri) = petri else {
        return (aggregate, fallback_cycles, fallback_time);
    };
    if petri.status != "optimal" {
        let status = match petri.status.as_str() {
            "unbounded" => CfgWcetStatus::Unbounded,
            "infeasible" => CfgWcetStatus::Unknown,
            _ => CfgWcetStatus::Partial,
        };
        return (status, None, None);
    }
    let Some(objective) = petri.objective else {
        return (CfgWcetStatus::Unknown, None, None);
    };
    let time = frequency_hz.map(|hz| objective * 1_000_000_000.0 / hz as f64);
    (aggregate, Some(objective), time)
}

#[allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn solve_timed_model(
    tasks: &[CfgSystemTask],
    system: Option<&SystemProfile>,
) -> Option<CfgSystemTimedInfo> {
    let system = system?;
    let slot_ns = system.slot_ns()?;
    let horizon_ns = system.horizon_ns()?;
    let mut caveats = vec![
        "Discrete-time-expanded model: execution is preemptible only at slot boundaries and local WCET is rounded up to whole slots."
            .to_owned(),
        "The timed model reports release/deadline feasibility only; it does not produce a per-task response-time upper bound."
            .to_owned(),
        "Fork/join links, cumulative resource budgets and other cores' workloads are not included in the timed feasibility model."
            .to_owned(),
        "Releases at or beyond horizon_ns have no execution window and are excluded from timed feasibility."
            .to_owned(),
    ];
    if slot_ns == 0 || horizon_ns == 0 {
        return Some(CfgSystemTimedInfo {
            model: "discrete-time-expanded-petri".to_owned(),
            slot_ns,
            horizon_slots: 0,
            status: "unsupported".to_owned(),
            activations: 0,
            execution_slots: 0,
            variables: 0,
            caveats,
        });
    }
    let horizon_slots = u32::try_from(horizon_ns / slot_ns).unwrap_or(u32::MAX);
    if tasks.iter().any(|task| task.time_ns.is_none()) {
        caveats.push(
            "At least one task has no local time estimate; timed feasibility was skipped."
                .to_owned(),
        );
        return Some(CfgSystemTimedInfo {
            model: "discrete-time-expanded-petri".to_owned(),
            slot_ns,
            horizon_slots,
            status: "no-local-time".to_owned(),
            activations: 0,
            execution_slots: 0,
            variables: 0,
            caveats,
        });
    }

    let mut instances = Vec::new();
    let mut total_variables = 0_u64;
    let mut execution_slots = 0_u64;

    for task in tasks {
        let time_ns = task.time_ns?;
        let execution_ns = time_ns.ceil().max(0.0) as u64;
        let slots_per_activation = execution_ns.div_ceil(slot_ns).max(1);
        let earliest = task
            .release_offset_ns
            .unwrap_or(0)
            .saturating_sub(task.release_jitter_ns.unwrap_or(0));
        for activation in 0..task.activation_bound {
            let release_ns = match task.period_ns {
                Some(period) => {
                    earliest.saturating_add(u64::from(activation).saturating_mul(period))
                }
                None => 0,
            };
            if release_ns >= horizon_ns {
                break;
            }
            let relative_deadline = task.deadline_ns.unwrap_or(horizon_ns);
            let deadline_ns = release_ns.saturating_add(relative_deadline).min(horizon_ns);
            let first_slot = release_ns.div_ceil(slot_ns);
            let last_slot = deadline_ns / slot_ns;
            if first_slot >= last_slot
                || last_slot.saturating_sub(first_slot) < slots_per_activation
            {
                execution_slots = execution_slots.saturating_add(slots_per_activation);
                return Some(CfgSystemTimedInfo {
                    model: "discrete-time-expanded-petri".to_owned(),
                    slot_ns,
                    horizon_slots,
                    status: "infeasible".to_owned(),
                    activations: u32::try_from(instances.len()).unwrap_or(u32::MAX),
                    execution_slots: u32::try_from(execution_slots).unwrap_or(u32::MAX),
                    variables: u32::try_from(total_variables).unwrap_or(u32::MAX),
                    caveats,
                });
            }
            total_variables = total_variables.saturating_add(last_slot.saturating_sub(first_slot));
            execution_slots = execution_slots.saturating_add(slots_per_activation);
            instances.push((first_slot, last_slot, slots_per_activation));
            if u32::try_from(instances.len()).unwrap_or(u32::MAX) > MAX_TIMED_ACTIVATIONS
                || total_variables > MAX_TIMED_VARIABLES
            {
                caveats.push(
                    "Timed model exceeds the activation or variable limit; increase slot_ns or shorten the horizon."
                        .to_owned(),
                );
                return Some(CfgSystemTimedInfo {
                    model: "discrete-time-expanded-petri".to_owned(),
                    slot_ns,
                    horizon_slots,
                    status: "unsupported".to_owned(),
                    activations: u32::try_from(instances.len()).unwrap_or(u32::MAX),
                    execution_slots: u32::try_from(execution_slots).unwrap_or(u32::MAX),
                    variables: u32::try_from(total_variables).unwrap_or(u32::MAX),
                    caveats,
                });
            }
        }
    }

    if instances.is_empty() {
        return Some(CfgSystemTimedInfo {
            model: "discrete-time-expanded-petri".to_owned(),
            slot_ns,
            horizon_slots,
            status: "feasible".to_owned(),
            activations: 0,
            execution_slots: 0,
            variables: 0,
            caveats,
        });
    }

    let mut variables = ProblemVariables::new();
    let mut objective = Expression::from(0.0);
    let mut slot_load: BTreeMap<u64, Expression> = BTreeMap::new();
    let mut activation_vars = Vec::with_capacity(instances.len());
    for &(first_slot, last_slot, slots_per_activation) in &instances {
        let mut vars = Vec::new();
        for slot in first_slot..last_slot {
            let variable = variables.add(good_lp::variable().binary());
            objective += variable;
            *slot_load
                .entry(slot)
                .or_insert_with(|| Expression::from(0.0)) += variable;
            vars.push(variable);
        }
        activation_vars.push((vars, slots_per_activation));
    }

    let mut constraints = Vec::new();
    for (vars, slots_per_activation) in activation_vars {
        let mut sum = Expression::from(0.0);
        for variable in vars {
            sum += variable;
        }
        constraints.push(constraint::eq(sum, slots_per_activation as f64));
    }
    for load in slot_load.into_values() {
        constraints.push(constraint::leq(load, 1.0));
    }

    let mut model = variables.maximise(objective).using(good_lp::microlp);
    for item in constraints {
        model = model.with(item);
    }
    let status = match model.solve() {
        Ok(_) => "feasible",
        Err(good_lp::ResolutionError::Infeasible) => "infeasible",
        Err(good_lp::ResolutionError::Unbounded) => "unbounded",
        Err(_) => "solver-error",
    };
    Some(CfgSystemTimedInfo {
        model: "discrete-time-expanded-petri".to_owned(),
        slot_ns,
        horizon_slots,
        status: status.to_owned(),
        activations: u32::try_from(instances.len()).unwrap_or(u32::MAX),
        execution_slots: u32::try_from(execution_slots).unwrap_or(u32::MAX),
        variables: u32::try_from(total_variables).unwrap_or(u32::MAX),
        caveats,
    })
}

const MAX_RESPONSE_ITERATIONS: usize = 4_096;
const MAX_RESPONSE_NS: f64 = 1.0e15;

/// Convert a nanosecond quantity to `f64` for the response-time arithmetic.
///
/// The response layer already caps windows at `MAX_RESPONSE_NS`, far below
/// the 2^53 integer range where `f64` is exact.
#[allow(clippy::cast_precision_loss)]
fn nanos(value: u64) -> f64 {
    value as f64
}

fn response_entry(
    target: &CfgSystemTask,
    status: &str,
    time_ns: Option<f64>,
    blocking_ns: Option<f64>,
    deadline_missed: bool,
    reason: Option<&str>,
) -> CfgSystemResponseTask {
    CfgSystemResponseTask {
        task: target.id.clone(),
        function: target.function.clone(),
        status: status.to_owned(),
        time_ns,
        blocking_ns,
        deadline_ns: target.deadline_ns,
        deadline_missed,
        reason: reason.map(str::to_owned),
    }
}

fn contributes(task: &CfgSystemTask) -> bool {
    task.activation_bound > 0 || task.period_ns.is_some()
}

fn blocking_analysis(
    tasks: &[CfgSystemTask],
    system: Option<&SystemProfile>,
) -> Result<Option<CfgSystemBlockingInfo>, String> {
    let Some(system) = system else {
        return Ok(None);
    };
    let Some(model) = system.blocking_model() else {
        return Ok(None);
    };
    for task in tasks {
        for lock in task.locks.keys() {
            if !system
                .locks()
                .iter()
                .any(|declared| declared.name() == lock)
            {
                return Err(format!(
                    "task {:?} uses lock {lock:?} that is not declared in [system.locks]",
                    task.id
                ));
            }
        }
    }
    blocking_for_model(tasks, model).map(Some)
}

fn blocking_for_model(
    tasks: &[CfgSystemTask],
    model: SystemBlockingModel,
) -> Result<CfgSystemBlockingInfo, String> {
    match model {
        SystemBlockingModel::PriorityCeiling => {
            if tasks.iter().any(|task| !task.locks.is_empty()) {
                let mut priorities: BTreeMap<u32, &str> = BTreeMap::new();
                for task in tasks.iter().filter(|task| contributes(task)) {
                    let Some(priority) = task.priority else {
                        return Err(format!(
                            "board profile blocking analysis requires a priority for every contributing task; task {:?} has none",
                            task.id
                        ));
                    };
                    if let Some(previous) = priorities.insert(priority, task.id.as_str()) {
                        return Err(format!(
                            "board profile priority-ceiling blocking requires distinct priorities; tasks {previous:?} and {:?} share priority {priority}",
                            task.id
                        ));
                    }
                }
            }
            Ok(priority_ceiling_blocking(tasks, model))
        }
    }
}

fn priority_inversions(users: &BTreeMap<String, Vec<&CfgSystemTask>>) -> Vec<CfgSystemInversion> {
    let mut inversions = Vec::new();
    for (lock, lock_users) in users {
        for blocked in lock_users {
            for blocker in lock_users {
                let (Some(high_priority), Some(low_priority)) =
                    (blocked.priority, blocker.priority)
                else {
                    continue;
                };
                if high_priority <= low_priority {
                    continue;
                }
                let Some(hold_ns) = blocker.locks.get(lock) else {
                    continue;
                };
                inversions.push(CfgSystemInversion {
                    lock: lock.clone(),
                    blocked: blocked.id.clone(),
                    blocker: blocker.id.clone(),
                    blocked_priority: high_priority,
                    blocker_priority: low_priority,
                    hold_ns: *hold_ns,
                });
            }
        }
    }
    inversions.sort_by(|left, right| {
        left.lock
            .cmp(&right.lock)
            .then_with(|| left.blocked.cmp(&right.blocked))
            .then_with(|| left.blocker.cmp(&right.blocker))
    });
    inversions
}

fn priority_ceiling_tasks(
    tasks: &[CfgSystemTask],
    ceilings: &BTreeMap<String, u32>,
) -> Vec<CfgSystemBlockingTask> {
    let mut blocking_tasks = Vec::with_capacity(tasks.len());
    for target in tasks {
        if !contributes(target) {
            blocking_tasks.push(CfgSystemBlockingTask {
                task: target.id.clone(),
                status: "bounded".to_owned(),
                time_ns: Some(0.0),
                blocker: None,
                lock: None,
                reason: Some("task has zero activation bound".to_owned()),
            });
            continue;
        }
        let Some(target_priority) = target.priority else {
            blocking_tasks.push(CfgSystemBlockingTask {
                task: target.id.clone(),
                status: "bounded".to_owned(),
                time_ns: Some(0.0),
                blocker: None,
                lock: None,
                reason: None,
            });
            continue;
        };
        let mut best: Option<(u64, &CfgSystemTask, &str)> = None;
        for blocker in tasks.iter().filter(|blocker| contributes(blocker)) {
            if blocker.id == target.id {
                continue;
            }
            let Some(blocker_priority) = blocker.priority else {
                continue;
            };
            if blocker_priority >= target_priority {
                continue;
            }
            for (lock, hold_ns) in &blocker.locks {
                let Some(ceiling) = ceilings.get(lock) else {
                    continue;
                };
                if *ceiling < target_priority {
                    continue;
                }
                if best.is_none_or(|(best_hold, _, _)| *hold_ns > best_hold) {
                    best = Some((*hold_ns, blocker, lock.as_str()));
                }
            }
        }
        let (time_ns, blocker, lock, reason) =
            best.map_or((0.0, None, None, None), |(hold_ns, blocker, lock)| {
                (
                    nanos(hold_ns),
                    Some(blocker.id.clone()),
                    Some(lock.to_owned()),
                    None,
                )
            });
        blocking_tasks.push(CfgSystemBlockingTask {
            task: target.id.clone(),
            status: "bounded".to_owned(),
            time_ns: Some(time_ns),
            blocker,
            lock,
            reason,
        });
    }
    blocking_tasks
}

fn priority_ceiling_blocking(
    tasks: &[CfgSystemTask],
    model: SystemBlockingModel,
) -> CfgSystemBlockingInfo {
    let mut ceilings: BTreeMap<String, u32> = BTreeMap::new();
    let mut users: BTreeMap<String, Vec<&CfgSystemTask>> = BTreeMap::new();
    for task in tasks.iter().filter(|task| contributes(task)) {
        let Some(priority) = task.priority else {
            continue;
        };
        for lock in task.locks.keys() {
            ceilings
                .entry(lock.clone())
                .and_modify(|ceiling| *ceiling = (*ceiling).max(priority))
                .or_insert(priority);
            users.entry(lock.clone()).or_default().push(task);
        }
    }

    let mut caveats = vec![
        "Blocking bounds assume the immediate priority ceiling protocol: at most one lower-priority critical section can block a task activation."
            .to_owned(),
        "Lock ceilings are derived as the maximum priority of modeled tasks that use the lock; every lock user must be in the modeled task set."
            .to_owned(),
        "Each hold_ns value must upper-bound one contiguous lock acquisition, including nested critical sections, on the analyzed core."
            .to_owned(),
        "Only lower-priority tasks contribute blocking; higher- and equal-priority execution is covered by response interference."
            .to_owned(),
        "Non-preemptive sections, interrupt masking, spinlocks, chained blocking and unmodeled lock users are not modeled."
            .to_owned(),
    ];
    if ceilings.is_empty() {
        caveats.push("No modeled locks are configured; all blocking times are zero.".to_owned());
    }

    CfgSystemBlockingInfo {
        model: model.name().to_owned(),
        tasks: priority_ceiling_tasks(tasks, &ceilings),
        inversions: priority_inversions(&users),
        caveats,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseModel {
    WorkConserving,
    FixedPriority,
}

impl ResponseModel {
    const fn name(self) -> &'static str {
        match self {
            Self::WorkConserving => "work-conserving-busy-period",
            Self::FixedPriority => "fixed-priority-busy-period",
        }
    }

    /// Whether `other` can delay `target` under this scheduling model.
    ///
    /// Equal-priority tasks are included because the tie-break order is not
    /// modeled. If a priority is unexpectedly missing, include the task rather
    /// than risk an unsound exclusion.
    fn interferes(self, other: &CfgSystemTask, target: &CfgSystemTask) -> bool {
        match self {
            Self::WorkConserving => true,
            Self::FixedPriority => match (other.priority, target.priority) {
                (Some(other), Some(target)) => other >= target,
                _ => true,
            },
        }
    }
}

/// Select the response model and count tasks that prevent priority-aware
/// analysis while some other task does configure a priority.
fn response_model(tasks: &[CfgSystemTask]) -> (ResponseModel, Option<usize>) {
    let contributing = tasks.iter().filter(|task| contributes(task)).count();
    let missing = tasks
        .iter()
        .filter(|task| contributes(task) && task.priority.is_none())
        .count();
    if contributing == 0 || missing == contributing {
        // No priorities configured, or no task contributes at all.
        (ResponseModel::WorkConserving, None)
    } else if missing == 0 {
        (ResponseModel::FixedPriority, None)
    } else {
        // A partial priority assignment cannot define a fixed-priority bound.
        (ResponseModel::WorkConserving, Some(missing))
    }
}

fn response_input_status(
    tasks: &[CfgSystemTask],
    target: &CfgSystemTask,
    model: ResponseModel,
) -> &'static str {
    let relevant = |task: &CfgSystemTask| {
        contributes(task) && (task.id == target.id || model.interferes(task, target))
    };
    if tasks
        .iter()
        .any(|task| relevant(task) && task.status == CfgWcetStatus::Unbounded)
    {
        "unbounded"
    } else if tasks
        .iter()
        .any(|task| relevant(task) && task.status == CfgWcetStatus::Unknown)
    {
        "unknown"
    } else if tasks
        .iter()
        .any(|task| relevant(task) && task.status == CfgWcetStatus::Partial)
    {
        "partial"
    } else {
        "bounded"
    }
}

enum ResponseInput {
    Time(f64),
    Unavailable(CfgSystemResponseTask),
}

fn response_input(
    tasks: &[CfgSystemTask],
    target: &CfgSystemTask,
    model: ResponseModel,
    blocking_ns: Option<f64>,
) -> ResponseInput {
    if target.activation_bound == 0 && target.period_ns.is_none() {
        return ResponseInput::Unavailable(response_entry(
            target,
            "bounded",
            Some(0.0),
            blocking_ns,
            false,
            Some("task has zero activation bound"),
        ));
    }
    let Some(time_ns) = target.time_ns else {
        return ResponseInput::Unavailable(response_entry(
            target,
            "no-local-time",
            None,
            blocking_ns,
            false,
            Some("local time estimate is unavailable"),
        ));
    };
    let interfering_without_time = tasks.iter().any(|task| {
        task.id != target.id
            && contributes(task)
            && model.interferes(task, target)
            && task.time_ns.is_none()
    });
    if interfering_without_time {
        return ResponseInput::Unavailable(response_entry(
            target,
            "no-local-time",
            None,
            blocking_ns,
            false,
            Some("an interfering task has no local time estimate"),
        ));
    }
    ResponseInput::Time(time_ns)
}

fn response_caveats(
    model: ResponseModel,
    priority_fallback: Option<usize>,
    blocking_active: bool,
) -> Vec<String> {
    let mut caveats = Vec::with_capacity(9);
    match model {
        ResponseModel::WorkConserving => {
            caveats.push(
                "Response bounds assume a single analyzed core and a work-conserving scheduler with arbitrary preemption order."
                    .to_owned(),
            );
            if let Some(missing) = priority_fallback {
                caveats.push(format!(
                    "Priority-aware analysis was not selected because {missing} modeled task(s) lack a priority; configure a priority for every modeled task. The work-conserving bound remains conservative."
                ));
            }
        }
        ResponseModel::FixedPriority => {
            caveats.push(
                "Response bounds assume a single analyzed core and a preemptive fixed-priority scheduler; larger priority values run first."
                    .to_owned(),
            );
            caveats.push(
                "A task interferes when its priority is greater than or equal to the target's priority; lower-priority tasks are excluded."
                    .to_owned(),
            );
            caveats.push(
                "Equal-priority tasks are conservatively treated as interference because the same-priority tie-break order is not modeled."
                    .to_owned(),
            );
            if blocking_active {
                caveats.push(
                    "Priority inversion is handled only by the configured priority-ceiling blocking model; priority inheritance and other blocking protocols are not modeled."
                        .to_owned(),
                );
            } else {
                caveats.push(
                    "Blocking, priority inversion, priority inheritance and priority-ceiling protocols are not modeled."
                        .to_owned(),
                );
            }
        }
    }
    caveats.push(
        "Each periodic task contributes one carry-in activation plus releases inside the busy window; non-periodic tasks contribute their full activation bound."
            .to_owned(),
    );
    caveats.push(
        "Periodic activation bounds derived from horizon_ns are horizon counts and do not truncate a busy window that extends past the horizon; the response layer counts releases for the full window."
            .to_owned(),
    );
    caveats.push(
        "The target task's own earlier activations are included as self-interference, so the result bounds any activation, including one with queued prior work."
            .to_owned(),
    );
    if blocking_active {
        caveats.push(
            "Response times include the configured blocking bound from system_model.blocking, added once per activation."
                .to_owned(),
        );
    }
    caveats.push(
        "Preemption cost, fork/join blocking, unmodeled locks, resources, interrupts, other cores, caches and CRPD are not modeled."
            .to_owned(),
    );
    caveats.push(
        "Partial or unbounded local WCET inputs make the response bound partial or unbounded."
            .to_owned(),
    );
    caveats
}

fn response_times(
    tasks: &[CfgSystemTask],
    blocking: Option<&CfgSystemBlockingInfo>,
) -> CfgSystemResponseInfo {
    let (model, priority_fallback) = response_model(tasks);
    let mut responses = Vec::with_capacity(tasks.len());
    for target in tasks {
        let blocking_ns = blocking
            .and_then(|info| info.tasks.iter().find(|entry| entry.task == target.id))
            .and_then(|entry| entry.time_ns);
        let blocking_time = blocking_ns.unwrap_or(0.0);
        let target_time = match response_input(tasks, target, model, blocking_ns) {
            ResponseInput::Time(time_ns) => time_ns,
            ResponseInput::Unavailable(response) => {
                responses.push(response);
                continue;
            }
        };

        let mut response = target_time + blocking_time;
        let mut diverged = false;
        let mut converged = false;
        for _ in 0..MAX_RESPONSE_ITERATIONS {
            let mut next = target_time + blocking_time;
            for other in tasks {
                if other.id == target.id {
                    next += self_extra_activations(other, response) * target_time;
                } else if model.interferes(other, target)
                    && let Some(other_time) = other.time_ns
                {
                    next += other_activations(other, response) * other_time;
                }
            }
            if !next.is_finite() || next > MAX_RESPONSE_NS {
                diverged = true;
                break;
            }
            // A post-fixed point f(R) <= R is already a safe upper bound and
            // avoids a tolerance that could understate the bound.
            if next <= response {
                converged = true;
                break;
            }
            response = next;
        }
        if diverged {
            responses.push(response_entry(
                target,
                "unbounded",
                None,
                blocking_ns,
                false,
                Some("busy-period iteration exceeded the response cap"),
            ));
        } else if !converged {
            responses.push(response_entry(
                target,
                "unknown",
                None,
                blocking_ns,
                false,
                Some("busy-period iteration limit reached without a post-fixed point"),
            ));
        } else {
            let deadline_missed = target
                .deadline_ns
                .is_some_and(|deadline| response > nanos(deadline));
            responses.push(response_entry(
                target,
                response_input_status(tasks, target, model),
                Some(response),
                blocking_ns,
                deadline_missed,
                None,
            ));
        }
    }
    CfgSystemResponseInfo {
        model: model.name().to_owned(),
        tasks: responses,
        caveats: response_caveats(model, priority_fallback, blocking.is_some()),
    }
}

/// Activations of another task that can contribute to a window of `window_ns`.
///
/// A periodic task gets one carry-in activation plus every release inside the
/// window. The configured activation bound is a per-horizon count for periodic
/// tasks, so it must not cap a window that extends past the horizon. A
/// non-periodic task contributes at most its total activation bound.
fn other_activations(task: &CfgSystemTask, window_ns: f64) -> f64 {
    match task.period_ns {
        Some(period) => {
            let jitter = task.release_jitter_ns.map_or(0.0, nanos);
            ((window_ns + jitter) / nanos(period)).floor() + 1.0
        }
        None => f64::from(task.activation_bound),
    }
}

/// Earlier activations of the target that can still be queued for the analyzed
/// activation. Periodic tasks include one carry-in plus releases in the window;
/// non-periodic tasks include every other activation in their total bound.
fn self_extra_activations(task: &CfgSystemTask, window_ns: f64) -> f64 {
    match task.period_ns {
        Some(period) => {
            let jitter = task.release_jitter_ns.map_or(0.0, nanos);
            ((window_ns + jitter) / nanos(period)).floor() + 1.0
        }
        None => f64::from(task.activation_bound.saturating_sub(1)),
    }
}

fn system_task(id: &str, root: &CfgWcetRoot, config: &TaskConfig) -> CfgSystemTask {
    CfgSystemTask {
        id: id.to_owned(),
        function: root.function.clone(),
        kind: root.kind,
        name: root.name.clone(),
        status: root.status,
        cycles: root.cycles,
        time_ns: root.time_ns,
        priority: config.priority,
        locks: config.locks.clone(),
        activation_bound: config.activations,
        period_ns: config.period_ns,
        release_offset_ns: config.release_offset_ns,
        release_jitter_ns: config.release_jitter_ns,
        deadline_ns: config.deadline_ns,
    }
}

fn periodic_releases(horizon_ns: u64, offset_ns: u64, jitter_ns: u64, period_ns: u64) -> u32 {
    if period_ns == 0 || horizon_ns == 0 {
        return 0;
    }
    let earliest = offset_ns.saturating_sub(jitter_ns);
    if earliest > horizon_ns {
        return 0;
    }
    let releases = (horizon_ns - earliest) / period_ns + 1;
    u32::try_from(releases).unwrap_or(u32::MAX)
}

fn resolve_task(
    program: &ProgramCfg,
    roots: &[&CfgWcetRoot],
    target: &str,
) -> Result<usize, String> {
    let target = target.trim();
    let address = parse_address(target);
    let matches: Vec<usize> = roots
        .iter()
        .enumerate()
        .filter(|(_, root)| {
            root.function.as_str() == target
                || root
                    .name
                    .as_deref()
                    .is_some_and(|name| name_matches(name, target))
                || program.function(&root.function).is_some_and(|function| {
                    name_matches(&function.primary_name, target)
                        || function
                            .demangled_name
                            .as_deref()
                            .is_some_and(|name| name_matches(name, target))
                        || function.symbols.iter().any(|name| name == target)
                        || address == Some(function.address)
                })
        })
        .map(|(index, _)| index)
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => Err(format!(
            "board profile system target {target:?} does not match an execution root"
        )),
        _ => Err(format!(
            "board profile system target {target:?} matches {} execution roots",
            matches.len()
        )),
    }
}

fn name_matches(candidate: &str, target: &str) -> bool {
    let candidate = normalize_crate_hashes(candidate);
    candidate == target
        || candidate
            .rsplit("::")
            .next()
            .is_some_and(|last| last == target)
}

fn parse_address(target: &str) -> Option<u64> {
    let hex = target
        .strip_prefix("0x")
        .or_else(|| target.strip_prefix("0X"))?;
    u64::from_str_radix(hex, 16).ok()
}

fn aggregate_status(tasks: &[CfgSystemTask]) -> CfgWcetStatus {
    if tasks.is_empty() {
        return CfgWcetStatus::Unknown;
    }
    if tasks
        .iter()
        .any(|task| task.status == CfgWcetStatus::Unbounded)
    {
        CfgWcetStatus::Unbounded
    } else if tasks
        .iter()
        .any(|task| task.status == CfgWcetStatus::Unknown)
    {
        CfgWcetStatus::Unknown
    } else if tasks
        .iter()
        .any(|task| task.status == CfgWcetStatus::Partial)
    {
        CfgWcetStatus::Partial
    } else {
        CfgWcetStatus::Bounded
    }
}

fn dependencies(program: &ProgramCfg) -> Vec<CfgSystemDependency> {
    program
        .concurrency
        .iter()
        .map(|site| {
            let (kind, to, candidates, runtime, api) = match &site.operation {
                CfgConcurrencyKind::Spawn {
                    runtime,
                    api,
                    entry,
                    candidates,
                    ..
                } => (
                    "spawn",
                    entry.clone(),
                    candidates.clone(),
                    Some(runtime.as_str().to_owned()),
                    Some(api.clone()),
                ),
                CfgConcurrencyKind::Join {
                    entry, candidates, ..
                } => ("join", entry.clone(), candidates.clone(), None, None),
                CfgConcurrencyKind::Await {
                    target, candidates, ..
                } => ("await", target.clone(), candidates.clone(), None, None),
                CfgConcurrencyKind::CallbackBind {
                    callback,
                    runtime,
                    api,
                } => (
                    "callback",
                    Some(callback.clone()),
                    Vec::new(),
                    Some(runtime.as_str().to_owned()),
                    Some(api.clone()),
                ),
                CfgConcurrencyKind::ScopeEnter { .. } => {
                    ("scope-enter", None, Vec::new(), None, None)
                }
                CfgConcurrencyKind::ScopeExit { .. } => {
                    ("scope-exit", None, Vec::new(), None, None)
                }
            };
            CfgSystemDependency {
                kind: kind.to_owned(),
                from: site.function.clone(),
                to,
                candidates,
                site: site.site,
                runtime,
                api,
                confidence: site.confidence,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{blocking_for_model, periodic_releases, response_times, solve_state_equation};
    use crate::board_profile::SystemBlockingModel;
    use crate::cfg::{
        CfgRootKind, CfgSystemPlace, CfgSystemTask, CfgSystemTransition, CfgWcetStatus,
    };
    use elf2tdg_schema::FunctionId;

    fn task(
        id: &str,
        time_ns: Option<f64>,
        activation_bound: u32,
        period_ns: Option<u64>,
    ) -> CfgSystemTask {
        CfgSystemTask {
            id: id.to_owned(),
            function: FunctionId::new(format!("fn:{id}")),
            kind: CfgRootKind::Task,
            name: Some(id.to_owned()),
            status: if time_ns.is_some() {
                CfgWcetStatus::Bounded
            } else {
                CfgWcetStatus::Unbounded
            },
            cycles: None,
            time_ns,
            priority: None,
            locks: BTreeMap::new(),
            activation_bound,
            period_ns,
            release_offset_ns: None,
            release_jitter_ns: None,
            deadline_ns: None,
        }
    }

    fn with_priority(mut task: CfgSystemTask, priority: u32) -> CfgSystemTask {
        task.priority = Some(priority);
        task
    }

    fn with_lock(mut task: CfgSystemTask, lock: &str, hold_ns: u64) -> CfgSystemTask {
        task.locks.insert(lock.to_owned(), hold_ns);
        task
    }

    fn response_for<'a>(
        result: &'a crate::cfg::CfgSystemResponseInfo,
        task: &str,
    ) -> &'a crate::cfg::CfgSystemResponseTask {
        result
            .tasks
            .iter()
            .find(|response| response.task == task)
            .expect("response entry")
    }

    #[test]
    fn response_counts_periodic_releases_without_activation_cap() {
        let tasks = vec![
            task("t0", Some(100.0), 1, None),
            // A bound of one activation in the horizon must not cap the
            // releases that interfere with a longer busy window.
            task("t1", Some(50.0), 1, Some(100)),
        ];
        let result = response_times(&tasks, None);
        let response = response_for(&result, "t0");
        assert_eq!(response.status, "bounded");
        assert_eq!(response.time_ns, Some(250.0));
    }

    #[test]
    fn response_includes_periodic_self_interference() {
        let mut target = task("t0", Some(100.0), 1, Some(1_000));
        target.deadline_ns = Some(150);
        let result = response_times(&[target], None);
        let response = response_for(&result, "t0");
        assert_eq!(response.status, "bounded");
        // One carry-in activation is included even though the activation bound
        // is one and the response window is shorter than the period.
        assert_eq!(response.time_ns, Some(200.0));
        assert!(response.deadline_missed);
    }

    #[test]
    fn response_reports_unbounded_under_overload() {
        let tasks = vec![
            task("t0", Some(100.0), 1, None),
            task("t1", Some(200.0), 1, Some(100)),
        ];
        let result = response_times(&tasks, None);
        let response = response_for(&result, "t0");
        assert_eq!(response.status, "unbounded");
        assert_eq!(response.time_ns, None);
    }

    #[test]
    fn response_zero_activation_is_exact() {
        let tasks = vec![task("t0", None, 0, None), task("t1", Some(10.0), 1, None)];
        let result = response_times(&tasks, None);
        let response = response_for(&result, "t0");
        assert_eq!(response.status, "bounded");
        assert_eq!(response.time_ns, Some(0.0));
    }

    #[test]
    fn fixed_priority_excludes_lower_priority_interference() {
        let mut target = task("t0", Some(100.0), 1, None);
        target.priority = Some(1);
        let mut high = task("t1", Some(50.0), 1, None);
        high.priority = Some(2);
        let mut equal = task("t2", Some(30.0), 1, None);
        equal.priority = Some(1);
        let mut low = task("t3", Some(1_000.0), 1, None);
        low.priority = Some(0);

        let result = response_times(&[target, high, equal, low], None);
        assert_eq!(result.model, "fixed-priority-busy-period");
        // t0: own work + higher-priority t1 + equal-priority t2; low t3 is
        // excluded.
        assert_eq!(response_for(&result, "t0").time_ns, Some(180.0));
        assert_eq!(response_for(&result, "t1").time_ns, Some(50.0));
        assert_eq!(response_for(&result, "t2").time_ns, Some(180.0));
        // The lowest-priority task still sees every other task.
        assert_eq!(response_for(&result, "t3").time_ns, Some(1_180.0));
    }

    #[test]
    fn fixed_priority_counts_periodic_higher_priority_releases() {
        let mut target = task("t0", Some(100.0), 1, None);
        target.priority = Some(1);
        let mut high = task("t1", Some(50.0), 1, Some(1_000));
        high.priority = Some(2);
        let mut low = task("t2", Some(1_000.0), 1, None);
        low.priority = Some(0);

        let result = response_times(&[target, high, low], None);
        assert_eq!(result.model, "fixed-priority-busy-period");
        assert_eq!(response_for(&result, "t0").time_ns, Some(150.0));
        assert_eq!(response_for(&result, "t2").time_ns, Some(1_200.0));
    }

    #[test]
    fn response_falls_back_when_priorities_are_incomplete() {
        let mut target = task("t0", Some(100.0), 1, None);
        target.priority = Some(1);
        let high = task("t1", Some(50.0), 1, None);

        let result = response_times(&[target, high], None);
        assert_eq!(result.model, "work-conserving-busy-period");
        assert_eq!(response_for(&result, "t0").time_ns, Some(150.0));
        assert!(
            result
                .caveats
                .iter()
                .any(|caveat| caveat.contains("lack a priority"))
        );
    }

    #[test]
    fn fixed_priority_ignores_lower_priority_input_status() {
        let mut target = task("t0", Some(100.0), 1, None);
        target.priority = Some(1);
        let mut high = task("t1", Some(50.0), 1, None);
        high.priority = Some(2);
        let mut low = task("t2", Some(10.0), 1, None);
        low.priority = Some(0);
        low.status = CfgWcetStatus::Partial;

        let result = response_times(&[target, high, low], None);
        assert_eq!(response_for(&result, "t0").status, "bounded");
        assert_eq!(response_for(&result, "t0").time_ns, Some(150.0));
    }

    #[test]
    fn priority_ceiling_uses_single_largest_lower_blocker() {
        let tasks = vec![
            with_lock(
                with_priority(task("t0", Some(10.0), 1, None), 3),
                "uart",
                100,
            ),
            with_lock(
                with_priority(task("t1", Some(10.0), 1, None), 1),
                "uart",
                500,
            ),
            with_lock(
                with_priority(task("t2", Some(10.0), 1, None), 2),
                "uart",
                300,
            ),
            with_lock(
                with_priority(task("t3", Some(10.0), 1, None), 0),
                "spi",
                900,
            ),
        ];
        let blocking =
            blocking_for_model(&tasks, SystemBlockingModel::PriorityCeiling).expect("blocking");
        assert_eq!(blocking.model, "priority-ceiling");
        let for_task = |id: &str| {
            blocking
                .tasks
                .iter()
                .find(|entry| entry.task == id)
                .expect("blocking entry")
        };
        assert_eq!(for_task("t0").time_ns, Some(500.0));
        assert_eq!(for_task("t0").blocker.as_deref(), Some("t1"));
        assert_eq!(for_task("t0").lock.as_deref(), Some("uart"));
        assert_eq!(for_task("t1").time_ns, Some(0.0));
        assert_eq!(for_task("t2").time_ns, Some(500.0));
        assert_eq!(for_task("t3").time_ns, Some(0.0));
        assert_eq!(blocking.inversions.len(), 3);
        assert!(blocking.inversions.iter().any(|inversion| {
            inversion.lock == "uart"
                && inversion.blocked == "t0"
                && inversion.blocker == "t1"
                && inversion.hold_ns == 500
        }));
    }

    #[test]
    fn priority_ceiling_can_block_task_without_own_locks() {
        let tasks = vec![
            with_priority(task("t0", Some(10.0), 1, None), 3),
            with_lock(
                with_priority(task("t1", Some(10.0), 1, None), 4),
                "uart",
                50,
            ),
            with_lock(
                with_priority(task("t2", Some(10.0), 1, None), 1),
                "uart",
                700,
            ),
            with_priority(task("t3", Some(10.0), 1, None), 2),
        ];
        let blocking =
            blocking_for_model(&tasks, SystemBlockingModel::PriorityCeiling).expect("blocking");
        let target = blocking
            .tasks
            .iter()
            .find(|entry| entry.task == "t0")
            .expect("t0 blocking");
        assert_eq!(target.time_ns, Some(700.0));
        assert_eq!(target.blocker.as_deref(), Some("t2"));
        assert_eq!(target.lock.as_deref(), Some("uart"));
    }

    #[test]
    fn blocking_requires_priorities_when_locks_are_configured() {
        let tasks = vec![
            with_lock(
                with_priority(task("t0", Some(10.0), 1, None), 3),
                "uart",
                100,
            ),
            task("t1", Some(10.0), 1, None),
        ];
        let error = blocking_for_model(&tasks, SystemBlockingModel::PriorityCeiling)
            .expect_err("incomplete priorities");
        assert!(error.contains("requires a priority"));
    }

    #[test]
    fn blocking_requires_distinct_priorities() {
        let tasks = vec![
            with_lock(
                with_priority(task("t0", Some(10.0), 1, None), 2),
                "uart",
                100,
            ),
            with_lock(
                with_priority(task("t1", Some(10.0), 1, None), 2),
                "uart",
                200,
            ),
        ];
        let error = blocking_for_model(&tasks, SystemBlockingModel::PriorityCeiling)
            .expect_err("duplicate priorities");
        assert!(error.contains("distinct priorities"));
    }

    fn place(id: &str, kind: &str, tokens: u32, capacity: u32) -> CfgSystemPlace {
        CfgSystemPlace {
            id: id.to_owned(),
            kind: kind.to_owned(),
            tokens,
            capacity,
        }
    }

    #[test]
    fn periodic_release_counts_are_conservative() {
        assert_eq!(periodic_releases(5_000_000, 0, 0, 1_000_000), 6);
        assert_eq!(periodic_releases(5_000_000, 1_000_000, 0, 1_000_000), 5);
        assert_eq!(
            periodic_releases(5_000_000, 5_000_000, 2_000_000, 1_000_000),
            3
        );
        assert_eq!(periodic_releases(0, 0, 0, 1_000_000), 0);
        assert_eq!(periodic_releases(5_000_000, 0, 0, 0), 0);
        assert_eq!(periodic_releases(5_000_000, 6_000_000, 0, 1_000_000), 0);
    }

    #[test]
    fn state_equation_solves_activation_bounds() {
        let places = vec![
            place("core:0", "core", 1, 1),
            place("ready:t0", "ready", 2, 2),
            place("done:t0", "done", 0, 2),
        ];
        let transitions = vec![CfgSystemTransition {
            id: "execute:t0".to_owned(),
            kind: "execute".to_owned(),
            task: "t0".to_owned(),
            cost_cycles: Some(10.0),
            activations: 2,
            inputs: vec!["ready:t0".to_owned(), "core:0".to_owned()],
            outputs: vec!["done:t0".to_owned(), "core:0".to_owned()],
        }];
        let solution = solve_state_equation(&places, &transitions, &[]).expect("solution");
        assert_eq!(solution.status, "optimal");
        assert_eq!(solution.firing.len(), 1);
        assert_eq!(solution.firing[0].fires, 2);
        assert_eq!(solution.objective, Some(20.0));
    }

    #[test]
    fn state_equation_respects_budget_capacity() {
        let places = vec![
            place("core:0", "core", 1, 1),
            place("ready:t0", "ready", 2, 2),
            place("done:t0", "done", 0, 2),
            place("budget:bus", "budget", 1, 1),
        ];
        let transitions = vec![CfgSystemTransition {
            id: "execute:t0".to_owned(),
            kind: "execute".to_owned(),
            task: "t0".to_owned(),
            cost_cycles: Some(10.0),
            activations: 2,
            inputs: vec![
                "ready:t0".to_owned(),
                "core:0".to_owned(),
                "budget:bus".to_owned(),
            ],
            outputs: vec!["done:t0".to_owned(), "core:0".to_owned()],
        }];
        let solution = solve_state_equation(&places, &transitions, &[]).expect("solution");
        assert_eq!(solution.status, "optimal");
        assert_eq!(solution.firing[0].fires, 1);
        assert_eq!(solution.objective, Some(10.0));
    }

    #[test]
    fn state_equation_serializes_shared_core_transitions() {
        let places = vec![
            place("core:0", "core", 1, 1),
            place("ready:t0", "ready", 1, 1),
            place("done:t0", "done", 0, 1),
            place("ready:t1", "ready", 1, 1),
            place("done:t1", "done", 0, 1),
        ];
        let transitions = vec![
            CfgSystemTransition {
                id: "execute:t0".to_owned(),
                kind: "execute".to_owned(),
                task: "t0".to_owned(),
                cost_cycles: Some(7.0),
                activations: 1,
                inputs: vec!["ready:t0".to_owned(), "core:0".to_owned()],
                outputs: vec!["done:t0".to_owned(), "core:0".to_owned()],
            },
            CfgSystemTransition {
                id: "execute:t1".to_owned(),
                kind: "execute".to_owned(),
                task: "t1".to_owned(),
                cost_cycles: Some(5.0),
                activations: 1,
                inputs: vec!["ready:t1".to_owned(), "core:0".to_owned()],
                outputs: vec!["done:t1".to_owned(), "core:0".to_owned()],
            },
        ];
        let solution = solve_state_equation(&places, &transitions, &[]).expect("solution");
        assert_eq!(solution.status, "optimal");
        assert_eq!(solution.objective, Some(12.0));
        assert_eq!(solution.firing.len(), 2);
    }
}
