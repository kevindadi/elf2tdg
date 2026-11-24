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

use crate::board_profile::BoardProfile;
use crate::cfg::{
    CfgConcurrencyKind, CfgSystemBound, CfgSystemDependency, CfgSystemFiring, CfgSystemModelInfo,
    CfgSystemPetriSolution, CfgSystemPlace, CfgSystemTask, CfgSystemTransition, CfgWcetRoot,
    CfgWcetStatus, ProgramCfg,
};
use crate::rules::normalize_crate_hashes;
use crate::wcet::frequency_hz;

#[derive(Clone, Debug)]
struct TaskConfig {
    activations: u32,
    period_ns: Option<u64>,
    release_offset_ns: Option<u64>,
    release_jitter_ns: Option<u64>,
    resources: BTreeMap<String, u32>,
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
            activations: 1,
            period_ns: None,
            release_offset_ns: None,
            release_jitter_ns: None,
            resources: BTreeMap::new(),
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
            configs[index].resources.clone_from(entry.resources());
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
    let petri = solve_state_equation(&places, &transitions);
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
        "Spawn/join/await/callback dependencies are recorded but not yet encoded as Petri-net arcs or ordering constraints."
            .to_owned(),
        "Lock/semaphore waiting, release instants, deadlines, preemption and scheduling order are not modeled in this layer."
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
            "Resource places are cumulative per-window budgets; lock/bus hold semantics, arbitration and resource waiting time are not modeled."
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
                "Periodic releases are approximated by a release count over horizon_ns; release instants, deadlines and ordering are not modeled."
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
        petri,
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
                "No release instant, deadline, preemption, scheduling order or lock-wait model is applied in this first layer."
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

fn system_task(id: &str, root: &CfgWcetRoot, config: &TaskConfig) -> CfgSystemTask {
    CfgSystemTask {
        id: id.to_owned(),
        function: root.function.clone(),
        kind: root.kind,
        name: root.name.clone(),
        status: root.status,
        cycles: root.cycles,
        time_ns: root.time_ns,
        activation_bound: config.activations,
        period_ns: config.period_ns,
        release_offset_ns: config.release_offset_ns,
        release_jitter_ns: config.release_jitter_ns,
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
    use super::{periodic_releases, solve_state_equation};
    use crate::cfg::{CfgSystemPlace, CfgSystemTransition};

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
        let solution = solve_state_equation(&places, &transitions).expect("solution");
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
        let solution = solve_state_equation(&places, &transitions).expect("solution");
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
        let solution = solve_state_equation(&places, &transitions).expect("solution");
        assert_eq!(solution.status, "optimal");
        assert_eq!(solution.objective, Some(12.0));
        assert_eq!(solution.firing.len(), 2);
    }
}
