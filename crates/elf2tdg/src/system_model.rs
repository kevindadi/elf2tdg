//! Layered system model for multicore composition.
//!
//! The local WCET layer is computed per execution root by the CFG/IPET
//! analyses. This module builds the next layer: a small Petri-net-shaped
//! workload model whose transitions carry the local root costs. The first
//! version deliberately solves only the closed-form single-activation
//! relaxation (all modeled roots execute once on the analyzed core). It
//! records the full task/place/transition/dependency structure so a later
//! state-equation or timed-Petri-net solver can consume the same model.

use crate::cfg::{
    CfgConcurrencyKind, CfgSystemBound, CfgSystemDependency, CfgSystemModelInfo, CfgSystemPlace,
    CfgSystemTask, CfgSystemTransition, CfgWcetRoot, CfgWcetStatus, ProgramCfg,
};

/// Builds the layered system model from the completed per-root WCET layer.
///
/// Returns `None` when no `[wcet]` analysis was configured.
#[must_use]
#[allow(clippy::too_many_lines)]
pub(crate) fn analyze(program: &ProgramCfg) -> Option<CfgSystemModelInfo> {
    let wcet = program.wcet.as_ref()?;
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

    let mut tasks = Vec::with_capacity(roots.len());
    let mut places = vec![CfgSystemPlace {
        id: core_place.clone(),
        kind: "core".to_owned(),
        tokens: 1,
        capacity: 1,
    }];
    let mut transitions = Vec::with_capacity(wcet.roots.len());
    let mut all_cycles = true;
    let mut all_time = true;
    let mut cycles = 0.0;
    let mut time_ns = 0.0;

    for (index, root) in roots.iter().enumerate() {
        let task_id = format!("t{index}");
        let ready_place = format!("ready:{task_id}");
        let done_place = format!("done:{task_id}");
        let task = system_task(&task_id, root);
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

        places.push(CfgSystemPlace {
            id: ready_place.clone(),
            kind: "ready".to_owned(),
            tokens: 1,
            capacity: 1,
        });
        places.push(CfgSystemPlace {
            id: done_place.clone(),
            kind: "done".to_owned(),
            tokens: 0,
            capacity: 1,
        });
        transitions.push(CfgSystemTransition {
            id: format!("execute:{task_id}"),
            kind: "execute".to_owned(),
            task: task_id.clone(),
            cost_cycles: task.cycles,
            activations: 1,
            inputs: vec![ready_place, core_place.clone()],
            outputs: vec![done_place, core_place.clone()],
        });
        tasks.push(task);
    }

    let status = aggregate_status(&tasks);
    let mut caveats = vec![
        "The layered bound is a coarse total-work bound over one activation per execution root, not a per-task response-time bound."
            .to_owned(),
        "Spawn/join/await/callback dependencies are recorded but not yet encoded as Petri-net arcs or ordering constraints."
            .to_owned(),
        "Lock/semaphore waiting, periodic activations, preemption and scheduling order are not modeled in this first layer."
            .to_owned(),
        "Places and transitions are a serializable Petri-net model; the current bound is its closed-form single-activation relaxation."
            .to_owned(),
    ];
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
        status,
        CfgWcetStatus::Partial | CfgWcetStatus::Unbounded | CfgWcetStatus::Unknown
    ) {
        caveats.push(
            "At least one execution root is not bounded; the aggregate number is not a safe upper bound."
                .to_owned(),
        );
    }

    Some(CfgSystemModelInfo {
        model: "layered-petri-single-activation".to_owned(),
        cores,
        core_id,
        tasks,
        boot_roots: u32::try_from(if fallback_to_boot_roots { 0 } else { boot_roots })
            .unwrap_or(u32::MAX),
        places,
        transitions,
        dependencies: dependencies(program),
        bound: CfgSystemBound {
            scope: "analyzed-core-single-activation".to_owned(),
            status,
            cycles: all_cycles.then_some(cycles),
            time_ns: all_time.then_some(time_ns),
            tasks: u32::try_from(roots.len()).unwrap_or(u32::MAX),
            assumptions: vec![
                "Each modeled execution root runs at most once in the bound window.".to_owned(),
                "All modeled roots execute on the analyzed core; other cores are represented only by the configured [multicore] budget."
                    .to_owned(),
                "Local root costs already include configured cache, pipeline, data-memory and multicore block costs; this layer does not add them again."
                    .to_owned(),
                "No periodic activation, preemption, scheduling order or lock-wait model is applied in this first layer."
                    .to_owned(),
            ],
        },
        caveats,
    })
}

fn system_task(id: &str, root: &CfgWcetRoot) -> CfgSystemTask {
    CfgSystemTask {
        id: id.to_owned(),
        function: root.function.clone(),
        kind: root.kind,
        name: root.name.clone(),
        status: root.status,
        cycles: root.cycles,
        time_ns: root.time_ns,
        activation_bound: 1,
    }
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
