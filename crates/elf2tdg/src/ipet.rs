//! IPET (Implicit Path Enumeration Technique) WCET analysis.
//!
//! Each function is modeled as an integer linear program over basic-block and
//! edge execution counts. Flow conservation links blocks to edges, natural
//! loops are bounded by `FlowFacts`, and the objective maximizes the sum of
//! block upper bounds plus resolved callee summaries. The pure-Rust `microlp`
//! backend solves the model.
//!
//! The analysis is modular: callee summaries are computed bottom-up over
//! call-graph SCCs. When contextual flow facts are present, each function is
//! analyzed once per caller chain and callee summaries are selected by the
//! caller context; otherwise a single context-insensitive summary is used.
//! Recursive SCCs are unbounded. Unresolved calls, unresolved control flow and
//! incomplete callee summaries mark the result `partial`; a partial numeric
//! objective is not a safe bound.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use good_lp::{
    Expression, ProblemVariables, Solution, SolutionStatus, SolverModel, Variable, constraint,
};
use petgraph::algo::tarjan_scc;
use petgraph::graph::DiGraph;
use petgraph::stable_graph::{EdgeIndex, NodeIndex};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};

use elf2tdg_schema::{BlockId, CostRange, FunctionId};

use crate::board_profile::BranchPredictionProfile;
use crate::branch_prediction::{PredictorModel, PredictorState, conditional_branch};
use crate::btb::{BtbGeometry, BtbState, probes_btb};
use crate::cache_persistence::{self, PersistenceAnalysis, PersistenceRegion};
use crate::cache_state::{
    CacheGeometry, CacheState, data_accesses, instruction_accesses, simulate,
};
use crate::ccg::{self, CcgApplication, CcgModel};
use crate::cfg::{
    CfgBlock, CfgCacheCcgInfo, CfgCacheConflictGraphInfo, CfgCachePersistenceInfo, CfgFunction,
    CfgFunctionWcet, CfgIpetBlockCount, CfgIpetSolution, CfgWcetInfo, CfgWcetStatus, FunctionCfg,
    ProgramCfg,
};
use crate::flow_facts::{
    BranchOutcome, CrossFunctionConstraint, CrossFunctionSlot, FactScope, FlowFacts,
    InfeasibleElement, InfeasibleEnforcement, InfeasibleScope, OrderedReset,
};
use crate::timing::{PipelineFunctionModel, PipelineState};
use crate::wcet::{
    CallContext, VersionSummaries, aggregate_context_summaries, build_call_info_with,
    callee_context, frequency_hz, function_call_targets, plan_contexts, root_results, time_ns,
    unbounded_summary, unknown_summary,
};

pub(crate) const MODEL_NAME: &str = "cfg-ipet";
const SOLVER_NAME: &str = "microlp";
const MAX_MODEL_VARIABLES: usize = 500_000;

/// Runs IPET without a branch-prediction profile.
#[cfg(test)]
#[must_use]
pub(crate) fn analyze_program(program: &mut ProgramCfg, facts: &FlowFacts) -> CfgWcetInfo {
    analyze_program_with_branch_prediction(program, facts, None)
}

/// Runs IPET with the selected branch-prediction profile.
#[must_use]
pub(crate) fn analyze_program_with_branch_prediction(
    program: &mut ProgramCfg,
    facts: &FlowFacts,
    branch_prediction: Option<&BranchPredictionProfile>,
) -> CfgWcetInfo {
    let interproc = branch_prediction
        .filter(|profile| {
            (profile.model() == crate::board_profile::BranchPredictionModel::Bimodal
                || profile.is_history_model())
                && !facts.has_contextual_facts()
        })
        .and_then(|profile| build_interproc_context(program, facts, profile));
    analyze_program_impl(program, facts, branch_prediction, interproc.as_ref())
}

/// Per-function branch-excluded costs plus lazy predictor-state summaries.
struct InterprocContext {
    base: BTreeMap<FunctionId, CfgFunctionWcet>,
    model: BranchInterprocModel,
}

fn build_interproc_context(
    program: &ProgramCfg,
    facts: &FlowFacts,
    profile: &BranchPredictionProfile,
) -> Option<InterprocContext> {
    if !program
        .functions
        .iter()
        .any(|function| !function_call_targets(&function.cfg).is_empty())
    {
        return None;
    }
    let effect_program = program.clone();
    let mut base_program = program.clone();
    strip_branch_penalties(&mut base_program, profile.mispredict_penalty());
    let _ = analyze_program_impl(&mut base_program, facts, None, None);
    let base: BTreeMap<FunctionId, CfgFunctionWcet> = base_program
        .functions
        .iter()
        .filter_map(|function| {
            function
                .wcet
                .clone()
                .map(|wcet| (function.id.clone(), wcet))
        })
        .collect();
    if base.is_empty() {
        return None;
    }
    Some(InterprocContext {
        base,
        model: BranchInterprocModel::new(&effect_program, facts, profile),
    })
}

fn strip_branch_penalties(program: &mut ProgramCfg, penalty: u32) {
    let penalty = f64::from(penalty);
    for function in &mut program.functions {
        for block in function.cfg.graph.node_weights_mut() {
            let Some(prediction) = block.branch_prediction.take() else {
                continue;
            };
            if let Some(cycles) = &mut block.cycles {
                cycles.min =
                    (cycles.min - f64::from(prediction.mispredicts_min) * penalty).max(0.0);
                cycles.max =
                    (cycles.max - f64::from(prediction.mispredicts_max) * penalty).max(0.0);
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn analyze_program_impl(
    program: &mut ProgramCfg,
    facts: &FlowFacts,
    branch_prediction: Option<&BranchPredictionProfile>,
    interproc: Option<&InterprocContext>,
) -> CfgWcetInfo {
    let frequency_hz = frequency_hz(program);
    let mut function_indices = Vec::new();
    let mut index_by_id: BTreeMap<FunctionId, usize> = BTreeMap::new();
    for (index, function) in program.functions.iter().enumerate() {
        if !function.cfg.blocks_by_address.is_empty() {
            index_by_id.insert(function.id.clone(), index);
            function_indices.push(index);
        }
    }
    let mut call_graph = DiGraph::<usize, ()>::new();
    let mut node_by_function: BTreeMap<FunctionId, NodeIndex> = BTreeMap::new();
    for &index in &function_indices {
        let node = call_graph.add_node(index);
        node_by_function.insert(program.functions[index].id.clone(), node);
    }
    for &index in &function_indices {
        let caller = &program.functions[index];
        let Some(&caller_node) = node_by_function.get(&caller.id) else {
            continue;
        };
        for target in function_call_targets(&caller.cfg) {
            let Some(&callee_index) = index_by_id.get(&target) else {
                continue;
            };
            let Some(&target_node) = node_by_function.get(&program.functions[callee_index].id)
            else {
                continue;
            };
            call_graph.add_edge(caller_node, target_node, ());
        }
    }

    let components = tarjan_scc(&call_graph);
    let mut recursive_functions = BTreeSet::new();
    for component in &components {
        let recursive = component.len() > 1
            || component
                .first()
                .is_some_and(|node| call_graph.find_edge(*node, *node).is_some());
        if recursive {
            for node in component {
                recursive_functions.insert(program.functions[call_graph[*node]].id.clone());
            }
        }
    }

    let context_requested = facts.has_contextual_facts();
    let context_plan = context_requested.then(|| plan_contexts(program, &recursive_functions));
    let use_contexts = context_plan.as_ref().is_some_and(|plan| !plan.overflowed);
    let fallback_partial = context_requested && !use_contexts;
    let mut summaries: Vec<Option<CfgFunctionWcet>> = vec![None; program.functions.len()];
    let mut aggregates: BTreeMap<FunctionId, CfgFunctionWcet> = BTreeMap::new();
    let mut versions: BTreeMap<(FunctionId, CallContext), CfgFunctionWcet> = BTreeMap::new();
    let mut recursive_summaries: BTreeMap<FunctionId, CfgFunctionWcet> = BTreeMap::new();

    for component in &components {
        let recursive = component.len() > 1
            || component
                .first()
                .is_some_and(|node| call_graph.find_edge(*node, *node).is_some());
        if recursive {
            for node in component {
                let index = call_graph[*node];
                let summary = unbounded_summary("recursive-call-cycle", 0, 0);
                recursive_summaries.insert(program.functions[index].id.clone(), summary.clone());
                aggregates.insert(program.functions[index].id.clone(), summary.clone());
                summaries[index] = Some(summary);
            }
            continue;
        }
        let Some(&node) = component.first() else {
            continue;
        };
        let index = call_graph[node];
        let function = &program.functions[index];
        if use_contexts {
            let empty = BTreeSet::from([CallContext::new()]);
            let contexts = context_plan
                .as_ref()
                .and_then(|plan| plan.versions.get(&function.id))
                .filter(|contexts| !contexts.is_empty())
                .unwrap_or(&empty)
                .clone();
            let mut context_summaries = Vec::new();
            for context in &contexts {
                let resolver = VersionSummaries {
                    versions: &versions,
                    recursive: &recursive_summaries,
                    callee_context: callee_context(&function.id, context),
                };
                let summary = analyze_function(
                    program,
                    function,
                    |target| resolver.summary(target),
                    facts,
                    FactScope::Context(context),
                    frequency_hz,
                    branch_prediction,
                    None,
                );
                versions.insert((function.id.clone(), context.clone()), summary.clone());
                context_summaries.push(summary);
            }
            if let Some(summary) = aggregate_context_summaries(&context_summaries) {
                aggregates.insert(function.id.clone(), summary);
            }
        } else {
            summaries[index] = Some(analyze_function(
                program,
                function,
                |target| {
                    index_by_id
                        .get(target)
                        .and_then(|index| summaries.get(*index))
                        .and_then(Option::as_ref)
                },
                facts,
                FactScope::Insensitive,
                frequency_hz,
                branch_prediction,
                interproc,
            ));
        }
    }

    if use_contexts {
        for (index, function) in program.functions.iter().enumerate() {
            summaries[index] = aggregates.get(&function.id).cloned();
        }
    } else if fallback_partial {
        for summary in summaries.iter_mut().flatten() {
            if summary.status == CfgWcetStatus::Bounded {
                summary.status = CfgWcetStatus::Partial;
                summary.reason = Some("context-limit".to_owned());
            } else if summary.status == CfgWcetStatus::Partial && summary.reason.is_none() {
                summary.reason = Some("context-limit".to_owned());
            }
        }
    }

    let roots = if use_contexts {
        let mut root_summaries: Vec<Option<CfgFunctionWcet>> = vec![None; program.functions.len()];
        for root in &program.roots {
            if let Some(&index) = index_by_id.get(&root.function) {
                root_summaries[index] = versions
                    .get(&(root.function.clone(), Vec::new()))
                    .cloned()
                    .or_else(|| aggregates.get(&root.function).cloned());
            }
        }
        root_results(&program.roots, &index_by_id, &root_summaries)
    } else {
        root_results(&program.roots, &index_by_id, &summaries)
    };
    let mut info = CfgWcetInfo {
        model: MODEL_NAME.to_owned(),
        default_loop_bound: facts.default_loop_bound(),
        max_states: 0,
        frequency_hz,
        solver: Some(SOLVER_NAME.to_owned()),
        flow_facts: Some(facts.info()),
        functions_analyzed: 0,
        functions_partial: 0,
        functions_unbounded: 0,
        functions_unknown: 0,
        roots,
        caveats: vec![
            "IPET maximizes block execution counts under flow conservation and configured loop bounds; it is a static estimate, not a hardware proof."
                .to_owned(),
            "Loop bounds come from the board profile, imported flow-fact files or conservative counted-loop inference; inferred patterns are not a general proof of loop termination."
                .to_owned(),
            "Branch and call flow facts constrain IPET edge/block counts in their matching caller contexts; conditional/multi-target call sites and blocks with multiple calls are skipped with warnings."
                .to_owned(),
            "Callee summaries are computed bottom-up; when contextual facts are present they are computed per caller context."
                .to_owned(),
            "Block execution counts describe one optimal solution; alternate optima may distribute counts differently while producing the same objective."
                .to_owned(),
            "Recursive call-graph SCCs are reported as unbounded."
                .to_owned(),
            "Unresolved calls, missing callee summaries, unresolved control flow or missing block timing produce partial results; a partial objective is not a safe upper bound."
                .to_owned(),
            "Branch-prediction and data-memory results are local and not path-sensitive; cache penalties are block-local unless the cache-state IPET model is selected."
                .to_owned(),
            "Interrupts, DMA, bus contention, multi-core interference and concurrency are not modeled."
                .to_owned(),
        ],
    };
    if program.cache.is_some() || program.data_cache.is_some() {
        info.caveats.push(
            "Cache-state IPET simulates the configured LRU caches with cold per-function entry and call-return invalidation when the cache analysis completes and invalidate_on_call is enabled. When the cache-state product is unavailable (ordered/cross-function automata or product overflow), a line-split model charges each persistent cache line at most once per loop entry and otherwise keeps per-line block bounds; cache-analysis fallback, unresolved data addresses, loops with calls or non-persistent lines keep per-block miss bounds."
                .to_owned(),
        );
    }
    if program.pipeline.is_some() {
        info.caveats.push(
            "Pipeline state IPET propagates resource and register readiness through the CFG when a full state table is available; otherwise first-order edge stalls are used. Call-return edges reset the modeled pipeline state because callee pipeline state is not part of the caller summary. The pipeline timing model remains statistical and is rejected by --require-safe."
                .to_owned(),
        );
    }
    if program.branch_prediction.is_some() {
        info.caveats.push(
            "Branch-prediction state IPET follows concrete predictor states from the configured initial state when the branch analysis completes. For bimodal, global-history, gshare, local-history, two-level and tournament it builds per-function branch-cost/exit-state summaries and carries predictor state through direct, statically resolved calls, including nested calls; indirect, unresolved or recursive calls, contextual facts, ordered/cross-function automata, callee analysis fallback and state/summary caps keep the per-function or per-block model."
                .to_owned(),
        );
    }
    if use_contexts {
        info.caveats.push(
            "Context-sensitive facts are analyzed per caller chain; function-level WCET is the maximum over analyzed contexts."
                .to_owned(),
        );
    } else if fallback_partial {
        info.caveats.push(
            "Context enumeration exceeded the analysis limit; contextual loop bounds were merged conservatively and contextual branch/call facts were not applied to the fallback model. Affected results are partial."
                .to_owned(),
        );
    }
    if facts.has_infeasible_paths() {
        info.caveats.push(
            "Infeasible-path conflicts use aggregate constraints when their scope is unordered and structurally enforceable. Ordered conflicts use aggregate reduction when reachability forces the order, otherwise a product sequence-progress automaton for function, loop or per-iteration scope. Cross-function ordered conflicts with one direct call group inline the selected callee in the product and require the callee elements to match within one invocation; the callee summary remains the cost bound. Specific-iteration, duplicate-edge, multi-group and ambiguous call-site conflicts are skipped with warnings, and automaton state-cap overflow makes the function unknown."
                .to_owned(),
        );
    }
    info.caveats.extend(facts.warnings().iter().cloned());
    for (index, summary) in summaries.into_iter().enumerate() {
        let Some(summary) = summary else {
            continue;
        };
        match summary.status {
            CfgWcetStatus::Bounded => {
                info.functions_analyzed = info.functions_analyzed.saturating_add(1);
            }
            CfgWcetStatus::Partial => {
                info.functions_partial = info.functions_partial.saturating_add(1);
            }
            CfgWcetStatus::Unbounded => {
                info.functions_unbounded = info.functions_unbounded.saturating_add(1);
            }
            CfgWcetStatus::Unknown => {
                info.functions_unknown = info.functions_unknown.saturating_add(1);
            }
        }
        program.functions[index].wcet = Some(summary);
    }
    info
}

#[allow(clippy::too_many_arguments)]
fn analyze_function<'a, F>(
    program: &ProgramCfg,
    function: &CfgFunction,
    summary_for: F,
    facts: &FlowFacts,
    scope: FactScope<'_>,
    frequency_hz: Option<u64>,
    branch_prediction: Option<&BranchPredictionProfile>,
    interproc: Option<&InterprocContext>,
) -> CfgFunctionWcet
where
    F: FnMut(&FunctionId) -> Option<&'a CfgFunctionWcet>,
{
    let Some(entry) = function.cfg.entry else {
        return unknown_summary("no-entry", 0, 0);
    };
    let analysis = crate::cfg_graph::analyze(&function.cfg);
    let reachable: BTreeSet<BlockId> = analysis.reachable.iter().cloned().collect();
    let reachable_nodes: BTreeSet<NodeIndex> = function
        .cfg
        .blocks_by_address
        .values()
        .copied()
        .filter(|node| reachable.contains(&function.cfg.graph[*node].id))
        .collect();
    if reachable_nodes.is_empty() {
        return unknown_summary("no-reachable-blocks", 0, 0);
    }
    let call_info = match build_call_info_with(&function.cfg, &reachable_nodes, summary_for) {
        Ok(info) => info,
        Err(reason) => return unbounded_summary(&reason, 0, 0),
    };
    let base_call_cycles = interproc.and_then(|context| {
        build_call_info_with(&function.cfg, &reachable_nodes, |target| {
            context.base.get(target)
        })
        .ok()
        .filter(|info| info.external_calls == 0 && info.unresolved_calls == 0 && !info.partial)
        .map(|info| info.block_cycles)
    });
    if reachable_nodes
        .iter()
        .any(|node| function.cfg.graph[*node].cycles.is_none())
    {
        return unknown_summary(
            "missing-block-timing",
            call_info.unresolved_calls,
            call_info.external_calls,
        );
    }
    let mut partial = analysis.blocked_by_unresolved
        || call_info.partial
        || !function.cfg.recovered_calls.is_empty();
    let outcome = match solve_function(
        program,
        &function.cfg,
        entry,
        &analysis,
        &reachable_nodes,
        &call_info.block_cycles,
        base_call_cycles.as_ref(),
        facts,
        &function.id,
        scope,
        branch_prediction,
        program.pipeline_states.get(&function.address),
        interproc.map(|context| &context.model),
    ) {
        Ok(outcome) => outcome,
        Err(IpetError::Unbounded(reason)) => {
            return unbounded_summary(
                &reason,
                call_info.unresolved_calls,
                call_info.external_calls,
            );
        }
        Err(IpetError::Unknown(reason)) => {
            return unknown_summary(
                &reason,
                call_info.unresolved_calls,
                call_info.external_calls,
            );
        }
    };
    partial |= outcome.partial;
    let cycles = outcome.solution.objective;
    let time_ns = time_ns(cycles, frequency_hz);
    CfgFunctionWcet {
        status: if partial {
            CfgWcetStatus::Partial
        } else {
            CfgWcetStatus::Bounded
        },
        cycles: Some(cycles),
        time_ns,
        path: Vec::new(),
        reason: partial.then(|| "incomplete-call-or-control-flow-model".to_owned()),
        unresolved_calls: call_info.unresolved_calls,
        external_calls: call_info.external_calls,
        ipet: Some(outcome.solution),
    }
}

#[derive(Debug)]
enum IpetError {
    Unbounded(String),
    Unknown(String),
}

struct IpetOutcome {
    solution: CfgIpetSolution,
    partial: bool,
    prediction_exit_costs: BTreeMap<PredictorState, f64>,
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn solve_function(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    entry: NodeIndex,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    reachable_nodes: &BTreeSet<NodeIndex>,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    base_call_cycles: Option<&BTreeMap<NodeIndex, f64>>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    branch_prediction: Option<&BranchPredictionProfile>,
    pipeline_model: Option<&PipelineFunctionModel>,
    branch_interproc: Option<&BranchInterprocModel>,
) -> Result<IpetOutcome, IpetError> {
    let loops = build_loops(cfg, entry, analysis, facts, scope)?;
    let automata = ordered_automata(facts, function_id, scope);
    let cross = cross_function_constraints(facts, function_id, scope);
    let pipeline_stalls = pipeline_edge_stalls(program, cfg);
    let cache_ccg = ccg::build(program, cfg, reachable_nodes)
        .filter(|model| model.variable_count() <= MAX_MODEL_VARIABLES / 2);
    let cache_persistence = build_cache_persistence_models(
        program,
        cfg,
        reachable_nodes,
        function_id,
        cache_ccg.is_some(),
    );
    let has_btb = reachable_nodes.iter().any(|node| {
        cfg.graph
            .edges_directed(*node, petgraph::Direction::Outgoing)
            .any(|edge| probes_btb(edge.weight().kind))
    });
    let btb_model = build_btb_ipet_model(program, cfg, reachable_nodes);
    if !cross.is_empty() {
        let mut outcome = solve_function_with_cross_function_automata(
            program,
            cfg,
            entry,
            reachable_nodes,
            call_cycles,
            facts,
            function_id,
            scope,
            &loops,
            &automata,
            &cross,
            &pipeline_stalls,
            &cache_persistence,
            cache_ccg.as_ref(),
        )?;
        if outcome.solution.cache_model.is_none() {
            outcome.solution.cache_model = cache_fallback_model(program);
        }
        outcome.solution.branch_model = branch_fallback_model(branch_prediction);
        apply_pipeline_fallback(&mut outcome, program);
        apply_btb_fallback(&mut outcome, program, has_btb);
        return Ok(outcome);
    }
    if !automata.is_empty() {
        let mut outcome = solve_function_with_automata(
            cfg,
            entry,
            reachable_nodes,
            call_cycles,
            facts,
            function_id,
            scope,
            &loops,
            &automata,
            &pipeline_stalls,
            &cache_persistence,
            cache_ccg.as_ref(),
        )?;
        if outcome.solution.cache_model.is_none() {
            outcome.solution.cache_model = cache_fallback_model(program);
        }
        outcome.solution.branch_model = branch_fallback_model(branch_prediction);
        apply_pipeline_fallback(&mut outcome, program);
        apply_btb_fallback(&mut outcome, program, has_btb);
        return Ok(outcome);
    }
    let cache_models = build_cache_ipet_models(program, cfg, reachable_nodes);
    let has_calls = reachable_nodes
        .iter()
        .any(|node| !cfg.graph[*node].calls.is_empty());
    let active_interproc = branch_interproc.filter(|_| base_call_cycles.is_some() && has_calls);
    let mut branch_model = build_branch_ipet_model(
        branch_prediction,
        cfg,
        reachable_nodes,
        active_interproc.is_some(),
    );
    if !cache_models.is_empty()
        || branch_model.is_some()
        || pipeline_model.is_some()
        || btb_model.is_some()
    {
        let state_call_cycles = if active_interproc.is_some() {
            base_call_cycles.unwrap_or(call_cycles)
        } else {
            call_cycles
        };
        let state_outcome = match solve_function_with_state_products(
            cfg,
            entry,
            reachable_nodes,
            state_call_cycles,
            facts,
            function_id,
            scope,
            &loops,
            &cache_models,
            branch_model.as_ref(),
            &pipeline_stalls,
            pipeline_model,
            active_interproc,
            None,
            btb_model.as_ref(),
        ) {
            Ok(outcome) => outcome,
            Err(IpetError::Unknown(reason)) if reason == "ipet-model-too-large" => None,
            Err(error) => return Err(error),
        };
        if let Some(mut outcome) = state_outcome {
            if outcome.solution.cache_model.is_none() {
                outcome.solution.cache_model = cache_fallback_model(program);
            }
            if outcome.solution.branch_model.is_none() {
                outcome.solution.branch_model = branch_fallback_model(branch_prediction);
            }
            apply_pipeline_fallback(&mut outcome, program);
            apply_btb_fallback(&mut outcome, program, has_btb);
            return Ok(outcome);
        }
    }
    branch_model = build_branch_ipet_model(branch_prediction, cfg, reachable_nodes, false);
    if !cache_models.is_empty()
        || branch_model.is_some()
        || pipeline_model.is_some()
        || btb_model.is_some()
    {
        let state_outcome = match solve_function_with_state_products(
            cfg,
            entry,
            reachable_nodes,
            call_cycles,
            facts,
            function_id,
            scope,
            &loops,
            &cache_models,
            branch_model.as_ref(),
            &pipeline_stalls,
            pipeline_model,
            None,
            None,
            btb_model.as_ref(),
        ) {
            Ok(outcome) => outcome,
            Err(IpetError::Unknown(reason)) if reason == "ipet-model-too-large" => None,
            Err(error) => return Err(error),
        };
        if let Some(mut outcome) = state_outcome {
            if outcome.solution.cache_model.is_none() {
                outcome.solution.cache_model = cache_fallback_model(program);
            }
            if outcome.solution.branch_model.is_none() {
                outcome.solution.branch_model = branch_fallback_model(branch_prediction);
            }
            apply_pipeline_fallback(&mut outcome, program);
            apply_btb_fallback(&mut outcome, program, has_btb);
            return Ok(outcome);
        }
    }

    let mut nodes: Vec<NodeIndex> = reachable_nodes.iter().copied().collect();
    nodes.sort_by_key(|node| (cfg.graph[*node].address, node.index()));
    let mut vars = ProblemVariables::new();
    let mut block_vars: BTreeMap<NodeIndex, Variable> = BTreeMap::new();
    for node in &nodes {
        block_vars.insert(*node, vars.add(good_lp::variable().integer().min(0.0)));
    }
    let mut edges: Vec<(EdgeIndex, NodeIndex, NodeIndex, u64)> = cfg
        .graph
        .edge_references()
        .filter(|edge| {
            reachable_nodes.contains(&edge.source()) && reachable_nodes.contains(&edge.target())
        })
        .map(|edge| (edge.id(), edge.source(), edge.target(), edge.weight().site))
        .collect();
    edges.sort_by_key(|(_, source, target, site)| {
        (
            cfg.graph[*source].address,
            cfg.graph[*target].address,
            *site,
        )
    });
    let mut edge_vars: BTreeMap<EdgeIndex, Variable> = BTreeMap::new();
    for (id, _, _, _) in &edges {
        edge_vars.insert(*id, vars.add(good_lp::variable().integer().min(0.0)));
    }
    let mut loop_exit_vars: BTreeMap<NodeIndex, Variable> = BTreeMap::new();
    for loop_ in &loops {
        if !loop_.has_exit && !loop_exit_vars.contains_key(&loop_.header) {
            loop_exit_vars.insert(
                loop_.header,
                vars.add(good_lp::variable().integer().min(0.0)),
            );
        }
    }
    if block_vars
        .len()
        .saturating_add(edge_vars.len())
        .saturating_add(loop_exit_vars.len())
        > MAX_MODEL_VARIABLES
    {
        return Err(IpetError::Unknown("ipet-model-too-large".to_owned()));
    }
    if !block_vars.contains_key(&entry) {
        return Err(IpetError::Unknown("entry-unreachable".to_owned()));
    }

    let mut objective = objective(
        cfg,
        &block_vars,
        call_cycles,
        &cache_persistence,
        cache_ccg.as_ref(),
    );
    for (edge, variable) in &edge_vars {
        if let Some(stall) = pipeline_stalls.get(edge) {
            objective += *variable * *stall;
        }
    }
    let mut model_constraints =
        constraints(cfg, entry, &loops, &block_vars, &edge_vars, &loop_exit_vars);
    model_constraints.extend(non_loop_constraints(
        cfg,
        &block_vars,
        &edge_vars,
        facts,
        function_id,
        scope,
    ));
    model_constraints.extend(infeasible_path_constraints(
        cfg,
        &block_vars,
        &edge_vars,
        facts,
        function_id,
        scope,
    ));
    let mut cache_variables = 0_usize;
    let mut cache_conflicts = 0_usize;
    let mut cache_conflict_sets = 0_usize;
    let mut cache_conflict_lines = 0_usize;
    let block_execution = |node: NodeIndex| -> Expression {
        block_vars
            .get(&node)
            .copied()
            .map_or(Expression::from(0.0), Expression::from)
    };
    let loop_entries = |loop_: &LoopModel| -> Expression {
        let mut expression = Expression::from(if loop_.is_entry { 1.0 } else { 0.0 });
        for edge in &loop_.entry_edges {
            if let Some(variable) = edge_vars.get(edge) {
                expression += *variable;
            }
        }
        expression
    };
    let mut ccg_application: Option<CcgApplication> = None;
    if let Some(ccg_model) = cache_ccg.as_ref() {
        let application = ccg::add_constraints(
            &mut vars,
            ccg_model,
            &block_execution,
            &mut model_constraints,
            &mut objective,
        );
        cache_variables = cache_variables.saturating_add(application.variables);
        ccg_application = Some(application);
    }
    if !cache_persistence.is_empty() {
        for model in [&cache_persistence.instruction, &cache_persistence.data]
            .into_iter()
            .flatten()
        {
            let application = add_cache_persistence_model(
                &mut vars,
                model,
                cfg,
                reachable_nodes,
                &loops,
                &block_execution,
                &loop_entries,
                &mut model_constraints,
                &mut objective,
            );
            cache_variables = cache_variables.saturating_add(application.variables);
            cache_conflicts = cache_conflicts.saturating_add(application.conflicts);
            cache_conflict_sets = cache_conflict_sets.saturating_add(application.conflict_sets);
            cache_conflict_lines = cache_conflict_lines.saturating_add(application.conflict_lines);
        }
    }
    if block_vars
        .len()
        .saturating_add(edge_vars.len())
        .saturating_add(loop_exit_vars.len())
        .saturating_add(cache_variables)
        > MAX_MODEL_VARIABLES
    {
        return Err(IpetError::Unknown("ipet-model-too-large".to_owned()));
    }
    let model = vars.maximise(objective.clone()).using(good_lp::microlp);
    let solution = model
        .with_all(model_constraints)
        .solve()
        .map_err(|error| match error {
            good_lp::ResolutionError::Unbounded => {
                IpetError::Unbounded("ipet-unbounded".to_owned())
            }
            other => IpetError::Unknown(format!("ipet-solver: {other}")),
        })?;
    let status = match solution.status() {
        SolutionStatus::Optimal => "optimal",
        SolutionStatus::TimeLimit => "time-limit",
        SolutionStatus::GapLimit => "gap-limit",
    };
    let mut partial = status != "optimal" || loops.iter().any(|loop_| !loop_.has_exit);
    let mut blocks = Vec::new();
    for (node, var) in &block_vars {
        let value = solution.value(*var);
        let rounded = value.round();
        if (value - rounded).abs() > 1e-4 {
            partial = true;
        }
        if rounded >= f64::from(i32::MAX) {
            return Err(IpetError::Unbounded(
                "ipet-solver-bound-saturated".to_owned(),
            ));
        }
        if rounded > 0.0 {
            blocks.push(CfgIpetBlockCount {
                block: cfg.graph[*node].id.clone(),
                executions: rounded as u64,
            });
        }
    }
    let objective = solution.eval(&objective);
    if !objective.is_finite() || objective < 0.0 {
        return Err(IpetError::Unknown("ipet-objective-not-finite".to_owned()));
    }
    let mut outcome = IpetOutcome {
        solution: CfgIpetSolution {
            solver: SOLVER_NAME.to_owned(),
            status: status.to_owned(),
            objective,
            cache_model: cache_model_name(cache_ccg.is_some(), cache_conflicts, &cache_persistence)
                .or_else(|| cache_fallback_model(program)),
            cache_conflicts: cache_conflict_info(
                cache_conflict_sets,
                cache_conflict_lines,
                cache_conflicts,
            ),
            cache_ccg: ccg_application.as_ref().map(cache_ccg_info),
            pipeline_model: None,
            branch_model: branch_fallback_model(branch_prediction),
            btb_model: None,
            blocks,
        },
        partial,
        prediction_exit_costs: BTreeMap::new(),
    };
    apply_pipeline_fallback(&mut outcome, program);
    apply_btb_fallback(&mut outcome, program, has_btb);
    Ok(outcome)
}

fn apply_pipeline_fallback(outcome: &mut IpetOutcome, program: &ProgramCfg) {
    if outcome.solution.pipeline_model.is_none() && program.pipeline.is_some() {
        outcome.solution.pipeline_model = Some("edge-context".to_owned());
    }
}

fn apply_btb_fallback(outcome: &mut IpetOutcome, program: &ProgramCfg, has_btb: bool) {
    if outcome.solution.btb_model.is_none() && has_btb && program.btb.is_some() {
        outcome.solution.btb_model = Some("block-bounds".to_owned());
    }
}

fn objective(
    cfg: &FunctionCfg,
    block_vars: &BTreeMap<NodeIndex, Variable>,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    cache_persistence: &CachePersistenceModels,
    cache_ccg: Option<&CcgModel>,
) -> Expression {
    let mut objective = Expression::from(0.0);
    for (node, var) in block_vars {
        let base = cache_persistence_base_cost(
            &cfg.graph[*node],
            *node,
            call_cycles,
            cache_persistence,
            cache_ccg,
        );
        objective += *var * base;
    }
    objective
}

struct LoopModel {
    header: NodeIndex,
    blocks: Vec<NodeIndex>,
    bound: u32,
    has_exit: bool,
    is_entry: bool,
    entry_edges: Vec<EdgeIndex>,
}

fn build_loops(
    cfg: &FunctionCfg,
    entry: NodeIndex,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    facts: &FlowFacts,
    scope: FactScope<'_>,
) -> Result<Vec<LoopModel>, IpetError> {
    let loop_blocks: BTreeSet<BlockId> = analysis
        .loops
        .iter()
        .flat_map(|loop_| loop_.blocks.iter().cloned())
        .collect();
    for scc in &analysis.sccs {
        if scc.cyclic
            && scc.reachable
            && !scc.blocks.iter().all(|block| loop_blocks.contains(block))
        {
            return Err(IpetError::Unbounded("unsupported-cycle".to_owned()));
        }
    }
    if has_irreducible_cycle(cfg, analysis) {
        return Err(IpetError::Unbounded(
            "unsupported-irreducible-cycle".to_owned(),
        ));
    }

    let node_by_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let mut loops = Vec::new();
    for loop_ in &analysis.loops {
        if !analysis.reachable.contains(&loop_.header) {
            continue;
        }
        let Some(&header) = node_by_id.get(&loop_.header) else {
            return Err(IpetError::Unknown("loop-header-missing".to_owned()));
        };
        let header_address = cfg.graph[header].address;
        let bound = match scope {
            FactScope::Context(context) => facts.bound_for_context(header_address, context),
            FactScope::Insensitive => facts.bound_for(header_address),
        };
        let Some(bound) = bound else {
            return Err(IpetError::Unbounded(format!(
                "loop-unbounded:0x{header_address:x}"
            )));
        };
        let loop_set: BTreeSet<BlockId> = loop_.blocks.iter().cloned().collect();
        let has_exit = cfg.graph.edge_references().any(|edge| {
            loop_set.contains(&cfg.graph[edge.source()].id)
                && !loop_set.contains(&cfg.graph[edge.target()].id)
                && analysis.reachable.contains(&cfg.graph[edge.target()].id)
        });
        if !has_exit && !facts.bound_nonterminating_loops() {
            return Err(IpetError::Unbounded(format!(
                "non-terminating-loop:0x{header_address:x}"
            )));
        }
        let entry_edges: Vec<EdgeIndex> = cfg
            .graph
            .edges_directed(header, petgraph::Direction::Incoming)
            .filter(|edge| !loop_set.contains(&cfg.graph[edge.source()].id))
            .map(|edge| edge.id())
            .collect();
        let blocks: Vec<NodeIndex> = loop_
            .blocks
            .iter()
            .filter_map(|block| node_by_id.get(block).copied())
            .collect();
        loops.push(LoopModel {
            header,
            blocks,
            bound,
            has_exit,
            is_entry: header == entry,
            entry_edges,
        });
    }
    Ok(loops)
}

/// Returns `true` when removing every natural-loop backedge still leaves a
/// cycle. Such a cycle is not covered by a loop-bound constraint, so IPET
/// cannot derive a finite bound from the configured flow facts.
fn has_irreducible_cycle(cfg: &FunctionCfg, analysis: &crate::cfg_graph::CfgGraphAnalysis) -> bool {
    let mut graph = DiGraph::<(), ()>::new();
    let mut nodes: BTreeMap<BlockId, NodeIndex> = BTreeMap::new();
    for block in &analysis.reachable {
        nodes.insert(block.clone(), graph.add_node(()));
    }
    let backedges: BTreeSet<(BlockId, BlockId)> = analysis
        .loops
        .iter()
        .flat_map(|loop_| {
            loop_
                .backedges
                .iter()
                .map(|edge| (edge.from.clone(), edge.to.clone()))
        })
        .collect();
    for edge in cfg.graph.edge_references() {
        let source = &cfg.graph[edge.source()].id;
        let target = &cfg.graph[edge.target()].id;
        let (Some(&source_node), Some(&target_node)) = (nodes.get(source), nodes.get(target))
        else {
            continue;
        };
        if backedges.contains(&(source.clone(), target.clone())) {
            continue;
        }
        graph.add_edge(source_node, target_node, ());
    }
    petgraph::algo::is_cyclic_directed(&graph)
}

fn constraints(
    cfg: &FunctionCfg,
    entry: NodeIndex,
    loops: &[LoopModel],
    block_vars: &BTreeMap<NodeIndex, Variable>,
    edge_vars: &BTreeMap<EdgeIndex, Variable>,
    loop_exit_vars: &BTreeMap<NodeIndex, Variable>,
) -> Vec<good_lp::Constraint> {
    let mut constraints = Vec::new();
    for (node, var) in block_vars {
        let x = Expression::from(*var);
        let mut incoming = Expression::from(0.0);
        for edge in cfg
            .graph
            .edges_directed(*node, petgraph::Direction::Incoming)
        {
            if let Some(edge_var) = edge_vars.get(&edge.id()) {
                incoming += *edge_var;
            }
        }
        if *node == entry {
            constraints.push(constraint::eq(x.clone() - incoming, 1.0));
        } else {
            constraints.push(constraint::eq(x.clone() - incoming, 0.0));
        }
        let mut outgoing = Expression::from(0.0);
        let mut has_outgoing = false;
        for edge in cfg
            .graph
            .edges_directed(*node, petgraph::Direction::Outgoing)
        {
            if let Some(edge_var) = edge_vars.get(&edge.id()) {
                outgoing += *edge_var;
                has_outgoing = true;
            }
        }
        if let Some(exit_var) = loop_exit_vars.get(node) {
            outgoing += *exit_var;
            has_outgoing = true;
        }
        if has_outgoing {
            constraints.push(constraint::eq(x - outgoing, 0.0));
        }
    }

    for loop_ in loops {
        let Some(&header_var) = block_vars.get(&loop_.header) else {
            continue;
        };
        let mut entry_flow = Expression::from(0.0);
        if loop_.is_entry {
            entry_flow += 1.0;
        }
        for edge_id in &loop_.entry_edges {
            if let Some(edge_var) = edge_vars.get(edge_id) {
                entry_flow += *edge_var;
            }
        }
        let lhs = Expression::from(header_var) - entry_flow * f64::from(loop_.bound);
        constraints.push(constraint::leq(lhs, 0.0));
    }
    constraints
}

fn infeasible_path_constraints(
    cfg: &FunctionCfg,
    block_vars: &BTreeMap<NodeIndex, Variable>,
    edge_vars: &BTreeMap<EdgeIndex, Variable>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> Vec<good_lp::Constraint> {
    let node_by_id: BTreeMap<_, _> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    facts
        .infeasible_paths()
        .iter()
        .filter(|conflict| {
            conflict.applied
                && matches!(conflict.enforcement, InfeasibleEnforcement::Aggregate)
                && conflict
                    .function
                    .as_ref()
                    .is_some_and(|function| function == function_id)
                && scope.matches(&conflict.context)
        })
        .filter_map(|conflict| {
            let mut lhs = Expression::from(0.0);
            for element in &conflict.elements {
                let variable = match element {
                    InfeasibleElement::Block { block } => {
                        let node = node_by_id.get(block)?;
                        *block_vars.get(node)?
                    }
                    InfeasibleElement::Edge {
                        source,
                        target,
                        site,
                    } => {
                        let source = node_by_id.get(source)?;
                        let target = node_by_id.get(target)?;
                        let edge = cfg
                            .graph
                            .edges_directed(*source, petgraph::Direction::Outgoing)
                            .find(|edge| edge.target() == *target && edge.weight().site == *site)?;
                        *edge_vars.get(&edge.id())?
                    }
                };
                lhs += variable;
            }
            let count = u32::try_from(conflict.elements.len()).ok()?;
            let bound = f64::from(count.saturating_sub(1));
            match conflict.scope.as_ref()? {
                InfeasibleScope::Function => Some(constraint::leq(lhs, bound)),
                InfeasibleScope::Loop { header } => {
                    let node = node_by_id.get(header)?;
                    let header = block_vars.get(node)?;
                    let rhs = Expression::from(*header) * bound;
                    Some(constraint::leq(lhs - rhs, 0.0))
                }
                InfeasibleScope::CrossFunction => None,
            }
        })
        .collect()
}

const MAX_AUTOMATON_NODES: usize = 100_000;
const MAX_AUTOMATON_EDGES: usize = 200_000;

#[derive(Clone, Debug)]
struct OrderedAutomaton {
    pattern: Vec<InfeasibleElement>,
    reset: OrderedReset,
}

fn ordered_automata(
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> Vec<OrderedAutomaton> {
    facts
        .infeasible_paths()
        .iter()
        .filter_map(|conflict| {
            if !conflict.applied
                || !conflict.ordered
                || conflict.function.as_ref() != Some(function_id)
                || !scope.matches(&conflict.context)
                || conflict.elements.is_empty()
            {
                return None;
            }
            let InfeasibleEnforcement::Automaton { reset } = &conflict.enforcement else {
                return None;
            };
            Some(OrderedAutomaton {
                pattern: conflict.elements.clone(),
                reset: reset.clone(),
            })
        })
        .collect()
}

fn cross_function_constraints<'a>(
    facts: &'a FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> Vec<&'a CrossFunctionConstraint> {
    facts
        .infeasible_paths()
        .iter()
        .filter_map(|conflict| {
            if !conflict.applied
                || !conflict.ordered
                || !matches!(
                    conflict.enforcement,
                    InfeasibleEnforcement::CrossFunctionAutomaton
                )
                || conflict.function.as_ref() != Some(function_id)
                || !scope.matches(&conflict.context)
            {
                return None;
            }
            conflict.cross_function.as_ref()
        })
        .collect()
}

struct AutomatonRuntime {
    pattern: Vec<InfeasibleElement>,
    reset: OrderedReset,
    loop_blocks: Option<BTreeSet<BlockId>>,
    backedges: BTreeSet<(BlockId, BlockId)>,
}

impl AutomatonRuntime {
    fn reset_on(&self, source: &BlockId, target: &BlockId) -> bool {
        match &self.reset {
            OrderedReset::Function => false,
            OrderedReset::LoopEntry { .. } => self
                .loop_blocks
                .as_ref()
                .is_some_and(|blocks| !blocks.contains(source) && blocks.contains(target)),
            OrderedReset::LoopIteration { .. } => {
                let entry = self
                    .loop_blocks
                    .as_ref()
                    .is_some_and(|blocks| !blocks.contains(source) && blocks.contains(target));
                entry || self.backedges.contains(&(source.clone(), target.clone()))
            }
        }
    }
}

fn automaton_runtimes(
    cfg: &FunctionCfg,
    automata: &[OrderedAutomaton],
) -> Result<Vec<AutomatonRuntime>, IpetError> {
    let analysis = crate::cfg_graph::analyze(cfg);
    automata
        .iter()
        .map(|automaton| match &automaton.reset {
            OrderedReset::Function => Ok(AutomatonRuntime {
                pattern: automaton.pattern.clone(),
                reset: OrderedReset::Function,
                loop_blocks: None,
                backedges: BTreeSet::new(),
            }),
            OrderedReset::LoopEntry { header } | OrderedReset::LoopIteration { header } => {
                let Some(loop_) = analysis.loops.iter().find(|loop_| loop_.header == *header)
                else {
                    return Err(IpetError::Unknown("ordered-loop-missing".to_owned()));
                };
                let backedges = if matches!(automaton.reset, OrderedReset::LoopIteration { .. }) {
                    loop_
                        .backedges
                        .iter()
                        .map(|edge| (edge.from.clone(), edge.to.clone()))
                        .collect()
                } else {
                    BTreeSet::new()
                };
                Ok(AutomatonRuntime {
                    pattern: automaton.pattern.clone(),
                    reset: automaton.reset.clone(),
                    loop_blocks: Some(loop_.blocks.iter().cloned().collect()),
                    backedges,
                })
            }
        })
        .collect()
}

fn initial_progress(runtimes: &[AutomatonRuntime], entry_block: &BlockId) -> Option<Vec<usize>> {
    let block = InfeasibleElement::Block {
        block: entry_block.clone(),
    };
    let mut progress = vec![0; runtimes.len()];
    for (index, runtime) in runtimes.iter().enumerate() {
        if runtime.pattern.first() == Some(&block) {
            progress[index] = 1;
            if progress[index] >= runtime.pattern.len() {
                return None;
            }
        }
    }
    Some(progress)
}

fn advance_progress(
    runtimes: &[AutomatonRuntime],
    progress: &[usize],
    source: &BlockId,
    target: &BlockId,
    edge_element: &InfeasibleElement,
) -> Option<Vec<usize>> {
    let block = InfeasibleElement::Block {
        block: target.clone(),
    };
    let mut next = Vec::with_capacity(runtimes.len());
    for (index, runtime) in runtimes.iter().enumerate() {
        let mut position = progress[index];
        if runtime.reset_on(source, target) {
            position = 0;
        }
        if runtime.pattern.get(position) == Some(edge_element) {
            position += 1;
            if position >= runtime.pattern.len() {
                return None;
            }
        }
        if runtime.pattern.get(position) == Some(&block) {
            position += 1;
            if position >= runtime.pattern.len() {
                return None;
            }
        }
        next.push(position);
    }
    Some(next)
}

struct ProductNode {
    original: NodeIndex,
    progress: Vec<usize>,
}

struct ProductEdge {
    original: EdgeIndex,
    from: usize,
    to: usize,
}

fn build_product_graph(
    cfg: &FunctionCfg,
    entry: NodeIndex,
    reachable_nodes: &BTreeSet<NodeIndex>,
    runtimes: &[AutomatonRuntime],
) -> Result<(Vec<ProductNode>, Vec<ProductEdge>), IpetError> {
    let entry_block = cfg.graph[entry].id.clone();
    let Some(start_progress) = initial_progress(runtimes, &entry_block) else {
        return Err(IpetError::Unknown("infeasible-ordered-entry".to_owned()));
    };
    let mut index_by_key: BTreeMap<(NodeIndex, Vec<usize>), usize> = BTreeMap::new();
    let mut nodes = vec![ProductNode {
        original: entry,
        progress: start_progress.clone(),
    }];
    index_by_key.insert((entry, start_progress), 0);
    let mut edges = Vec::new();
    let mut queue = VecDeque::from([0usize]);
    while let Some(from) = queue.pop_front() {
        let node = &nodes[from];
        let source = node.original;
        let source_id = cfg.graph[source].id.clone();
        let progress = node.progress.clone();
        for edge in cfg
            .graph
            .edges_directed(source, petgraph::Direction::Outgoing)
        {
            let target = edge.target();
            if !reachable_nodes.contains(&target) {
                continue;
            }
            let target_id = cfg.graph[target].id.clone();
            let edge_element = InfeasibleElement::Edge {
                source: source_id.clone(),
                target: target_id.clone(),
                site: edge.weight().site,
            };
            let Some(next_progress) =
                advance_progress(runtimes, &progress, &source_id, &target_id, &edge_element)
            else {
                continue;
            };
            let key = (target, next_progress.clone());
            let to = if let Some(index) = index_by_key.get(&key) {
                *index
            } else {
                if nodes.len() >= MAX_AUTOMATON_NODES {
                    return Err(IpetError::Unknown("ipet-automaton-too-large".to_owned()));
                }
                let index = nodes.len();
                nodes.push(ProductNode {
                    original: target,
                    progress: next_progress,
                });
                index_by_key.insert(key, index);
                queue.push_back(index);
                index
            };
            if edges.len() >= MAX_AUTOMATON_EDGES {
                return Err(IpetError::Unknown("ipet-automaton-too-large".to_owned()));
            }
            edges.push(ProductEdge {
                original: edge.id(),
                from,
                to,
            });
        }
    }
    Ok((nodes, edges))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn solve_function_with_automata(
    cfg: &FunctionCfg,
    entry: NodeIndex,
    reachable_nodes: &BTreeSet<NodeIndex>,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    loops: &[LoopModel],
    automata: &[OrderedAutomaton],
    pipeline_stalls: &BTreeMap<EdgeIndex, f64>,
    cache_persistence: &CachePersistenceModels,
    cache_ccg: Option<&CcgModel>,
) -> Result<IpetOutcome, IpetError> {
    let runtimes = automaton_runtimes(cfg, automata)?;
    let (nodes, edges) = build_product_graph(cfg, entry, reachable_nodes, &runtimes)?;
    let node_by_block_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let nonexit_headers: BTreeSet<NodeIndex> = loops
        .iter()
        .filter(|loop_| !loop_.has_exit)
        .map(|loop_| loop_.header)
        .collect();
    let mut vars = ProblemVariables::new();
    let node_variables: Vec<Variable> = nodes
        .iter()
        .map(|_| vars.add(good_lp::variable().integer().min(0.0)))
        .collect();
    let edge_variables: Vec<Variable> = edges
        .iter()
        .map(|_| vars.add(good_lp::variable().integer().min(0.0)))
        .collect();
    let mut exit_variables: BTreeMap<usize, Variable> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        if nonexit_headers.contains(&node.original) {
            exit_variables.insert(index, vars.add(good_lp::variable().integer().min(0.0)));
        }
    }
    if nodes
        .len()
        .saturating_add(edges.len())
        .saturating_add(exit_variables.len())
        > MAX_MODEL_VARIABLES
    {
        return Err(IpetError::Unknown("ipet-model-too-large".to_owned()));
    }

    let mut nodes_by_original: BTreeMap<NodeIndex, Vec<usize>> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        nodes_by_original
            .entry(node.original)
            .or_default()
            .push(index);
    }
    let mut edges_by_original: BTreeMap<EdgeIndex, Vec<usize>> = BTreeMap::new();
    let mut incoming: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    let mut outgoing: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (index, edge) in edges.iter().enumerate() {
        edges_by_original
            .entry(edge.original)
            .or_default()
            .push(index);
        incoming[edge.to].push(index);
        outgoing[edge.from].push(index);
    }

    let mut objective = Expression::from(0.0);
    for (index, node) in nodes.iter().enumerate() {
        let base = cache_persistence_base_cost(
            &cfg.graph[node.original],
            node.original,
            call_cycles,
            cache_persistence,
            cache_ccg,
        );
        objective += node_variables[index] * base;
    }
    for (index, edge) in edges.iter().enumerate() {
        if let Some(stall) = pipeline_stalls.get(&edge.original) {
            objective += edge_variables[index] * *stall;
        }
    }

    let block_expression = |block: &BlockId| -> Expression {
        let Some(node) = node_by_block_id.get(block) else {
            return Expression::from(0.0);
        };
        let Some(indices) = nodes_by_original.get(node) else {
            return Expression::from(0.0);
        };
        let mut expression = Expression::from(0.0);
        for index in indices {
            expression += node_variables[*index];
        }
        expression
    };
    let edge_expression = |edge: EdgeIndex| -> Expression {
        let Some(indices) = edges_by_original.get(&edge) else {
            return Expression::from(0.0);
        };
        let mut expression = Expression::from(0.0);
        for index in indices {
            expression += edge_variables[*index];
        }
        expression
    };

    let mut constraints = Vec::new();
    let has_reachable_outgoing: BTreeSet<NodeIndex> = reachable_nodes
        .iter()
        .copied()
        .filter(|node| {
            cfg.graph
                .edges_directed(*node, petgraph::Direction::Outgoing)
                .any(|edge| reachable_nodes.contains(&edge.target()))
        })
        .collect();
    for (index, node) in nodes.iter().enumerate() {
        let variable = node_variables[index];
        let mut incoming_flow = Expression::from(0.0);
        for edge in &incoming[index] {
            incoming_flow += edge_variables[*edge];
        }
        let entry_flow = if index == 0 { 1.0 } else { 0.0 };
        constraints.push(constraint::eq(
            Expression::from(variable) - incoming_flow,
            entry_flow,
        ));
        let mut outgoing_flow = Expression::from(0.0);
        let mut has_outgoing = false;
        for edge in &outgoing[index] {
            outgoing_flow += edge_variables[*edge];
            has_outgoing = true;
        }
        if let Some(exit) = exit_variables.get(&index) {
            outgoing_flow += *exit;
            has_outgoing = true;
        }
        if has_outgoing {
            constraints.push(constraint::eq(
                Expression::from(variable) - outgoing_flow,
                0.0,
            ));
        } else if has_reachable_outgoing.contains(&node.original) {
            constraints.push(constraint::leq(Expression::from(variable), 0.0));
        }
    }

    for loop_ in loops {
        let Some(header_indices) = nodes_by_original.get(&loop_.header) else {
            continue;
        };
        let mut header = Expression::from(0.0);
        for index in header_indices {
            header += node_variables[*index];
        }
        let mut entries = Expression::from(if loop_.is_entry { 1.0 } else { 0.0 });
        for entry_edge in &loop_.entry_edges {
            if let Some(indices) = edges_by_original.get(entry_edge) {
                for index in indices {
                    entries += edge_variables[*index];
                }
            }
        }
        constraints.push(constraint::leq(
            header - entries * f64::from(loop_.bound),
            0.0,
        ));
    }

    for branch in facts
        .branches()
        .iter()
        .filter(|branch| &branch.function == function_id && scope.matches(&branch.context))
    {
        match branch.outcome {
            BranchOutcome::Both => {
                constraints.push(constraint::leq(block_expression(&branch.block), 0.0));
            }
            BranchOutcome::Taken | BranchOutcome::NotTaken => {
                let Some(&node) = node_by_block_id.get(&branch.block) else {
                    continue;
                };
                let kind = if branch.outcome == BranchOutcome::Taken {
                    crate::cfg::CfgEdgeKind::Branch
                } else {
                    crate::cfg::CfgEdgeKind::Fallthrough
                };
                let edge = cfg
                    .graph
                    .edges_directed(node, petgraph::Direction::Outgoing)
                    .find(|edge| edge.weight().site == branch.site && edge.weight().kind == kind);
                if let Some(edge) = edge {
                    constraints.push(constraint::leq(
                        edge_expression(edge.id()),
                        f64::from(branch.max_count),
                    ));
                }
            }
        }
    }
    for call in facts
        .calls()
        .iter()
        .filter(|call| &call.function == function_id && scope.matches(&call.context))
    {
        constraints.push(constraint::leq(
            block_expression(&call.block),
            f64::from(call.max_count),
        ));
    }
    for conflict in facts.infeasible_paths().iter().filter(|conflict| {
        conflict.applied
            && matches!(conflict.enforcement, InfeasibleEnforcement::Aggregate)
            && conflict
                .function
                .as_ref()
                .is_some_and(|function| function == function_id)
            && scope.matches(&conflict.context)
    }) {
        let mut sum = Expression::from(0.0);
        for element in &conflict.elements {
            match element {
                InfeasibleElement::Block { block } => sum += block_expression(block),
                InfeasibleElement::Edge {
                    source,
                    target,
                    site,
                } => {
                    let Some(&source) = node_by_block_id.get(source) else {
                        continue;
                    };
                    let Some(&target) = node_by_block_id.get(target) else {
                        continue;
                    };
                    if let Some(edge) = cfg
                        .graph
                        .edges_directed(source, petgraph::Direction::Outgoing)
                        .find(|edge| edge.target() == target && edge.weight().site == *site)
                    {
                        sum += edge_expression(edge.id());
                    }
                }
            }
        }
        let Ok(count) = u32::try_from(conflict.elements.len()) else {
            continue;
        };
        let bound = f64::from(count.saturating_sub(1));
        match conflict.scope.as_ref() {
            Some(InfeasibleScope::Function) => {
                constraints.push(constraint::leq(sum, bound));
            }
            Some(InfeasibleScope::Loop { header }) => {
                let header_expression = block_expression(header);
                constraints.push(constraint::leq(sum - header_expression * bound, 0.0));
            }
            Some(InfeasibleScope::CrossFunction) | None => {}
        }
    }

    let mut cache_variables = 0_usize;
    let mut cache_conflicts = 0_usize;
    let mut cache_conflict_sets = 0_usize;
    let mut cache_conflict_lines = 0_usize;
    let block_execution = |node: NodeIndex| -> Expression {
        let mut expression = Expression::from(0.0);
        if let Some(indices) = nodes_by_original.get(&node) {
            for index in indices {
                expression += node_variables[*index];
            }
        }
        expression
    };
    let loop_entries = |loop_: &LoopModel| -> Expression {
        let mut expression = Expression::from(if loop_.is_entry { 1.0 } else { 0.0 });
        for edge in &loop_.entry_edges {
            if let Some(indices) = edges_by_original.get(edge) {
                for index in indices {
                    expression += edge_variables[*index];
                }
            }
        }
        expression
    };
    let mut ccg_application: Option<CcgApplication> = None;
    if let Some(ccg_model) = cache_ccg {
        let application = ccg::add_constraints(
            &mut vars,
            ccg_model,
            &block_execution,
            &mut constraints,
            &mut objective,
        );
        cache_variables = cache_variables.saturating_add(application.variables);
        ccg_application = Some(application);
    }
    if !cache_persistence.is_empty() {
        for model in [&cache_persistence.instruction, &cache_persistence.data]
            .into_iter()
            .flatten()
        {
            let application = add_cache_persistence_model(
                &mut vars,
                model,
                cfg,
                reachable_nodes,
                loops,
                &block_execution,
                &loop_entries,
                &mut constraints,
                &mut objective,
            );
            cache_variables = cache_variables.saturating_add(application.variables);
            cache_conflicts = cache_conflicts.saturating_add(application.conflicts);
            cache_conflict_sets = cache_conflict_sets.saturating_add(application.conflict_sets);
            cache_conflict_lines = cache_conflict_lines.saturating_add(application.conflict_lines);
        }
    }
    if nodes
        .len()
        .saturating_add(edges.len())
        .saturating_add(exit_variables.len())
        .saturating_add(cache_variables)
        > MAX_MODEL_VARIABLES
    {
        return Err(IpetError::Unknown("ipet-model-too-large".to_owned()));
    }

    let model = vars.maximise(objective.clone()).using(good_lp::microlp);
    let solution = model
        .with_all(constraints)
        .solve()
        .map_err(|error| match error {
            good_lp::ResolutionError::Unbounded => {
                IpetError::Unbounded("ipet-unbounded".to_owned())
            }
            other => IpetError::Unknown(format!("ipet-solver: {other}")),
        })?;
    let status = match solution.status() {
        SolutionStatus::Optimal => "optimal",
        SolutionStatus::TimeLimit => "time-limit",
        SolutionStatus::GapLimit => "gap-limit",
    };
    let mut partial = status != "optimal" || loops.iter().any(|loop_| !loop_.has_exit);
    let mut counts: BTreeMap<NodeIndex, u64> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        let value = solution.value(node_variables[index]);
        let rounded = value.round();
        if (value - rounded).abs() > 1e-4 {
            partial = true;
        }
        if rounded < 0.0 {
            partial = true;
            continue;
        }
        let count = rounded as u64;
        if count >= u64::from(i32::MAX as u32) {
            return Err(IpetError::Unbounded(
                "ipet-solver-bound-saturated".to_owned(),
            ));
        }
        let entry = counts.entry(node.original).or_default();
        *entry = entry
            .checked_add(count)
            .ok_or_else(|| IpetError::Unbounded("ipet-solver-bound-saturated".to_owned()))?;
        if *entry >= u64::from(i32::MAX as u32) {
            return Err(IpetError::Unbounded(
                "ipet-solver-bound-saturated".to_owned(),
            ));
        }
    }
    let objective = solution.eval(&objective);
    if !objective.is_finite() || objective < 0.0 {
        return Err(IpetError::Unknown("ipet-objective-not-finite".to_owned()));
    }
    let blocks = counts
        .into_iter()
        .filter(|(_, executions)| *executions > 0)
        .map(|(node, executions)| CfgIpetBlockCount {
            block: cfg.graph[node].id.clone(),
            executions,
        })
        .collect();
    Ok(IpetOutcome {
        solution: CfgIpetSolution {
            solver: SOLVER_NAME.to_owned(),
            status: status.to_owned(),
            objective,
            cache_model: cache_model_name(cache_ccg.is_some(), cache_conflicts, cache_persistence),
            cache_conflicts: cache_conflict_info(
                cache_conflict_sets,
                cache_conflict_lines,
                cache_conflicts,
            ),
            cache_ccg: ccg_application.as_ref().map(cache_ccg_info),
            pipeline_model: None,
            branch_model: None,
            btb_model: None,
            blocks,
        },
        partial,
        prediction_exit_costs: BTreeMap::new(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelEdgeKind {
    Caller,
    EnterCall,
    CalleeEdge,
    ReturnCall,
}

struct ModelNode {
    block: BlockId,
    caller: Option<NodeIndex>,
    cost: f64,
}

struct ModelEdge {
    source: usize,
    target: usize,
    kind: ModelEdgeKind,
    /// Caller edge for `Caller`/`ReturnCall`, callee edge for `CalleeEdge`, and
    /// the replaced call-return edge for `EnterCall`.
    original: EdgeIndex,
    call: Option<usize>,
}

struct InlineCallSpec {
    id: usize,
    caller_block: NodeIndex,
    continuation: NodeIndex,
    call_return_edge: EdgeIndex,
    callee_index: usize,
    callee_entry: NodeIndex,
    callee_reachable: BTreeSet<NodeIndex>,
    callee_loops: Vec<LoopModel>,
}

struct ModelGraph {
    nodes: Vec<ModelNode>,
    edges: Vec<ModelEdge>,
    entry: usize,
    specs: Vec<InlineCallSpec>,
    caller_nodes: BTreeMap<NodeIndex, usize>,
    callee_nodes: Vec<BTreeMap<NodeIndex, usize>>,
    caller_edge_models: BTreeMap<EdgeIndex, Vec<usize>>,
    callee_edge_models: Vec<BTreeMap<EdgeIndex, Vec<usize>>>,
    enter_edges: Vec<usize>,
    constraint_specs: Vec<usize>,
    outgoing: Vec<Vec<usize>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CrossState {
    slot: usize,
    sub: usize,
}

struct CrossAutomatonModel {
    call: usize,
    slots: Vec<CrossFunctionSlot>,
    group_start: usize,
    group_len: usize,
}

fn caller_node_by_block(cfg: &FunctionCfg, block: &BlockId) -> Option<NodeIndex> {
    cfg.blocks_by_address
        .values()
        .copied()
        .find(|node| &cfg.graph[*node].id == block)
}

fn inline_call_return(
    cfg: &FunctionCfg,
    caller_block: NodeIndex,
    constraint: &CrossFunctionConstraint,
) -> Result<(EdgeIndex, NodeIndex), IpetError> {
    let InfeasibleElement::Edge { target, site, .. } = &constraint.call_return else {
        return Err(IpetError::Unknown("cross-function-call-return".to_owned()));
    };
    let mut candidates = cfg
        .graph
        .edges_directed(caller_block, petgraph::Direction::Outgoing)
        .filter(|edge| {
            edge.weight().kind == crate::cfg::CfgEdgeKind::CallReturn
                && cfg.graph[edge.target()].id == *target
                && edge.weight().site == *site
        });
    let edge = candidates
        .next()
        .ok_or_else(|| IpetError::Unknown("cross-function-call-return-missing".to_owned()))?;
    if candidates.next().is_some() {
        return Err(IpetError::Unknown(
            "cross-function-call-return-ambiguous".to_owned(),
        ));
    }
    Ok((edge.id(), edge.target()))
}

#[allow(
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn build_cross_model(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    entry: NodeIndex,
    reachable_nodes: &BTreeSet<NodeIndex>,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    cross: &[&CrossFunctionConstraint],
) -> Result<ModelGraph, IpetError> {
    let callee_chain = match scope {
        FactScope::Context(context) => Some(callee_context(function_id, context)),
        FactScope::Insensitive => None,
    };
    let callee_scope = match &callee_chain {
        Some(chain) => FactScope::Context(chain),
        None => FactScope::Insensitive,
    };

    let mut specs: Vec<InlineCallSpec> = Vec::new();
    let mut spec_by_key: BTreeMap<(NodeIndex, EdgeIndex, FunctionId), usize> = BTreeMap::new();
    let mut constraint_specs = Vec::with_capacity(cross.len());
    for constraint in cross {
        let caller_block = caller_node_by_block(cfg, &constraint.call_block)
            .ok_or_else(|| IpetError::Unknown("cross-function-call-block-missing".to_owned()))?;
        let callee_index = program
            .functions
            .iter()
            .position(|function| function.id == constraint.callee)
            .ok_or_else(|| IpetError::Unknown("cross-function-callee-missing".to_owned()))?;
        let callee = &program.functions[callee_index];
        let callee_entry = callee
            .cfg
            .entry
            .ok_or_else(|| IpetError::Unknown("cross-function-callee-entry".to_owned()))?;
        let analysis = crate::cfg_graph::analyze(&callee.cfg);
        let reachable_ids: BTreeSet<BlockId> = analysis.reachable.iter().cloned().collect();
        let callee_reachable: BTreeSet<NodeIndex> = callee
            .cfg
            .blocks_by_address
            .values()
            .copied()
            .filter(|node| reachable_ids.contains(&callee.cfg.graph[*node].id))
            .collect();
        if callee_reachable.is_empty() {
            return Err(IpetError::Unknown(
                "cross-function-callee-unreachable".to_owned(),
            ));
        }
        let callee_loops = build_loops(&callee.cfg, callee_entry, &analysis, facts, callee_scope)
            .map_err(|error| match error {
            IpetError::Unbounded(reason) | IpetError::Unknown(reason) => {
                IpetError::Unknown(format!("cross-function-callee-{reason}"))
            }
        })?;
        let (call_return_edge, continuation) = inline_call_return(cfg, caller_block, constraint)?;
        let key = (caller_block, call_return_edge, callee.id.clone());
        let spec_id = if let Some(&id) = spec_by_key.get(&key) {
            id
        } else {
            let id = specs.len();
            specs.push(InlineCallSpec {
                id,
                caller_block,
                continuation,
                call_return_edge,
                callee_index,
                callee_entry,
                callee_reachable,
                callee_loops,
            });
            spec_by_key.insert(key, id);
            id
        };
        constraint_specs.push(spec_id);
    }

    let mut nodes = Vec::new();
    let mut caller_nodes = BTreeMap::new();
    let mut caller_order: Vec<NodeIndex> = reachable_nodes.iter().copied().collect();
    caller_order.sort_by_key(|node| (cfg.graph[*node].address, node.index()));
    for node in caller_order {
        let block = &cfg.graph[node];
        let base = block.cycles.map_or(0.0, |cycles| cycles.max);
        let call = call_cycles.get(&node).copied().unwrap_or(0.0);
        let index = nodes.len();
        nodes.push(ModelNode {
            block: block.id.clone(),
            caller: Some(node),
            cost: base + call,
        });
        caller_nodes.insert(node, index);
    }
    let entry_model = *caller_nodes
        .get(&entry)
        .ok_or_else(|| IpetError::Unknown("entry-unreachable".to_owned()))?;

    let mut callee_nodes = Vec::with_capacity(specs.len());
    for spec in &specs {
        let callee = &program.functions[spec.callee_index];
        let mut order: Vec<NodeIndex> = spec.callee_reachable.iter().copied().collect();
        order.sort_by_key(|node| (callee.cfg.graph[*node].address, node.index()));
        let mut map = BTreeMap::new();
        for node in order {
            let index = nodes.len();
            nodes.push(ModelNode {
                block: callee.cfg.graph[node].id.clone(),
                caller: None,
                cost: 0.0,
            });
            map.insert(node, index);
        }
        callee_nodes.push(map);
    }

    let removed: BTreeSet<EdgeIndex> = specs.iter().map(|spec| spec.call_return_edge).collect();
    let mut edges = Vec::new();
    let mut caller_edge_models: BTreeMap<EdgeIndex, Vec<usize>> = BTreeMap::new();
    let mut caller_edges: Vec<(EdgeIndex, NodeIndex, NodeIndex, u64)> = cfg
        .graph
        .edge_references()
        .filter(|edge| {
            reachable_nodes.contains(&edge.source())
                && reachable_nodes.contains(&edge.target())
                && !removed.contains(&edge.id())
        })
        .map(|edge| (edge.id(), edge.source(), edge.target(), edge.weight().site))
        .collect();
    caller_edges.sort_by_key(|(_, source, target, site)| {
        (
            cfg.graph[*source].address,
            cfg.graph[*target].address,
            *site,
            source.index(),
            target.index(),
        )
    });
    for (id, source, target, _) in caller_edges {
        let index = edges.len();
        edges.push(ModelEdge {
            source: caller_nodes[&source],
            target: caller_nodes[&target],
            kind: ModelEdgeKind::Caller,
            original: id,
            call: None,
        });
        caller_edge_models.entry(id).or_default().push(index);
    }

    let mut callee_edge_models: Vec<BTreeMap<EdgeIndex, Vec<usize>>> =
        vec![BTreeMap::new(); specs.len()];
    let mut enter_edges = vec![0; specs.len()];
    for spec in &specs {
        let callee = &program.functions[spec.callee_index];
        let enter_index = edges.len();
        edges.push(ModelEdge {
            source: caller_nodes[&spec.caller_block],
            target: callee_nodes[spec.id][&spec.callee_entry],
            kind: ModelEdgeKind::EnterCall,
            original: spec.call_return_edge,
            call: Some(spec.id),
        });
        enter_edges[spec.id] = enter_index;

        let mut callee_edges: Vec<(EdgeIndex, NodeIndex, NodeIndex, u64)> = callee
            .cfg
            .graph
            .edge_references()
            .filter(|edge| {
                spec.callee_reachable.contains(&edge.source())
                    && spec.callee_reachable.contains(&edge.target())
            })
            .map(|edge| (edge.id(), edge.source(), edge.target(), edge.weight().site))
            .collect();
        callee_edges.sort_by_key(|(_, source, target, site)| {
            (
                callee.cfg.graph[*source].address,
                callee.cfg.graph[*target].address,
                *site,
                source.index(),
                target.index(),
            )
        });
        for (id, source, target, _) in callee_edges {
            let index = edges.len();
            edges.push(ModelEdge {
                source: callee_nodes[spec.id][&source],
                target: callee_nodes[spec.id][&target],
                kind: ModelEdgeKind::CalleeEdge,
                original: id,
                call: Some(spec.id),
            });
            callee_edge_models[spec.id]
                .entry(id)
                .or_default()
                .push(index);
        }

        let mut exit_nodes: BTreeSet<NodeIndex> = spec
            .callee_reachable
            .iter()
            .copied()
            .filter(|node| {
                !callee
                    .cfg
                    .graph
                    .edges_directed(*node, petgraph::Direction::Outgoing)
                    .any(|edge| spec.callee_reachable.contains(&edge.target()))
            })
            .collect();
        for loop_ in &spec.callee_loops {
            if !loop_.has_exit && spec.callee_reachable.contains(&loop_.header) {
                exit_nodes.insert(loop_.header);
            }
        }
        let mut exit_nodes: Vec<NodeIndex> = exit_nodes.into_iter().collect();
        exit_nodes.sort_by_key(|node| (callee.cfg.graph[*node].address, node.index()));
        for node in exit_nodes {
            edges.push(ModelEdge {
                source: callee_nodes[spec.id][&node],
                target: caller_nodes[&spec.continuation],
                kind: ModelEdgeKind::ReturnCall,
                original: spec.call_return_edge,
                call: Some(spec.id),
            });
        }
    }

    let mut outgoing = vec![Vec::new(); nodes.len()];
    for (index, edge) in edges.iter().enumerate() {
        outgoing[edge.source].push(index);
    }

    Ok(ModelGraph {
        nodes,
        edges,
        entry: entry_model,
        specs,
        caller_nodes,
        callee_nodes,
        caller_edge_models,
        callee_edge_models,
        enter_edges,
        constraint_specs,
        outgoing,
    })
}

fn cross_automaton_models(
    model: &ModelGraph,
    cross: &[&CrossFunctionConstraint],
) -> Result<Vec<CrossAutomatonModel>, IpetError> {
    if model.constraint_specs.len() != cross.len() {
        return Err(IpetError::Unknown("cross-function-model".to_owned()));
    }
    cross
        .iter()
        .zip(&model.constraint_specs)
        .map(|(constraint, &call)| {
            let slots = constraint.pattern.clone();
            let group_start = slots
                .iter()
                .position(|slot| matches!(slot, CrossFunctionSlot::Callee(_)))
                .ok_or_else(|| IpetError::Unknown("cross-function-pattern".to_owned()))?;
            let group_len = slots
                .iter()
                .filter(|slot| matches!(slot, CrossFunctionSlot::Callee(_)))
                .count();
            if group_len == 0
                || slots[group_start..group_start + group_len]
                    .iter()
                    .any(|slot| matches!(slot, CrossFunctionSlot::Caller(_)))
                || slots[group_start + group_len..]
                    .iter()
                    .any(|slot| matches!(slot, CrossFunctionSlot::Callee(_)))
            {
                return Err(IpetError::Unknown(
                    "cross-function-pattern-order".to_owned(),
                ));
            }
            Ok(CrossAutomatonModel {
                call,
                slots,
                group_start,
                group_len,
            })
        })
        .collect()
}

fn caller_edge_element(cfg: &FunctionCfg, edge: EdgeIndex) -> InfeasibleElement {
    let (source, target) = cfg
        .graph
        .edge_endpoints(edge)
        .expect("model graph edge endpoint");
    InfeasibleElement::Edge {
        source: cfg.graph[source].id.clone(),
        target: cfg.graph[target].id.clone(),
        site: cfg.graph[edge].site,
    }
}

fn callee_edge_element(cfg: &FunctionCfg, edge: EdgeIndex) -> InfeasibleElement {
    caller_edge_element(cfg, edge)
}

fn advance_caller_pattern(
    slots: &[CrossFunctionSlot],
    mut slot: usize,
    edge: Option<&InfeasibleElement>,
    block: Option<&BlockId>,
) -> Option<usize> {
    if let Some(element) = edge
        && slot < slots.len()
        && matches!(&slots[slot], CrossFunctionSlot::Caller(candidate) if candidate == element)
    {
        slot += 1;
        if slot == slots.len() {
            return None;
        }
    }
    if let Some(block) = block {
        let element = InfeasibleElement::Block {
            block: block.clone(),
        };
        if slot < slots.len()
            && matches!(&slots[slot], CrossFunctionSlot::Caller(candidate) if candidate == &element)
        {
            slot += 1;
            if slot == slots.len() {
                return None;
            }
        }
    }
    Some(slot)
}

fn slot_matches_callee_edge(slot: &CrossFunctionSlot, edge: &InfeasibleElement) -> bool {
    matches!(slot, CrossFunctionSlot::Callee(candidate) if candidate == edge)
}

fn slot_matches_callee_block(slot: &CrossFunctionSlot, block: &BlockId) -> bool {
    matches!(
        slot,
        CrossFunctionSlot::Callee(InfeasibleElement::Block { block: candidate })
            if candidate == block
    )
}

fn initial_cross_state(
    automaton: &CrossAutomatonModel,
    entry_block: &BlockId,
) -> Option<CrossState> {
    if let Some(CrossFunctionSlot::Caller(InfeasibleElement::Block { block })) =
        automaton.slots.first()
        && block == entry_block
    {
        let slot = 1;
        if slot == automaton.slots.len() {
            return None;
        }
        return Some(CrossState { slot, sub: 0 });
    }
    Some(CrossState { slot: 0, sub: 0 })
}

fn advance_cross_state(
    model: &ModelGraph,
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    automaton: &CrossAutomatonModel,
    state: CrossState,
    edge: &ModelEdge,
) -> Option<CrossState> {
    match edge.kind {
        ModelEdgeKind::Caller => {
            let element = caller_edge_element(cfg, edge.original);
            let target = &model.nodes[edge.target].block;
            let slot =
                advance_caller_pattern(&automaton.slots, state.slot, Some(&element), Some(target))?;
            Some(CrossState { slot, sub: 0 })
        }
        ModelEdgeKind::EnterCall => {
            if edge.call != Some(automaton.call) {
                return Some(state);
            }
            let mut sub = 0;
            if state.slot == automaton.group_start
                && slot_matches_callee_block(
                    &automaton.slots[automaton.group_start],
                    &model.nodes[edge.target].block,
                )
            {
                sub = 1;
            }
            Some(CrossState {
                slot: state.slot,
                sub,
            })
        }
        ModelEdgeKind::CalleeEdge => {
            if edge.call != Some(automaton.call) || state.slot != automaton.group_start {
                return Some(state);
            }
            let spec = &model.specs[automaton.call];
            let callee = &program.functions[spec.callee_index];
            let element = callee_edge_element(&callee.cfg, edge.original);
            let target = &model.nodes[edge.target].block;
            let mut sub = state.sub;
            if sub < automaton.group_len {
                if slot_matches_callee_edge(&automaton.slots[automaton.group_start + sub], &element)
                {
                    sub += 1;
                }
                if sub < automaton.group_len
                    && slot_matches_callee_block(
                        &automaton.slots[automaton.group_start + sub],
                        target,
                    )
                {
                    sub += 1;
                }
            }
            Some(CrossState {
                slot: state.slot,
                sub,
            })
        }
        ModelEdgeKind::ReturnCall => {
            let same_call = edge.call == Some(automaton.call);
            let mut slot = state.slot;
            let mut sub = state.sub;
            if slot == automaton.group_start {
                if same_call && sub == automaton.group_len {
                    slot = automaton.group_start + automaton.group_len;
                    if slot == automaton.slots.len() {
                        return None;
                    }
                }
                sub = 0;
            } else {
                sub = 0;
            }
            let element = caller_edge_element(cfg, edge.original);
            let target = &model.nodes[edge.target].block;
            let slot =
                advance_caller_pattern(&automaton.slots, slot, Some(&element), Some(target))?;
            Some(CrossState { slot, sub })
        }
    }
}

fn advance_existing_on_model(
    cfg: &FunctionCfg,
    runtimes: &[AutomatonRuntime],
    progress: &[usize],
    edge: &ModelEdge,
) -> Option<Vec<usize>> {
    match edge.kind {
        ModelEdgeKind::Caller | ModelEdgeKind::ReturnCall => {
            let (source, target) = cfg
                .graph
                .edge_endpoints(edge.original)
                .expect("model graph caller edge endpoint");
            let element = caller_edge_element(cfg, edge.original);
            advance_progress(
                runtimes,
                progress,
                &cfg.graph[source].id,
                &cfg.graph[target].id,
                &element,
            )
        }
        ModelEdgeKind::EnterCall | ModelEdgeKind::CalleeEdge => Some(progress.to_vec()),
    }
}

struct CrossProductNode {
    model: usize,
    existing: Vec<usize>,
    cross: Vec<CrossState>,
}

struct CrossProductEdge {
    model_edge: usize,
    from: usize,
    to: usize,
}

fn build_cross_product_graph(
    model: &ModelGraph,
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    runtimes: &[AutomatonRuntime],
    automata: &[CrossAutomatonModel],
) -> Result<(Vec<CrossProductNode>, Vec<CrossProductEdge>), IpetError> {
    let entry_block = model.nodes[model.entry].block.clone();
    let Some(start_existing) = initial_progress(runtimes, &entry_block) else {
        return Err(IpetError::Unknown("infeasible-ordered-entry".to_owned()));
    };
    let mut start_cross = Vec::with_capacity(automata.len());
    for automaton in automata {
        let Some(state) = initial_cross_state(automaton, &entry_block) else {
            return Err(IpetError::Unknown("infeasible-ordered-entry".to_owned()));
        };
        start_cross.push(state);
    }
    let mut index_by_key: BTreeMap<(usize, Vec<usize>, Vec<CrossState>), usize> = BTreeMap::new();
    let mut nodes = vec![CrossProductNode {
        model: model.entry,
        existing: start_existing.clone(),
        cross: start_cross.clone(),
    }];
    index_by_key.insert((model.entry, start_existing, start_cross), 0);
    let mut edges = Vec::new();
    let mut queue = VecDeque::from([0usize]);
    while let Some(from) = queue.pop_front() {
        let source_model = nodes[from].model;
        let existing = nodes[from].existing.clone();
        let cross = nodes[from].cross.clone();
        for &model_edge in &model.outgoing[source_model] {
            let edge = &model.edges[model_edge];
            let Some(next_existing) = advance_existing_on_model(cfg, runtimes, &existing, edge)
            else {
                continue;
            };
            let mut next_cross = Vec::with_capacity(automata.len());
            let mut allowed = true;
            for (index, automaton) in automata.iter().enumerate() {
                let Some(state) =
                    advance_cross_state(model, program, cfg, automaton, cross[index], edge)
                else {
                    allowed = false;
                    break;
                };
                next_cross.push(state);
            }
            if !allowed {
                continue;
            }
            let key = (edge.target, next_existing.clone(), next_cross.clone());
            let to = if let Some(&index) = index_by_key.get(&key) {
                index
            } else {
                if nodes.len() >= MAX_AUTOMATON_NODES {
                    return Err(IpetError::Unknown("ipet-automaton-too-large".to_owned()));
                }
                let index = nodes.len();
                nodes.push(CrossProductNode {
                    model: edge.target,
                    existing: next_existing,
                    cross: next_cross,
                });
                index_by_key.insert(key, index);
                queue.push_back(index);
                index
            };
            if edges.len() >= MAX_AUTOMATON_EDGES {
                return Err(IpetError::Unknown("ipet-automaton-too-large".to_owned()));
            }
            edges.push(CrossProductEdge {
                model_edge,
                from,
                to,
            });
        }
    }
    Ok((nodes, edges))
}

struct ModelLoop {
    header: usize,
    bound: u32,
    constant_entry: f64,
    entry_edges: Vec<usize>,
}

fn build_model_loops(model: &ModelGraph, caller_loops: &[LoopModel]) -> Vec<ModelLoop> {
    let mut loops = Vec::with_capacity(caller_loops.len());
    for loop_ in caller_loops {
        let Some(&header) = model.caller_nodes.get(&loop_.header) else {
            continue;
        };
        let mut entry_edges = Vec::new();
        for edge in &loop_.entry_edges {
            if let Some(indices) = model.caller_edge_models.get(edge) {
                entry_edges.extend(indices.iter().copied());
            }
        }
        entry_edges.sort_unstable();
        entry_edges.dedup();
        loops.push(ModelLoop {
            header,
            bound: loop_.bound,
            constant_entry: if loop_.is_entry { 1.0 } else { 0.0 },
            entry_edges,
        });
    }
    for spec in &model.specs {
        let callee_nodes = &model.callee_nodes[spec.id];
        for loop_ in &spec.callee_loops {
            let Some(&header) = callee_nodes.get(&loop_.header) else {
                continue;
            };
            let mut entry_edges = Vec::new();
            for edge in &loop_.entry_edges {
                if let Some(indices) = model.callee_edge_models[spec.id].get(edge) {
                    entry_edges.extend(indices.iter().copied());
                }
            }
            if loop_.header == spec.callee_entry {
                entry_edges.push(model.enter_edges[spec.id]);
            }
            entry_edges.sort_unstable();
            entry_edges.dedup();
            loops.push(ModelLoop {
                header,
                bound: loop_.bound,
                constant_entry: 0.0,
                entry_edges,
            });
        }
    }
    loops
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn solve_function_with_cross_function_automata(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    entry: NodeIndex,
    reachable_nodes: &BTreeSet<NodeIndex>,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    loops: &[LoopModel],
    automata: &[OrderedAutomaton],
    cross: &[&CrossFunctionConstraint],
    pipeline_stalls: &BTreeMap<EdgeIndex, f64>,
    cache_persistence: &CachePersistenceModels,
    cache_ccg: Option<&CcgModel>,
) -> Result<IpetOutcome, IpetError> {
    let model = build_cross_model(
        program,
        cfg,
        entry,
        reachable_nodes,
        call_cycles,
        facts,
        function_id,
        scope,
        cross,
    )?;
    let runtimes = automaton_runtimes(cfg, automata)?;
    let cross_automata = cross_automaton_models(&model, cross)?;
    let model_loops = build_model_loops(&model, loops);
    let (product_nodes, product_edges) =
        build_cross_product_graph(&model, program, cfg, &runtimes, &cross_automata)?;

    let nonexit_headers: BTreeSet<usize> = loops
        .iter()
        .filter(|loop_| !loop_.has_exit)
        .filter_map(|loop_| model.caller_nodes.get(&loop_.header).copied())
        .collect();
    let mut vars = ProblemVariables::new();
    let node_variables: Vec<Variable> = product_nodes
        .iter()
        .map(|_| vars.add(good_lp::variable().integer().min(0.0)))
        .collect();
    let edge_variables: Vec<Variable> = product_edges
        .iter()
        .map(|_| vars.add(good_lp::variable().integer().min(0.0)))
        .collect();
    let mut exit_variables: BTreeMap<usize, Variable> = BTreeMap::new();
    for (index, node) in product_nodes.iter().enumerate() {
        if nonexit_headers.contains(&node.model) {
            exit_variables.insert(index, vars.add(good_lp::variable().integer().min(0.0)));
        }
    }
    if node_variables
        .len()
        .saturating_add(edge_variables.len())
        .saturating_add(exit_variables.len())
        > MAX_MODEL_VARIABLES
    {
        return Err(IpetError::Unknown("ipet-model-too-large".to_owned()));
    }

    let mut nodes_by_caller: BTreeMap<NodeIndex, Vec<usize>> = BTreeMap::new();
    let mut product_nodes_by_model: Vec<Vec<usize>> = vec![Vec::new(); model.nodes.len()];
    for (index, node) in product_nodes.iter().enumerate() {
        product_nodes_by_model[node.model].push(index);
        if let Some(caller) = model.nodes[node.model].caller {
            nodes_by_caller.entry(caller).or_default().push(index);
        }
    }
    let mut edges_by_caller: BTreeMap<EdgeIndex, Vec<usize>> = BTreeMap::new();
    let mut product_edges_by_model: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, edge) in product_edges.iter().enumerate() {
        product_edges_by_model
            .entry(edge.model_edge)
            .or_default()
            .push(index);
        let model_edge = &model.edges[edge.model_edge];
        if matches!(
            model_edge.kind,
            ModelEdgeKind::Caller | ModelEdgeKind::ReturnCall
        ) {
            edges_by_caller
                .entry(model_edge.original)
                .or_default()
                .push(index);
        }
    }
    let mut incoming = vec![Vec::new(); product_nodes.len()];
    let mut outgoing = vec![Vec::new(); product_nodes.len()];
    for (index, edge) in product_edges.iter().enumerate() {
        incoming[edge.to].push(index);
        outgoing[edge.from].push(index);
    }

    let block_expression = |block: &BlockId| -> Expression {
        let mut expression = Expression::from(0.0);
        for candidate in cfg.blocks_by_address.values() {
            if cfg.graph[*candidate].id == *block {
                if let Some(indices) = nodes_by_caller.get(candidate) {
                    for index in indices {
                        expression += node_variables[*index];
                    }
                }
                break;
            }
        }
        expression
    };
    let edge_expression = |edge: EdgeIndex| -> Expression {
        let mut expression = Expression::from(0.0);
        if let Some(indices) = edges_by_caller.get(&edge) {
            for index in indices {
                expression += edge_variables[*index];
            }
        }
        expression
    };
    let node_by_block_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();

    let mut constraints = Vec::new();
    let structural_outgoing: Vec<bool> = model
        .outgoing
        .iter()
        .map(|edges| !edges.is_empty())
        .collect();
    for (index, product) in product_nodes.iter().enumerate() {
        let variable = node_variables[index];
        let mut incoming_flow = Expression::from(0.0);
        for edge in &incoming[index] {
            incoming_flow += edge_variables[*edge];
        }
        constraints.push(constraint::eq(
            Expression::from(variable) - incoming_flow,
            if index == 0 { 1.0 } else { 0.0 },
        ));
        let mut outgoing_flow = Expression::from(0.0);
        let mut has_outgoing = false;
        for edge in &outgoing[index] {
            outgoing_flow += edge_variables[*edge];
            has_outgoing = true;
        }
        if let Some(exit) = exit_variables.get(&index) {
            outgoing_flow += *exit;
            has_outgoing = true;
        }
        if has_outgoing {
            constraints.push(constraint::eq(
                Expression::from(variable) - outgoing_flow,
                0.0,
            ));
        } else if structural_outgoing[product.model] {
            constraints.push(constraint::leq(Expression::from(variable), 0.0));
        }
    }

    for loop_ in &model_loops {
        let header_nodes = &product_nodes_by_model[loop_.header];
        if header_nodes.is_empty() {
            continue;
        }
        let mut header = Expression::from(0.0);
        for index in header_nodes {
            header += node_variables[*index];
        }
        let mut entries = Expression::from(loop_.constant_entry);
        for model_edge in &loop_.entry_edges {
            if let Some(indices) = product_edges_by_model.get(model_edge) {
                for index in indices {
                    entries += edge_variables[*index];
                }
            }
        }
        constraints.push(constraint::leq(
            header - entries * f64::from(loop_.bound),
            0.0,
        ));
    }

    for branch in facts
        .branches()
        .iter()
        .filter(|branch| &branch.function == function_id && scope.matches(&branch.context))
    {
        match branch.outcome {
            BranchOutcome::Both => {
                constraints.push(constraint::leq(block_expression(&branch.block), 0.0));
            }
            BranchOutcome::Taken | BranchOutcome::NotTaken => {
                let Some(&node) = node_by_block_id.get(&branch.block) else {
                    continue;
                };
                let kind = if branch.outcome == BranchOutcome::Taken {
                    crate::cfg::CfgEdgeKind::Branch
                } else {
                    crate::cfg::CfgEdgeKind::Fallthrough
                };
                let edge = cfg
                    .graph
                    .edges_directed(node, petgraph::Direction::Outgoing)
                    .find(|edge| edge.weight().site == branch.site && edge.weight().kind == kind);
                if let Some(edge) = edge {
                    constraints.push(constraint::leq(
                        edge_expression(edge.id()),
                        f64::from(branch.max_count),
                    ));
                }
            }
        }
    }
    for call in facts
        .calls()
        .iter()
        .filter(|call| &call.function == function_id && scope.matches(&call.context))
    {
        constraints.push(constraint::leq(
            block_expression(&call.block),
            f64::from(call.max_count),
        ));
    }
    for conflict in facts.infeasible_paths().iter().filter(|conflict| {
        conflict.applied
            && matches!(conflict.enforcement, InfeasibleEnforcement::Aggregate)
            && conflict
                .function
                .as_ref()
                .is_some_and(|function| function == function_id)
            && scope.matches(&conflict.context)
    }) {
        let mut sum = Expression::from(0.0);
        for element in &conflict.elements {
            match element {
                InfeasibleElement::Block { block } => sum += block_expression(block),
                InfeasibleElement::Edge {
                    source,
                    target,
                    site,
                } => {
                    let Some(&source) = node_by_block_id.get(source) else {
                        continue;
                    };
                    let Some(&target) = node_by_block_id.get(target) else {
                        continue;
                    };
                    if let Some(edge) = cfg
                        .graph
                        .edges_directed(source, petgraph::Direction::Outgoing)
                        .find(|edge| edge.target() == target && edge.weight().site == *site)
                    {
                        sum += edge_expression(edge.id());
                    }
                }
            }
        }
        let Ok(count) = u32::try_from(conflict.elements.len()) else {
            continue;
        };
        let bound = f64::from(count.saturating_sub(1));
        match conflict.scope.as_ref() {
            Some(InfeasibleScope::Function) => {
                constraints.push(constraint::leq(sum, bound));
            }
            Some(InfeasibleScope::Loop { header }) => {
                let header_expression = block_expression(header);
                constraints.push(constraint::leq(sum - header_expression * bound, 0.0));
            }
            Some(InfeasibleScope::CrossFunction) | None => {}
        }
    }

    let mut objective = Expression::from(0.0);
    for (index, product) in product_nodes.iter().enumerate() {
        let cost = if let Some(caller) = model.nodes[product.model].caller {
            cache_persistence_base_cost(
                &cfg.graph[caller],
                caller,
                call_cycles,
                cache_persistence,
                cache_ccg,
            )
        } else {
            model.nodes[product.model].cost
        };
        if cost != 0.0 {
            objective += node_variables[index] * cost;
        }
    }
    for (index, edge) in product_edges.iter().enumerate() {
        let model_edge = &model.edges[edge.model_edge];
        if matches!(
            model_edge.kind,
            ModelEdgeKind::Caller | ModelEdgeKind::ReturnCall
        ) && let Some(stall) = pipeline_stalls.get(&model_edge.original)
        {
            objective += edge_variables[index] * *stall;
        }
    }

    let mut cache_variables = 0_usize;
    let mut cache_conflicts = 0_usize;
    let mut cache_conflict_sets = 0_usize;
    let mut cache_conflict_lines = 0_usize;
    let block_execution = |node: NodeIndex| -> Expression {
        let mut expression = Expression::from(0.0);
        if let Some(indices) = nodes_by_caller.get(&node) {
            for index in indices {
                expression += node_variables[*index];
            }
        }
        expression
    };
    let loop_entries = |loop_: &LoopModel| -> Expression {
        let mut expression = Expression::from(if loop_.is_entry { 1.0 } else { 0.0 });
        for edge in &loop_.entry_edges {
            if let Some(indices) = edges_by_caller.get(edge) {
                for index in indices {
                    expression += edge_variables[*index];
                }
            }
        }
        expression
    };
    let mut ccg_application: Option<CcgApplication> = None;
    if let Some(ccg_model) = cache_ccg {
        let application = ccg::add_constraints(
            &mut vars,
            ccg_model,
            &block_execution,
            &mut constraints,
            &mut objective,
        );
        cache_variables = cache_variables.saturating_add(application.variables);
        ccg_application = Some(application);
    }
    if !cache_persistence.is_empty() {
        for model in [&cache_persistence.instruction, &cache_persistence.data]
            .into_iter()
            .flatten()
        {
            let application = add_cache_persistence_model(
                &mut vars,
                model,
                cfg,
                reachable_nodes,
                loops,
                &block_execution,
                &loop_entries,
                &mut constraints,
                &mut objective,
            );
            cache_variables = cache_variables.saturating_add(application.variables);
            cache_conflicts = cache_conflicts.saturating_add(application.conflicts);
            cache_conflict_sets = cache_conflict_sets.saturating_add(application.conflict_sets);
            cache_conflict_lines = cache_conflict_lines.saturating_add(application.conflict_lines);
        }
    }
    if product_nodes
        .len()
        .saturating_add(product_edges.len())
        .saturating_add(exit_variables.len())
        .saturating_add(cache_variables)
        > MAX_MODEL_VARIABLES
    {
        return Err(IpetError::Unknown("ipet-model-too-large".to_owned()));
    }

    let problem = vars.maximise(objective.clone()).using(good_lp::microlp);
    let solution = problem
        .with_all(constraints)
        .solve()
        .map_err(|error| match error {
            good_lp::ResolutionError::Unbounded => {
                IpetError::Unbounded("ipet-unbounded".to_owned())
            }
            other => IpetError::Unknown(format!("ipet-solver: {other}")),
        })?;
    let status = match solution.status() {
        SolutionStatus::Optimal => "optimal",
        SolutionStatus::TimeLimit => "time-limit",
        SolutionStatus::GapLimit => "gap-limit",
    };
    let mut partial = status != "optimal" || loops.iter().any(|loop_| !loop_.has_exit);
    for spec in &model.specs {
        partial |= spec.callee_loops.iter().any(|loop_| !loop_.has_exit);
    }
    let mut counts: BTreeMap<NodeIndex, u64> = BTreeMap::new();
    for (index, product) in product_nodes.iter().enumerate() {
        let Some(caller) = model.nodes[product.model].caller else {
            continue;
        };
        let value = solution.value(node_variables[index]);
        let rounded = value.round();
        if (value - rounded).abs() > 1e-4 {
            partial = true;
        }
        if rounded < 0.0 {
            partial = true;
            continue;
        }
        let count = rounded as u64;
        if count >= u64::from(i32::MAX as u32) {
            return Err(IpetError::Unbounded(
                "ipet-solver-bound-saturated".to_owned(),
            ));
        }
        let entry = counts.entry(caller).or_default();
        *entry = entry
            .checked_add(count)
            .ok_or_else(|| IpetError::Unbounded("ipet-solver-bound-saturated".to_owned()))?;
        if *entry >= u64::from(i32::MAX as u32) {
            return Err(IpetError::Unbounded(
                "ipet-solver-bound-saturated".to_owned(),
            ));
        }
    }
    let objective = solution.eval(&objective);
    if !objective.is_finite() || objective < 0.0 {
        return Err(IpetError::Unknown("ipet-objective-not-finite".to_owned()));
    }
    let blocks = counts
        .into_iter()
        .filter(|(_, executions)| *executions > 0)
        .map(|(node, executions)| CfgIpetBlockCount {
            block: cfg.graph[node].id.clone(),
            executions,
        })
        .collect();
    Ok(IpetOutcome {
        solution: CfgIpetSolution {
            solver: SOLVER_NAME.to_owned(),
            status: status.to_owned(),
            objective,
            cache_model: cache_model_name(cache_ccg.is_some(), cache_conflicts, cache_persistence),
            cache_conflicts: cache_conflict_info(
                cache_conflict_sets,
                cache_conflict_lines,
                cache_conflicts,
            ),
            cache_ccg: ccg_application.as_ref().map(cache_ccg_info),
            pipeline_model: None,
            branch_model: None,
            btb_model: None,
            blocks,
        },
        partial,
        prediction_exit_costs: BTreeMap::new(),
    })
}

#[derive(Clone, Copy, Debug)]
struct CacheIpetModel {
    geometry: CacheGeometry,
    write_allocate: bool,
    miss_penalty: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct CacheIpetModels {
    instruction: Option<CacheIpetModel>,
    data: Option<CacheIpetModel>,
}

impl CacheIpetModels {
    fn is_empty(&self) -> bool {
        self.instruction.is_none() && self.data.is_none()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PersistenceCacheKind {
    Instruction,
    Data,
}

struct CachePersistenceIpetModel {
    kind: PersistenceCacheKind,
    geometry: CacheGeometry,
    write_allocate: bool,
    miss_penalty: u32,
    analysis: cache_persistence::PersistenceAnalysis,
}

#[derive(Default)]
struct CachePersistenceModels {
    instruction: Option<CachePersistenceIpetModel>,
    data: Option<CachePersistenceIpetModel>,
}

impl CachePersistenceModels {
    fn is_empty(&self) -> bool {
        self.instruction.is_none() && self.data.is_none()
    }

    fn has_regions(&self) -> bool {
        self.instruction
            .as_ref()
            .is_some_and(|model| !model.analysis.is_empty())
            || self
                .data
                .as_ref()
                .is_some_and(|model| !model.analysis.is_empty())
    }
}

fn cache_model_name(
    ccg: bool,
    conflicts: usize,
    models: &CachePersistenceModels,
) -> Option<String> {
    if ccg {
        Some("ccg".to_owned())
    } else if conflicts > 0 {
        Some("conflict-graph".to_owned())
    } else if models.has_regions() {
        Some("line-split".to_owned())
    } else {
        None
    }
}

fn cache_ccg_info(application: &CcgApplication) -> CfgCacheCcgInfo {
    CfgCacheCcgInfo {
        model: "instruction-ccg-lru".to_owned(),
        sets: u32::try_from(application.sets).unwrap_or(u32::MAX),
        nodes: u32::try_from(application.nodes).unwrap_or(u32::MAX),
        edges: u32::try_from(application.edges).unwrap_or(u32::MAX),
        constraints: u32::try_from(application.constraints).unwrap_or(u32::MAX),
        caveats: vec![
            "CCG flow guarantees a hit only when the immediate previous access in the same cache set is the same line; hits from other ways, call boundaries and unresolved control flow are not modeled."
                .to_owned(),
        ],
    }
}

fn cache_conflict_info(
    sets: usize,
    lines: usize,
    constraints: usize,
) -> Option<CfgCacheConflictGraphInfo> {
    (constraints > 0).then(|| CfgCacheConflictGraphInfo {
        model: "line-conflict-graph".to_owned(),
        sets: u32::try_from(sets).unwrap_or(u32::MAX),
        lines: u32::try_from(lines).unwrap_or(u32::MAX),
        constraints: u32::try_from(constraints).unwrap_or(u32::MAX),
        caveats: vec![
            "Conflict bounds allow one miss per loop entry plus one potential eviction per access to another line in the same cache set; associativity and access ordering are over-approximated."
                .to_owned(),
        ],
    })
}

struct BranchIpetModel {
    predictor: PredictorModel,
}

impl BranchIpetModel {
    fn penalty(&self) -> f64 {
        f64::from(self.predictor.mispredict_penalty())
    }
}

/// Branch cost and possible predictor exit states for one callee invocation.
#[derive(Clone, Debug)]
struct BranchEffect {
    exits: BTreeMap<PredictorState, f64>,
}

const MAX_BRANCH_EFFECTS: usize = 4_096;
const MAX_BRANCH_EXIT_STATES: usize = 256;

/// Interprocedural predictor-state summaries.
///
/// Each summary is computed lazily for a concrete entry predictor state. It
/// runs the callee's branch-only IPET model (zero base costs) and recursively
/// applies callee summaries at nested call sites. Each possible exit state
/// keeps the maximum branch cost of the callee paths that reach it.
struct BranchInterprocModel {
    program: ProgramCfg,
    facts: FlowFacts,
    profile: BranchPredictionProfile,
    index_by_id: BTreeMap<FunctionId, usize>,
    cache: RefCell<BTreeMap<(FunctionId, PredictorState), Option<BranchEffect>>>,
    visiting: RefCell<BTreeSet<FunctionId>>,
    effects: Cell<usize>,
}

impl BranchInterprocModel {
    fn new(program: &ProgramCfg, facts: &FlowFacts, profile: &BranchPredictionProfile) -> Self {
        let index_by_id = program
            .functions
            .iter()
            .enumerate()
            .map(|(index, function)| (function.id.clone(), index))
            .collect();
        Self {
            program: program.clone(),
            facts: facts.clone(),
            profile: profile.clone(),
            index_by_id,
            cache: RefCell::new(BTreeMap::new()),
            visiting: RefCell::new(BTreeSet::new()),
            effects: Cell::new(0),
        }
    }

    fn effect(&self, function: &FunctionId, state: &PredictorState) -> Option<BranchEffect> {
        let key = (function.clone(), state.clone());
        if let Some(cached) = self.cache.borrow().get(&key) {
            return cached.clone();
        }
        if self.effects.get() >= MAX_BRANCH_EFFECTS
            || !self.visiting.borrow_mut().insert(function.clone())
        {
            return None;
        }
        let effect = self.compute_effect(function, state);
        self.visiting.borrow_mut().remove(function);
        if effect.is_some() {
            self.effects.set(self.effects.get().saturating_add(1));
        }
        self.cache.borrow_mut().insert(key, effect.clone());
        effect
    }

    fn compute_effect(
        &self,
        function_id: &FunctionId,
        state: &PredictorState,
    ) -> Option<BranchEffect> {
        let index = *self.index_by_id.get(function_id)?;
        let function = self.program.functions.get(index)?;
        let entry = function.cfg.entry?;
        let analysis = crate::cfg_graph::analyze(&function.cfg);
        let reachable_nodes: BTreeSet<NodeIndex> = function
            .cfg
            .blocks_by_address
            .values()
            .copied()
            .filter(|node| analysis.reachable.contains(&function.cfg.graph[*node].id))
            .collect();
        if reachable_nodes.is_empty() {
            return None;
        }
        let loops = build_loops(
            &function.cfg,
            entry,
            &analysis,
            &self.facts,
            FactScope::Insensitive,
        )
        .ok()?;
        let branch =
            build_branch_ipet_model(Some(&self.profile), &function.cfg, &reachable_nodes, true)?;
        let mut branch_cfg = function.cfg.clone();
        for block in branch_cfg.graph.node_weights_mut() {
            block.cycles = Some(CostRange::exact(0.0));
        }
        let outcome = solve_function_with_state_products(
            &branch_cfg,
            entry,
            &reachable_nodes,
            &BTreeMap::new(),
            &self.facts,
            &function.id,
            FactScope::Insensitive,
            &loops,
            &CacheIpetModels::default(),
            Some(&branch),
            &BTreeMap::new(),
            None,
            Some(self),
            Some(state),
            None,
        )
        .ok()??;
        if outcome.partial || outcome.prediction_exit_costs.is_empty() {
            return None;
        }
        Some(BranchEffect {
            exits: outcome.prediction_exit_costs,
        })
    }
}

struct BtbIpetModel {
    geometry: BtbGeometry,
}

impl BtbIpetModel {
    fn penalty(&self) -> f64 {
        f64::from(self.geometry.miss_penalty)
    }
}

fn build_btb_ipet_model(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    reachable_nodes: &BTreeSet<NodeIndex>,
) -> Option<BtbIpetModel> {
    let info = program.btb.as_ref()?;
    let mut has_transfer = false;
    for node in reachable_nodes {
        let transfers = cfg
            .graph
            .edges_directed(*node, petgraph::Direction::Outgoing)
            .any(|edge| probes_btb(edge.weight().kind));
        if !transfers {
            continue;
        }
        has_transfer = true;
        let metadata = cfg.graph[*node].btb.as_ref()?;
        if metadata.fallback {
            return None;
        }
    }
    has_transfer.then(|| BtbIpetModel {
        geometry: BtbGeometry {
            sets: info.sets,
            ways: usize::try_from(info.ways).unwrap_or(usize::MAX),
            miss_penalty: info.miss_penalty,
        },
    })
}

fn branch_fallback_model(profile: Option<&BranchPredictionProfile>) -> Option<String> {
    profile.map(|_| "block-bounds".to_owned())
}

fn build_branch_ipet_model(
    profile: Option<&BranchPredictionProfile>,
    cfg: &FunctionCfg,
    reachable_nodes: &BTreeSet<NodeIndex>,
    allow_empty: bool,
) -> Option<BranchIpetModel> {
    let profile = profile?;
    let mut has_branch = false;
    for node in reachable_nodes {
        if conditional_branch(cfg, *node).is_some() {
            has_branch = true;
            let prediction = cfg.graph[*node].branch_prediction.as_ref()?;
            if prediction.fallback {
                return None;
            }
        }
    }
    (has_branch || allow_empty).then(|| BranchIpetModel {
        predictor: PredictorModel::from_profile(profile),
    })
}

fn cache_fallback_model(program: &ProgramCfg) -> Option<String> {
    (program.cache.is_some() || program.data_cache.is_some()).then(|| "block-bounds".to_owned())
}

fn pipeline_edge_stalls(program: &ProgramCfg, cfg: &FunctionCfg) -> BTreeMap<EdgeIndex, f64> {
    let Some(pipeline) = &program.pipeline else {
        return BTreeMap::new();
    };
    let mut by_address = BTreeMap::new();
    for edge in &pipeline.edges {
        by_address
            .entry((edge.source.get(), edge.target.get(), edge.site.get()))
            .and_modify(|current: &mut f64| *current = current.max(edge.stall_cycles))
            .or_insert(edge.stall_cycles);
    }
    let mut stalls = BTreeMap::new();
    for edge in cfg.graph.edge_references() {
        let source = cfg.graph[edge.source()].address;
        let target = cfg.graph[edge.target()].address;
        if let Some(&stall) = by_address.get(&(source, target, edge.weight().site))
            && stall > 0.0
        {
            stalls.insert(edge.id(), stall);
        }
    }
    stalls
}

fn build_cache_ipet_models(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    reachable_nodes: &BTreeSet<NodeIndex>,
) -> CacheIpetModels {
    let mut models = CacheIpetModels::default();
    if let Some(info) = &program.cache
        && info.invalidate_on_call
        && info.sets > 0
        && info.line_bytes > 0
        && let Ok(ways) = usize::try_from(info.ways)
        && ways > 0
        && reachable_nodes.iter().all(|node| {
            cfg.graph[*node]
                .cache
                .as_ref()
                .is_some_and(|cache| !cache.fallback)
        })
    {
        models.instruction = Some(CacheIpetModel {
            geometry: CacheGeometry {
                line_bytes: u64::from(info.line_bytes),
                sets: info.sets,
                ways,
            },
            write_allocate: true,
            miss_penalty: info.miss_penalty,
        });
    }
    if let Some(info) = &program.data_cache
        && info.invalidate_on_call
        && info.sets > 0
        && info.line_bytes > 0
        && let Ok(ways) = usize::try_from(info.ways)
        && ways > 0
        && reachable_nodes.iter().all(|node| {
            cfg.graph[*node]
                .data_cache
                .as_ref()
                .is_some_and(|cache| !cache.fallback && cache.unresolved_memory_accesses == 0)
        })
    {
        models.data = Some(CacheIpetModel {
            geometry: CacheGeometry {
                line_bytes: u64::from(info.line_bytes),
                sets: info.sets,
                ways,
            },
            write_allocate: info.write_allocate,
            miss_penalty: info.miss_penalty,
        });
    }
    models
}

fn build_cache_persistence_models(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    reachable_nodes: &BTreeSet<NodeIndex>,
    function_id: &FunctionId,
    ccg_active: bool,
) -> CachePersistenceModels {
    let mut models = CachePersistenceModels::default();
    if !ccg_active
        && let Some(info) = &program.cache
        && info.invalidate_on_call
        && info.sets > 0
        && info.line_bytes > 0
        && let Ok(ways) = usize::try_from(info.ways)
        && ways > 0
        && reachable_nodes
            .iter()
            .all(|node| cfg.graph[*node].cache.is_some())
    {
        let geometry = CacheGeometry {
            line_bytes: u64::from(info.line_bytes),
            sets: info.sets,
            ways,
        };
        let analysis = persistence_from_info(&info.persistence, function_id, cfg);
        if !analysis.is_empty() || has_loop_lines(cfg, geometry, PersistenceCacheKind::Instruction)
        {
            models.instruction = Some(CachePersistenceIpetModel {
                kind: PersistenceCacheKind::Instruction,
                geometry,
                write_allocate: true,
                miss_penalty: info.miss_penalty,
                analysis,
            });
        }
    }
    if let Some(info) = &program.data_cache
        && info.invalidate_on_call
        && info.sets > 0
        && info.line_bytes > 0
        && let Ok(ways) = usize::try_from(info.ways)
        && ways > 0
        && reachable_nodes.iter().all(|node| {
            cfg.graph[*node]
                .data_cache
                .as_ref()
                .is_some_and(|cache| cache.unresolved_memory_accesses == 0)
        })
    {
        let geometry = CacheGeometry {
            line_bytes: u64::from(info.line_bytes),
            sets: info.sets,
            ways,
        };
        let analysis = persistence_from_info(&info.persistence, function_id, cfg);
        if !analysis.is_empty() || has_loop_lines(cfg, geometry, PersistenceCacheKind::Data) {
            models.data = Some(CachePersistenceIpetModel {
                kind: PersistenceCacheKind::Data,
                geometry,
                write_allocate: info.write_allocate,
                miss_penalty: info.miss_penalty,
                analysis,
            });
        }
    }
    models
}

fn has_loop_lines(cfg: &FunctionCfg, geometry: CacheGeometry, kind: PersistenceCacheKind) -> bool {
    if geometry.line_bytes == 0 || geometry.sets == 0 {
        return false;
    }
    let graph = crate::cfg_graph::analyze(cfg);
    let node_by_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    graph.loops.iter().any(|loop_| {
        loop_.blocks.iter().any(|block| {
            node_by_id.get(block).is_some_and(|node| {
                cache_block_line_data(&cfg.graph[*node], kind).is_some_and(|(lines, _)| {
                    lines
                        .iter()
                        .any(|line| line.accesses > 0 && line.misses_max > 0)
                })
            })
        })
    })
}

fn persistence_from_info(
    info: &CfgCachePersistenceInfo,
    function_id: &FunctionId,
    cfg: &FunctionCfg,
) -> PersistenceAnalysis {
    if info.regions.is_empty() || cfg.blocks_by_address.is_empty() {
        return PersistenceAnalysis::default();
    }
    let graph = crate::cfg_graph::analyze(cfg);
    let node_by_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let mut regions = Vec::new();
    for region in &info.regions {
        if &region.function != function_id || region.lines.is_empty() {
            continue;
        }
        let Some(loop_) = graph
            .loops
            .iter()
            .find(|candidate| candidate.header == region.header)
        else {
            continue;
        };
        let blocks: Vec<NodeIndex> = loop_
            .blocks
            .iter()
            .filter_map(|block| node_by_id.get(block).copied())
            .collect();
        if blocks.is_empty() {
            continue;
        }
        regions.push(PersistenceRegion {
            header: region.header.clone(),
            blocks,
            lines: region.lines.iter().map(|line| line.get()).collect(),
        });
    }
    if regions.is_empty() {
        return PersistenceAnalysis::default();
    }
    PersistenceAnalysis {
        loops_analyzed: u32::try_from(graph.loops.len()).unwrap_or(u32::MAX),
        loops_persistent: u32::try_from(regions.len()).unwrap_or(u32::MAX),
        regions,
    }
}

fn cache_persistence_base_cost(
    block: &CfgBlock,
    node: NodeIndex,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    models: &CachePersistenceModels,
    ccg: Option<&CcgModel>,
) -> f64 {
    let mut cost = block.cycles.map_or(0.0, |cycles| cycles.max)
        + call_cycles.get(&node).copied().unwrap_or(0.0);
    if let Some(model) = &models.instruction
        && let Some(cache) = &block.cache
    {
        cost -= f64::from(cache.misses_max) * f64::from(model.miss_penalty);
    } else if let Some(model) = ccg
        && let Some(cache) = &block.cache
    {
        cost -= f64::from(cache.misses_max) * f64::from(model.miss_penalty());
    }
    if let Some(model) = &models.data
        && let Some(cache) = &block.data_cache
    {
        cost -= f64::from(cache.misses_max) * f64::from(model.miss_penalty);
    }
    cost.max(0.0)
}

#[derive(Clone, Copy, Debug)]
struct CacheLineData {
    line: u64,
    accesses: u32,
    misses_max: u32,
    writes: u32,
}

type BlockCacheLineData = (Vec<CacheLineData>, u32);

fn cache_block_line_data(
    block: &CfgBlock,
    kind: PersistenceCacheKind,
) -> Option<BlockCacheLineData> {
    match kind {
        PersistenceCacheKind::Instruction => {
            let cache = block.cache.as_ref()?;
            Some((
                cache
                    .lines
                    .iter()
                    .map(|line| CacheLineData {
                        line: line.line.get(),
                        accesses: line.accesses,
                        misses_max: line.misses_max,
                        writes: 0,
                    })
                    .collect(),
                cache.misses_max,
            ))
        }
        PersistenceCacheKind::Data => {
            let cache = block.data_cache.as_ref()?;
            Some((
                cache
                    .lines
                    .iter()
                    .map(|line| CacheLineData {
                        line: line.line.get(),
                        accesses: line.accesses,
                        misses_max: line.misses_max,
                        writes: line.writes,
                    })
                    .collect(),
                cache.misses_max,
            ))
        }
    }
}

struct CachePersistenceApplication {
    variables: usize,
    conflict_sets: usize,
    conflict_lines: usize,
    conflicts: usize,
}

#[derive(Default)]
struct ConflictGraphUse {
    sets: usize,
    lines: usize,
    constraints: usize,
}

#[allow(clippy::too_many_arguments)]
fn add_cache_persistence_model(
    vars: &mut ProblemVariables,
    model: &CachePersistenceIpetModel,
    cfg: &FunctionCfg,
    reachable_nodes: &BTreeSet<NodeIndex>,
    loops: &[LoopModel],
    block_execution: &dyn Fn(NodeIndex) -> Expression,
    loop_entries: &dyn Fn(&LoopModel) -> Expression,
    constraints: &mut Vec<good_lp::Constraint>,
    objective: &mut Expression,
) -> CachePersistenceApplication {
    let mut added = 0_usize;
    let mut line_variables: BTreeMap<(NodeIndex, u64), Variable> = BTreeMap::new();
    let mut block_lines: BTreeMap<NodeIndex, Vec<CacheLineData>> = BTreeMap::new();
    for node in reachable_nodes {
        let Some((lines, total_misses)) = cache_block_line_data(&cfg.graph[*node], model.kind)
        else {
            continue;
        };
        let execution = block_execution(*node);
        let mut block_sum = Expression::from(0.0);
        let mut all_lines = Vec::new();
        for line in lines {
            if line.accesses == 0 {
                continue;
            }
            all_lines.push(line);
            if line.misses_max == 0 {
                continue;
            }
            let variable = vars.add(good_lp::variable().integer().min(0.0));
            added = added.saturating_add(1);
            constraints.push(constraint::leq(
                Expression::from(variable) - execution.clone() * f64::from(line.accesses),
                0.0,
            ));
            constraints.push(constraint::leq(
                Expression::from(variable) - execution.clone() * f64::from(line.misses_max),
                0.0,
            ));
            block_sum += variable;
            *objective += variable * f64::from(model.miss_penalty);
            line_variables.insert((*node, line.line), variable);
        }
        if !all_lines.is_empty() {
            block_lines.insert(*node, all_lines);
        }
        if total_misses > 0 {
            constraints.push(constraint::leq(
                block_sum - execution * f64::from(total_misses),
                0.0,
            ));
        }
    }
    let node_by_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    for region in &model.analysis.regions {
        let Some(&header) = node_by_id.get(&region.header) else {
            continue;
        };
        let Some(loop_model) = loops.iter().find(|candidate| candidate.header == header) else {
            continue;
        };
        let entries = loop_entries(loop_model);
        for line in &region.lines {
            let mut sum = Expression::from(0.0);
            let mut any = false;
            for block in &region.blocks {
                if let Some(variable) = line_variables.get(&(*block, *line)) {
                    sum += *variable;
                    any = true;
                }
            }
            if any {
                constraints.push(constraint::leq(sum - entries.clone(), 0.0));
            }
        }
    }
    let conflict_use = add_conflict_graph_constraints(
        model,
        cfg,
        loops,
        &block_lines,
        &line_variables,
        block_execution,
        loop_entries,
        constraints,
    );
    CachePersistenceApplication {
        variables: added,
        conflict_sets: conflict_use.sets,
        conflict_lines: conflict_use.lines,
        conflicts: conflict_use.constraints,
    }
}

#[allow(clippy::too_many_arguments)]
fn add_conflict_graph_constraints(
    model: &CachePersistenceIpetModel,
    cfg: &FunctionCfg,
    loops: &[LoopModel],
    block_lines: &BTreeMap<NodeIndex, Vec<CacheLineData>>,
    line_variables: &BTreeMap<(NodeIndex, u64), Variable>,
    block_execution: &dyn Fn(NodeIndex) -> Expression,
    loop_entries: &dyn Fn(&LoopModel) -> Expression,
    constraints: &mut Vec<good_lp::Constraint>,
) -> ConflictGraphUse {
    let mut use_ = ConflictGraphUse::default();
    for loop_ in loops {
        if loop_.blocks.is_empty() {
            continue;
        }
        let node_set: BTreeSet<NodeIndex> = loop_.blocks.iter().copied().collect();
        if cfg.graph.edge_references().any(|edge| {
            let source_in = node_set.contains(&edge.source());
            let target_in = node_set.contains(&edge.target());
            (edge.weight().kind == crate::cfg::CfgEdgeKind::CallReturn && source_in)
                || (target_in && !source_in && edge.target() != loop_.header)
        }) {
            continue;
        }
        let mut by_set: BTreeMap<u64, BTreeMap<u64, (Expression, bool)>> = BTreeMap::new();
        for block in &loop_.blocks {
            let Some(lines) = block_lines.get(block) else {
                continue;
            };
            for line in lines {
                let set = (line.line / model.geometry.line_bytes) % model.geometry.sets;
                let entry = by_set
                    .entry(set)
                    .or_default()
                    .entry(line.line)
                    .or_insert_with(|| (Expression::from(0.0), false));
                entry.0 += block_execution(*block) * f64::from(line.accesses);
                entry.1 |= line.writes > 0;
            }
        }
        let entries = loop_entries(loop_);
        for lines in by_set.values() {
            let mut set_lines = 0_usize;
            for (line, (_, writes)) in lines {
                if !model.write_allocate && *writes {
                    // Non-allocating stores can miss repeatedly without an
                    // intervening access to another line.
                    continue;
                }
                let mut miss_sum = Expression::from(0.0);
                let mut any = false;
                for block in &loop_.blocks {
                    if let Some(variable) = line_variables.get(&(*block, *line)) {
                        miss_sum += *variable;
                        any = true;
                    }
                }
                if !any {
                    continue;
                }
                let mut conflict_sum = Expression::from(0.0);
                for (other, (accesses, _)) in lines {
                    if other != line {
                        conflict_sum += accesses.clone();
                    }
                }
                constraints.push(constraint::leq(
                    miss_sum - conflict_sum - entries.clone(),
                    0.0,
                ));
                set_lines = set_lines.saturating_add(1);
            }
            if set_lines > 0 {
                use_.sets = use_.sets.saturating_add(1);
                use_.lines = use_.lines.saturating_add(set_lines);
                use_.constraints = use_.constraints.saturating_add(set_lines);
            }
        }
    }
    use_
}

fn state_base_cost(
    block: &CfgBlock,
    node: NodeIndex,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    models: &CacheIpetModels,
    branch: Option<&BranchIpetModel>,
    pipeline_cost: Option<(f64, f64)>,
    btb_model: Option<&BtbIpetModel>,
) -> f64 {
    let mut cost = block.cycles.map_or(0.0, |cycles| cycles.max)
        + call_cycles.get(&node).copied().unwrap_or(0.0);
    if let Some(model) = &models.instruction
        && let Some(cache) = &block.cache
    {
        cost -= f64::from(cache.misses_max) * f64::from(model.miss_penalty);
    }
    if let Some(model) = &models.data
        && let Some(cache) = &block.data_cache
    {
        cost -= f64::from(cache.misses_max) * f64::from(model.miss_penalty);
    }
    if let Some(branch) = branch
        && let Some(prediction) = &block.branch_prediction
    {
        cost -= f64::from(prediction.mispredicts_max) * branch.penalty();
    }
    if let Some((default, state_cost)) = pipeline_cost {
        cost -= default;
        cost += state_cost;
    }
    if let Some(model) = btb_model
        && let Some(btb) = &block.btb
    {
        cost -= f64::from(btb.misses_max) * model.penalty();
    }
    cost.max(0.0)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct StateProductKey {
    node: NodeIndex,
    instruction: Option<CacheState>,
    data: Option<CacheState>,
    prediction: Option<PredictorState>,
    pipeline: Option<PipelineState>,
    btb: Option<BtbState>,
}

struct StateProductNode {
    key: StateProductKey,
    cost: f64,
    exit_instruction: Option<CacheState>,
    exit_data: Option<CacheState>,
    exit_pipeline: Option<PipelineState>,
}

struct StateProductEdge {
    from: usize,
    to: usize,
    original: EdgeIndex,
    branch_cost: f64,
}

fn state_product_node(
    cfg: &FunctionCfg,
    key: StateProductKey,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    models: &CacheIpetModels,
    branch: Option<&BranchIpetModel>,
    pipeline_model: Option<&PipelineFunctionModel>,
    btb_model: Option<&BtbIpetModel>,
) -> Option<StateProductNode> {
    debug_assert_eq!(
        models.instruction.is_some(),
        key.instruction.is_some(),
        "instruction-cache state/model mismatch"
    );
    debug_assert_eq!(
        models.data.is_some(),
        key.data.is_some(),
        "data-cache state/model mismatch"
    );
    debug_assert_eq!(
        branch.is_some(),
        key.prediction.is_some(),
        "branch-prediction state/model mismatch"
    );
    debug_assert_eq!(
        pipeline_model.is_some(),
        key.pipeline.is_some(),
        "pipeline state/model mismatch"
    );
    debug_assert_eq!(
        btb_model.is_some(),
        key.btb.is_some(),
        "BTB state/model mismatch"
    );
    let block = &cfg.graph[key.node];
    let (pipeline_cost, exit_pipeline) = if let Some(model) = pipeline_model {
        let state = key.pipeline.as_ref()?;
        let (state_cost, exit) = model.transition(block.address, state)?;
        let default = model.default_cost(block.address)?;
        (Some((default, state_cost)), Some(exit))
    } else {
        (None, None)
    };
    let mut cost = state_base_cost(
        block,
        key.node,
        call_cycles,
        models,
        branch,
        pipeline_cost,
        btb_model,
    );
    let mut exit_instruction = key.instruction.clone();
    let mut exit_data = key.data.clone();
    if let Some(model) = &models.instruction
        && let Some(state) = key.instruction.as_ref()
    {
        let accesses = instruction_accesses(block, model.geometry);
        let simulation = simulate(&accesses, state, model.geometry, true);
        cost += f64::from(simulation.misses) * f64::from(model.miss_penalty);
        exit_instruction = Some(simulation.state);
    }
    if let Some(model) = &models.data
        && let Some(state) = key.data.as_ref()
    {
        let accesses = data_accesses(block, model.geometry);
        let simulation = simulate(&accesses, state, model.geometry, model.write_allocate);
        cost += f64::from(simulation.misses) * f64::from(model.miss_penalty);
        exit_data = Some(simulation.state);
    }
    Some(StateProductNode {
        key,
        cost,
        exit_instruction,
        exit_data,
        exit_pipeline,
    })
}

fn branch_edge_transition(
    cfg: &FunctionCfg,
    node: NodeIndex,
    state: &PredictorState,
    model: &BranchIpetModel,
    kind: crate::cfg::CfgEdgeKind,
) -> Vec<(PredictorState, f64)> {
    let Some(branch) = conditional_branch(cfg, node) else {
        return vec![(state.clone(), 0.0)];
    };
    let actual = match kind {
        crate::cfg::CfgEdgeKind::Branch => crate::cfg::CfgBranchDirection::Taken,
        crate::cfg::CfgEdgeKind::Fallthrough => crate::cfg::CfgBranchDirection::NotTaken,
        crate::cfg::CfgEdgeKind::Jump | crate::cfg::CfgEdgeKind::CallReturn => {
            return vec![(state.clone(), 0.0)];
        }
    };
    let mut transitions: BTreeMap<PredictorState, f64> = BTreeMap::new();
    for counter in model.predictor.possible_counters(state, branch.site) {
        let predicted =
            model
                .predictor
                .predict_with_counter(branch.site, branch.taken_is_backward, counter);
        let cost = if predicted == actual {
            0.0
        } else {
            model.penalty()
        };
        let next = model
            .predictor
            .next_state_for_counter(state, branch.site, counter, actual);
        transitions
            .entry(next)
            .and_modify(|current| *current = current.max(cost))
            .or_insert(cost);
    }
    transitions.into_iter().collect()
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_state_product_graph(
    cfg: &FunctionCfg,
    entry: NodeIndex,
    reachable_nodes: &BTreeSet<NodeIndex>,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    models: &CacheIpetModels,
    branch: Option<&BranchIpetModel>,
    pipeline_model: Option<&PipelineFunctionModel>,
    branch_interproc: Option<&BranchInterprocModel>,
    entry_prediction: Option<&PredictorState>,
    btb_model: Option<&BtbIpetModel>,
) -> Option<(Vec<StateProductNode>, Vec<StateProductEdge>)> {
    let start_key = StateProductKey {
        node: entry,
        instruction: models.instruction.map(|model| model.geometry.cold()),
        data: models.data.map(|model| model.geometry.cold()),
        prediction: branch.map(|model| {
            entry_prediction
                .cloned()
                .unwrap_or_else(|| model.predictor.entry_state())
        }),
        pipeline: pipeline_model.map(|model| model.entry_state().clone()),
        btb: btb_model.map(|_| BtbState::default()),
    };
    let mut index_by_key: BTreeMap<StateProductKey, usize> = BTreeMap::new();
    index_by_key.insert(start_key.clone(), 0);
    let mut nodes = vec![state_product_node(
        cfg,
        start_key,
        call_cycles,
        models,
        branch,
        pipeline_model,
        btb_model,
    )?];
    let mut edges = Vec::new();
    let mut queue = VecDeque::from([0_usize]);
    while let Some(from) = queue.pop_front() {
        let key = nodes[from].key.clone();
        let exit_instruction = nodes[from].exit_instruction.clone();
        let exit_data = nodes[from].exit_data.clone();
        let exit_pipeline = nodes[from].exit_pipeline.clone();
        for edge in cfg
            .graph
            .edges_directed(key.node, petgraph::Direction::Outgoing)
        {
            let target = edge.target();
            if !reachable_nodes.contains(&target) {
                continue;
            }
            let reset = edge.weight().kind == crate::cfg::CfgEdgeKind::CallReturn;
            let transitions: Vec<(PredictorState, f64)> =
                if let (Some(branch), Some(state)) = (branch, key.prediction.as_ref()) {
                    if reset && let Some(interproc) = branch_interproc {
                        interproc_call_effect(cfg, key.node, state, interproc)?
                    } else {
                        branch_edge_transition(cfg, key.node, state, branch, edge.weight().kind)
                    }
                } else {
                    vec![(PredictorState::default(), 0.0)]
                };
            let (btb_cost, next_btb) = if let Some(model) = btb_model {
                let state = key.btb.as_ref()?;
                if probes_btb(edge.weight().kind) {
                    let (miss, next) =
                        model
                            .geometry
                            .access(state, edge.weight().site, cfg.graph[target].address);
                    (if miss { model.penalty() } else { 0.0 }, Some(next))
                } else {
                    (0.0, Some(state.clone()))
                }
            } else {
                (0.0, None)
            };
            for (prediction, branch_cost) in transitions {
                let next_key = StateProductKey {
                    node: target,
                    instruction: if reset {
                        models.instruction.map(|model| model.geometry.cold())
                    } else {
                        exit_instruction.clone()
                    },
                    data: if reset {
                        models.data.map(|model| model.geometry.cold())
                    } else {
                        exit_data.clone()
                    },
                    prediction: branch.map(|_| prediction),
                    pipeline: match pipeline_model {
                        Some(model) if reset => Some(model.entry_state().clone()),
                        Some(_) => Some(exit_pipeline.clone()?),
                        None => None,
                    },
                    btb: next_btb.clone(),
                };
                let to = if let Some(&index) = index_by_key.get(&next_key) {
                    index
                } else {
                    if nodes.len() >= MAX_AUTOMATON_NODES {
                        return None;
                    }
                    let index = nodes.len();
                    index_by_key.insert(next_key.clone(), index);
                    nodes.push(state_product_node(
                        cfg,
                        next_key,
                        call_cycles,
                        models,
                        branch,
                        pipeline_model,
                        btb_model,
                    )?);
                    queue.push_back(index);
                    index
                };
                if edges.len() >= MAX_AUTOMATON_EDGES {
                    return None;
                }
                edges.push(StateProductEdge {
                    from,
                    to,
                    original: edge.id(),
                    branch_cost: branch_cost + btb_cost,
                });
            }
        }
    }
    Some((nodes, edges))
}

/// Conservatively combines the branch effects of every call in a block.
///
/// A block with several calls applies them in address order. Each possible
/// callee exit state keeps the branch cost of the callee path that reaches it.
fn interproc_call_effect(
    cfg: &FunctionCfg,
    node: NodeIndex,
    state: &PredictorState,
    interproc: &BranchInterprocModel,
) -> Option<Vec<(PredictorState, f64)>> {
    let block = &cfg.graph[node];
    let mut states = vec![(state.clone(), 0.0_f64)];
    let mut saw_call = false;
    for call in &block.calls {
        if call.null_target {
            continue;
        }
        saw_call = true;
        if call.unresolved || call.heuristic || !call.candidates.is_empty() {
            return None;
        }
        let target = call.target_function.as_ref()?;
        let mut next: BTreeMap<PredictorState, f64> = BTreeMap::new();
        for (state, accumulated) in &states {
            let effect = interproc.effect(target, state)?;
            for (exit, cost) in effect.exits {
                let total = accumulated + cost;
                next.entry(exit)
                    .and_modify(|current| *current = current.max(total))
                    .or_insert(total);
            }
        }
        if next.is_empty() {
            return None;
        }
        states = next.into_iter().collect();
    }
    if !saw_call {
        return Some(states);
    }
    Some(states)
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn solve_function_with_state_products(
    cfg: &FunctionCfg,
    entry: NodeIndex,
    reachable_nodes: &BTreeSet<NodeIndex>,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    loops: &[LoopModel],
    models: &CacheIpetModels,
    branch: Option<&BranchIpetModel>,
    pipeline_stalls: &BTreeMap<EdgeIndex, f64>,
    pipeline_model: Option<&PipelineFunctionModel>,
    branch_interproc: Option<&BranchInterprocModel>,
    entry_prediction: Option<&PredictorState>,
    btb_model: Option<&BtbIpetModel>,
) -> Result<Option<IpetOutcome>, IpetError> {
    let Some((product_nodes, product_edges)) = build_state_product_graph(
        cfg,
        entry,
        reachable_nodes,
        call_cycles,
        models,
        branch,
        pipeline_model,
        branch_interproc,
        entry_prediction,
        btb_model,
    ) else {
        return Ok(None);
    };

    let blocks_with_outgoing: BTreeSet<NodeIndex> = reachable_nodes
        .iter()
        .copied()
        .filter(|node| {
            cfg.graph
                .edges_directed(*node, petgraph::Direction::Outgoing)
                .any(|edge| reachable_nodes.contains(&edge.target()))
        })
        .collect();
    let mut exit_nodes_by_prediction: BTreeMap<PredictorState, Vec<usize>> = BTreeMap::new();
    for (index, node) in product_nodes.iter().enumerate() {
        if let Some(prediction) = &node.key.prediction
            && !blocks_with_outgoing.contains(&node.key.node)
        {
            exit_nodes_by_prediction
                .entry(prediction.clone())
                .or_default()
                .push(index);
        }
    }
    let nonexit_headers: BTreeSet<NodeIndex> = loops
        .iter()
        .filter(|loop_| !loop_.has_exit)
        .map(|loop_| loop_.header)
        .collect();
    let mut vars = ProblemVariables::new();
    let node_variables: Vec<Variable> = product_nodes
        .iter()
        .map(|_| vars.add(good_lp::variable().integer().min(0.0)))
        .collect();
    let edge_variables: Vec<Variable> = product_edges
        .iter()
        .map(|_| vars.add(good_lp::variable().integer().min(0.0)))
        .collect();
    let mut exit_variables: BTreeMap<usize, Variable> = BTreeMap::new();
    for (index, node) in product_nodes.iter().enumerate() {
        if nonexit_headers.contains(&node.key.node) {
            exit_variables.insert(index, vars.add(good_lp::variable().integer().min(0.0)));
        }
    }
    if node_variables
        .len()
        .saturating_add(edge_variables.len())
        .saturating_add(exit_variables.len())
        > MAX_MODEL_VARIABLES
    {
        return Err(IpetError::Unknown("ipet-model-too-large".to_owned()));
    }

    let node_by_block_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let mut nodes_by_block: BTreeMap<NodeIndex, Vec<usize>> = BTreeMap::new();
    for (index, node) in product_nodes.iter().enumerate() {
        nodes_by_block.entry(node.key.node).or_default().push(index);
    }
    let mut edges_by_original: BTreeMap<EdgeIndex, Vec<usize>> = BTreeMap::new();
    for (index, edge) in product_edges.iter().enumerate() {
        edges_by_original
            .entry(edge.original)
            .or_default()
            .push(index);
    }
    let mut incoming = vec![Vec::new(); product_nodes.len()];
    let mut outgoing = vec![Vec::new(); product_nodes.len()];
    for (index, edge) in product_edges.iter().enumerate() {
        incoming[edge.to].push(index);
        outgoing[edge.from].push(index);
    }

    let block_expression = |block: &BlockId| -> Expression {
        let Some(&node) = node_by_block_id.get(block) else {
            return Expression::from(0.0);
        };
        let Some(indices) = nodes_by_block.get(&node) else {
            return Expression::from(0.0);
        };
        let mut expression = Expression::from(0.0);
        for index in indices {
            expression += node_variables[*index];
        }
        expression
    };
    let edge_expression = |edge: EdgeIndex| -> Expression {
        let Some(indices) = edges_by_original.get(&edge) else {
            return Expression::from(0.0);
        };
        let mut expression = Expression::from(0.0);
        for index in indices {
            expression += edge_variables[*index];
        }
        expression
    };

    let mut constraints = Vec::new();
    for (index, node) in product_nodes.iter().enumerate() {
        let variable = node_variables[index];
        let mut incoming_flow = Expression::from(0.0);
        for edge in &incoming[index] {
            incoming_flow += edge_variables[*edge];
        }
        constraints.push(constraint::eq(
            Expression::from(variable) - incoming_flow,
            if index == 0 { 1.0 } else { 0.0 },
        ));
        let mut outgoing_flow = Expression::from(0.0);
        let mut has_outgoing = false;
        for edge in &outgoing[index] {
            outgoing_flow += edge_variables[*edge];
            has_outgoing = true;
        }
        if let Some(exit) = exit_variables.get(&index) {
            outgoing_flow += *exit;
            has_outgoing = true;
        }
        if has_outgoing {
            constraints.push(constraint::eq(
                Expression::from(variable) - outgoing_flow,
                0.0,
            ));
        } else if blocks_with_outgoing.contains(&node.key.node) {
            constraints.push(constraint::leq(Expression::from(variable), 0.0));
        }
    }

    for loop_ in loops {
        let Some(header_nodes) = nodes_by_block.get(&loop_.header) else {
            continue;
        };
        let mut header = Expression::from(0.0);
        for index in header_nodes {
            header += node_variables[*index];
        }
        let mut entries = Expression::from(if loop_.is_entry { 1.0 } else { 0.0 });
        for edge in &loop_.entry_edges {
            if let Some(indices) = edges_by_original.get(edge) {
                for index in indices {
                    entries += edge_variables[*index];
                }
            }
        }
        constraints.push(constraint::leq(
            header - entries * f64::from(loop_.bound),
            0.0,
        ));
    }

    for branch in facts
        .branches()
        .iter()
        .filter(|branch| &branch.function == function_id && scope.matches(&branch.context))
    {
        match branch.outcome {
            BranchOutcome::Both => {
                constraints.push(constraint::leq(block_expression(&branch.block), 0.0));
            }
            BranchOutcome::Taken | BranchOutcome::NotTaken => {
                let Some(&node) = node_by_block_id.get(&branch.block) else {
                    continue;
                };
                let kind = if branch.outcome == BranchOutcome::Taken {
                    crate::cfg::CfgEdgeKind::Branch
                } else {
                    crate::cfg::CfgEdgeKind::Fallthrough
                };
                let edge = cfg
                    .graph
                    .edges_directed(node, petgraph::Direction::Outgoing)
                    .find(|edge| edge.weight().site == branch.site && edge.weight().kind == kind);
                if let Some(edge) = edge {
                    constraints.push(constraint::leq(
                        edge_expression(edge.id()),
                        f64::from(branch.max_count),
                    ));
                }
            }
        }
    }
    for call in facts
        .calls()
        .iter()
        .filter(|call| &call.function == function_id && scope.matches(&call.context))
    {
        constraints.push(constraint::leq(
            block_expression(&call.block),
            f64::from(call.max_count),
        ));
    }
    for conflict in facts.infeasible_paths().iter().filter(|conflict| {
        conflict.applied
            && matches!(conflict.enforcement, InfeasibleEnforcement::Aggregate)
            && conflict
                .function
                .as_ref()
                .is_some_and(|function| function == function_id)
            && scope.matches(&conflict.context)
    }) {
        let mut sum = Expression::from(0.0);
        for element in &conflict.elements {
            match element {
                InfeasibleElement::Block { block } => sum += block_expression(block),
                InfeasibleElement::Edge {
                    source,
                    target,
                    site,
                } => {
                    let Some(&source) = node_by_block_id.get(source) else {
                        continue;
                    };
                    let Some(&target) = node_by_block_id.get(target) else {
                        continue;
                    };
                    if let Some(edge) = cfg
                        .graph
                        .edges_directed(source, petgraph::Direction::Outgoing)
                        .find(|edge| edge.target() == target && edge.weight().site == *site)
                    {
                        sum += edge_expression(edge.id());
                    }
                }
            }
        }
        let Ok(count) = u32::try_from(conflict.elements.len()) else {
            continue;
        };
        let bound = f64::from(count.saturating_sub(1));
        match conflict.scope.as_ref() {
            Some(InfeasibleScope::Function) => {
                constraints.push(constraint::leq(sum, bound));
            }
            Some(InfeasibleScope::Loop { header }) => {
                let header_expression = block_expression(header);
                constraints.push(constraint::leq(sum - header_expression * bound, 0.0));
            }
            Some(InfeasibleScope::CrossFunction) | None => {}
        }
    }

    let mut objective = Expression::from(0.0);
    for (index, node) in product_nodes.iter().enumerate() {
        if node.cost != 0.0 {
            objective += node_variables[index] * node.cost;
        }
    }
    for (index, edge) in product_edges.iter().enumerate() {
        let stall = if pipeline_model.is_some() {
            0.0
        } else {
            pipeline_stalls.get(&edge.original).copied().unwrap_or(0.0)
        };
        if stall != 0.0 || edge.branch_cost != 0.0 {
            objective += edge_variables[index] * (stall + edge.branch_cost);
        }
    }

    let exit_solve = branch_interproc.is_some() && entry_prediction.is_some();
    let exit_vars = exit_solve.then(|| vars.clone());
    let exit_constraints = exit_solve.then(|| constraints.clone());
    let problem = vars.maximise(objective.clone()).using(good_lp::microlp);
    let solution = problem
        .with_all(constraints)
        .solve()
        .map_err(|error| match error {
            good_lp::ResolutionError::Unbounded => {
                IpetError::Unbounded("ipet-unbounded".to_owned())
            }
            other => IpetError::Unknown(format!("ipet-solver: {other}")),
        })?;
    let status = match solution.status() {
        SolutionStatus::Optimal => "optimal",
        SolutionStatus::TimeLimit => "time-limit",
        SolutionStatus::GapLimit => "gap-limit",
    };
    let mut prediction_exit_costs = BTreeMap::new();
    if let (Some(exit_vars), Some(exit_constraints)) = (exit_vars, exit_constraints) {
        if exit_nodes_by_prediction.len() > MAX_BRANCH_EXIT_STATES {
            return Err(IpetError::Unknown("ipet-model-too-large".to_owned()));
        }
        for prediction in exit_nodes_by_prediction.keys() {
            let mut constraints = exit_constraints.clone();
            for (other, other_nodes) in &exit_nodes_by_prediction {
                if other == prediction {
                    continue;
                }
                for index in other_nodes {
                    constraints.push(constraint::eq(
                        Expression::from(node_variables[*index]),
                        0.0,
                    ));
                }
            }
            let solution = match exit_vars
                .clone()
                .maximise(objective.clone())
                .using(good_lp::microlp)
                .with_all(constraints)
                .solve()
            {
                Ok(solution) => solution,
                Err(good_lp::ResolutionError::Infeasible) => continue,
                Err(good_lp::ResolutionError::Unbounded) => {
                    return Err(IpetError::Unbounded("ipet-unbounded".to_owned()));
                }
                Err(error) => {
                    return Err(IpetError::Unknown(format!("ipet-solver: {error}")));
                }
            };
            if !matches!(solution.status(), SolutionStatus::Optimal) {
                return Err(IpetError::Unknown("ipet-branch-effect-timeout".to_owned()));
            }
            let cost = solution.eval(&objective);
            if !cost.is_finite() || cost < 0.0 {
                return Err(IpetError::Unknown("ipet-objective-not-finite".to_owned()));
            }
            prediction_exit_costs.insert(prediction.clone(), cost);
        }
    }
    let mut partial = status != "optimal" || loops.iter().any(|loop_| !loop_.has_exit);
    let mut counts: BTreeMap<NodeIndex, u64> = BTreeMap::new();
    for (index, node) in product_nodes.iter().enumerate() {
        let value = solution.value(node_variables[index]);
        let rounded = value.round();
        if (value - rounded).abs() > 1e-4 {
            partial = true;
        }
        if rounded < 0.0 {
            partial = true;
            continue;
        }
        let count = rounded as u64;
        if count >= u64::from(i32::MAX as u32) {
            return Err(IpetError::Unbounded(
                "ipet-solver-bound-saturated".to_owned(),
            ));
        }
        let entry = counts.entry(node.key.node).or_default();
        *entry = entry
            .checked_add(count)
            .ok_or_else(|| IpetError::Unbounded("ipet-solver-bound-saturated".to_owned()))?;
        if *entry >= u64::from(i32::MAX as u32) {
            return Err(IpetError::Unbounded(
                "ipet-solver-bound-saturated".to_owned(),
            ));
        }
    }
    let objective = solution.eval(&objective);
    if !objective.is_finite() || objective < 0.0 {
        return Err(IpetError::Unknown("ipet-objective-not-finite".to_owned()));
    }
    let blocks = counts
        .into_iter()
        .filter(|(_, executions)| *executions > 0)
        .map(|(node, executions)| CfgIpetBlockCount {
            block: cfg.graph[node].id.clone(),
            executions,
        })
        .collect();
    Ok(Some(IpetOutcome {
        solution: CfgIpetSolution {
            solver: SOLVER_NAME.to_owned(),
            status: status.to_owned(),
            objective,
            cache_model: (!models.is_empty()).then(|| "state-product".to_owned()),
            cache_conflicts: None,
            cache_ccg: None,
            pipeline_model: pipeline_model.map(|_| "state-product".to_owned()),
            branch_model: branch.map(|_| {
                if branch_interproc.is_some() {
                    "interprocedural-state-product"
                } else {
                    "state-product"
                }
                .to_owned()
            }),
            btb_model: btb_model.map(|_| "state-product".to_owned()),
            blocks,
        },
        partial,
        prediction_exit_costs,
    }))
}

fn non_loop_constraints(
    cfg: &FunctionCfg,
    block_vars: &BTreeMap<NodeIndex, Variable>,
    edge_vars: &BTreeMap<EdgeIndex, Variable>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> Vec<good_lp::Constraint> {
    let node_by_id: BTreeMap<_, _> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let mut constraints = Vec::new();
    for branch in facts
        .branches()
        .iter()
        .filter(|branch| &branch.function == function_id && scope.matches(&branch.context))
    {
        let Some(&node) = node_by_id.get(&branch.block) else {
            continue;
        };
        let Some(&block_var) = block_vars.get(&node) else {
            continue;
        };
        match branch.outcome {
            BranchOutcome::Both => {
                constraints.push(constraint::leq(Expression::from(block_var), 0.0));
            }
            BranchOutcome::Taken | BranchOutcome::NotTaken => {
                let kind = if branch.outcome == BranchOutcome::Taken {
                    crate::cfg::CfgEdgeKind::Branch
                } else {
                    crate::cfg::CfgEdgeKind::Fallthrough
                };
                let edge = cfg
                    .graph
                    .edges_directed(node, petgraph::Direction::Outgoing)
                    .find(|edge| edge.weight().site == branch.site && edge.weight().kind == kind);
                if let Some(edge_var) = edge.and_then(|edge| edge_vars.get(&edge.id())) {
                    constraints.push(constraint::leq(
                        Expression::from(*edge_var),
                        f64::from(branch.max_count),
                    ));
                }
            }
        }
    }
    for call in facts
        .calls()
        .iter()
        .filter(|call| &call.function == function_id && scope.matches(&call.context))
    {
        let Some(&node) = node_by_id.get(&call.block) else {
            continue;
        };
        let Some(&block_var) = block_vars.get(&node) else {
            continue;
        };
        constraints.push(constraint::leq(
            Expression::from(block_var),
            f64::from(call.max_count),
        ));
    }
    constraints
}

#[cfg(test)]
mod tests {
    use super::{analyze_program, analyze_program_with_branch_prediction};
    use crate::board_profile::BoardProfile;
    use crate::cfg::{
        CfgBlockDraft, CfgCallSite, CfgEdgeDraft, CfgEdgeKind, CfgFunction, CfgInstruction,
        CfgMemoryAccess, CfgMemoryAccessKind, CfgMemoryResolution, CfgPipelineEdgeInfo,
        CfgPipelineInfo, CfgTerminator, FunctionCfg, ProgramCfg,
    };
    use crate::flow_facts::{
        FlowFactDocument, FlowFacts, InfeasibleEnforcement, InfeasibleScope, OrderedReset,
    };
    use elf2tdg_schema::{Addr, CostRange, FunctionId, FunctionKind, Language};

    fn profile() -> BoardProfile {
        BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:ipet-conflict-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
"#,
        )
        .expect("valid profile")
    }

    fn facts() -> FlowFacts {
        let board = profile();
        FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"))
    }

    fn instruction(address: u64, terminator: CfgTerminator, cycles: f64) -> CfgInstruction {
        CfgInstruction {
            address,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "nop".to_owned(),
            operands: String::new(),
            text: "nop".to_owned(),
            is_call: false,
            is_jump: matches!(terminator, CfgTerminator::Branch | CfgTerminator::Jump),
            is_return: terminator == CfgTerminator::Return,
            is_conditional: terminator == CfgTerminator::Branch,
            direct_target: None,
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: Some(CostRange::exact(cycles)),
            source: None,
        }
    }

    fn block(address: u64, terminator: CfgTerminator, cycles: f64) -> CfgBlockDraft {
        CfgBlockDraft {
            address,
            size: 2,
            instructions: vec![instruction(address, terminator, cycles)],
            calls: Vec::new(),
            cycles: Some(CostRange::exact(cycles)),
            terminator,
        }
    }

    fn edge(from: u64, to: u64, kind: CfgEdgeKind) -> CfgEdgeDraft {
        CfgEdgeDraft {
            from,
            to,
            kind,
            site: from,
            conditional: kind == CfgEdgeKind::Branch,
        }
    }

    fn function(address: u64, cfg: FunctionCfg) -> CfgFunction {
        CfgFunction {
            id: FunctionId::new(format!("fn:0x{address:x}")),
            primary_name: "main".to_owned(),
            demangled_name: None,
            symbols: Vec::new(),
            language: Language::C,
            kind: FunctionKind::Normal,
            address,
            size: 0x40,
            section: ".text".to_owned(),
            source: None,
            inline_frames: Vec::new(),
            noreturn: None,
            cfg,
            wcet: None,
        }
    }

    fn analyze_with(program: &ProgramCfg, text: &str) -> (f64, FlowFacts) {
        let mut constrained = program.clone();
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(text, "conflict.ffx").expect("parse");
        facts
            .apply_document(document, program)
            .expect("apply conflict");
        let _ = analyze_program(&mut constrained, &facts);
        let cycles = constrained.functions[0]
            .wcet
            .as_ref()
            .expect("function WCET")
            .cycles
            .expect("finite cycles");
        (cycles, facts)
    }

    fn analyze_baseline(program: &ProgramCfg) -> f64 {
        let mut program = program.clone();
        let _ = analyze_program(&mut program, &facts());
        program.functions[0]
            .wcet
            .as_ref()
            .expect("function WCET")
            .cycles
            .expect("finite cycles")
    }

    fn diamond_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x1000,
            FunctionCfg::build(
                vec![
                    block(0x1000, CfgTerminator::Branch, 1.0),
                    block(0x1002, CfgTerminator::Fallthrough, 10.0),
                    block(0x1004, CfgTerminator::Fallthrough, 20.0),
                    block(0x1006, CfgTerminator::Return, 1.0),
                    block(0x1008, CfgTerminator::Fallthrough, 5.0),
                ],
                vec![
                    edge(0x1000, 0x1002, CfgEdgeKind::Branch),
                    edge(0x1000, 0x1008, CfgEdgeKind::Fallthrough),
                    edge(0x1002, 0x1004, CfgEdgeKind::Fallthrough),
                    edge(0x1004, 0x1006, CfgEdgeKind::Fallthrough),
                    edge(0x1008, 0x1006, CfgEdgeKind::Fallthrough),
                ],
                Some(0x1000),
            ),
        )])
    }

    fn loop_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x2000,
            FunctionCfg::build(
                vec![
                    block(0x2000, CfgTerminator::Fallthrough, 1.0),
                    block(0x2002, CfgTerminator::Branch, 1.0),
                    block(0x2004, CfgTerminator::Fallthrough, 10.0),
                    block(0x2006, CfgTerminator::Fallthrough, 20.0),
                    block(0x2008, CfgTerminator::Fallthrough, 5.0),
                    block(0x200a, CfgTerminator::Branch, 1.0),
                    block(0x200c, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x2000, 0x2002, CfgEdgeKind::Fallthrough),
                    edge(0x2002, 0x2004, CfgEdgeKind::Branch),
                    edge(0x2002, 0x2008, CfgEdgeKind::Fallthrough),
                    edge(0x2004, 0x2006, CfgEdgeKind::Fallthrough),
                    edge(0x2006, 0x200a, CfgEdgeKind::Fallthrough),
                    edge(0x2008, 0x200a, CfgEdgeKind::Fallthrough),
                    edge(0x200a, 0x2002, CfgEdgeKind::Branch),
                    edge(0x200a, 0x200c, CfgEdgeKind::Fallthrough),
                ],
                Some(0x2000),
            ),
        )])
    }

    fn named_function(address: u64, name: &str, cfg: FunctionCfg) -> CfgFunction {
        let mut function = function(address, cfg);
        function.primary_name = name.to_owned();
        function
    }

    fn call_site(site: u64, target: u64) -> CfgCallSite {
        CfgCallSite {
            site,
            target: Some(target),
            target_function: Some(FunctionId::new(format!("fn:0x{target:x}"))),
            direct: true,
            tail: false,
            conditional: false,
            heuristic: false,
            unresolved: false,
            null_target: false,
            noreturn: false,
            candidates: Vec::new(),
        }
    }

    fn call_block(address: u64, cycles: f64, target: u64) -> CfgBlockDraft {
        let mut instruction = instruction(address, CfgTerminator::Call, cycles);
        instruction.is_call = true;
        CfgBlockDraft {
            address,
            size: 2,
            instructions: vec![instruction],
            calls: vec![call_site(address, target)],
            cycles: Some(CostRange::exact(cycles)),
            terminator: CfgTerminator::Call,
        }
    }

    fn straight_callee_program(caller: FunctionCfg) -> ProgramCfg {
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0x2000, CfgTerminator::Fallthrough, 1.0),
                block(0x2002, CfgTerminator::Fallthrough, 1.0),
                block(0x2004, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x2000, 0x2002, CfgEdgeKind::Fallthrough),
                edge(0x2002, 0x2004, CfgEdgeKind::Fallthrough),
            ],
            Some(0x2000),
        );
        ProgramCfg::new(vec![
            named_function(0x1000, "main", caller),
            named_function(0x2000, "helper", helper_cfg),
        ])
    }

    fn branching_callee_program(caller: FunctionCfg) -> ProgramCfg {
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0x2000, CfgTerminator::Fallthrough, 1.0),
                block(0x2002, CfgTerminator::Branch, 1.0),
                block(0x2004, CfgTerminator::Fallthrough, 1.0),
                block(0x2006, CfgTerminator::Fallthrough, 1.0),
                block(0x2008, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x2000, 0x2002, CfgEdgeKind::Fallthrough),
                edge(0x2002, 0x2004, CfgEdgeKind::Branch),
                edge(0x2002, 0x2006, CfgEdgeKind::Fallthrough),
                edge(0x2004, 0x2008, CfgEdgeKind::Fallthrough),
                edge(0x2006, 0x2008, CfgEdgeKind::Fallthrough),
            ],
            Some(0x2000),
        );
        ProgramCfg::new(vec![
            named_function(0x1000, "main", caller),
            named_function(0x2000, "helper", helper_cfg),
        ])
    }

    fn branch_caller_program() -> ProgramCfg {
        let caller = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Fallthrough, 1.0),
                block(0x1002, CfgTerminator::Branch, 1.0),
                block(0x1004, CfgTerminator::Fallthrough, 50.0),
                call_block(0x1006, 2.0, 0x2000),
                block(0x1008, CfgTerminator::Fallthrough, 5.0),
                block(0x100a, CfgTerminator::Return, 1.0),
                block(0x100c, CfgTerminator::Fallthrough, 1.0),
                block(0x100e, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                edge(0x1002, 0x1004, CfgEdgeKind::Branch),
                edge(0x1002, 0x100c, CfgEdgeKind::Fallthrough),
                edge(0x1004, 0x1006, CfgEdgeKind::Fallthrough),
                edge(0x1006, 0x1008, CfgEdgeKind::CallReturn),
                edge(0x1008, 0x100a, CfgEdgeKind::Fallthrough),
                edge(0x100c, 0x100e, CfgEdgeKind::Fallthrough),
            ],
            Some(0x1000),
        );
        straight_callee_program(caller)
    }

    fn loop_caller_program(branching: bool) -> ProgramCfg {
        let caller = FunctionCfg::build(
            vec![
                block(0x3000, CfgTerminator::Fallthrough, 1.0),
                block(0x3002, CfgTerminator::Branch, 1.0),
                call_block(0x3004, 1.0, 0x2000),
                block(0x3006, CfgTerminator::Fallthrough, 1.0),
                block(0x3008, CfgTerminator::Branch, 1.0),
                block(0x300a, CfgTerminator::Fallthrough, 50.0),
                block(0x300c, CfgTerminator::Fallthrough, 1.0),
                block(0x300e, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x3000, 0x3002, CfgEdgeKind::Fallthrough),
                edge(0x3002, 0x3004, CfgEdgeKind::Branch),
                edge(0x3002, 0x3008, CfgEdgeKind::Fallthrough),
                edge(0x3004, 0x3006, CfgEdgeKind::CallReturn),
                edge(0x3006, 0x3002, CfgEdgeKind::Branch),
                edge(0x3008, 0x300a, CfgEdgeKind::Branch),
                edge(0x3008, 0x300c, CfgEdgeKind::Fallthrough),
                edge(0x300a, 0x300e, CfgEdgeKind::Fallthrough),
                edge(0x300c, 0x300e, CfgEdgeKind::Fallthrough),
            ],
            Some(0x3000),
        );
        if branching {
            branching_callee_program(caller)
        } else {
            let helper_cfg = FunctionCfg::build(
                vec![
                    block(0x2000, CfgTerminator::Fallthrough, 1.0),
                    block(0x2002, CfgTerminator::Fallthrough, 1.0),
                    block(0x2004, CfgTerminator::Fallthrough, 1.0),
                    block(0x2006, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x2000, 0x2002, CfgEdgeKind::Fallthrough),
                    edge(0x2002, 0x2004, CfgEdgeKind::Fallthrough),
                    edge(0x2004, 0x2006, CfgEdgeKind::Fallthrough),
                ],
                Some(0x2000),
            );
            ProgramCfg::new(vec![
                named_function(0x1000, "main", caller),
                named_function(0x2000, "helper", helper_cfg),
            ])
        }
    }

    fn dominating_caller_cfg() -> FunctionCfg {
        FunctionCfg::build(
            vec![
                block(0x5000, CfgTerminator::Fallthrough, 1.0),
                call_block(0x5002, 1.0, 0x2000),
                block(0x5004, CfgTerminator::Branch, 1.0),
                block(0x5006, CfgTerminator::Fallthrough, 50.0),
                block(0x5008, CfgTerminator::Fallthrough, 1.0),
                block(0x500a, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x5000, 0x5002, CfgEdgeKind::Fallthrough),
                edge(0x5002, 0x5004, CfgEdgeKind::CallReturn),
                edge(0x5004, 0x5006, CfgEdgeKind::Branch),
                edge(0x5004, 0x5008, CfgEdgeKind::Fallthrough),
                edge(0x5006, 0x500a, CfgEdgeKind::Fallthrough),
                edge(0x5008, 0x500a, CfgEdgeKind::Fallthrough),
            ],
            Some(0x5000),
        )
    }

    fn dominating_call_program() -> ProgramCfg {
        let caller = dominating_caller_cfg();
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0x2000, CfgTerminator::Fallthrough, 1.0),
                block(0x2002, CfgTerminator::Fallthrough, 1.0),
                block(0x2004, CfgTerminator::Fallthrough, 1.0),
                block(0x2006, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x2000, 0x2002, CfgEdgeKind::Fallthrough),
                edge(0x2002, 0x2004, CfgEdgeKind::Fallthrough),
                edge(0x2004, 0x2006, CfgEdgeKind::Fallthrough),
            ],
            Some(0x2000),
        );
        ProgramCfg::new(vec![
            named_function(0x1000, "main", caller),
            named_function(0x2000, "helper", helper_cfg),
        ])
    }

    fn loop_callee_program() -> ProgramCfg {
        let caller = dominating_caller_cfg();
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0x2000, CfgTerminator::Branch, 1.0),
                block(0x2002, CfgTerminator::Fallthrough, 1.0),
                block(0x2004, CfgTerminator::Fallthrough, 1.0),
                block(0x2006, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x2000, 0x2002, CfgEdgeKind::Branch),
                edge(0x2000, 0x2006, CfgEdgeKind::Fallthrough),
                edge(0x2002, 0x2004, CfgEdgeKind::Fallthrough),
                edge(0x2004, 0x2000, CfgEdgeKind::Branch),
            ],
            Some(0x2000),
        );
        ProgramCfg::new(vec![
            named_function(0x1000, "main", caller),
            named_function(0x2000, "helper", helper_cfg),
        ])
    }

    #[test]
    fn edge_conflict_removes_a_feasible_high_cost_path() {
        let program = diamond_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <edge src="0x1002" dst="0x1004"/>
      <edge src="0x1004" dst="0x1006"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(baseline, 32.0);
        assert_eq!(constrained, 7.0);
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(conflict.scope, Some(InfeasibleScope::Function));
        assert_eq!(conflict.elements.len(), 2);
    }

    #[test]
    fn loop_conflict_uses_the_header_iteration_budget() {
        let program = loop_program();
        let baseline = analyze_baseline(&program);
        let (constrained, applied_facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="*">
        <conflict>
          <block address="0x2004"/>
          <block address="0x2006"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(constrained < baseline, "{constrained} < {baseline}");
        assert!(constrained > 0.0);
        let conflict = &applied_facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0x2002"
        ));

        let mut exit_facts = facts();
        let exit_document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="*">
        <conflict>
          <block address="0x2004"/>
          <edge src="0x200a" dst="0x200c"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            "exit-conflict.ffx",
        )
        .expect("parse");
        exit_facts
            .apply_document(exit_document, &program)
            .expect("apply conflict");
        let conflict = &exit_facts.infeasible_paths()[0];
        assert!(!conflict.applied);
        assert!(
            conflict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("outside the loop"))
        );
    }

    #[test]
    fn structurally_forced_ordered_conflicts_are_applied() {
        let program = diamond_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <edge src="0x1002" dst="0x1004"/>
      <edge src="0x1004" dst="0x1006"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(baseline, 32.0);
        assert_eq!(constrained, 7.0);
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(conflict.ordered);
        assert_eq!(facts.info().conflicts[0].mode.as_deref(), Some("aggregate"));
    }

    #[test]
    fn structurally_impossible_ordered_conflicts_add_no_constraint() {
        let program = diamond_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <edge src="0x1004" dst="0x1006"/>
      <edge src="0x1002" dst="0x1004"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(constrained, baseline);
        let conflict = &facts.infeasible_paths()[0];
        assert!(!conflict.applied);
        assert!(conflict.ordered);
        assert!(
            conflict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("structurally impossible"))
        );
    }

    #[test]
    fn ordered_iteration_conflicts_use_forced_in_iteration_order() {
        let program = loop_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="*">
        <conflict ordered="yes">
          <block address="0x2004"/>
          <block address="0x2006"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(constrained < baseline, "{constrained} < {baseline}");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0x2002"
        ));
    }

    #[test]
    fn whole_loop_ordered_conflicts_use_the_automaton_product() {
        let program = loop_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <conflict ordered="yes">
        <block address="0x2004"/>
        <block address="0x2006"/>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(constrained < baseline, "{constrained} < {baseline}");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopEntry { .. }
            }
        ));
        assert_eq!(facts.info().conflicts[0].mode.as_deref(), Some("automaton"));
    }

    #[test]
    fn cross_iteration_sequence_forbids_the_loop_backedge() {
        let program = loop_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x200a"/>
      <block address="0x2002"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert!(
            constrained < baseline,
            "latch-then-header must exclude later iterations: {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::Function
            }
        ));
    }

    #[test]
    fn automaton_product_applies_branch_facts() {
        let program = loop_program();
        let (automaton_only, _) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x200a"/>
      <block address="0x2002"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        let (constrained, _) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x200a"/>
      <block address="0x2002"/>
    </conflict>
    <conditional address="0x2002">
      <case cond="1" executed="false"/>
    </conditional>
  </function>
</flowfacts>
"#,
        );
        assert!(
            constrained < automaton_only,
            "branch fact must apply in the automaton product: {constrained} < {automaton_only}"
        );
    }

    #[test]
    fn multiple_ordered_automata_combine_states() {
        let program = loop_program();
        let (single, _) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x200a"/>
      <block address="0x2002"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        let (combined, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x200a"/>
      <block address="0x2002"/>
    </conflict>
    <conflict ordered="yes">
      <block address="0x2004"/>
      <block address="0x2006"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert!(
            combined < single,
            "a second automaton must further constrain the product: {combined} < {single}"
        );
        assert_eq!(facts.infeasible_paths().len(), 2);
        assert!(
            facts
                .infeasible_paths()
                .iter()
                .all(|conflict| conflict.applied)
        );
    }

    #[test]
    fn function_order_across_iterations_uses_the_automaton_product() {
        let program = loop_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x2004"/>
      <block address="0x2006"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert!(constrained < baseline, "{constrained} < {baseline}");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::Function
            }
        ));
    }

    #[test]
    fn cross_function_conflict_prunes_a_caller_branch() {
        let program = branch_caller_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x1004"/>
      <call name="helper">
        <block address="0x2002"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(baseline, 63.0);
        assert_eq!(constrained, 4.0);
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(conflict.scope, Some(InfeasibleScope::CrossFunction));
        assert_eq!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossFunctionAutomaton
        );
        assert_eq!(conflict.elements.len(), 2);
        let info = facts.info();
        assert_eq!(info.conflicts[0].scope.as_deref(), Some("cross-function"));
        assert_eq!(info.conflicts[0].mode.as_deref(), Some("automaton"));
        let call = info.conflicts[0].call.as_ref().expect("call boundary");
        assert_eq!(call.callee.as_str(), "fn:0x2000");
        assert_eq!(call.block.as_str(), "bb:0x1006");
        assert_eq!(call.continuation.as_str(), "bb:0x1008");
        assert_eq!(
            info.conflicts[0].elements[0]
                .function
                .as_ref()
                .unwrap()
                .as_str(),
            "fn:0x1000"
        );
        assert_eq!(
            info.conflicts[0].elements[1]
                .function
                .as_ref()
                .unwrap()
                .as_str(),
            "fn:0x2000"
        );
    }

    #[test]
    fn cross_function_group_completes_within_one_call() {
        let program = dominating_call_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <call name="helper">
        <block address="0x2002"/>
        <block address="0x2004"/>
      </call>
      <block address="0x5006"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(baseline, 58.0);
        assert_eq!(constrained, 9.0);
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(conflict.scope, Some(InfeasibleScope::CrossFunction));
    }

    #[test]
    fn cross_function_callee_loops_stay_bounded() {
        let program = loop_callee_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <call name="helper">
        <block address="0x2002"/>
      </call>
      <block address="0x5006"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert!(baseline.is_finite());
        assert!(constrained.is_finite());
        assert!(
            constrained <= baseline,
            "the inlined callee must not add caller paths: {constrained} <= {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(conflict.scope, Some(InfeasibleScope::CrossFunction));
    }

    #[test]
    fn cross_function_group_does_not_span_call_invocations() {
        let program = loop_caller_program(true);
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <call name="helper">
        <block address="0x2004"/>
        <block address="0x2006"/>
      </call>
      <block address="0x300a"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(baseline, 75.0);
        assert_eq!(constrained, baseline);
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn cross_function_group_progress_rolls_back_at_return() {
        let program = loop_caller_program(true);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <call name="helper">
        <block address="0x2004"/>
        <block address="0x2006"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
            "rollback.ffx",
        )
        .expect("parse");
        facts
            .apply_document(document, &program)
            .expect("apply conflict");
        let caller = &program.functions[0];
        let analysis = crate::cfg_graph::analyze(&caller.cfg);
        let reachable: std::collections::BTreeSet<_> = caller
            .cfg
            .blocks_by_address
            .values()
            .copied()
            .filter(|node| analysis.reachable.contains(&caller.cfg.graph[*node].id))
            .collect();
        let scope = crate::flow_facts::FactScope::Insensitive;
        let cross = super::cross_function_constraints(&facts, &caller.id, scope);
        let model = super::build_cross_model(
            &program,
            &caller.cfg,
            caller.cfg.entry.expect("entry"),
            &reachable,
            &std::collections::BTreeMap::new(),
            &facts,
            &caller.id,
            scope,
            &cross,
        )
        .expect("cross model");
        let automata = super::cross_automaton_models(&model, &cross).expect("automata");
        let automaton = &automata[0];
        let find_edge = |predicate: &dyn Fn(&super::ModelEdge) -> bool| {
            model.edges.iter().position(predicate).expect("model edge")
        };
        let enter = find_edge(&|edge| edge.kind == super::ModelEdgeKind::EnterCall);
        let b_edge = find_edge(&|edge| {
            edge.kind == super::ModelEdgeKind::CalleeEdge
                && model.nodes[edge.target].block.as_str() == "bb:0x2004"
        });
        let c_edge = find_edge(&|edge| {
            edge.kind == super::ModelEdgeKind::CalleeEdge
                && model.nodes[edge.target].block.as_str() == "bb:0x2006"
        });
        let return_edge = find_edge(&|edge| edge.kind == super::ModelEdgeKind::ReturnCall);
        let mut state = super::initial_cross_state(automaton, &model.nodes[model.entry].block)
            .expect("initial state");
        state = super::advance_cross_state(
            &model,
            &program,
            &caller.cfg,
            automaton,
            state,
            &model.edges[enter],
        )
        .expect("enter");
        state = super::advance_cross_state(
            &model,
            &program,
            &caller.cfg,
            automaton,
            state,
            &model.edges[b_edge],
        )
        .expect("first group element");
        assert_eq!(state.sub, 1);
        state = super::advance_cross_state(
            &model,
            &program,
            &caller.cfg,
            automaton,
            state,
            &model.edges[return_edge],
        )
        .expect("return");
        assert_eq!(state.slot, automaton.group_start);
        assert_eq!(state.sub, 0);
        state = super::advance_cross_state(
            &model,
            &program,
            &caller.cfg,
            automaton,
            state,
            &model.edges[enter],
        )
        .expect("re-enter");
        state = super::advance_cross_state(
            &model,
            &program,
            &caller.cfg,
            automaton,
            state,
            &model.edges[c_edge],
        )
        .expect("second invocation");
        assert_eq!(
            state.sub, 0,
            "the group must not continue across call invocations"
        );
    }

    #[test]
    fn ambiguous_cross_function_call_sites_are_ignored() {
        let caller = FunctionCfg::build(
            vec![
                block(0x4000, CfgTerminator::Fallthrough, 1.0),
                call_block(0x4002, 1.0, 0x2000),
                call_block(0x4004, 1.0, 0x2000),
                block(0x4006, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x4000, 0x4002, CfgEdgeKind::Fallthrough),
                edge(0x4002, 0x4004, CfgEdgeKind::CallReturn),
                edge(0x4004, 0x4006, CfgEdgeKind::CallReturn),
            ],
            Some(0x4000),
        );
        let program = straight_callee_program(caller);
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x4000"/>
      <call name="helper">
        <block address="0x2002"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(constrained, baseline);
        let conflict = &facts.infeasible_paths()[0];
        assert!(!conflict.applied);
        assert!(
            conflict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no unique call site"))
        );
    }

    #[test]
    fn unsupported_cross_function_shapes_are_ignored() {
        let program = branch_caller_program();
        let (loop_scoped, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x1002">
      <conflict ordered="yes">
        <block address="0x1004"/>
        <call name="helper">
          <block address="0x2002"/>
        </call>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(loop_scoped, 63.0);
        let conflict = &facts.infeasible_paths()[0];
        assert!(!conflict.applied);
        assert!(
            conflict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("loop- or iteration-scoped"))
        );

        let (multi_group, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <call name="helper">
        <block address="0x2002"/>
      </call>
      <call name="helper">
        <block address="0x2004"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(multi_group, 63.0);
        let conflict = &facts.infeasible_paths()[0];
        assert!(!conflict.applied);
        assert!(
            conflict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("exactly one <call> group"))
        );
    }

    fn cache_board(extra: &str) -> BoardProfile {
        BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:ipet-cache-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

{extra}

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
bound_nonterminating_loops = true
"#
        ))
        .expect("valid cache profile")
    }

    fn cache_loop_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x1000,
            FunctionCfg::build(
                vec![block(0x1000, CfgTerminator::Jump, 1.0)],
                vec![edge(0x1000, 0x1000, CfgEdgeKind::Jump)],
                Some(0x1000),
            ),
        )])
    }

    fn cache_conflict_program() -> ProgramCfg {
        let a_instructions = (0..8)
            .map(|index| instruction(0x4010 + 2 * index, CfgTerminator::Fallthrough, 1.0))
            .collect();
        ProgramCfg::new(vec![function(
            0x4000,
            FunctionCfg::build(
                vec![
                    block(0x4000, CfgTerminator::Fallthrough, 1.0),
                    CfgBlockDraft {
                        address: 0x4010,
                        size: 16,
                        instructions: a_instructions,
                        calls: Vec::new(),
                        cycles: Some(CostRange::exact(8.0)),
                        terminator: CfgTerminator::Fallthrough,
                    },
                    block(0x4030, CfgTerminator::Branch, 1.0),
                    block(0x4050, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x4000, 0x4010, CfgEdgeKind::Fallthrough),
                    edge(0x4010, 0x4030, CfgEdgeKind::Fallthrough),
                    edge(0x4030, 0x4000, CfgEdgeKind::Branch),
                    edge(0x4030, 0x4050, CfgEdgeKind::Fallthrough),
                ],
                Some(0x4000),
            ),
        )])
    }

    fn cache_line_split_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x3000,
            FunctionCfg::build(
                vec![
                    block(0x3000, CfgTerminator::Fallthrough, 1.0),
                    block(0x3010, CfgTerminator::Branch, 1.0),
                    block(0x3030, CfgTerminator::Jump, 1.0),
                    block(0x3050, CfgTerminator::Jump, 1.0),
                ],
                vec![
                    edge(0x3000, 0x3010, CfgEdgeKind::Fallthrough),
                    edge(0x3010, 0x3030, CfgEdgeKind::Fallthrough),
                    edge(0x3010, 0x3050, CfgEdgeKind::Branch),
                    edge(0x3030, 0x3000, CfgEdgeKind::Jump),
                    edge(0x3050, 0x3000, CfgEdgeKind::Jump),
                ],
                Some(0x3000),
            ),
        )])
    }

    fn cache_loop_header_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x2000,
            FunctionCfg::build(
                vec![
                    block(0x2002, CfgTerminator::Branch, 1.0),
                    block(0x2004, CfgTerminator::Fallthrough, 10.0),
                    block(0x2006, CfgTerminator::Fallthrough, 20.0),
                    block(0x2008, CfgTerminator::Fallthrough, 5.0),
                    block(0x200a, CfgTerminator::Branch, 1.0),
                    block(0x200c, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x2002, 0x2004, CfgEdgeKind::Branch),
                    edge(0x2002, 0x2008, CfgEdgeKind::Fallthrough),
                    edge(0x2004, 0x2006, CfgEdgeKind::Fallthrough),
                    edge(0x2006, 0x200a, CfgEdgeKind::Fallthrough),
                    edge(0x2008, 0x200a, CfgEdgeKind::Fallthrough),
                    edge(0x200a, 0x2002, CfgEdgeKind::Branch),
                    edge(0x200a, 0x200c, CfgEdgeKind::Fallthrough),
                ],
                Some(0x2002),
            ),
        )])
    }

    fn data_cache_loop_program() -> ProgramCfg {
        let mut instruction = instruction(0x1000, CfgTerminator::Jump, 1.0);
        instruction.memory_accesses = vec![CfgMemoryAccess {
            kind: CfgMemoryAccessKind::Read,
            address: Some(Addr::new(0x2000)),
            width: 4,
            resolution: CfgMemoryResolution::Direct,
            base: None,
            index: None,
            disp: 0,
        }];
        let block = CfgBlockDraft {
            address: 0x1000,
            size: 2,
            instructions: vec![instruction],
            calls: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            terminator: CfgTerminator::Jump,
        };
        ProgramCfg::new(vec![function(
            0x1000,
            FunctionCfg::build(
                vec![block],
                vec![edge(0x1000, 0x1000, CfgEdgeKind::Jump)],
                Some(0x1000),
            ),
        )])
    }

    fn data_cache_write_loop_program() -> ProgramCfg {
        let mut instruction = instruction(0x1000, CfgTerminator::Jump, 1.0);
        instruction.memory_accesses = vec![
            CfgMemoryAccess {
                kind: CfgMemoryAccessKind::Read,
                address: Some(Addr::new(0x2000)),
                width: 4,
                resolution: CfgMemoryResolution::Direct,
                base: None,
                index: None,
                disp: 0,
            },
            CfgMemoryAccess {
                kind: CfgMemoryAccessKind::Write,
                address: Some(Addr::new(0x2000)),
                width: 4,
                resolution: CfgMemoryResolution::Direct,
                base: None,
                index: None,
                disp: 0,
            },
        ];
        let block = CfgBlockDraft {
            address: 0x1000,
            size: 2,
            instructions: vec![instruction],
            calls: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            terminator: CfgTerminator::Jump,
        };
        ProgramCfg::new(vec![function(
            0x1000,
            FunctionCfg::build(
                vec![block],
                vec![edge(0x1000, 0x1000, CfgEdgeKind::Jump)],
                Some(0x1000),
            ),
        )])
    }

    fn prepare_cache_program(program: &mut ProgramCfg, board: &BoardProfile) {
        if let Some(cache) = board.instruction_cache() {
            let info = crate::icache::analyze_program(program, cache);
            program.cache = Some(info);
        }
        if let Some(cache) = board.data_cache() {
            let info = crate::dcache::analyze_program(program, cache);
            program.data_cache = Some(info);
        }
    }

    fn disable_cache_state_ipet(program: &mut ProgramCfg) {
        if let Some(cache) = &mut program.cache {
            cache.invalidate_on_call = false;
        }
        if let Some(cache) = &mut program.data_cache {
            cache.invalidate_on_call = false;
        }
    }

    fn run_ipet(program: &mut ProgramCfg, board: &BoardProfile) -> (f64, Option<String>) {
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let _ = analyze_program(program, &facts);
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("IPET solution");
        (ipet.objective, ipet.cache_model.clone())
    }

    #[test]
    fn instruction_cache_state_product_avoids_repeated_misses() {
        let board = cache_board(
            r"
[instruction_cache]
size = 32
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
",
        );
        let mut program = cache_loop_program();
        prepare_cache_program(&mut program, &board);

        let mut block_bounds = program.clone();
        disable_cache_state_ipet(&mut block_bounds);
        let (block_objective, block_model) = run_ipet(&mut block_bounds, &board);
        assert_eq!(block_objective, 44.0);
        assert_eq!(block_model.as_deref(), Some("block-bounds"));

        let (objective, model) = run_ipet(&mut program, &board);
        assert_eq!(objective, 14.0);
        assert_eq!(model.as_deref(), Some("state-product"));
    }

    #[test]
    fn data_cache_state_product_avoids_repeated_misses() {
        let board = cache_board(
            r"
[data_cache]
size = 64
line_bytes = 32
ways = 2
miss_penalty = 10
write_allocate = true
max_states = 16
",
        );
        let mut program = data_cache_loop_program();
        prepare_cache_program(&mut program, &board);

        let mut block_bounds = program.clone();
        disable_cache_state_ipet(&mut block_bounds);
        let (block_objective, _) = run_ipet(&mut block_bounds, &board);
        assert_eq!(block_objective, 44.0);

        let (objective, model) = run_ipet(&mut program, &board);
        assert_eq!(objective, 14.0);
        assert_eq!(model.as_deref(), Some("state-product"));
    }

    #[test]
    fn cache_persistence_constraints_apply_in_the_automaton_product() {
        let board = cache_board(
            r"
[instruction_cache]
size = 32
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
",
        );
        let mut program = cache_loop_header_program();
        prepare_cache_program(&mut program, &board);
        let conflict = r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <conflict ordered="yes">
        <block address="0x2004"/>
        <block address="0x2006"/>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#;
        let mut bounded = program.clone();
        bounded
            .cache
            .as_mut()
            .expect("cache info")
            .invalidate_on_call = false;
        let mut bounded_facts = facts();
        let document =
            FlowFactDocument::parse_text(conflict, "cache-persistence.ffx").expect("parse");
        bounded_facts
            .apply_document(document, &bounded)
            .expect("apply conflict");
        let _ = analyze_program(&mut bounded, &bounded_facts);
        let bounded_ipet = bounded.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("bounded IPET");
        assert_eq!(bounded_ipet.cache_model.as_deref(), Some("block-bounds"));

        let mut constrained = program.clone();
        let mut constrained_facts = facts();
        let document =
            FlowFactDocument::parse_text(conflict, "cache-persistence.ffx").expect("parse");
        constrained_facts
            .apply_document(document, &constrained)
            .expect("apply conflict");
        let _ = analyze_program(&mut constrained, &constrained_facts);
        let ipet = constrained.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("persistence IPET");
        assert_eq!(ipet.cache_model.as_deref(), Some("ccg"));
        assert!(
            ipet.objective < bounded_ipet.objective,
            "CCG flow must cap repeated loop misses: {} < {}",
            ipet.objective,
            bounded_ipet.objective
        );
    }

    #[test]
    fn line_split_tracks_a_persistent_line_inside_a_conflicting_set() {
        let board = cache_board(
            r"
[instruction_cache]
size = 64
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 64
",
        );
        let mut program = cache_line_split_program();
        prepare_cache_program(&mut program, &board);
        let persistence = &program.cache.as_ref().expect("cache info").persistence;
        assert!(
            persistence
                .regions
                .iter()
                .any(|region| region.lines.iter().any(|line| line.get() == 0x3010)),
            "the shared branch line must be persistent even though the set has three lines"
        );
        let conflict = r#"
<flowfacts>
  <function name="main">
    <loop address="0x3000">
      <conflict ordered="yes">
        <block address="0x3010"/>
        <block address="0x3030"/>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#;
        let mut bounded = program.clone();
        bounded
            .cache
            .as_mut()
            .expect("cache info")
            .invalidate_on_call = false;
        let mut bounded_facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let document = FlowFactDocument::parse_text(conflict, "line-split.ffx").expect("parse");
        bounded_facts
            .apply_document(document, &bounded)
            .expect("apply conflict");
        let _ = analyze_program(&mut bounded, &bounded_facts);
        let bounded_ipet = bounded.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("bounded IPET");

        let mut constrained = program.clone();
        let mut constrained_facts =
            FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let document = FlowFactDocument::parse_text(conflict, "line-split.ffx").expect("parse");
        constrained_facts
            .apply_document(document, &constrained)
            .expect("apply conflict");
        let _ = analyze_program(&mut constrained, &constrained_facts);
        let ipet = constrained.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("conflict-graph IPET");
        assert_eq!(ipet.cache_model.as_deref(), Some("conflict-graph"));
        assert!(
            ipet.objective < bounded_ipet.objective,
            "conflict-graph constraints must cap the persistent line: {} < {}",
            ipet.objective,
            bounded_ipet.objective
        );
    }

    #[test]
    fn conflict_graph_applies_when_the_concrete_cache_analysis_falls_back() {
        let board = cache_board(
            r"
[instruction_cache]
size = 32
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 1
",
        );
        let mut program = cache_loop_header_program();
        prepare_cache_program(&mut program, &board);
        let cache_info = program.cache.as_ref().expect("cache info");
        assert!(
            cache_info.functions_fallback > 0,
            "max_states = 1 must force the concrete analysis fallback"
        );
        assert!(cache_info.persistence.regions.is_empty());

        let mut bounded = program.clone();
        bounded
            .cache
            .as_mut()
            .expect("cache info")
            .invalidate_on_call = false;
        let bounded_facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let _ = analyze_program(&mut bounded, &bounded_facts);
        let bounded_ipet = bounded.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("bounded IPET");

        let mut constrained = program.clone();
        let constrained_facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let _ = analyze_program(&mut constrained, &constrained_facts);
        let ipet = constrained.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("conflict-graph IPET");
        assert_eq!(ipet.cache_model.as_deref(), Some("ccg"));
        assert!(
            ipet.objective < bounded_ipet.objective,
            "CCG flow must work without concrete state persistence: {} < {}",
            ipet.objective,
            bounded_ipet.objective
        );
        let ccg = ipet.cache_ccg.as_ref().expect("CCG summary");
        assert!(ccg.nodes > 0 && ccg.edges > 0 && ccg.constraints > 0);
        let json = serde_json::to_value(ipet).expect("IPET JSON");
        assert_eq!(json["cache_ccg"]["model"], "instruction-ccg-lru");
        assert!(
            json["cache_ccg"]["nodes"]
                .as_u64()
                .is_some_and(|nodes| nodes > 0)
        );
    }

    #[test]
    fn conflict_graph_caps_repeated_line_misses_across_blocks() {
        let board = cache_board(
            r"
[instruction_cache]
size = 64
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 1
",
        );
        let mut program = cache_conflict_program();
        prepare_cache_program(&mut program, &board);
        assert!(
            program
                .cache
                .as_ref()
                .expect("cache info")
                .functions_fallback
                > 0,
            "max_states = 1 must force fallback"
        );

        let mut bounded = program.clone();
        bounded
            .cache
            .as_mut()
            .expect("cache info")
            .invalidate_on_call = false;
        let bounded_facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let _ = analyze_program(&mut bounded, &bounded_facts);
        let bounded_ipet = bounded.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("bounded IPET");

        let mut constrained = program.clone();
        let constrained_facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let _ = analyze_program(&mut constrained, &constrained_facts);
        let ipet = constrained.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("conflict-graph IPET");
        assert_eq!(ipet.cache_model.as_deref(), Some("ccg"));
        assert!(
            ipet.objective < bounded_ipet.objective,
            "CCG flow must cap repeated line misses: {} < {}",
            ipet.objective,
            bounded_ipet.objective
        );
    }

    #[test]
    fn conflict_graph_does_not_cap_nonallocating_store_misses() {
        let board = cache_board(
            r"
[data_cache]
size = 64
line_bytes = 32
ways = 2
miss_penalty = 10
write_allocate = false
max_states = 1
",
        );
        let mut program = data_cache_write_loop_program();
        prepare_cache_program(&mut program, &board);
        let (objective, model) = run_ipet(&mut program, &board);
        assert_eq!(objective, 84.0);
        assert_eq!(model.as_deref(), Some("block-bounds"));
    }

    #[test]
    fn combined_cache_state_product_models_both_caches() {
        let board = cache_board(
            r"
[instruction_cache]
size = 32
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16

[data_cache]
size = 64
line_bytes = 32
ways = 2
miss_penalty = 10
write_allocate = true
max_states = 16
",
        );
        let mut program = data_cache_loop_program();
        prepare_cache_program(&mut program, &board);

        let mut block_bounds = program.clone();
        disable_cache_state_ipet(&mut block_bounds);
        let (block_objective, _) = run_ipet(&mut block_bounds, &board);
        assert_eq!(block_objective, 84.0);

        let (objective, model) = run_ipet(&mut program, &board);
        assert_eq!(objective, 24.0);
        assert_eq!(model.as_deref(), Some("state-product"));
    }

    fn branch_loop_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x1000,
            FunctionCfg::build(
                vec![
                    block(0x1000, CfgTerminator::Branch, 1.0),
                    block(0x1002, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x1000, 0x1000, CfgEdgeKind::Branch),
                    edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                ],
                Some(0x1000),
            ),
        )])
    }

    fn branch_board(max_states: usize) -> BoardProfile {
        BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:ipet-branch-test"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 1_000_000

[branch_prediction]
model = "bimodal"
mispredict_penalty = 3
initial_state = "weakly-not-taken"
max_states = {max_states}

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
"#
        ))
        .expect("valid branch profile")
    }

    fn two_call_branching_program() -> ProgramCfg {
        let caller = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Fallthrough, 1.0),
                call_block(0x1002, 1.0, 0x2000),
                block(0x1004, CfgTerminator::Fallthrough, 1.0),
                call_block(0x1006, 1.0, 0x2000),
                block(0x1008, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                edge(0x1002, 0x1004, CfgEdgeKind::CallReturn),
                edge(0x1004, 0x1006, CfgEdgeKind::Fallthrough),
                edge(0x1006, 0x1008, CfgEdgeKind::CallReturn),
            ],
            Some(0x1000),
        );
        branching_callee_program(caller)
    }

    fn global_history_board(model: &str, max_states: usize) -> BoardProfile {
        BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:ipet-global-history-test"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 1_000_000

[branch_prediction]
model = "{model}"
mispredict_penalty = 3
initial_state = "weakly-not-taken"
history_bits = 3
initial_history = 0
max_states = {max_states}

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
"#
        ))
        .expect("valid global-history branch profile")
    }

    fn two_level_board(level1: &str, level2: &str, max_states: usize) -> BoardProfile {
        BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:ipet-two-level-test"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 1_000_000

[branch_prediction]
model = "two-level"
mispredict_penalty = 3
initial_state = "weakly-not-taken"
history_bits = 3
initial_history = 0
level1_history = "{level1}"
level2_table = "{level2}"
max_states = {max_states}

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
"#
        ))
        .expect("valid two-level branch profile")
    }

    fn tournament_board(max_states: usize) -> BoardProfile {
        BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:ipet-tournament-test"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 1_000_000

[branch_prediction]
model = "tournament"
mispredict_penalty = 3
initial_state = "weakly-not-taken"
history_bits = 3
initial_history = 0
choice_initial_state = "weakly-not-taken"
max_states = {max_states}

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
"#
        ))
        .expect("valid tournament branch profile")
    }

    fn unknown_first_branch_board(max_states: usize) -> BoardProfile {
        BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:ipet-unknown-first-test"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 1_000_000

[branch_prediction]
model = "bimodal"
mispredict_penalty = 3
initial_state = "weakly-not-taken"
first_execution = "unknown"
max_states = {max_states}

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
"#
        ))
        .expect("valid unknown-first branch profile")
    }

    #[test]
    fn btb_state_product_models_cold_and_repeated_transfers() {
        let board = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:ipet-btb-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[branch_target_buffer]
entries = 2
ways = 1
miss_penalty = 2
max_states = 16

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
"#,
        )
        .expect("valid BTB profile");
        let btb_profile = board.branch_target_buffer().expect("BTB profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let mut program = diamond_program();
        let info = crate::btb::analyze_program(&mut program, btb_profile);
        program.btb = Some(info);
        let _ = analyze_program(&mut program, &facts);
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("BTB IPET");
        assert_eq!(ipet.btb_model.as_deref(), Some("state-product"));
        assert!(ipet.objective > 0.0);
    }

    #[test]
    fn branch_state_product_models_loop_warmup() {
        let board = branch_board(16);
        let prediction = board.branch_prediction().expect("branch profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let mut program = branch_loop_program();
        let _ = crate::branch_prediction::analyze_program(&mut program, prediction);

        let mut block_bounds = program.clone();
        let _ = analyze_program(&mut block_bounds, &facts);
        let block_ipet = block_bounds.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("block-bounds IPET");
        assert_eq!(block_ipet.objective, 17.0);

        let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
        let state_ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("state-product IPET");
        assert_eq!(state_ipet.objective, 11.0);
        assert_eq!(state_ipet.branch_model.as_deref(), Some("state-product"));
        assert_eq!(state_ipet.cache_model, None);
    }

    #[test]
    fn branch_state_product_models_unknown_first_execution() {
        let board = unknown_first_branch_board(16);
        let prediction = board.branch_prediction().expect("branch profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let mut program = branch_loop_program();
        let info = crate::branch_prediction::analyze_program(&mut program, prediction);
        assert_eq!(info.first_execution.as_deref(), Some("unknown"));
        let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("unknown-first IPET");
        assert_eq!(ipet.branch_model.as_deref(), Some("state-product"));
        assert!(ipet.objective > 11.0);
    }

    #[test]
    fn branch_state_product_models_global_history() {
        for model in ["global-history", "gshare", "local-history"] {
            let board = global_history_board(model, 128);
            let prediction = board.branch_prediction().expect("branch profile");
            let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
            let mut program = branch_loop_program();
            let info = crate::branch_prediction::analyze_program(&mut program, prediction);
            assert_eq!(info.model, model);
            assert_eq!(info.history_bits, Some(3));
            assert_eq!(info.initial_history, Some(0));
            let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
            let ipet = program.functions[0]
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.ipet.as_ref())
                .expect("global-history IPET");
            assert_eq!(ipet.branch_model.as_deref(), Some("state-product"));
            assert!(ipet.objective > 0.0);
        }
    }

    #[test]
    fn branch_state_product_models_two_level_history() {
        for (level1, level2) in [("local", "global"), ("global", "per-address")] {
            let board = two_level_board(level1, level2, 32);
            let prediction = board.branch_prediction().expect("branch profile");
            let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
            let mut program = branch_loop_program();
            let info = crate::branch_prediction::analyze_program(&mut program, prediction);
            assert_eq!(info.model, "two-level");
            assert_eq!(info.level1_history.as_deref(), Some(level1));
            assert_eq!(info.level2_table.as_deref(), Some(level2));
            let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
            let ipet = program.functions[0]
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.ipet.as_ref())
                .expect("two-level IPET");
            assert_eq!(ipet.branch_model.as_deref(), Some("state-product"));
            assert!(ipet.objective > 0.0);
        }
    }

    #[test]
    fn interprocedural_state_product_models_two_level_history() {
        for (level1, level2) in [("local", "global"), ("global", "per-address")] {
            let board = two_level_board(level1, level2, 128);
            let prediction = board.branch_prediction().expect("branch profile");
            let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
            let mut program = two_call_branching_program();
            let _ = crate::branch_prediction::analyze_program(&mut program, prediction);
            let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
            let ipet = program.functions[0]
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.ipet.as_ref())
                .expect("two-level interprocedural IPET");
            assert_eq!(
                ipet.branch_model.as_deref(),
                Some("interprocedural-state-product")
            );
            assert!(ipet.objective > 0.0);
        }
    }

    #[test]
    fn branch_state_product_models_tournament_history() {
        let board = tournament_board(32);
        let prediction = board.branch_prediction().expect("branch profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let mut program = branch_loop_program();
        let info = crate::branch_prediction::analyze_program(&mut program, prediction);
        assert_eq!(info.model, "tournament");
        assert_eq!(
            info.choice_initial_state.as_deref(),
            Some("weakly-not-taken")
        );
        let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("tournament IPET");
        assert_eq!(ipet.branch_model.as_deref(), Some("state-product"));
        assert!(ipet.objective > 0.0);
    }

    #[test]
    fn interprocedural_state_product_models_tournament_history() {
        let board = tournament_board(128);
        let prediction = board.branch_prediction().expect("branch profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let mut program = two_call_branching_program();
        let _ = crate::branch_prediction::analyze_program(&mut program, prediction);
        let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("tournament interprocedural IPET");
        assert_eq!(
            ipet.branch_model.as_deref(),
            Some("interprocedural-state-product")
        );
        assert!(ipet.objective > 0.0);
    }

    #[test]
    fn interprocedural_branch_state_models_callee_warmup() {
        let board = branch_board(16);
        let prediction = board.branch_prediction().expect("branch profile");
        let mut facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let caller = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Fallthrough, 1.0),
                call_block(0x1002, 1.0, 0x2000),
                block(0x1004, CfgTerminator::Fallthrough, 1.0),
                call_block(0x1006, 1.0, 0x2000),
                block(0x1008, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                edge(0x1002, 0x1004, CfgEdgeKind::CallReturn),
                edge(0x1004, 0x1006, CfgEdgeKind::Fallthrough),
                edge(0x1006, 0x1008, CfgEdgeKind::CallReturn),
            ],
            Some(0x1000),
        );
        let mut program = branching_callee_program(caller);
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <conditional>
    <condition address="0x2002"/>
    <case cond="0" executed="false"/>
  </conditional>
</flowfacts>
"#,
            "force-taken.ffx",
        )
        .expect("branch fact");
        facts
            .apply_document(document, &program)
            .expect("apply branch fact");
        let _ = crate::branch_prediction::analyze_program(&mut program, prediction);
        let mut baseline = program.clone();
        let _ = super::analyze_program_impl(&mut baseline, &facts, Some(prediction), None);
        let baseline_ipet = baseline.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("baseline IPET");
        let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("interprocedural IPET");
        assert_eq!(
            ipet.branch_model.as_deref(),
            Some("interprocedural-state-product")
        );
        let json = serde_json::to_value(ipet).expect("IPET JSON");
        assert_eq!(json["branch_model"], "interprocedural-state-product");
        assert!(ipet.objective < baseline_ipet.objective);
        assert!(ipet.objective > 0.0);
    }

    #[test]
    fn interprocedural_state_product_models_global_history() {
        for model in ["global-history", "gshare", "local-history"] {
            let board = global_history_board(model, 128);
            let prediction = board.branch_prediction().expect("branch profile");
            let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
            let mut program = two_call_branching_program();
            let _ = crate::branch_prediction::analyze_program(&mut program, prediction);
            let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
            let ipet = program.functions[0]
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.ipet.as_ref())
                .expect("history-model interprocedural IPET");
            assert_eq!(
                ipet.branch_model.as_deref(),
                Some("interprocedural-state-product"),
                "model {model} should use interprocedural state"
            );
            assert!(ipet.objective > 0.0);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn interprocedural_branch_state_tracks_unknown_first_execution() {
        let board = unknown_first_branch_board(16);
        let prediction = board.branch_prediction().expect("branch profile");
        let mut facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let caller = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Fallthrough, 1.0),
                call_block(0x1002, 1.0, 0x2000),
                block(0x1004, CfgTerminator::Fallthrough, 1.0),
                call_block(0x1006, 1.0, 0x2000),
                block(0x1008, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                edge(0x1002, 0x1004, CfgEdgeKind::CallReturn),
                edge(0x1004, 0x1006, CfgEdgeKind::Fallthrough),
                edge(0x1006, 0x1008, CfgEdgeKind::CallReturn),
            ],
            Some(0x1000),
        );
        let mut program = branching_callee_program(caller);
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <conditional>
    <condition address="0x2002"/>
    <case cond="0" executed="false"/>
  </conditional>
</flowfacts>
"#,
            "force-taken.ffx",
        )
        .expect("branch fact");
        facts
            .apply_document(document, &program)
            .expect("apply branch fact");
        let _ = crate::branch_prediction::analyze_program(&mut program, prediction);
        let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("unknown-first interprocedural IPET");
        assert_eq!(
            ipet.branch_model.as_deref(),
            Some("interprocedural-state-product")
        );
        assert!(ipet.objective > 0.0);
    }

    #[test]
    fn branch_state_ipet_falls_back_when_analysis_falls_back() {
        let board = branch_board(1);
        let prediction = board.branch_prediction().expect("branch profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let mut program = branch_loop_program();
        let _ = crate::branch_prediction::analyze_program(&mut program, prediction);
        let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("fallback IPET");
        assert_eq!(ipet.objective, 17.0);
        assert_eq!(ipet.branch_model.as_deref(), Some("block-bounds"));
    }

    #[test]
    fn cache_and_branch_state_products_combine() {
        let board = BoardProfile::parse_toml(
            r"
schema_version = 2
id = 'board:ipet-cache-branch-test'
arch = 'thumb'
cpu = 'cortex-m4'

[clocks.core]
hz = 1_000_000

[instruction_cache]
size = 32
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16

[branch_prediction]
model = 'bimodal'
mispredict_penalty = 3
initial_state = 'weakly-not-taken'
max_states = 16

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
",
        )
        .expect("valid combined profile");
        let cache = board.instruction_cache().expect("cache profile");
        let prediction = board.branch_prediction().expect("branch profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let mut program = branch_loop_program();
        let info = crate::icache::analyze_program(&mut program, cache);
        program.cache = Some(info);
        let _ = crate::branch_prediction::analyze_program(&mut program, prediction);

        let mut block_bounds = program.clone();
        let _ = analyze_program(&mut block_bounds, &facts);
        let block_objective = block_bounds.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("block IPET")
            .objective;

        let _ = analyze_program_with_branch_prediction(&mut program, &facts, Some(prediction));
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("combined IPET");
        assert_eq!(ipet.cache_model.as_deref(), Some("state-product"));
        assert_eq!(ipet.branch_model.as_deref(), Some("state-product"));
        assert!(ipet.objective > 0.0 && ipet.objective <= block_objective);
    }

    #[test]
    fn pipeline_edge_stalls_add_to_ipet_objective() {
        let mut program = ProgramCfg::new(vec![function(
            0x1000,
            FunctionCfg::build(
                vec![
                    block(0x1000, CfgTerminator::Fallthrough, 1.0),
                    block(0x1002, CfgTerminator::Fallthrough, 1.0),
                    block(0x1004, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                    edge(0x1002, 0x1004, CfgEdgeKind::Fallthrough),
                ],
                Some(0x1000),
            ),
        )]);
        let facts = facts();
        let mut baseline = program.clone();
        let _ = analyze_program(&mut baseline, &facts);
        assert_eq!(
            baseline.functions[0]
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.ipet.as_ref())
                .expect("baseline IPET")
                .objective,
            3.0
        );

        program.pipeline = Some(CfgPipelineInfo {
            model: "test-edge-context".to_owned(),
            edges: vec![CfgPipelineEdgeInfo {
                function: FunctionId::new("fn:0x1000"),
                source: Addr::new(0x1000),
                target: Addr::new(0x1002),
                site: Addr::new(0x1000),
                stall_cycles: 5.0,
            }],
            caveats: Vec::new(),
        });
        let _ = analyze_program(&mut program, &facts);
        assert_eq!(
            program.functions[0]
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.ipet.as_ref())
                .expect("pipeline IPET")
                .objective,
            8.0
        );
    }

    #[test]
    fn conflict_graph_applies_when_cache_analysis_falls_back() {
        let board = cache_board(
            r"
[instruction_cache]
size = 32
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 1
",
        );
        let mut program = cache_loop_program();
        prepare_cache_program(&mut program, &board);
        let (objective, model) = run_ipet(&mut program, &board);
        assert_eq!(objective, 14.0);
        assert_eq!(model.as_deref(), Some("conflict-graph"));
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("IPET solution");
        let conflicts = ipet.cache_conflicts.as_ref().expect("conflict graph");
        assert_eq!(conflicts.model, "line-conflict-graph");
        assert!(conflicts.constraints > 0);
        let json = serde_json::to_value(ipet).expect("IPET JSON");
        assert_eq!(json["cache_conflicts"]["model"], "line-conflict-graph");
        assert!(
            json["cache_conflicts"]["constraints"]
                .as_u64()
                .is_some_and(|constraints| constraints > 0)
        );
    }

    #[test]
    fn unordered_cross_function_conflicts_are_ignored() {
        let program = branch_caller_program();
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <block address="0x1004"/>
      <call name="helper">
        <block address="0x2002"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(constrained, 63.0);
        let conflict = &facts.infeasible_paths()[0];
        assert!(!conflict.applied);
        assert!(
            conflict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("ordered=\"yes\""))
        );
    }
}
