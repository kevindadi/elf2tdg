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
use petgraph::stable_graph::{EdgeIndex, NodeIndex, StableDiGraph};
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
    CfgBlock, CfgCacheCcgInfo, CfgCacheConflictGraphInfo, CfgCachePersistenceInfo, CfgEdge,
    CfgEdgeKind, CfgFunction, CfgFunctionWcet, CfgIpetBlockCount, CfgIpetPartitioningInfo,
    CfgIpetSolution, CfgTerminator, CfgWcetInfo, CfgWcetStatus, FunctionCfg, ProgramCfg,
};
use crate::flow_facts::{
    BranchOutcome, CrossFunctionConstraint, CrossFunctionSlot, FactScope, FlowFacts,
    InfeasibleElement, InfeasibleEnforcement, InfeasibleScope, OrderedReset, SpecificIteration,
};
use crate::ras::RasState;
use crate::timing::{PipelineFunctionModel, PipelineState};
use crate::wcet::{
    CallContext, VersionSummaries, aggregate_context_summaries, build_call_info_with,
    callee_context, frequency_hz, function_call_targets, plan_contexts_with_sites, root_results,
    time_ns, unbounded_summary, unknown_summary,
};

pub(crate) const MODEL_NAME: &str = "cfg-ipet";
const SOLVER_NAME: &str = "microlp";
const MAX_MODEL_VARIABLES: usize = 500_000;
const MAX_PARTITION_BLOCKS: usize = 4096;
const MAX_PARTITION_REGIONS: u32 = 512;
const MAX_PARTITION_SCAN_STEPS: usize = 10_000_000;

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
    let site_sensitive = facts.has_call_site_contexts();
    let context_plan = context_requested
        .then(|| plan_contexts_with_sites(program, &recursive_functions, site_sensitive));
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
                    caller: &function.id,
                    caller_context: context,
                    site_sensitive,
                };
                let summary = analyze_function(
                    program,
                    function,
                    |target, site| resolver.summary(target, site),
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
                |target, _site| {
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
            "Infeasible-path conflicts use aggregate constraints when their scope is unordered and structurally enforceable; same-function unordered conflicts without a linear structural form (mixed loop/non-loop, nested or disjoint loops) use binary presence indicators at function scope so a repeated loop element counts as one present element. A same-function unordered conflict with a numeric or last iteration scope uses a loop product that tracks inside elements in the selected iteration and outside elements across the invocation; last-iteration paths defer a completed iteration at a backedge until the loop exits and outside elements may complete the conflict afterwards. An all-iteration unordered conflict keeps the common-loop aggregate when available, otherwise a presence product resets inside elements per iteration and retains outside elements across the invocation. Cross-function unordered conflicts use presence for caller elements and non-empty call groups; a group is present only when all its callee elements occur in one callee invocation. A loop-scoped conflict resets presence at each loop entry and spans its iterations; numeric/last iteration scopes track inside items only in the selected iteration, all-iteration scopes reset them every iteration, and outside items span the invocation. Ordered conflicts use aggregate reduction when reachability forces the order, otherwise a product sequence-progress automaton for function, loop or per-iteration scope. A numeric iteration scope selects one 1-based iteration, and -1 selects the last iteration. Nested loop contexts select the innermost declared loop containing all caller events; mixed loop/non-loop ordering uses function scope unless a numeric, last or all-iteration scope keeps the selected loop. Cross-function ordered conflicts with one or more direct call groups inline the selected callees in the product and require each group's elements to match within one invocation; loop-scoped sequences reset on loop entry, or on every backedge for iteration scope. The callee summary remains the cost bound. Nested-group, duplicate-edge and ambiguous call-site conflicts are skipped with warnings, and automaton state-cap overflow makes the function unknown."
                .to_owned(),
        );
    }
    info.caveats.extend(facts.warnings().iter().cloned());
    if summaries.iter().flatten().any(|summary| {
        summary
            .ipet
            .as_ref()
            .is_some_and(|ipet| ipet.partitioning.is_some())
    }) {
        info.caveats.push(
            "IPET CFG partitioning summarizes SESE branch regions with an exact per-entry local model and expands their block counts into the final solution. Fixed per-call-block callee costs are included in both local and final models. Supported branch/call facts and infeasible-path constraints are enforced by the final model; regions touching referenced blocks stay monolithic. Exact state-free partitioning supports ordered and cross-function automata, including loop-scoped resets; state-product partitioning keeps ordered and cross-function automata monolithic. Other shapes use monolithic IPET."
                .to_owned(),
        );
    }
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
    F: FnMut(&FunctionId, u64) -> Option<&'a CfgFunctionWcet>,
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
        build_call_info_with(&function.cfg, &reachable_nodes, |target, _site| {
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
    if let Some(outcome) = try_solve_partitioned(
        program,
        cfg,
        analysis,
        call_cycles,
        facts,
        function_id,
        scope,
        branch_prediction,
        pipeline_model,
    ) {
        return Ok(outcome);
    }
    let loops = build_loops(cfg, entry, analysis, facts, scope)?;
    let automata: Vec<_> = ordered_automata(facts, function_id, scope)
        .into_iter()
        .filter(|automaton| ordered_automaton_possible(cfg, facts, scope, automaton))
        .collect();
    let cross: Vec<_> = cross_function_constraints(facts, function_id, scope)
        .into_iter()
        .filter(|cross| specific_iteration_possible(cfg, facts, scope, cross))
        .collect();
    let presence = presence_automata(cfg, facts, function_id, scope);
    let cross_unordered = cross_unordered_function_constraints(cfg, facts, function_id, scope);
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
    let has_ras = reachable_nodes
        .iter()
        .any(|node| cfg.graph[*node].terminator == crate::cfg::CfgTerminator::Return);
    let ras_model = build_ras_ipet_model(program, cfg, reachable_nodes);
    if !cross.is_empty() || !cross_unordered.is_empty() {
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
            &presence,
            &cross,
            &cross_unordered,
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
        apply_ras_fallback(&mut outcome, program, has_ras);
        return Ok(outcome);
    }
    if !automata.is_empty() || !presence.is_empty() {
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
            &presence,
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
        apply_ras_fallback(&mut outcome, program, has_ras);
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
        || ras_model.is_some()
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
            ras_model.as_ref(),
            true,
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
            apply_ras_fallback(&mut outcome, program, has_ras);
            return Ok(outcome);
        }
    }
    branch_model = build_branch_ipet_model(branch_prediction, cfg, reachable_nodes, false);
    if !cache_models.is_empty()
        || branch_model.is_some()
        || pipeline_model.is_some()
        || btb_model.is_some()
        || ras_model.is_some()
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
            ras_model.as_ref(),
            true,
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
            apply_ras_fallback(&mut outcome, program, has_ras);
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
        &mut vars,
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
            partitioning: None,
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
            ras_model: None,
            blocks,
        },
        partial,
        prediction_exit_costs: BTreeMap::new(),
    };
    apply_pipeline_fallback(&mut outcome, program);
    apply_btb_fallback(&mut outcome, program, has_btb);
    apply_ras_fallback(&mut outcome, program, has_ras);
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

fn apply_ras_fallback(outcome: &mut IpetOutcome, program: &ProgramCfg, has_ras: bool) {
    if outcome.solution.ras_model.is_none() && has_ras && program.ras.is_some() {
        outcome.solution.ras_model = Some("block-bounds".to_owned());
    }
}

const PARTITION_MODEL: &str = "sese-branch-regions";
const STATE_PARTITION_MODEL: &str = "sese-state-product-regions";
const MAX_STATE_PARTITION_ENTRY_STATES: usize = 128;

fn recovered_call_partition_caveat(cfg: &FunctionCfg) -> Option<String> {
    (!cfg.recovered_calls.is_empty()).then(|| {
        format!(
            "{} recovered call site(s) have no containing basic block. They stay function-level, are not assigned to a region, and keep the result partial.",
            cfg.recovered_calls.len()
        )
    })
}

fn call_site_partition_caveat(scope: FactScope<'_>) -> Option<String> {
    let FactScope::Context(context) = scope else {
        return None;
    };
    context
        .iter()
        .any(|frame| frame.site.is_some())
        .then(|| {
            "This partition summary belongs to one call-site-sensitive function version; call-site-specific loop/fact bounds and callee costs are selected by the caller frame chain."
                .to_owned()
        })
}
const MAX_STATE_PARTITION_EXIT_STATES: usize = 256;
const MAX_STATE_PARTITION_LOCAL_NODES: usize = 20_000;

#[derive(Clone, Debug)]
struct SimpleIpetResult {
    objective: f64,
    status: String,
    partial: bool,
    block_counts: BTreeMap<BlockId, u64>,
}

#[derive(Clone, Debug)]
struct PartitionSummary {
    counts_per_entry: BTreeMap<BlockId, u64>,
}

struct PartitionRegion {
    entry: NodeIndex,
    exit: NodeIndex,
    blocks: BTreeSet<NodeIndex>,
}

fn partition_facts_supported(
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    allow_ordered_automata: bool,
    allow_cross_function: bool,
) -> bool {
    facts.infeasible_paths().iter().all(|conflict| {
        if !conflict.applied
            || conflict.function.as_ref() != Some(function_id)
            || !scope.matches(&conflict.context)
        {
            return true;
        }
        match conflict.enforcement {
            InfeasibleEnforcement::Aggregate => {
                conflict.cross_function.is_none()
                    && !matches!(conflict.scope, Some(InfeasibleScope::CrossFunction))
            }
            InfeasibleEnforcement::PresenceAutomaton { .. }
            | InfeasibleEnforcement::CrossUnorderedPresence => false,
            InfeasibleEnforcement::Automaton { .. } => {
                allow_ordered_automata
                    && conflict.ordered
                    && conflict.cross_function.is_none()
                    && !matches!(conflict.scope, Some(InfeasibleScope::CrossFunction))
            }
            InfeasibleEnforcement::CrossFunctionAutomaton => {
                allow_cross_function
                    && conflict.ordered
                    && conflict.cross_function.is_some()
                    && matches!(
                        conflict.scope,
                        Some(InfeasibleScope::CrossFunction | InfeasibleScope::Loop { .. })
                    )
            }
        }
    })
}

fn insert_infeasible_element_blocks(element: &InfeasibleElement, blocks: &mut BTreeSet<BlockId>) {
    match element {
        InfeasibleElement::Block { block } => {
            blocks.insert(block.clone());
        }
        InfeasibleElement::Edge { source, target, .. } => {
            blocks.insert(source.clone());
            blocks.insert(target.clone());
        }
    }
}

/// Blocks referenced by supported non-loop flow facts for one function version.
///
/// A region may be summarized only when none of its blocks or boundary edges
/// participate in a non-loop fact. Facts then remain enforceable in the final
/// model instead of disappearing with the region nodes. An edge is covered by
/// recording both endpoint blocks.
fn non_loop_fact_blocks(
    cfg: &FunctionCfg,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> BTreeSet<BlockId> {
    let node_by_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let mut loop_analysis = None;
    let mut blocks = BTreeSet::new();
    for branch in facts
        .branches()
        .iter()
        .filter(|branch| &branch.function == function_id && scope.matches(&branch.context))
    {
        blocks.insert(branch.block.clone());
        if branch.outcome == BranchOutcome::Both {
            continue;
        }
        let Some(&node) = node_by_id.get(&branch.block) else {
            continue;
        };
        let kind = if branch.outcome == BranchOutcome::Taken {
            crate::cfg::CfgEdgeKind::Branch
        } else {
            crate::cfg::CfgEdgeKind::Fallthrough
        };
        if let Some(edge) = cfg
            .graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .find(|edge| edge.weight().site == branch.site && edge.weight().kind == kind)
        {
            blocks.insert(cfg.graph[edge.target()].id.clone());
        }
    }
    for call in facts
        .calls()
        .iter()
        .filter(|call| &call.function == function_id && scope.matches(&call.context))
    {
        blocks.insert(call.block.clone());
    }
    for conflict in facts.infeasible_paths().iter().filter(|conflict| {
        conflict.applied
            && conflict.function.as_ref() == Some(function_id)
            && scope.matches(&conflict.context)
    }) {
        for element in &conflict.elements {
            insert_infeasible_element_blocks(element, &mut blocks);
        }
        if let Some(cross) = &conflict.cross_function {
            for group in &cross.groups {
                blocks.insert(group.call_block.clone());
                blocks.insert(group.continuation.clone());
                insert_infeasible_element_blocks(&group.call_return, &mut blocks);
            }
            for slot in &cross.pattern {
                if let CrossFunctionSlot::Caller(element) = slot {
                    insert_infeasible_element_blocks(element, &mut blocks);
                }
            }
        }
        if let Some(InfeasibleScope::Loop { header }) = &conflict.scope {
            blocks.insert(header.clone());
        }
        let reset = match &conflict.enforcement {
            InfeasibleEnforcement::Automaton { reset } => Some(reset),
            InfeasibleEnforcement::CrossFunctionAutomaton => {
                conflict.cross_function.as_ref().map(|cross| &cross.reset)
            }
            InfeasibleEnforcement::PresenceAutomaton { .. }
            | InfeasibleEnforcement::CrossUnorderedPresence
            | InfeasibleEnforcement::Aggregate => None,
        };
        if let Some(
            OrderedReset::LoopEntry { header }
            | OrderedReset::LoopIteration { header }
            | OrderedReset::LoopSpecific { header, .. },
        ) = reset
            && let Some(loop_) = loop_analysis
                .get_or_insert_with(|| cfg.analyze_graph())
                .loops
                .iter()
                .find(|loop_| loop_.header == *header)
        {
            blocks.extend(loop_.blocks.iter().cloned());
            for backedge in &loop_.backedges {
                blocks.insert(backedge.from.clone());
                blocks.insert(backedge.to.clone());
            }
        }
    }
    blocks
}

#[allow(clippy::too_many_arguments)]
fn partition_eligible(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    branch_prediction: Option<&BranchPredictionProfile>,
    pipeline_model: Option<&PipelineFunctionModel>,
) -> bool {
    if cfg.graph.node_count() > MAX_PARTITION_BLOCKS
        || analysis.blocked_by_unresolved
        || branch_prediction.is_some()
        || pipeline_model.is_some()
        || program.cache.is_some()
        || program.data_cache.is_some()
        || program.branch_prediction.is_some()
        || program.btb.is_some()
        || program.ras.is_some()
        || program.pipeline.is_some()
    {
        return false;
    }
    partition_facts_supported(facts, function_id, scope, true, true)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn try_solve_partitioned(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    branch_prediction: Option<&BranchPredictionProfile>,
    pipeline_model: Option<&PipelineFunctionModel>,
) -> Option<IpetOutcome> {
    if !partition_eligible(
        program,
        cfg,
        analysis,
        facts,
        function_id,
        scope,
        branch_prediction,
        pipeline_model,
    ) {
        return None;
    }
    let call_cycles_by_id: BTreeMap<BlockId, f64> = call_cycles
        .iter()
        .map(|(node, cycles)| (cfg.graph[*node].id.clone(), *cycles))
        .collect();
    let mut working = cfg.clone();
    let mut summaries: BTreeMap<BlockId, PartitionSummary> = BTreeMap::new();
    let mut regions = 0_u32;
    let mut summarized_blocks = 0_u32;
    let mut partial = false;
    let mut counter = 0_usize;
    let mut scan_steps = 0_usize;
    let fact_blocks = non_loop_fact_blocks(cfg, facts, function_id, scope);
    while regions < MAX_PARTITION_REGIONS {
        let Some(function_entry) = working.entry else {
            break;
        };
        let working_analysis = working.analyze_graph();
        let Some(region) = select_partition_region(
            &working,
            &working_analysis,
            function_entry,
            &fact_blocks,
            &mut scan_steps,
        ) else {
            break;
        };
        let local = solve_partition_region(
            &working,
            &region,
            &call_cycles_by_id,
            facts,
            function_id,
            scope,
            counter,
        )?;
        partial |= local.partial;
        let counts_per_entry = expand_partition_counts(&local.block_counts, &summaries);
        let hidden_originals = region
            .blocks
            .iter()
            .filter(|node| !summaries.contains_key(&working.graph[**node].id))
            .count();
        summarized_blocks =
            summarized_blocks.saturating_add(u32::try_from(hidden_originals).unwrap_or(u32::MAX));
        let macro_id = BlockId::new(format!("bb:partition:{counter}"));
        let cost_per_entry = local.objective;
        if !replace_region(&mut working, &region, &macro_id, cost_per_entry, counter) {
            return None;
        }
        summaries.insert(macro_id, PartitionSummary { counts_per_entry });
        regions = regions.saturating_add(1);
        counter = counter.saturating_add(1);
    }
    if regions == 0 {
        return None;
    }
    let final_entry = working.entry?;
    let automata: Vec<_> = ordered_automata(facts, function_id, scope)
        .into_iter()
        .filter(|automaton| ordered_automaton_possible(cfg, facts, scope, automaton))
        .collect();
    let cross: Vec<_> = cross_function_constraints(facts, function_id, scope)
        .into_iter()
        .filter(|cross| specific_iteration_possible(cfg, facts, scope, cross))
        .collect();
    let (final_status, final_objective, final_counts, final_partial) = if automata.is_empty()
        && cross.is_empty()
    {
        let result = solve_simple_ipet(
            &working,
            final_entry,
            &call_cycles_by_id,
            facts,
            function_id,
            scope,
        )
        .ok()?;
        (
            result.status,
            result.objective,
            result.block_counts,
            result.partial,
        )
    } else {
        let final_analysis = working.analyze_graph();
        let final_reachable: BTreeSet<NodeIndex> = working
            .blocks_by_address
            .values()
            .copied()
            .filter(|node| final_analysis.reachable.contains(&working.graph[*node].id))
            .collect();
        if final_reachable.is_empty() {
            return None;
        }
        let final_loops = build_loops(&working, final_entry, &final_analysis, facts, scope).ok()?;
        let final_call_cycles: BTreeMap<NodeIndex, f64> = working
            .blocks_by_address
            .values()
            .filter_map(|node| {
                call_cycles_by_id
                    .get(&working.graph[*node].id)
                    .map(|cycles| (*node, *cycles))
            })
            .collect();
        let outcome = if cross.is_empty() {
            solve_function_with_automata(
                &working,
                final_entry,
                &final_reachable,
                &final_call_cycles,
                facts,
                function_id,
                scope,
                &final_loops,
                &automata,
                &[],
                &BTreeMap::new(),
                &CachePersistenceModels::default(),
                None,
            )
        } else {
            solve_function_with_cross_function_automata(
                program,
                &working,
                final_entry,
                &final_reachable,
                &final_call_cycles,
                facts,
                function_id,
                scope,
                &final_loops,
                &automata,
                &[],
                &cross,
                &[],
                &BTreeMap::new(),
                &CachePersistenceModels::default(),
                None,
            )
        }
        .ok()?;
        let block_counts = outcome
            .solution
            .blocks
            .iter()
            .map(|block| (block.block.clone(), block.executions))
            .collect();
        (
            outcome.solution.status,
            outcome.solution.objective,
            block_counts,
            outcome.partial,
        )
    };
    partial |= final_partial;
    let counts = expand_partition_counts(&final_counts, &summaries);
    let mut address_by_id: BTreeMap<BlockId, u64> = BTreeMap::new();
    for (address, node) in &cfg.blocks_by_address {
        address_by_id.insert(cfg.graph[*node].id.clone(), *address);
    }
    let mut ordered_counts: Vec<(BlockId, u64)> =
        counts.into_iter().filter(|(_, count)| *count > 0).collect();
    ordered_counts.sort_by_key(|(id, _)| address_by_id.get(id).copied().unwrap_or(u64::MAX));
    let blocks = ordered_counts
        .into_iter()
        .map(|(block, executions)| CfgIpetBlockCount { block, executions })
        .collect();
    let mut caveats = vec![
        "Branch-entry SESE regions are solved locally with an entry count of one, replaced bottom-up by a per-entry cost block, and expanded when the parent model assigns executions to that block. Block execution counts are reconstructed from the per-entry region solutions.".to_owned(),
        "Partitioning is used only for functions without instruction/data-cache, pipeline, branch-prediction, BTB or RAS state models. Supported branch/call facts and infeasible-path constraints are enforced by the final model; ordered automata with loop resets also keep their reset loop monolithic, and cross-function constraints keep all call-group boundaries and caller-side pattern blocks monolithic. Regions that touch any referenced block are left monolithic.".to_owned(),
    ];
    if let Some(caveat) = call_site_partition_caveat(scope) {
        caveats.push(caveat);
    }
    if let Some(caveat) = recovered_call_partition_caveat(cfg) {
        caveats.push(caveat);
    }
    let partitioning = CfgIpetPartitioningInfo {
        model: PARTITION_MODEL.to_owned(),
        regions,
        summarized_blocks,
        caveats,
    };
    Some(IpetOutcome {
        solution: CfgIpetSolution {
            solver: SOLVER_NAME.to_owned(),
            status: final_status,
            objective: final_objective,
            partitioning: Some(partitioning),
            cache_model: None,
            cache_conflicts: None,
            cache_ccg: None,
            pipeline_model: None,
            branch_model: None,
            btb_model: None,
            ras_model: None,
            blocks,
        },
        partial,
        prediction_exit_costs: BTreeMap::new(),
    })
}

fn select_partition_region(
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    function_entry: NodeIndex,
    fact_blocks: &BTreeSet<BlockId>,
    scan_steps: &mut usize,
) -> Option<PartitionRegion> {
    let node_by_id = partition_nodes_by_id(cfg);
    let mut candidates = Vec::new();
    for entry in partition_branch_nodes(cfg, analysis, &node_by_id) {
        if let Some(region) = partition_region_for_entry(
            cfg,
            analysis,
            &node_by_id,
            entry,
            function_entry,
            fact_blocks,
            scan_steps,
        ) {
            candidates.push(region);
        }
    }
    candidates.sort_by_key(|region| {
        (
            region.blocks.len(),
            cfg.graph[region.entry].address,
            region.entry.index(),
        )
    });
    candidates.into_iter().next()
}

fn partition_nodes_by_id(cfg: &FunctionCfg) -> BTreeMap<BlockId, NodeIndex> {
    cfg.blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect()
}

fn partition_branch_nodes(
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    node_by_id: &BTreeMap<BlockId, NodeIndex>,
) -> Vec<NodeIndex> {
    let mut branch_nodes: Vec<NodeIndex> = analysis
        .reachable
        .iter()
        .filter_map(|id| node_by_id.get(id).copied())
        .collect();
    branch_nodes.sort_by_key(|node| (cfg.graph[*node].address, node.index()));
    branch_nodes
}

fn partition_region_for_entry(
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    node_by_id: &BTreeMap<BlockId, NodeIndex>,
    entry: NodeIndex,
    function_entry: NodeIndex,
    fact_blocks: &BTreeSet<BlockId>,
    scan_steps: &mut usize,
) -> Option<PartitionRegion> {
    *scan_steps = scan_steps.saturating_add(1);
    if *scan_steps > MAX_PARTITION_SCAN_STEPS {
        return None;
    }
    let targets: BTreeSet<NodeIndex> = cfg
        .graph
        .edges_directed(entry, petgraph::Direction::Outgoing)
        .map(|edge| edge.target())
        .collect();
    if targets.len() < 2 {
        return None;
    }
    let entry_id = &cfg.graph[entry].id;
    let exit_id = analysis.immediate_post_dominators.get(entry_id)?;
    let exit = *node_by_id.get(exit_id)?;
    if exit == entry || exit == function_entry || exit_id == entry_id {
        return None;
    }
    let mut blocks = BTreeSet::new();
    for id in &analysis.reachable {
        *scan_steps = scan_steps.saturating_add(1);
        if *scan_steps > MAX_PARTITION_SCAN_STEPS {
            return None;
        }
        if id == exit_id {
            continue;
        }
        let Some(&node) = node_by_id.get(id) else {
            continue;
        };
        let dominated = analysis
            .dominators
            .get(id)
            .is_some_and(|set| set.contains(entry_id));
        let postdominated = analysis
            .post_dominators
            .get(id)
            .is_some_and(|set| set.contains(exit_id));
        if dominated && postdominated {
            blocks.insert(node);
        }
    }
    if blocks.len() < 2 || !blocks.contains(&entry) {
        return None;
    }
    *scan_steps = scan_steps.saturating_add(blocks.len().saturating_mul(4));
    if *scan_steps > MAX_PARTITION_SCAN_STEPS {
        return None;
    }
    if !valid_partition_region(cfg, analysis, &blocks, entry, exit, function_entry) {
        return None;
    }
    if blocks
        .iter()
        .any(|node| fact_blocks.contains(&cfg.graph[*node].id))
    {
        return None;
    }
    Some(PartitionRegion {
        entry,
        exit,
        blocks,
    })
}

fn collect_state_partition_candidates(
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    function_entry: NodeIndex,
    fact_blocks: &BTreeSet<BlockId>,
    scan_steps: &mut usize,
) -> Vec<PartitionRegion> {
    let node_by_id = partition_nodes_by_id(cfg);
    let mut candidates = Vec::new();
    for entry in partition_branch_nodes(cfg, analysis, &node_by_id) {
        if let Some(region) = partition_region_for_entry(
            cfg,
            analysis,
            &node_by_id,
            entry,
            function_entry,
            fact_blocks,
            scan_steps,
        ) && state_partition_region_allowed(cfg, analysis, &region)
        {
            candidates.push(region);
        }
    }
    candidates.sort_by(|left, right| {
        right
            .blocks
            .len()
            .cmp(&left.blocks.len())
            .then_with(|| {
                cfg.graph[left.entry]
                    .address
                    .cmp(&cfg.graph[right.entry].address)
            })
            .then_with(|| left.entry.index().cmp(&right.entry.index()))
    });
    candidates
}

fn state_partition_region_allowed(
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    region: &PartitionRegion,
) -> bool {
    let block_ids: BTreeSet<BlockId> = region
        .blocks
        .iter()
        .map(|node| cfg.graph[*node].id.clone())
        .collect();
    if analysis.loops.iter().any(|loop_| {
        block_ids.contains(&loop_.header)
            || loop_.latches.iter().any(|latch| block_ids.contains(latch))
    }) {
        return false;
    }
    let exit_id = &cfg.graph[region.exit].id;
    !analysis.loops.iter().any(|loop_| &loop_.header == exit_id)
}

fn valid_partition_region(
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    blocks: &BTreeSet<NodeIndex>,
    entry: NodeIndex,
    exit: NodeIndex,
    function_entry: NodeIndex,
) -> bool {
    let block_ids: BTreeSet<BlockId> = blocks
        .iter()
        .map(|node| cfg.graph[*node].id.clone())
        .collect();
    let mut external_incoming = 0_u32;
    let mut boundary_exits = 0_u32;
    for node in blocks {
        for edge in cfg
            .graph
            .edges_directed(*node, petgraph::Direction::Incoming)
        {
            if !blocks.contains(&edge.source()) {
                if *node != entry || edge.source() == exit {
                    return false;
                }
                external_incoming = external_incoming.saturating_add(1);
            }
        }
        for edge in cfg
            .graph
            .edges_directed(*node, petgraph::Direction::Outgoing)
        {
            if !blocks.contains(&edge.target()) {
                if edge.target() != exit {
                    return false;
                }
                boundary_exits = boundary_exits.saturating_add(1);
            }
        }
    }
    if (external_incoming == 0 && entry != function_entry) || boundary_exits == 0 {
        return false;
    }
    for loop_ in &analysis.loops {
        if !loop_.blocks.iter().any(|block| block_ids.contains(block)) {
            continue;
        }
        let controls_loop = block_ids.contains(&loop_.header)
            || loop_.latches.iter().any(|latch| block_ids.contains(latch));
        if controls_loop && !loop_.blocks.iter().all(|block| block_ids.contains(block)) {
            return false;
        }
    }
    true
}

fn solve_partition_region(
    cfg: &FunctionCfg,
    region: &PartitionRegion,
    call_cycles: &BTreeMap<BlockId, f64>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    counter: usize,
) -> Option<SimpleIpetResult> {
    let mut nodes: Vec<NodeIndex> = region.blocks.iter().copied().collect();
    nodes.sort_by_key(|node| (cfg.graph[*node].address, node.index()));
    let mut graph = StableDiGraph::new();
    let mut node_map: BTreeMap<NodeIndex, NodeIndex> = BTreeMap::new();
    let mut blocks_by_address: BTreeMap<u64, NodeIndex> = BTreeMap::new();
    for node in &nodes {
        let block = cfg.graph[*node].clone();
        let address = block.address;
        let new_node = graph.add_node(block);
        node_map.insert(*node, new_node);
        blocks_by_address.insert(address, new_node);
    }
    let dummy_address = unique_address(&blocks_by_address, u64::MAX, counter);
    let dummy_id = BlockId::new(format!("bb:partition-exit:{counter}"));
    let dummy = CfgBlock {
        id: dummy_id.clone(),
        address: dummy_address,
        size: 0,
        instructions: Vec::new(),
        calls: Vec::new(),
        cycles: Some(CostRange::exact(0.0)),
        cache: None,
        data_cache: None,
        branch_prediction: None,
        btb: None,
        ras: None,
        data_memory: None,
        multicore: None,
        terminator: CfgTerminator::Return,
    };
    let dummy_node = graph.add_node(dummy);
    blocks_by_address.insert(dummy_address, dummy_node);
    for node in &nodes {
        let source = *node_map.get(node)?;
        for edge in cfg
            .graph
            .edges_directed(*node, petgraph::Direction::Outgoing)
        {
            let target = if region.blocks.contains(&edge.target()) {
                *node_map.get(&edge.target())?
            } else if edge.target() == region.exit {
                dummy_node
            } else {
                return None;
            };
            graph.add_edge(source, target, edge.weight().clone());
        }
    }
    let entry = *node_map.get(&region.entry)?;
    let region_cfg = FunctionCfg {
        entry: Some(entry),
        graph,
        blocks_by_address,
        recovered_calls: Vec::new(),
        referenced_addresses: Vec::new(),
    };
    let mut result =
        solve_simple_ipet(&region_cfg, entry, call_cycles, facts, function_id, scope).ok()?;
    result.block_counts.remove(&dummy_id);
    Some(result)
}

fn replace_region(
    cfg: &mut FunctionCfg,
    region: &PartitionRegion,
    macro_id: &BlockId,
    cost_per_entry: f64,
    counter: usize,
) -> bool {
    let mut incoming: Vec<(NodeIndex, CfgEdge)> = Vec::new();
    let mut boundary_exits = 0_u32;
    for node in &region.blocks {
        for edge in cfg
            .graph
            .edges_directed(*node, petgraph::Direction::Incoming)
        {
            if !region.blocks.contains(&edge.source()) {
                incoming.push((edge.source(), edge.weight().clone()));
            }
        }
        for edge in cfg
            .graph
            .edges_directed(*node, petgraph::Direction::Outgoing)
        {
            if !region.blocks.contains(&edge.target()) {
                if edge.target() != region.exit {
                    return false;
                }
                boundary_exits = boundary_exits.saturating_add(1);
            }
        }
    }
    let is_function_entry = cfg.entry == Some(region.entry);
    if (incoming.is_empty() && !is_function_entry) || boundary_exits == 0 {
        return false;
    }
    let removed_addresses: Vec<u64> = region
        .blocks
        .iter()
        .map(|node| cfg.graph[*node].address)
        .collect();
    for node in &region.blocks {
        cfg.graph.remove_node(*node);
    }
    for address in removed_addresses {
        cfg.blocks_by_address.remove(&address);
    }
    let address = unique_address(&cfg.blocks_by_address, u64::MAX, counter);
    let macro_block = CfgBlock {
        id: macro_id.clone(),
        address,
        size: 0,
        instructions: Vec::new(),
        calls: Vec::new(),
        cycles: Some(CostRange::exact(cost_per_entry)),
        cache: None,
        data_cache: None,
        branch_prediction: None,
        btb: None,
        ras: None,
        data_memory: None,
        multicore: None,
        terminator: CfgTerminator::Fallthrough,
    };
    let node = cfg.graph.add_node(macro_block);
    cfg.blocks_by_address.insert(address, node);
    if is_function_entry {
        cfg.entry = Some(node);
    }
    for (source, weight) in incoming {
        cfg.graph.add_edge(source, node, weight);
    }
    cfg.graph.add_edge(
        node,
        region.exit,
        CfgEdge {
            kind: CfgEdgeKind::Fallthrough,
            site: address,
            conditional: false,
        },
    );
    true
}

fn unique_address(blocks_by_address: &BTreeMap<u64, NodeIndex>, start: u64, offset: usize) -> u64 {
    let mut candidate = start.saturating_sub(u64::try_from(offset).unwrap_or(u64::MAX));
    while blocks_by_address.contains_key(&candidate) {
        candidate = candidate.saturating_sub(1);
    }
    candidate
}

fn expand_partition_counts(
    counts: &BTreeMap<BlockId, u64>,
    summaries: &BTreeMap<BlockId, PartitionSummary>,
) -> BTreeMap<BlockId, u64> {
    let mut expanded: BTreeMap<BlockId, u64> = BTreeMap::new();
    for (block, count) in counts {
        if let Some(summary) = summaries.get(block) {
            for (original, per_entry) in &summary.counts_per_entry {
                let scaled = per_entry.saturating_mul(*count);
                let total = expanded.entry(original.clone()).or_default();
                *total = total.saturating_add(scaled);
            }
        } else {
            let total = expanded.entry(block.clone()).or_default();
            *total = total.saturating_add(*count);
        }
    }
    expanded
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]
fn solve_simple_ipet(
    cfg: &FunctionCfg,
    entry: NodeIndex,
    call_cycles: &BTreeMap<BlockId, f64>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> Result<SimpleIpetResult, IpetError> {
    let analysis = cfg.analyze_graph();
    let reachable_nodes: BTreeSet<NodeIndex> = cfg
        .blocks_by_address
        .values()
        .copied()
        .filter(|node| analysis.reachable.contains(&cfg.graph[*node].id))
        .collect();
    if reachable_nodes.is_empty() {
        return Err(IpetError::Unknown("no-reachable-blocks".to_owned()));
    }
    if reachable_nodes
        .iter()
        .any(|node| cfg.graph[*node].cycles.is_none())
    {
        return Err(IpetError::Unknown("missing-block-timing".to_owned()));
    }
    let loops = build_loops(cfg, entry, &analysis, facts, scope)?;
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
    let mut objective = Expression::from(0.0);
    for (node, variable) in &block_vars {
        let block = &cfg.graph[*node];
        let cycles = block.cycles.expect("checked block timing");
        let call_cycles = call_cycles.get(&block.id).copied().unwrap_or(0.0);
        objective += *variable * (cycles.max + call_cycles);
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
        &mut vars,
    ));
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
    let mut block_counts = BTreeMap::new();
    for (node, variable) in &block_vars {
        let value = solution.value(*variable);
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
            block_counts.insert(cfg.graph[*node].id.clone(), rounded as u64);
        }
    }
    let objective = solution.eval(&objective);
    if !objective.is_finite() || objective < 0.0 {
        return Err(IpetError::Unknown("ipet-objective-not-finite".to_owned()));
    }
    Ok(SimpleIpetResult {
        objective,
        status: status.to_owned(),
        partial,
        block_counts,
    })
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

const MAX_PRESENCE_COUNT: f64 = 1e15;

fn presence_element_bound(
    cfg: &FunctionCfg,
    facts: &FlowFacts,
    scope: FactScope<'_>,
    element: &InfeasibleElement,
) -> Option<f64> {
    let analysis = cfg.analyze_graph();
    let blocks: Vec<&BlockId> = match element {
        InfeasibleElement::Block { block } => vec![block],
        InfeasibleElement::Edge { source, target, .. } => vec![source, target],
    };
    let mut bound = 1.0_f64;
    for loop_ in &analysis.loops {
        if !analysis.reachable.contains(&loop_.header) {
            continue;
        }
        let contains_element = blocks
            .iter()
            .any(|block| loop_.blocks.iter().any(|candidate| candidate == *block));
        if !contains_element {
            continue;
        }
        let header = cfg
            .blocks_by_address
            .values()
            .find(|node| cfg.graph[**node].id == loop_.header)?;
        let address = cfg.graph[*header].address;
        let loop_bound = match scope {
            FactScope::Context(context) => facts.bound_for_context(address, context),
            FactScope::Insensitive => facts.bound_for(address),
        }?;
        let block_set: BTreeSet<&BlockId> = loop_.blocks.iter().collect();
        let entries = cfg
            .graph
            .edges_directed(*header, petgraph::Direction::Incoming)
            .filter(|edge| !block_set.contains(&cfg.graph[edge.source()].id))
            .count()
            .max(1);
        let entries = u32::try_from(entries).unwrap_or(u32::MAX);
        bound *= f64::from(loop_bound) * f64::from(entries);
        if !bound.is_finite() || bound > MAX_PRESENCE_COUNT {
            return None;
        }
    }
    Some(bound)
}

/// Enforce an unordered conflict through exact presence indicators at function
/// scope. This covers mixed loop/non-loop elements, nested loops and disjoint
/// loops. Binary presence variables make `not all elements present` expressible
/// without excluding feasible paths that execute one element several times.
fn presence_constraints(
    cfg: &FunctionCfg,
    facts: &FlowFacts,
    scope: FactScope<'_>,
    conflict: &crate::flow_facts::InfeasiblePathConstraint,
    element_expression: &dyn Fn(&InfeasibleElement) -> Option<Expression>,
    vars: &mut ProblemVariables,
) -> Vec<good_lp::Constraint> {
    let Some(count) = u32::try_from(conflict.elements.len()).ok() else {
        return Vec::new();
    };
    if count < 2 {
        return Vec::new();
    }
    let mut expressions = Vec::with_capacity(conflict.elements.len());
    let mut bounds = Vec::with_capacity(conflict.elements.len());
    for element in &conflict.elements {
        let Some(expression) = element_expression(element) else {
            return Vec::new();
        };
        let Some(bound) = presence_element_bound(cfg, facts, scope, element) else {
            return Vec::new();
        };
        expressions.push(expression);
        bounds.push(bound);
    }
    let mut presence = Vec::with_capacity(expressions.len());
    let mut constraints = Vec::with_capacity(expressions.len() * 2 + 1);
    for (expression, bound) in expressions.into_iter().zip(bounds) {
        let variable = vars.add(good_lp::variable().integer().min(0.0).max(1.0));
        constraints.push(constraint::leq(
            expression.clone() - Expression::from(variable) * bound,
            0.0,
        ));
        constraints.push(constraint::leq(
            Expression::from(variable) - expression,
            0.0,
        ));
        presence.push(variable);
    }
    let mut sum = Expression::from(0.0);
    for variable in &presence {
        sum += *variable;
    }
    constraints.push(constraint::leq(sum, f64::from(count - 1)));
    constraints
}

#[allow(clippy::too_many_arguments)]
fn aggregate_conflict_constraints(
    cfg: &FunctionCfg,
    node_by_block_id: &BTreeMap<BlockId, NodeIndex>,
    block_expression: &dyn Fn(&BlockId) -> Expression,
    edge_expression: &dyn Fn(EdgeIndex) -> Expression,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
    vars: &mut ProblemVariables,
) -> Vec<good_lp::Constraint> {
    let element_expression = |element: &InfeasibleElement| -> Option<Expression> {
        match element {
            InfeasibleElement::Block { block } => {
                node_by_block_id.get(block)?;
                Some(block_expression(block))
            }
            InfeasibleElement::Edge {
                source,
                target,
                site,
            } => {
                let source = node_by_block_id.get(source)?;
                let target = node_by_block_id.get(target)?;
                let edge = cfg
                    .graph
                    .edges_directed(*source, petgraph::Direction::Outgoing)
                    .find(|edge| edge.target() == *target && edge.weight().site == *site)?;
                Some(edge_expression(edge.id()))
            }
        }
    };
    let mut constraints = Vec::new();
    for conflict in facts.infeasible_paths().iter().filter(|conflict| {
        conflict.applied
            && matches!(conflict.enforcement, InfeasibleEnforcement::Aggregate)
            && conflict
                .function
                .as_ref()
                .is_some_and(|function| function == function_id)
            && scope.matches(&conflict.context)
    }) {
        if conflict.presence {
            constraints.extend(presence_constraints(
                cfg,
                facts,
                scope,
                conflict,
                &element_expression,
                vars,
            ));
            continue;
        }
        let mut sum = Expression::from(0.0);
        let mut resolved = true;
        for element in &conflict.elements {
            if let Some(expression) = element_expression(element) {
                sum += expression;
            } else {
                resolved = false;
                break;
            }
        }
        if !resolved {
            continue;
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
                if !node_by_block_id.contains_key(header) {
                    continue;
                }
                let header_expression = block_expression(header);
                constraints.push(constraint::leq(sum - header_expression * bound, 0.0));
            }
            Some(InfeasibleScope::CrossFunction) | None => {}
        }
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
    vars: &mut ProblemVariables,
) -> Vec<good_lp::Constraint> {
    let node_by_id: BTreeMap<_, _> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let element_expression = |element: &InfeasibleElement| -> Option<Expression> {
        match element {
            InfeasibleElement::Block { block } => {
                let node = node_by_id.get(block)?;
                Some(Expression::from(*block_vars.get(node)?))
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
                Some(Expression::from(*edge_vars.get(&edge.id())?))
            }
        }
    };
    let mut constraints = Vec::new();
    for conflict in facts.infeasible_paths().iter().filter(|conflict| {
        conflict.applied
            && matches!(conflict.enforcement, InfeasibleEnforcement::Aggregate)
            && conflict
                .function
                .as_ref()
                .is_some_and(|function| function == function_id)
            && scope.matches(&conflict.context)
    }) {
        if conflict.presence {
            constraints.extend(presence_constraints(
                cfg,
                facts,
                scope,
                conflict,
                &element_expression,
                vars,
            ));
            continue;
        }
        let mut lhs = Expression::from(0.0);
        let mut resolved = true;
        for element in &conflict.elements {
            if let Some(expression) = element_expression(element) {
                lhs += expression;
            } else {
                resolved = false;
                break;
            }
        }
        if !resolved {
            continue;
        }
        let Some(count) = u32::try_from(conflict.elements.len()).ok() else {
            continue;
        };
        let bound = f64::from(count.saturating_sub(1));
        match conflict.scope.as_ref() {
            Some(InfeasibleScope::Function) => {
                constraints.push(constraint::leq(lhs, bound));
            }
            Some(InfeasibleScope::Loop { header }) => {
                let Some(node) = node_by_id.get(header) else {
                    continue;
                };
                let Some(header) = block_vars.get(node) else {
                    continue;
                };
                let rhs = Expression::from(*header) * bound;
                constraints.push(constraint::leq(lhs - rhs, 0.0));
            }
            Some(InfeasibleScope::CrossFunction) | None => {}
        }
    }
    constraints
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

#[derive(Clone, Debug)]
struct PresenceAutomaton {
    elements: Vec<InfeasibleElement>,
    header: BlockId,
    /// `None` applies the presence check to every loop iteration.
    iteration: Option<SpecificIteration>,
}

fn presence_automata(
    cfg: &FunctionCfg,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> Vec<PresenceAutomaton> {
    facts
        .infeasible_paths()
        .iter()
        .filter_map(|conflict| {
            if !conflict.applied
                || conflict.ordered
                || conflict.function.as_ref() != Some(function_id)
                || !scope.matches(&conflict.context)
                || conflict.elements.is_empty()
            {
                return None;
            }
            let InfeasibleEnforcement::PresenceAutomaton { header, iteration } =
                &conflict.enforcement
            else {
                return None;
            };
            if let Some(SpecificIteration::Number(number)) = iteration
                && !specific_iteration_within_loop_bound(cfg, facts, scope, header, *number)
            {
                return None;
            }
            Some(PresenceAutomaton {
                elements: conflict.elements.clone(),
                header: header.clone(),
                iteration: *iteration,
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

fn cross_unordered_function_constraints<'a>(
    cfg: &FunctionCfg,
    facts: &'a FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> Vec<&'a CrossFunctionConstraint> {
    facts
        .infeasible_paths()
        .iter()
        .filter_map(|conflict| {
            if !conflict.applied
                || conflict.ordered
                || !matches!(
                    conflict.enforcement,
                    InfeasibleEnforcement::CrossUnorderedPresence
                )
                || conflict.function.as_ref() != Some(function_id)
                || !scope.matches(&conflict.context)
            {
                return None;
            }
            let cross = conflict.cross_function.as_ref()?;
            if let OrderedReset::LoopSpecific {
                header,
                iteration: SpecificIteration::Number(number),
            } = &cross.reset
                && !specific_iteration_within_loop_bound(cfg, facts, scope, header, *number)
            {
                return None;
            }
            Some(cross)
        })
        .collect()
}

fn specific_iteration_within_loop_bound(
    cfg: &FunctionCfg,
    facts: &FlowFacts,
    scope: FactScope<'_>,
    header: &BlockId,
    iteration: u32,
) -> bool {
    let Some(node) = cfg
        .blocks_by_address
        .values()
        .find(|node| &cfg.graph[**node].id == header)
    else {
        return true;
    };
    let address = cfg.graph[*node].address;
    let bound = match scope {
        FactScope::Context(context) => facts.bound_for_context(address, context),
        FactScope::Insensitive => facts.bound_for(address),
    };
    bound.is_none_or(|bound| iteration <= bound)
}

/// A numeric iteration beyond the configured per-entry loop bound can never
/// execute. Dropping the constraint is exact and avoids unrolling the
/// iteration counter up to an unreachable target.
fn specific_iteration_possible(
    cfg: &FunctionCfg,
    facts: &FlowFacts,
    scope: FactScope<'_>,
    cross: &CrossFunctionConstraint,
) -> bool {
    let Some(SpecificIteration::Number(iteration)) = cross.specific_iteration else {
        return true;
    };
    let OrderedReset::LoopIteration { header } = &cross.reset else {
        return true;
    };
    specific_iteration_within_loop_bound(cfg, facts, scope, header, iteration)
}

fn ordered_automaton_possible(
    cfg: &FunctionCfg,
    facts: &FlowFacts,
    scope: FactScope<'_>,
    automaton: &OrderedAutomaton,
) -> bool {
    match &automaton.reset {
        OrderedReset::LoopSpecific {
            header,
            iteration: SpecificIteration::Number(iteration),
        } => specific_iteration_within_loop_bound(cfg, facts, scope, header, *iteration),
        _ => true,
    }
}

struct AutomatonRuntime {
    pattern: Vec<InfeasibleElement>,
    reset: OrderedReset,
    iteration_guard: Option<SpecificIteration>,
    all_mixed: bool,
    loop_blocks: Option<BTreeSet<BlockId>>,
    backedges: BTreeSet<(BlockId, BlockId)>,
    loop_header: Option<BlockId>,
    header_has_exit: bool,
    /// A specific-iteration conflict with events on both sides of its loop.
    mixed: bool,
    slot_outside: Vec<bool>,
    /// Number of leading pattern slots outside the reset loop.
    outside_prefix: usize,
}

impl AutomatonRuntime {
    fn reset_on(&self, source: &BlockId, target: &BlockId) -> bool {
        sequence_resets(
            &self.reset,
            self.loop_blocks.as_ref(),
            &self.backedges,
            source,
            target,
        )
    }

    fn initial_iteration(&self, entry_block: &BlockId) -> u32 {
        if self.iteration_guard.is_none() {
            return 0;
        }
        u32::from(
            self.loop_blocks
                .as_ref()
                .is_some_and(|blocks| blocks.contains(entry_block)),
        )
    }
}

#[derive(Clone, Debug)]
struct PresenceRuntime {
    elements: Vec<InfeasibleElement>,
    inside_element: Vec<bool>,
    blocks: BTreeSet<BlockId>,
    backedges: BTreeSet<(BlockId, BlockId)>,
    header: BlockId,
    header_has_exit: bool,
    selected: Option<SpecificIteration>,
    inside_full: Vec<u64>,
    outside_full: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PresenceState {
    /// 0 outside the loop, 1-based iteration inside. Numeric selectors cap the
    /// value at `selected + 1` once the target iteration has passed.
    iteration: u32,
    /// Elements inside the selected loop that occurred in the tracked iteration.
    inside: Vec<u64>,
    /// Elements outside the selected loop that occurred anywhere in the
    /// invocation. This mask is not reset at loop iteration boundaries.
    outside: Vec<u64>,
    /// Last-iteration only: the iteration that just ended at a backedge had
    /// every inside element, and a header exit would make it the last iteration.
    candidate_inside_full: bool,
    /// Numeric selectors: the selected iteration already contained every inside
    /// element. Outside elements may still appear later in the invocation.
    selected_inside_full: bool,
    /// Last selectors: the last completed loop iteration already contained every
    /// inside element. Outside elements may still appear after the loop.
    last_inside_full: bool,
}

impl PresenceRuntime {
    fn zero_mask(&self) -> Vec<u64> {
        vec![0; self.elements.len().div_ceil(64)]
    }

    fn inside_complete(&self, mask: &[u64]) -> bool {
        mask == self.inside_full.as_slice()
    }

    fn outside_complete(&self, mask: &[u64]) -> bool {
        mask == self.outside_full.as_slice()
    }

    fn tracking(&self, iteration: u32) -> bool {
        match self.selected {
            None | Some(SpecificIteration::Last) => iteration > 0,
            Some(SpecificIteration::Number(number)) => iteration == number,
        }
    }

    fn uses_selected_iteration(&self) -> bool {
        !matches!(self.selected, Some(SpecificIteration::Last))
    }

    fn apply(
        &self,
        element: &InfeasibleElement,
        track_inside: bool,
        inside: &mut [u64],
        outside: &mut [u64],
    ) {
        let Some(index) = self
            .elements
            .iter()
            .position(|candidate| candidate == element)
        else {
            return;
        };
        if self.inside_element[index] {
            if track_inside {
                inside[index / 64] |= 1_u64 << (index % 64);
            }
        } else {
            outside[index / 64] |= 1_u64 << (index % 64);
        }
    }
}

fn presence_runtimes(
    cfg: &FunctionCfg,
    automata: &[PresenceAutomaton],
) -> Result<Vec<PresenceRuntime>, IpetError> {
    let analysis = cfg.analyze_graph();
    automata
        .iter()
        .map(|automaton| {
            let Some(loop_) = analysis
                .loops
                .iter()
                .find(|loop_| loop_.header == automaton.header)
            else {
                return Err(IpetError::Unknown("presence-loop-missing".to_owned()));
            };
            let blocks: BTreeSet<BlockId> = loop_.blocks.iter().cloned().collect();
            let backedges = loop_
                .backedges
                .iter()
                .map(|edge| (edge.from.clone(), edge.to.clone()))
                .collect();
            let header_has_exit = loop_header_has_exit(cfg, &automaton.header, &blocks);
            let inside_element: Vec<bool> = automaton
                .elements
                .iter()
                .map(|element| element_within_blocks(element, &blocks))
                .collect();
            let mut inside_full = vec![0_u64; automaton.elements.len().div_ceil(64)];
            let mut outside_full = inside_full.clone();
            for (index, inside) in inside_element.iter().enumerate() {
                let full = if *inside {
                    &mut inside_full
                } else {
                    &mut outside_full
                };
                full[index / 64] |= 1_u64 << (index % 64);
            }
            Ok(PresenceRuntime {
                elements: automaton.elements.clone(),
                inside_element,
                blocks,
                backedges,
                header: automaton.header.clone(),
                header_has_exit,
                selected: automaton.iteration,
                inside_full,
                outside_full,
            })
        })
        .collect()
}

fn initial_presence_progress(
    runtimes: &[PresenceRuntime],
    entry_block: &BlockId,
) -> Option<Vec<PresenceState>> {
    let mut progress = Vec::with_capacity(runtimes.len());
    for runtime in runtimes {
        let iteration = u32::from(runtime.blocks.contains(entry_block));
        let mut state = PresenceState {
            iteration,
            inside: runtime.zero_mask(),
            outside: runtime.zero_mask(),
            candidate_inside_full: false,
            selected_inside_full: false,
            last_inside_full: false,
        };
        let track_inside = iteration > 0 && runtime.tracking(iteration);
        runtime.apply(
            &InfeasibleElement::Block {
                block: entry_block.clone(),
            },
            track_inside,
            &mut state.inside,
            &mut state.outside,
        );
        if track_inside
            && runtime.uses_selected_iteration()
            && runtime.inside_complete(&state.inside)
        {
            state.selected_inside_full = true;
        }
        if state.selected_inside_full && runtime.outside_complete(&state.outside) {
            return None;
        }
        progress.push(state);
    }
    Some(progress)
}

#[allow(clippy::too_many_lines)]
fn advance_presence_progress(
    runtimes: &[PresenceRuntime],
    progress: &[PresenceState],
    source: &BlockId,
    target: &BlockId,
    edge_element: &InfeasibleElement,
    block: &InfeasibleElement,
) -> Option<Vec<PresenceState>> {
    let mut next = Vec::with_capacity(runtimes.len());
    for (index, runtime) in runtimes.iter().enumerate() {
        let mut state = progress[index].clone();
        let source_inside = runtime.blocks.contains(source);
        let target_inside = runtime.blocks.contains(target);
        let backedge = runtime
            .backedges
            .contains(&(source.clone(), target.clone()));
        let track_inside = if source_inside && !target_inside {
            match runtime.selected {
                None => {
                    if runtime.inside_complete(&state.inside) {
                        state.selected_inside_full = true;
                    }
                }
                Some(SpecificIteration::Number(number)) => {
                    if state.iteration == number && runtime.inside_complete(&state.inside) {
                        state.selected_inside_full = true;
                    }
                }
                Some(SpecificIteration::Last) => {
                    let current_full = runtime.inside_complete(&state.inside);
                    let last_full = if runtime.header == *source {
                        state.candidate_inside_full
                    } else {
                        current_full
                    };
                    if last_full && runtime.outside_complete(&state.outside) {
                        return None;
                    }
                    state.last_inside_full |= last_full;
                }
            }
            state.iteration = 0;
            state.inside = runtime.zero_mask();
            state.candidate_inside_full = false;
            false
        } else if !source_inside && target_inside {
            state.iteration = 1;
            state.inside = runtime.zero_mask();
            state.candidate_inside_full = false;
            runtime.tracking(1)
        } else if source_inside && target_inside && backedge {
            match runtime.selected {
                None => {
                    if runtime.inside_complete(&state.inside) {
                        state.selected_inside_full = true;
                    }
                    // Every iteration runs the same check, so the exact count
                    // need not be part of the product state.
                    state.iteration = 1;
                    state.candidate_inside_full = false;
                }
                Some(SpecificIteration::Number(number)) => {
                    if state.iteration == number && runtime.inside_complete(&state.inside) {
                        state.selected_inside_full = true;
                    }
                    state.iteration = state
                        .iteration
                        .saturating_add(1)
                        .min(number.saturating_add(1));
                    state.candidate_inside_full = false;
                }
                Some(SpecificIteration::Last) => {
                    state.candidate_inside_full =
                        runtime.header_has_exit && runtime.inside_complete(&state.inside);
                    state.iteration = 1;
                }
            }
            state.inside = runtime.zero_mask();
            runtime.tracking(state.iteration)
        } else if source_inside && target_inside {
            if matches!(runtime.selected, Some(SpecificIteration::Last))
                && runtime.header == *source
            {
                state.candidate_inside_full = false;
            }
            runtime.tracking(state.iteration)
        } else {
            false
        };
        runtime.apply(
            edge_element,
            track_inside,
            &mut state.inside,
            &mut state.outside,
        );
        runtime.apply(block, track_inside, &mut state.inside, &mut state.outside);
        if track_inside
            && runtime.uses_selected_iteration()
            && runtime.inside_complete(&state.inside)
        {
            state.selected_inside_full = true;
        }
        let violated = match runtime.selected {
            None | Some(SpecificIteration::Number(_)) => {
                state.selected_inside_full && runtime.outside_complete(&state.outside)
            }
            Some(SpecificIteration::Last) => {
                state.last_inside_full && runtime.outside_complete(&state.outside)
            }
        };
        if violated {
            return None;
        }
        next.push(state);
    }
    Some(next)
}

fn sequence_resets(
    reset: &OrderedReset,
    loop_blocks: Option<&BTreeSet<BlockId>>,
    backedges: &BTreeSet<(BlockId, BlockId)>,
    source: &BlockId,
    target: &BlockId,
) -> bool {
    match reset {
        OrderedReset::Function => false,
        OrderedReset::LoopEntry { .. } => {
            loop_blocks.is_some_and(|blocks| !blocks.contains(source) && blocks.contains(target))
        }
        OrderedReset::LoopIteration { .. } | OrderedReset::LoopSpecific { .. } => {
            let entry = loop_blocks
                .is_some_and(|blocks| !blocks.contains(source) && blocks.contains(target));
            entry || backedges.contains(&(source.clone(), target.clone()))
        }
    }
}

fn element_within_blocks(element: &InfeasibleElement, blocks: &BTreeSet<BlockId>) -> bool {
    match element {
        InfeasibleElement::Block { block } => blocks.contains(block),
        InfeasibleElement::Edge { source, target, .. } => {
            blocks.contains(source) && blocks.contains(target)
        }
    }
}

fn loop_header_has_exit(cfg: &FunctionCfg, header: &BlockId, blocks: &BTreeSet<BlockId>) -> bool {
    cfg.blocks_by_address
        .values()
        .find(|node| cfg.graph[**node].id == *header)
        .is_some_and(|node| {
            cfg.graph
                .edges_directed(*node, petgraph::Direction::Outgoing)
                .any(|edge| !blocks.contains(&cfg.graph[edge.target()].id))
        })
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
                iteration_guard: None,
                all_mixed: false,
                loop_blocks: None,
                backedges: BTreeSet::new(),
                loop_header: None,
                header_has_exit: false,
                mixed: false,
                slot_outside: Vec::new(),
                outside_prefix: 0,
            }),
            OrderedReset::LoopEntry { header }
            | OrderedReset::LoopIteration { header }
            | OrderedReset::LoopSpecific { header, .. } => {
                let Some(loop_) = analysis.loops.iter().find(|loop_| loop_.header == *header)
                else {
                    return Err(IpetError::Unknown("ordered-loop-missing".to_owned()));
                };
                let backedges = if matches!(
                    automaton.reset,
                    OrderedReset::LoopIteration { .. } | OrderedReset::LoopSpecific { .. }
                ) {
                    loop_
                        .backedges
                        .iter()
                        .map(|edge| (edge.from.clone(), edge.to.clone()))
                        .collect()
                } else {
                    BTreeSet::new()
                };
                let blocks: BTreeSet<BlockId> = loop_.blocks.iter().cloned().collect();
                let header_has_exit = loop_header_has_exit(cfg, header, &blocks);
                let raw_specific = match &automaton.reset {
                    OrderedReset::LoopSpecific { iteration, .. } => Some(*iteration),
                    _ => None,
                };
                let slot_outside: Vec<bool> = automaton
                    .pattern
                    .iter()
                    .map(|element| !element_within_blocks(element, &blocks))
                    .collect();
                let has_inside = slot_outside.iter().any(|outside| !outside);
                let has_outside = slot_outside.iter().any(|outside| *outside);
                let iteration_scope = matches!(
                    automaton.reset,
                    OrderedReset::LoopIteration { .. } | OrderedReset::LoopSpecific { .. }
                );
                let mixed = iteration_scope && has_inside && has_outside;
                let all_mixed = mixed && raw_specific.is_none();
                let iteration_guard = raw_specific.or(all_mixed.then_some(SpecificIteration::Last));
                let outside_prefix = slot_outside.iter().take_while(|outside| **outside).count();
                Ok(AutomatonRuntime {
                    pattern: automaton.pattern.clone(),
                    reset: automaton.reset.clone(),
                    iteration_guard,
                    all_mixed,
                    loop_blocks: Some(blocks),
                    backedges,
                    loop_header: Some(header.clone()),
                    header_has_exit,
                    mixed,
                    slot_outside,
                    outside_prefix,
                })
            }
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AutomatonProgress {
    slot: usize,
    iteration: u32,
    pending: bool,
    last_pending: bool,
    /// Slot of the most recently completed iteration for mixed last-iteration
    /// matching; `usize::MAX` when no candidate is pending.
    candidate_slot: usize,
}

impl AutomatonProgress {
    const fn scoped(slot: usize, iteration: u32) -> Self {
        Self {
            slot,
            iteration,
            pending: false,
            last_pending: false,
            candidate_slot: usize::MAX,
        }
    }
}

fn pattern_completed_progress(runtime: &AutomatonRuntime, state: &mut AutomatonProgress) -> bool {
    if runtime.all_mixed {
        return false;
    }
    if matches!(runtime.iteration_guard, Some(SpecificIteration::Last)) {
        if runtime.mixed && state.iteration == 0 {
            return false;
        }
        state.pending = true;
        true
    } else {
        false
    }
}

fn automaton_slot_allowed(
    runtime: &AutomatonRuntime,
    state: AutomatonProgress,
    slot: usize,
) -> bool {
    if state.pending {
        return false;
    }
    if runtime.mixed && runtime.slot_outside.get(slot).copied().unwrap_or(false) {
        return true;
    }
    iteration_active(runtime.iteration_guard, state.iteration)
}

fn advance_automaton_pattern(
    runtime: &AutomatonRuntime,
    state: &mut AutomatonProgress,
    edge_element: &InfeasibleElement,
    block: &InfeasibleElement,
) -> bool {
    if runtime.pattern.get(state.slot) == Some(edge_element)
        && automaton_slot_allowed(runtime, *state, state.slot)
    {
        state.slot += 1;
        if state.slot >= runtime.pattern.len() {
            return pattern_completed_progress(runtime, state);
        }
    }
    if runtime.pattern.get(state.slot) == Some(block)
        && automaton_slot_allowed(runtime, *state, state.slot)
    {
        state.slot += 1;
        if state.slot >= runtime.pattern.len() {
            return pattern_completed_progress(runtime, state);
        }
    }
    true
}

fn initial_progress(
    runtimes: &[AutomatonRuntime],
    entry_block: &BlockId,
) -> Option<Vec<AutomatonProgress>> {
    let block = InfeasibleElement::Block {
        block: entry_block.clone(),
    };
    let mut progress = Vec::with_capacity(runtimes.len());
    for runtime in runtimes {
        let iteration = runtime.initial_iteration(entry_block);
        let mut state = AutomatonProgress::scoped(0, iteration);
        if runtime.pattern.first() == Some(&block) && automaton_slot_allowed(runtime, state, 0) {
            state.slot = 1;
            if state.slot >= runtime.pattern.len()
                && !pattern_completed_progress(runtime, &mut state)
            {
                return None;
            }
        }
        progress.push(state);
    }
    Some(progress)
}

fn advance_progress(
    runtimes: &[AutomatonRuntime],
    progress: &[AutomatonProgress],
    source: &BlockId,
    target: &BlockId,
    edge_element: &InfeasibleElement,
) -> Option<Vec<AutomatonProgress>> {
    let block = InfeasibleElement::Block {
        block: target.clone(),
    };
    let mut next = Vec::with_capacity(runtimes.len());
    for (index, runtime) in runtimes.iter().enumerate() {
        let mut state = progress[index];
        let mut active = true;
        if let Some(specific) = runtime.iteration_guard {
            let old_iteration = state.iteration;
            let step = advance_specific_iteration(
                specific,
                runtime.loop_blocks.as_ref(),
                &runtime.backedges,
                runtime.loop_header.as_ref(),
                runtime.header_has_exit,
                state.iteration,
                state.pending,
                state.last_pending,
                source,
                target,
            )?;
            if runtime.mixed {
                match specific {
                    SpecificIteration::Number(target_iteration) => {
                        if matches!(step.action, IterationAction::Boundary)
                            && old_iteration < target_iteration
                        {
                            state.slot = runtime.outside_prefix;
                        }
                    }
                    SpecificIteration::Last => match step.action {
                        IterationAction::Boundary if old_iteration == 0 => {
                            state.slot = runtime.outside_prefix;
                            state.candidate_slot = usize::MAX;
                        }
                        IterationAction::Boundary => {
                            state.candidate_slot =
                                if !state.pending && state.slot > runtime.outside_prefix {
                                    state.slot
                                } else {
                                    usize::MAX
                                };
                            state.slot = runtime.outside_prefix;
                        }
                        IterationAction::Exit => {
                            if state.candidate_slot != usize::MAX {
                                state.slot = state.candidate_slot;
                            }
                            state.candidate_slot = usize::MAX;
                        }
                        IterationAction::None => {
                            if state.candidate_slot != usize::MAX
                                && runtime.loop_header.as_ref() == Some(source)
                                && runtime
                                    .loop_blocks
                                    .as_ref()
                                    .is_some_and(|blocks| blocks.contains(target))
                            {
                                state.candidate_slot = usize::MAX;
                            }
                        }
                    },
                }
                active = true;
            } else {
                if step.resets() {
                    state.slot = 0;
                }
                active = step.active(specific);
            }
            state.iteration = step.iteration;
            state.pending = step.pending;
            state.last_pending = step.last_pending;
        } else if runtime.reset_on(source, target) {
            state.slot = 0;
        }
        if active && !advance_automaton_pattern(runtime, &mut state, edge_element, &block) {
            return None;
        }
        next.push(state);
    }
    Some(next)
}

struct ProductNode {
    original: NodeIndex,
    progress: Vec<AutomatonProgress>,
    presence: Vec<PresenceState>,
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
    presence_runtimes: &[PresenceRuntime],
) -> Result<(Vec<ProductNode>, Vec<ProductEdge>), IpetError> {
    let entry_block = cfg.graph[entry].id.clone();
    let Some(start_progress) = initial_progress(runtimes, &entry_block) else {
        return Err(IpetError::Unknown("infeasible-ordered-entry".to_owned()));
    };
    let Some(start_presence) = initial_presence_progress(presence_runtimes, &entry_block) else {
        return Err(IpetError::Unknown("infeasible-presence-entry".to_owned()));
    };
    let mut index_by_key: BTreeMap<(NodeIndex, Vec<AutomatonProgress>, Vec<PresenceState>), usize> =
        BTreeMap::new();
    let mut nodes = vec![ProductNode {
        original: entry,
        progress: start_progress.clone(),
        presence: start_presence.clone(),
    }];
    index_by_key.insert((entry, start_progress, start_presence), 0);
    let mut edges = Vec::new();
    let mut queue = VecDeque::from([0usize]);
    while let Some(from) = queue.pop_front() {
        let node = &nodes[from];
        let source = node.original;
        let source_id = cfg.graph[source].id.clone();
        let progress = node.progress.clone();
        let presence = node.presence.clone();
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
            let Some(next_presence) = advance_presence_progress(
                presence_runtimes,
                &presence,
                &source_id,
                &target_id,
                &edge_element,
                &InfeasibleElement::Block {
                    block: target_id.clone(),
                },
            ) else {
                continue;
            };
            let key = (target, next_progress.clone(), next_presence.clone());
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
                    presence: next_presence,
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

/// Remove product states that cannot reach a function exit. IPET flow
/// conservation alone permits circulations in such dead states.
fn prune_dead_product_nodes(
    cfg: &FunctionCfg,
    reachable_nodes: &BTreeSet<NodeIndex>,
    nonexit_headers: &BTreeSet<NodeIndex>,
    nodes: Vec<ProductNode>,
    edges: Vec<ProductEdge>,
) -> Result<(Vec<ProductNode>, Vec<ProductEdge>), IpetError> {
    let has_reachable_outgoing = |node: NodeIndex| {
        cfg.graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .any(|edge| reachable_nodes.contains(&edge.target()))
    };
    let mut reverse = vec![Vec::new(); nodes.len()];
    for edge in &edges {
        reverse[edge.to].push(edge.from);
    }
    let mut live = vec![false; nodes.len()];
    let mut queue = VecDeque::new();
    for (index, node) in nodes.iter().enumerate() {
        if !has_reachable_outgoing(node.original) || nonexit_headers.contains(&node.original) {
            live[index] = true;
            queue.push_back(index);
        }
    }
    while let Some(index) = queue.pop_front() {
        for &source in &reverse[index] {
            if !live[source] {
                live[source] = true;
                queue.push_back(source);
            }
        }
    }
    if !live[0] {
        return Err(IpetError::Unknown("ordered-product-no-exit".to_owned()));
    }
    let mut index_by_old = vec![usize::MAX; nodes.len()];
    let mut pruned_nodes = Vec::new();
    for (old, node) in nodes.into_iter().enumerate() {
        if live[old] {
            index_by_old[old] = pruned_nodes.len();
            pruned_nodes.push(node);
        }
    }
    let mut pruned_edges = Vec::new();
    for edge in edges {
        let from = index_by_old[edge.from];
        let to = index_by_old[edge.to];
        if from != usize::MAX && to != usize::MAX {
            pruned_edges.push(ProductEdge {
                original: edge.original,
                from,
                to,
            });
        }
    }
    Ok((pruned_nodes, pruned_edges))
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
    presence: &[PresenceAutomaton],
    pipeline_stalls: &BTreeMap<EdgeIndex, f64>,
    cache_persistence: &CachePersistenceModels,
    cache_ccg: Option<&CcgModel>,
) -> Result<IpetOutcome, IpetError> {
    let runtimes = automaton_runtimes(cfg, automata)?;
    let presence_runtimes = presence_runtimes(cfg, presence)?;
    let nonexit_headers: BTreeSet<NodeIndex> = loops
        .iter()
        .filter(|loop_| !loop_.has_exit)
        .map(|loop_| loop_.header)
        .collect();
    let (nodes, edges) =
        build_product_graph(cfg, entry, reachable_nodes, &runtimes, &presence_runtimes)?;
    let (nodes, edges) =
        prune_dead_product_nodes(cfg, reachable_nodes, &nonexit_headers, nodes, edges)?;
    let node_by_block_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
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
    constraints.extend(aggregate_conflict_constraints(
        cfg,
        &node_by_block_id,
        &block_expression,
        &edge_expression,
        facts,
        function_id,
        scope,
        &mut vars,
    ));

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
            partitioning: None,
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
            ras_model: None,
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
    /// One spec id per `<call>` group, in pattern order.
    constraint_groups: Vec<Vec<usize>>,
    /// One spec id per unordered cross-function group, in constraint order.
    unordered_groups: Vec<Vec<usize>>,
    outgoing: Vec<Vec<usize>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CrossState {
    slot: usize,
    sub: usize,
    /// 1-based loop iteration while inside the reset loop; 0 outside. Unused
    /// for constraints without a specific iteration.
    iteration: u32,
    /// The requested sequence completed in the current iteration of a
    /// last-iteration constraint. A loop exit rejects the path; a following
    /// body entry clears it because the completed iteration was not last.
    pending: bool,
    /// The iteration that just ended at a backedge completed the sequence and
    /// the loop header can exit. Exiting at the header rejects the path; a
    /// following body entry clears the flag because the loop continues.
    last_pending: bool,
    /// Slot of the most recently completed mixed-iteration prefix;
    /// `usize::MAX` when no candidate is pending.
    candidate_slot: usize,
}

impl CrossState {
    const fn unscoped(slot: usize, sub: usize) -> Self {
        Self {
            slot,
            sub,
            iteration: 0,
            pending: false,
            last_pending: false,
            candidate_slot: usize::MAX,
        }
    }

    const fn scoped(slot: usize, sub: usize, iteration: u32) -> Self {
        Self {
            slot,
            sub,
            iteration,
            pending: false,
            last_pending: false,
            candidate_slot: usize::MAX,
        }
    }

    const fn with_slot(self, slot: usize) -> Self {
        Self {
            slot,
            sub: 0,
            ..self
        }
    }

    const fn with_pending(self) -> Self {
        Self {
            sub: 0,
            pending: true,
            ..self
        }
    }
}

struct CrossGroupModel {
    call: usize,
    start: usize,
    len: usize,
}

#[derive(Clone, Debug)]
struct CrossUnorderedGroupModel {
    spec: usize,
    elements: Vec<InfeasibleElement>,
    full: Vec<u64>,
    /// Group boundaries are inside the selected loop.
    inside: bool,
}

impl CrossUnorderedGroupModel {
    fn zero_mask(&self) -> Vec<u64> {
        vec![0; self.elements.len().div_ceil(64)]
    }

    fn mask_full(&self, mask: &[u64]) -> bool {
        mask == self.full.as_slice()
    }

    fn apply(&self, element: &InfeasibleElement, mask: &mut [u64]) {
        if let Some(index) = self
            .elements
            .iter()
            .position(|candidate| candidate == element)
        {
            mask[index / 64] |= 1_u64 << (index % 64);
        }
    }
}

#[derive(Clone, Debug)]
struct CrossUnorderedModel {
    caller_inside_elements: Vec<InfeasibleElement>,
    caller_inside_full: Vec<u64>,
    caller_outside_elements: Vec<InfeasibleElement>,
    caller_outside_full: Vec<u64>,
    groups: Vec<CrossUnorderedGroupModel>,
    /// Reset and enforce presence inside this loop; `None` is function
    /// invocation scope.
    loop_blocks: Option<BTreeSet<BlockId>>,
    backedges: BTreeSet<(BlockId, BlockId)>,
    /// `Some` limits presence to one selected loop iteration. `None` with
    /// `loop_blocks` spans all iterations of one loop entry or checks every
    /// iteration when `all_iterations` is set.
    specific_iteration: Option<SpecificIteration>,
    all_iterations: bool,
    header: Option<BlockId>,
    header_has_exit: bool,
}

impl CrossUnorderedModel {
    fn zero_inside_caller_mask(&self) -> Vec<u64> {
        vec![0; self.caller_inside_elements.len().div_ceil(64)]
    }

    fn zero_outside_caller_mask(&self) -> Vec<u64> {
        vec![0; self.caller_outside_elements.len().div_ceil(64)]
    }

    fn mask_complete(mask: &[u64], full: &[u64]) -> bool {
        mask == full
    }

    fn caller_apply(elements: &[InfeasibleElement], element: &InfeasibleElement, mask: &mut [u64]) {
        if let Some(index) = elements.iter().position(|candidate| candidate == element) {
            mask[index / 64] |= 1_u64 << (index % 64);
        }
    }

    fn clear_inside(&self, state: &mut CrossUnorderedState) {
        state.caller_inside = self.zero_inside_caller_mask();
        for (index, group) in self.groups.iter().enumerate() {
            if group.inside {
                state.group_masks[index] = group.zero_mask();
                state.group_present[index] = false;
            }
        }
    }

    fn inside_complete(&self, state: &CrossUnorderedState) -> bool {
        Self::mask_complete(&state.caller_inside, &self.caller_inside_full)
            && self
                .groups
                .iter()
                .enumerate()
                .all(|(index, group)| !group.inside || state.group_present[index])
    }

    fn outside_complete(&self, state: &CrossUnorderedState) -> bool {
        Self::mask_complete(&state.caller_outside, &self.caller_outside_full)
            && self
                .groups
                .iter()
                .enumerate()
                .all(|(index, group)| group.inside || state.group_present[index])
    }

    fn tracking(&self, iteration: u32) -> bool {
        match self.specific_iteration {
            None => true,
            Some(SpecificIteration::Number(number)) => iteration == number,
            Some(SpecificIteration::Last) => iteration > 0,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CrossUnorderedState {
    active: bool,
    /// 1-based iteration while inside a loop; 0 outside. Kept at 1 for
    /// entry-scoped conflicts because they span all iterations.
    iteration: u32,
    caller_inside: Vec<u64>,
    caller_outside: Vec<u64>,
    group_masks: Vec<Vec<u64>>,
    group_present: Vec<bool>,
    /// Last-iteration conflict: the iteration ending at a backedge completed
    /// all inside items, and a header exit would make it the last iteration.
    candidate_inside_full: bool,
    /// Numeric selectors: the selected iteration completed all inside items.
    selected_inside_full: bool,
    /// Last selectors: the last completed iteration completed all inside
    /// items. Outside items may still appear after the loop.
    last_inside_full: bool,
    /// All-iteration selectors: some iteration completed all inside items.
    any_inside_full: bool,
}

struct CrossAutomatonModel {
    slots: Vec<CrossFunctionSlot>,
    groups: Vec<CrossGroupModel>,
    reset: OrderedReset,
    iteration_guard: Option<SpecificIteration>,
    all_mixed: bool,
    loop_blocks: Option<BTreeSet<BlockId>>,
    backedges: BTreeSet<(BlockId, BlockId)>,
    /// The reset loop header.
    loop_header: Option<BlockId>,
    /// The reset loop header has an outgoing edge that leaves the loop.
    header_has_exit: bool,
    /// A specific-iteration conflict with slots on both sides of the loop.
    mixed: bool,
    slot_outside: Vec<bool>,
    /// Number of leading pattern slots outside the reset loop.
    outside_prefix: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoopTransition {
    None,
    Entry,
    Backedge,
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IterationAction {
    /// Continue the current iteration.
    None,
    /// Enter a new iteration and reset pattern progress.
    Boundary,
    /// Leave the loop and reset pattern progress.
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IterationStep {
    iteration: u32,
    pending: bool,
    last_pending: bool,
    action: IterationAction,
}

impl IterationStep {
    fn active(self, specific: SpecificIteration) -> bool {
        !self.pending && iteration_active(Some(specific), self.iteration)
    }

    fn resets(self) -> bool {
        !matches!(self.action, IterationAction::None)
    }

    fn boundary(self) -> bool {
        matches!(self.action, IterationAction::Boundary)
    }
}

fn iteration_active(specific: Option<SpecificIteration>, iteration: u32) -> bool {
    match specific {
        None => true,
        Some(SpecificIteration::Number(number)) => iteration == number,
        Some(SpecificIteration::Last) => iteration > 0,
    }
}

fn sequence_loop_transition(
    loop_blocks: Option<&BTreeSet<BlockId>>,
    backedges: &BTreeSet<(BlockId, BlockId)>,
    source: &BlockId,
    target: &BlockId,
) -> LoopTransition {
    let Some(blocks) = loop_blocks else {
        return LoopTransition::None;
    };
    match (blocks.contains(source), blocks.contains(target)) {
        (false, true) => LoopTransition::Entry,
        (true, false) => LoopTransition::Exit,
        (true, true) if backedges.contains(&(source.clone(), target.clone())) => {
            LoopTransition::Backedge
        }
        _ => LoopTransition::None,
    }
}

/// Advance the iteration counter and last-iteration state for a numeric or
/// last-iteration sequence.
#[allow(clippy::too_many_arguments)]
fn advance_specific_iteration(
    specific: SpecificIteration,
    loop_blocks: Option<&BTreeSet<BlockId>>,
    backedges: &BTreeSet<(BlockId, BlockId)>,
    loop_header: Option<&BlockId>,
    header_has_exit: bool,
    iteration: u32,
    pending: bool,
    last_pending: bool,
    source: &BlockId,
    target: &BlockId,
) -> Option<IterationStep> {
    let transition = sequence_loop_transition(loop_blocks, backedges, source, target);
    match transition {
        LoopTransition::Entry => Some(IterationStep {
            iteration: 1,
            pending: false,
            last_pending: false,
            action: IterationAction::Boundary,
        }),
        LoopTransition::Backedge => {
            let iteration = match specific {
                SpecificIteration::Number(number) => {
                    iteration.saturating_add(1).min(number.saturating_add(1))
                }
                SpecificIteration::Last => 1,
            };
            let last_pending = matches!(specific, SpecificIteration::Last)
                && (pending || last_pending)
                && header_has_exit;
            Some(IterationStep {
                iteration,
                pending: false,
                last_pending,
                action: IterationAction::Boundary,
            })
        }
        LoopTransition::Exit => {
            let violated = if loop_header == Some(source) {
                last_pending
            } else {
                pending
            };
            if violated {
                None
            } else {
                Some(IterationStep {
                    iteration: 0,
                    pending: false,
                    last_pending: false,
                    action: IterationAction::Exit,
                })
            }
        }
        LoopTransition::None => {
            let last_pending = !(last_pending
                && loop_header == Some(source)
                && loop_blocks.is_some_and(|blocks| blocks.contains(target)));
            Some(IterationStep {
                iteration,
                pending,
                last_pending,
                action: IterationAction::None,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CrossIterationStep {
    state: CrossState,
    /// Pattern and group progress may advance in this state.
    active: bool,
    /// The edge entered or left the loop iteration boundary.
    boundary: bool,
}

impl CrossAutomatonModel {
    fn reset_on(&self, source: &BlockId, target: &BlockId) -> bool {
        sequence_resets(
            &self.reset,
            self.loop_blocks.as_ref(),
            &self.backedges,
            source,
            target,
        )
    }

    fn slot_allowed(&self, state: CrossState, slot: usize) -> bool {
        if state.pending {
            return false;
        }
        if self.mixed && self.slot_outside.get(slot).copied().unwrap_or(false) {
            return true;
        }
        iteration_active(self.iteration_guard, state.iteration)
    }

    fn initial_iteration(&self, entry_block: &BlockId) -> u32 {
        if self.iteration_guard.is_none() {
            return 0;
        }
        u32::from(
            self.loop_blocks
                .as_ref()
                .is_some_and(|blocks| blocks.contains(entry_block)),
        )
    }

    fn advance_iteration(
        &self,
        state: CrossState,
        source: &BlockId,
        target: &BlockId,
    ) -> Option<CrossIterationStep> {
        let Some(specific) = self.iteration_guard else {
            if self.reset_on(source, target) {
                return Some(CrossIterationStep {
                    state: CrossState::unscoped(0, 0),
                    active: true,
                    boundary: true,
                });
            }
            return Some(CrossIterationStep {
                state,
                active: true,
                boundary: false,
            });
        };
        let step = advance_specific_iteration(
            specific,
            self.loop_blocks.as_ref(),
            &self.backedges,
            self.loop_header.as_ref(),
            self.header_has_exit,
            state.iteration,
            state.pending,
            state.last_pending,
            source,
            target,
        )?;
        let mut next = state;
        if self.mixed {
            match specific {
                SpecificIteration::Number(target_iteration) => {
                    if matches!(step.action, IterationAction::Boundary)
                        && state.iteration < target_iteration
                    {
                        next.slot = self.outside_prefix;
                    }
                    if matches!(
                        step.action,
                        IterationAction::Boundary | IterationAction::Exit
                    ) {
                        next.sub = 0;
                    }
                }
                SpecificIteration::Last => match step.action {
                    IterationAction::Boundary if state.iteration == 0 => {
                        next.slot = self.outside_prefix;
                        next.sub = 0;
                        next.candidate_slot = usize::MAX;
                    }
                    IterationAction::Boundary => {
                        next.candidate_slot = if !state.pending && state.slot > self.outside_prefix
                        {
                            state.slot
                        } else {
                            usize::MAX
                        };
                        next.slot = self.outside_prefix;
                        next.sub = 0;
                    }
                    IterationAction::Exit => {
                        if next.candidate_slot != usize::MAX {
                            next.slot = next.candidate_slot;
                        }
                        next.candidate_slot = usize::MAX;
                        next.sub = 0;
                    }
                    IterationAction::None => {
                        if next.candidate_slot != usize::MAX
                            && self.loop_header.as_ref() == Some(source)
                            && self
                                .loop_blocks
                                .as_ref()
                                .is_some_and(|blocks| blocks.contains(target))
                        {
                            next.candidate_slot = usize::MAX;
                        }
                    }
                },
            }
        } else if step.resets() {
            next.slot = 0;
            next.sub = 0;
        }
        next.iteration = step.iteration;
        next.pending = step.pending;
        next.last_pending = step.last_pending;
        Some(CrossIterationStep {
            state: next,
            active: step.active(specific),
            boundary: step.boundary(),
        })
    }
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
    call_return: &InfeasibleElement,
) -> Result<(EdgeIndex, NodeIndex), IpetError> {
    let InfeasibleElement::Edge { target, site, .. } = call_return else {
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
    unordered: &[&CrossFunctionConstraint],
) -> Result<ModelGraph, IpetError> {
    let mut specs: Vec<InlineCallSpec> = Vec::new();
    let mut spec_by_key: BTreeMap<(NodeIndex, EdgeIndex, FunctionId), usize> = BTreeMap::new();
    let mut constraint_groups: Vec<Vec<usize>> = Vec::with_capacity(cross.len());
    let mut unordered_groups: Vec<Vec<usize>> = Vec::with_capacity(unordered.len());
    let all_constraints: Vec<(&CrossFunctionConstraint, bool)> = cross
        .iter()
        .map(|constraint| (*constraint, true))
        .chain(unordered.iter().map(|constraint| (*constraint, false)))
        .collect();
    for (constraint, ordered) in all_constraints {
        let mut group_specs = Vec::with_capacity(constraint.groups.len());
        for group in &constraint.groups {
            let caller_block = caller_node_by_block(cfg, &group.call_block).ok_or_else(|| {
                IpetError::Unknown("cross-function-call-block-missing".to_owned())
            })?;
            let callee_index = program
                .functions
                .iter()
                .position(|function| function.id == group.callee)
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
            let callee_chain = match scope {
                FactScope::Context(context) => {
                    Some(callee_context(function_id, context, Some(group.call_site)))
                }
                FactScope::Insensitive => None,
            };
            let callee_scope = callee_chain
                .as_ref()
                .map_or(FactScope::Insensitive, |chain| FactScope::Context(chain));
            let callee_loops =
                build_loops(&callee.cfg, callee_entry, &analysis, facts, callee_scope).map_err(
                    |error| match error {
                        IpetError::Unbounded(reason) | IpetError::Unknown(reason) => {
                            IpetError::Unknown(format!("cross-function-callee-{reason}"))
                        }
                    },
                )?;
            let (call_return_edge, continuation) =
                inline_call_return(cfg, caller_block, &group.call_return)?;
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
            group_specs.push(spec_id);
        }
        if group_specs.is_empty() {
            return Err(IpetError::Unknown(
                "cross-function-groups-missing".to_owned(),
            ));
        }
        if ordered {
            constraint_groups.push(group_specs);
        } else {
            unordered_groups.push(group_specs);
        }
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
        constraint_groups,
        unordered_groups,
        outgoing,
    })
}

fn cross_slot_classification(
    slots: &[CrossFunctionSlot],
    groups: &[CrossGroupModel],
    constraint: &CrossFunctionConstraint,
    blocks: &BTreeSet<BlockId>,
    specific: bool,
) -> (bool, Vec<bool>, usize) {
    let slot_outside: Vec<bool> = slots
        .iter()
        .enumerate()
        .map(|(index, slot)| match slot {
            CrossFunctionSlot::Caller(element) => !element_within_blocks(element, blocks),
            CrossFunctionSlot::Callee(_) => groups
                .iter()
                .find(|group| index >= group.start && index < group.start + group.len)
                .is_none_or(|group| {
                    !blocks.contains(&constraint.groups[group.call].call_block)
                        || !blocks.contains(&constraint.groups[group.call].continuation)
                }),
        })
        .collect();
    let has_inside = slot_outside.iter().any(|outside| !outside);
    let has_outside = slot_outside.iter().any(|outside| *outside);
    let outside_prefix = slot_outside.iter().take_while(|outside| **outside).count();
    (
        specific && has_inside && has_outside,
        slot_outside,
        outside_prefix,
    )
}

#[allow(clippy::too_many_lines)]
fn cross_automaton_models(
    model: &ModelGraph,
    cfg: &FunctionCfg,
    cross: &[&CrossFunctionConstraint],
) -> Result<Vec<CrossAutomatonModel>, IpetError> {
    let analysis = crate::cfg_graph::analyze(cfg);
    if model.constraint_groups.len() != cross.len() {
        return Err(IpetError::Unknown("cross-function-model".to_owned()));
    }
    cross
        .iter()
        .zip(&model.constraint_groups)
        .map(|(constraint, specs)| {
            if specs.len() != constraint.groups.len() {
                return Err(IpetError::Unknown("cross-function-groups".to_owned()));
            }
            let slots = constraint.pattern.clone();
            let mut groups = Vec::with_capacity(constraint.groups.len());
            let mut covered = BTreeSet::new();
            let mut previous_end = 0_usize;
            for (group, &call) in constraint.groups.iter().zip(specs) {
                let start = group.slot_start;
                let len = group.slot_len;
                let end = start.saturating_add(len);
                if len == 0
                    || end > slots.len()
                    || start < previous_end
                    || slots[start..end]
                        .iter()
                        .any(|slot| matches!(slot, CrossFunctionSlot::Caller(_)))
                {
                    return Err(IpetError::Unknown(
                        "cross-function-pattern-order".to_owned(),
                    ));
                }
                for index in start..end {
                    if !covered.insert(index) {
                        return Err(IpetError::Unknown(
                            "cross-function-pattern-order".to_owned(),
                        ));
                    }
                }
                groups.push(CrossGroupModel { call, start, len });
                previous_end = end;
            }
            if slots.iter().enumerate().any(|(index, slot)| {
                matches!(slot, CrossFunctionSlot::Callee(_)) && !covered.contains(&index)
            }) {
                return Err(IpetError::Unknown(
                    "cross-function-pattern-order".to_owned(),
                ));
            }
            let (loop_blocks, backedges, loop_header, header_has_exit) = match &constraint.reset {
                OrderedReset::Function => (None, BTreeSet::new(), None, false),
                OrderedReset::LoopEntry { header }
                | OrderedReset::LoopIteration { header }
                | OrderedReset::LoopSpecific { header, .. } => {
                    let Some(loop_) = analysis.loops.iter().find(|loop_| loop_.header == *header)
                    else {
                        return Err(IpetError::Unknown("ordered-loop-missing".to_owned()));
                    };
                    let backedges = if matches!(
                        constraint.reset,
                        OrderedReset::LoopIteration { .. } | OrderedReset::LoopSpecific { .. }
                    ) {
                        loop_
                            .backedges
                            .iter()
                            .map(|edge| (edge.from.clone(), edge.to.clone()))
                            .collect()
                    } else {
                        BTreeSet::new()
                    };
                    let blocks: BTreeSet<BlockId> = loop_.blocks.iter().cloned().collect();
                    let header_has_exit = loop_header_has_exit(cfg, header, &blocks);
                    (
                        Some(blocks),
                        backedges,
                        Some(header.clone()),
                        header_has_exit,
                    )
                }
            };
            if constraint.specific_iteration.is_some()
                && !matches!(
                    constraint.reset,
                    OrderedReset::LoopIteration { .. } | OrderedReset::LoopSpecific { .. }
                )
            {
                return Err(IpetError::Unknown("specific-iteration-scope".to_owned()));
            }
            let (mixed, slot_outside, outside_prefix) = loop_blocks.as_ref().map_or_else(
                || (false, vec![false; slots.len()], 0),
                |blocks| {
                    cross_slot_classification(
                        &slots,
                        &groups,
                        constraint,
                        blocks,
                        matches!(
                            constraint.reset,
                            OrderedReset::LoopIteration { .. } | OrderedReset::LoopSpecific { .. }
                        ),
                    )
                },
            );
            let all_mixed = mixed && constraint.specific_iteration.is_none();
            let iteration_guard = constraint
                .specific_iteration
                .or(all_mixed.then_some(SpecificIteration::Last));
            Ok(CrossAutomatonModel {
                slots,
                groups,
                reset: constraint.reset.clone(),
                iteration_guard,
                all_mixed,
                loop_blocks,
                backedges,
                loop_header,
                header_has_exit,
                mixed,
                slot_outside,
                outside_prefix,
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

fn pattern_completed(automaton: &CrossAutomatonModel, state: CrossState) -> Option<CrossState> {
    if automaton.all_mixed {
        return None;
    }
    if matches!(automaton.iteration_guard, Some(SpecificIteration::Last)) {
        if automaton.mixed && state.iteration == 0 {
            return None;
        }
        Some(state.with_pending())
    } else {
        None
    }
}

fn advance_cross_caller(
    automaton: &CrossAutomatonModel,
    state: CrossState,
    edge: &InfeasibleElement,
    target: &BlockId,
) -> Option<CrossState> {
    let mut slot = state.slot;
    if slot < automaton.slots.len()
        && automaton.slot_allowed(state, slot)
        && matches!(&automaton.slots[slot], CrossFunctionSlot::Caller(candidate) if candidate == edge)
    {
        slot += 1;
        if slot == automaton.slots.len() {
            return pattern_completed(automaton, state);
        }
    }
    let block = InfeasibleElement::Block {
        block: target.clone(),
    };
    if slot < automaton.slots.len()
        && automaton.slot_allowed(state, slot)
        && matches!(&automaton.slots[slot], CrossFunctionSlot::Caller(candidate) if candidate == &block)
    {
        slot += 1;
        if slot == automaton.slots.len() {
            return pattern_completed(automaton, state);
        }
    }
    Some(state.with_slot(slot))
}

fn initial_cross_state(
    automaton: &CrossAutomatonModel,
    entry_block: &BlockId,
) -> Option<CrossState> {
    let iteration = automaton.initial_iteration(entry_block);
    let state = CrossState::scoped(0, 0, iteration);
    if let Some(CrossFunctionSlot::Caller(InfeasibleElement::Block { block })) =
        automaton.slots.first()
        && block == entry_block
        && automaton.slot_allowed(state, 0)
    {
        let slot = 1;
        if slot == automaton.slots.len() {
            return pattern_completed(automaton, state);
        }
        return Some(state.with_slot(slot));
    }
    Some(state)
}

fn cross_group_for_call(
    automaton: &CrossAutomatonModel,
    call: Option<usize>,
    slot: usize,
) -> Option<&CrossGroupModel> {
    let call = call?;
    automaton
        .groups
        .iter()
        .find(|group| group.call == call && group.start == slot)
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
            let (source, target_node) = cfg
                .graph
                .edge_endpoints(edge.original)
                .expect("model graph caller edge endpoint");
            let step = automaton.advance_iteration(
                state,
                &cfg.graph[source].id,
                &cfg.graph[target_node].id,
            )?;
            if !step.active && !automaton.mixed {
                return Some(step.state);
            }
            let element = caller_edge_element(cfg, edge.original);
            let target = &model.nodes[edge.target].block;
            advance_cross_caller(automaton, step.state, &element, target)
        }
        ModelEdgeKind::EnterCall => {
            let Some(group) = cross_group_for_call(automaton, edge.call, state.slot) else {
                return Some(state);
            };
            if !automaton.slot_allowed(state, group.start) {
                return Some(state);
            }
            let mut sub = 0;
            if slot_matches_callee_block(
                &automaton.slots[group.start],
                &model.nodes[edge.target].block,
            ) {
                sub = 1;
            }
            Some(CrossState { sub, ..state })
        }
        ModelEdgeKind::CalleeEdge => {
            let Some(group) = cross_group_for_call(automaton, edge.call, state.slot) else {
                return Some(state);
            };
            if !automaton.slot_allowed(state, group.start) {
                return Some(state);
            }
            let spec = &model.specs[group.call];
            let callee = &program.functions[spec.callee_index];
            let element = callee_edge_element(&callee.cfg, edge.original);
            let target = &model.nodes[edge.target].block;
            let mut sub = state.sub;
            if sub < group.len {
                if slot_matches_callee_edge(&automaton.slots[group.start + sub], &element) {
                    sub += 1;
                }
                if sub < group.len
                    && slot_matches_callee_block(&automaton.slots[group.start + sub], target)
                {
                    sub += 1;
                }
            }
            Some(CrossState { sub, ..state })
        }
        ModelEdgeKind::ReturnCall => {
            let (source, target_node) = cfg
                .graph
                .edge_endpoints(edge.original)
                .expect("model graph caller edge endpoint");
            let step = automaton.advance_iteration(
                state,
                &cfg.graph[source].id,
                &cfg.graph[target_node].id,
            )?;
            if !step.active && !automaton.mixed {
                return Some(step.state);
            }
            let mut slot = step.state.slot;
            if !step.boundary
                && automaton.slot_allowed(step.state, step.state.slot)
                && let Some(group) = cross_group_for_call(automaton, edge.call, step.state.slot)
                && step.state.sub == group.len
            {
                slot = group.start + group.len;
                if slot == automaton.slots.len() {
                    return pattern_completed(automaton, step.state);
                }
            }
            let element = caller_edge_element(cfg, edge.original);
            let target = &model.nodes[edge.target].block;
            advance_cross_caller(automaton, step.state.with_slot(slot), &element, target)
        }
    }
}

fn advance_existing_on_model(
    cfg: &FunctionCfg,
    runtimes: &[AutomatonRuntime],
    progress: &[AutomatonProgress],
    edge: &ModelEdge,
) -> Option<Vec<AutomatonProgress>> {
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

fn advance_presence_on_model(
    cfg: &FunctionCfg,
    runtimes: &[PresenceRuntime],
    progress: &[PresenceState],
    edge: &ModelEdge,
) -> Option<Vec<PresenceState>> {
    match edge.kind {
        ModelEdgeKind::Caller | ModelEdgeKind::ReturnCall => {
            let (source, target) = cfg
                .graph
                .edge_endpoints(edge.original)
                .expect("model graph caller edge endpoint");
            let source_id = cfg.graph[source].id.clone();
            let target_id = cfg.graph[target].id.clone();
            advance_presence_progress(
                runtimes,
                progress,
                &source_id,
                &target_id,
                &InfeasibleElement::Edge {
                    source: source_id.clone(),
                    target: target_id.clone(),
                    site: cfg.graph[edge.original].site,
                },
                &InfeasibleElement::Block {
                    block: target_id.clone(),
                },
            )
        }
        ModelEdgeKind::EnterCall | ModelEdgeKind::CalleeEdge => Some(progress.to_vec()),
    }
}

#[allow(clippy::too_many_lines)]
fn cross_unordered_models(
    model: &ModelGraph,
    cfg: &FunctionCfg,
    constraints: &[&CrossFunctionConstraint],
) -> Result<Vec<CrossUnorderedModel>, IpetError> {
    if model.unordered_groups.len() != constraints.len() {
        return Err(IpetError::Unknown("cross-unordered-model".to_owned()));
    }
    let analysis = crate::cfg_graph::analyze(cfg);
    constraints
        .iter()
        .zip(&model.unordered_groups)
        .map(|(constraint, specs)| {
            if specs.len() != constraint.groups.len() {
                return Err(IpetError::Unknown("cross-unordered-groups".to_owned()));
            }
            let (
                loop_blocks,
                backedges,
                header,
                header_has_exit,
                specific_iteration,
                all_iterations,
            ) = match &constraint.reset {
                OrderedReset::Function => (None, BTreeSet::new(), None, false, None, false),
                OrderedReset::LoopEntry { header }
                | OrderedReset::LoopIteration { header }
                | OrderedReset::LoopSpecific { header, .. } => {
                    let Some(loop_) = analysis.loops.iter().find(|loop_| loop_.header == *header)
                    else {
                        return Err(IpetError::Unknown(
                            "cross-unordered-loop-missing".to_owned(),
                        ));
                    };
                    let blocks: BTreeSet<BlockId> = loop_.blocks.iter().cloned().collect();
                    let specific = match &constraint.reset {
                        OrderedReset::LoopSpecific { iteration, .. } => Some(*iteration),
                        _ => None,
                    };
                    (
                        Some(blocks.clone()),
                        loop_
                            .backedges
                            .iter()
                            .map(|edge| (edge.from.clone(), edge.to.clone()))
                            .collect(),
                        Some(header.clone()),
                        loop_header_has_exit(cfg, header, &blocks),
                        specific,
                        matches!(constraint.reset, OrderedReset::LoopIteration { .. }),
                    )
                }
            };
            let full_mask = |len: usize| {
                let mut full = vec![0_u64; len.div_ceil(64)];
                for index in 0..len {
                    full[index / 64] |= 1_u64 << (index % 64);
                }
                full
            };
            let inside_blocks = if specific_iteration.is_some() || all_iterations {
                loop_blocks.as_ref()
            } else {
                None
            };
            let mut caller_inside = Vec::new();
            let mut caller_outside = Vec::new();
            for element in constraint.pattern.iter().filter_map(|slot| match slot {
                CrossFunctionSlot::Caller(element) => Some(element),
                CrossFunctionSlot::Callee(_) => None,
            }) {
                let inside =
                    inside_blocks.is_none_or(|blocks| element_within_blocks(element, blocks));
                if inside {
                    caller_inside.push(element.clone());
                } else {
                    caller_outside.push(element.clone());
                }
            }
            let caller_inside_full = full_mask(caller_inside.len());
            let caller_outside_full = full_mask(caller_outside.len());
            let mut groups = Vec::with_capacity(constraint.groups.len());
            for (group, &spec) in constraint.groups.iter().zip(specs) {
                let start = group.slot_start;
                let end = start.saturating_add(group.slot_len);
                if group.slot_len == 0 || end > constraint.pattern.len() {
                    return Err(IpetError::Unknown(
                        "cross-unordered-pattern-order".to_owned(),
                    ));
                }
                let elements: Vec<InfeasibleElement> = constraint.pattern[start..end]
                    .iter()
                    .filter_map(|slot| match slot {
                        CrossFunctionSlot::Callee(element) => Some(element.clone()),
                        CrossFunctionSlot::Caller(_) => None,
                    })
                    .collect();
                if elements.is_empty() {
                    return Err(IpetError::Unknown(
                        "cross-unordered-pattern-order".to_owned(),
                    ));
                }
                let inside = inside_blocks.is_none_or(|blocks| {
                    let call_block = blocks.contains(&group.call_block);
                    let continuation = blocks.contains(&group.continuation);
                    let call_return = element_within_blocks(&group.call_return, blocks);
                    let count = usize::from(call_block)
                        + usize::from(continuation)
                        + usize::from(call_return);
                    if count != 0 && count != 3 {
                        // The resolver rejects straddling groups; keep the
                        // product conservative if one slips through.
                        false
                    } else {
                        count == 3
                    }
                });
                let full = full_mask(elements.len());
                groups.push(CrossUnorderedGroupModel {
                    spec,
                    elements,
                    full,
                    inside,
                });
            }
            Ok(CrossUnorderedModel {
                caller_inside_elements: caller_inside,
                caller_inside_full,
                caller_outside_elements: caller_outside,
                caller_outside_full,
                groups,
                loop_blocks,
                backedges,
                specific_iteration,
                all_iterations,
                header,
                header_has_exit,
            })
        })
        .collect()
}

fn initial_cross_unordered_progress(
    models: &[CrossUnorderedModel],
    entry_block: &BlockId,
) -> Vec<CrossUnorderedState> {
    models
        .iter()
        .map(|model| {
            let inside = model
                .loop_blocks
                .as_ref()
                .is_some_and(|blocks| blocks.contains(entry_block));
            let active = model.loop_blocks.is_none() || inside;
            let iteration = u32::from(inside);
            let block = InfeasibleElement::Block {
                block: entry_block.clone(),
            };
            let mut caller_inside = model.zero_inside_caller_mask();
            let mut caller_outside = model.zero_outside_caller_mask();
            CrossUnorderedModel::caller_apply(
                &model.caller_outside_elements,
                &block,
                &mut caller_outside,
            );
            if active && model.tracking(iteration) {
                CrossUnorderedModel::caller_apply(
                    &model.caller_inside_elements,
                    &block,
                    &mut caller_inside,
                );
            }
            CrossUnorderedState {
                active,
                iteration,
                caller_inside,
                caller_outside,
                group_masks: model
                    .groups
                    .iter()
                    .map(CrossUnorderedGroupModel::zero_mask)
                    .collect(),
                group_present: vec![false; model.groups.len()],
                candidate_inside_full: false,
                selected_inside_full: false,
                last_inside_full: false,
                any_inside_full: false,
            }
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn advance_cross_unordered(
    model: &ModelGraph,
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    runtimes: &[CrossUnorderedModel],
    states: &[CrossUnorderedState],
    edge: &ModelEdge,
) -> Option<Vec<CrossUnorderedState>> {
    let mut next = Vec::with_capacity(runtimes.len());
    for (index, runtime) in runtimes.iter().enumerate() {
        let mut state = states[index].clone();
        let caller_transition =
            if matches!(edge.kind, ModelEdgeKind::Caller | ModelEdgeKind::ReturnCall) {
                let (source, target) = cfg
                    .graph
                    .edge_endpoints(edge.original)
                    .expect("model graph caller edge endpoint");
                Some((cfg.graph[source].id.clone(), cfg.graph[target].id.clone()))
            } else {
                None
            };
        if let Some(blocks) = &runtime.loop_blocks
            && let Some((source, target)) = &caller_transition
        {
            let source_inside = blocks.contains(source);
            let target_inside = blocks.contains(target);
            if !source_inside && target_inside {
                state.active = true;
                state.iteration = 1;
                state.candidate_inside_full = false;
                runtime.clear_inside(&mut state);
            } else if source_inside && !target_inside {
                let complete = if state.active {
                    match runtime.specific_iteration {
                        Some(SpecificIteration::Number(number)) => {
                            if state.iteration == number && runtime.inside_complete(&state) {
                                state.selected_inside_full = true;
                            }
                            false
                        }
                        Some(SpecificIteration::Last) => {
                            let last_full = if runtime.header.as_ref() == Some(source) {
                                state.candidate_inside_full
                            } else {
                                runtime.inside_complete(&state)
                            };
                            state.last_inside_full |= last_full;
                            false
                        }
                        None => {
                            if runtime.all_iterations {
                                if state.active && runtime.inside_complete(&state) {
                                    state.any_inside_full = true;
                                }
                                false
                            } else {
                                runtime.inside_complete(&state)
                            }
                        }
                    }
                } else {
                    false
                };
                if complete && runtime.outside_complete(&state) {
                    return None;
                }
                state.active = false;
                state.iteration = 0;
                state.candidate_inside_full = false;
                runtime.clear_inside(&mut state);
            } else if !source_inside && !target_inside {
                state.active = false;
                state.iteration = 0;
                state.candidate_inside_full = false;
                runtime.clear_inside(&mut state);
            } else if source_inside && target_inside {
                let backedge = runtime
                    .backedges
                    .contains(&(source.clone(), target.clone()));
                if backedge {
                    match runtime.specific_iteration {
                        Some(SpecificIteration::Number(number)) => {
                            if state.iteration == number && runtime.inside_complete(&state) {
                                state.selected_inside_full = true;
                            }
                            state.iteration = state
                                .iteration
                                .saturating_add(1)
                                .min(number.saturating_add(1));
                            state.candidate_inside_full = false;
                            runtime.clear_inside(&mut state);
                        }
                        Some(SpecificIteration::Last) => {
                            state.candidate_inside_full =
                                runtime.header_has_exit && runtime.inside_complete(&state);
                            state.iteration = 1;
                            runtime.clear_inside(&mut state);
                        }
                        None => {
                            if runtime.all_iterations {
                                if runtime.inside_complete(&state) {
                                    state.any_inside_full = true;
                                }
                                state.iteration = 1;
                                state.candidate_inside_full = false;
                                runtime.clear_inside(&mut state);
                            }
                        }
                    }
                } else if matches!(runtime.specific_iteration, Some(SpecificIteration::Last))
                    && runtime.header.as_ref() == Some(source)
                {
                    state.candidate_inside_full = false;
                }
            }
        }
        let track_inside = state.active && runtime.tracking(state.iteration);
        if let Some((_, target)) = &caller_transition {
            CrossUnorderedModel::caller_apply(
                &runtime.caller_outside_elements,
                &caller_edge_element(cfg, edge.original),
                &mut state.caller_outside,
            );
            CrossUnorderedModel::caller_apply(
                &runtime.caller_outside_elements,
                &InfeasibleElement::Block {
                    block: target.clone(),
                },
                &mut state.caller_outside,
            );
            if track_inside {
                CrossUnorderedModel::caller_apply(
                    &runtime.caller_inside_elements,
                    &caller_edge_element(cfg, edge.original),
                    &mut state.caller_inside,
                );
                CrossUnorderedModel::caller_apply(
                    &runtime.caller_inside_elements,
                    &InfeasibleElement::Block {
                        block: target.clone(),
                    },
                    &mut state.caller_inside,
                );
            }
        }
        if let Some(spec) = edge.call {
            for (group_index, group) in runtime.groups.iter().enumerate() {
                if group.spec != spec {
                    continue;
                }
                let group_active = !group.inside || track_inside;
                match edge.kind {
                    ModelEdgeKind::EnterCall => {
                        state.group_masks[group_index] = group.zero_mask();
                        if group_active {
                            group.apply(
                                &InfeasibleElement::Block {
                                    block: model.nodes[edge.target].block.clone(),
                                },
                                &mut state.group_masks[group_index],
                            );
                        }
                    }
                    ModelEdgeKind::CalleeEdge => {
                        if group_active {
                            let call = model.specs.get(spec)?;
                            let callee = program.functions.get(call.callee_index)?;
                            let (_, target) = callee
                                .cfg
                                .graph
                                .edge_endpoints(edge.original)
                                .expect("model graph callee edge endpoint");
                            group.apply(
                                &callee_edge_element(&callee.cfg, edge.original),
                                &mut state.group_masks[group_index],
                            );
                            group.apply(
                                &InfeasibleElement::Block {
                                    block: callee.cfg.graph[target].id.clone(),
                                },
                                &mut state.group_masks[group_index],
                            );
                        }
                    }
                    ModelEdgeKind::ReturnCall => {
                        if group_active && group.mask_full(&state.group_masks[group_index]) {
                            state.group_present[group_index] = true;
                        }
                        state.group_masks[group_index] = group.zero_mask();
                    }
                    ModelEdgeKind::Caller => {}
                }
            }
        }
        if track_inside
            && matches!(
                runtime.specific_iteration,
                Some(SpecificIteration::Number(_))
            )
            && runtime.inside_complete(&state)
        {
            state.selected_inside_full = true;
        }
        if track_inside && runtime.all_iterations && runtime.inside_complete(&state) {
            state.any_inside_full = true;
        }
        let violated = match runtime.specific_iteration {
            Some(SpecificIteration::Number(_)) => {
                state.selected_inside_full && runtime.outside_complete(&state)
            }
            Some(SpecificIteration::Last) => {
                state.last_inside_full && runtime.outside_complete(&state)
            }
            None => {
                if runtime.all_iterations {
                    state.any_inside_full && runtime.outside_complete(&state)
                } else {
                    state.active
                        && track_inside
                        && runtime.inside_complete(&state)
                        && runtime.outside_complete(&state)
                }
            }
        };
        if violated {
            return None;
        }
        next.push(state);
    }
    Some(next)
}

type CrossProductKey = (
    usize,
    Vec<AutomatonProgress>,
    Vec<PresenceState>,
    Vec<CrossUnorderedState>,
    Vec<CrossState>,
);

struct CrossProductNode {
    model: usize,
    existing: Vec<AutomatonProgress>,
    presence: Vec<PresenceState>,
    unordered: Vec<CrossUnorderedState>,
    cross: Vec<CrossState>,
}

struct CrossProductEdge {
    model_edge: usize,
    from: usize,
    to: usize,
}

#[allow(clippy::too_many_lines)]
fn build_cross_product_graph(
    model: &ModelGraph,
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    runtimes: &[AutomatonRuntime],
    presence_runtimes: &[PresenceRuntime],
    unordered_models: &[CrossUnorderedModel],
    automata: &[CrossAutomatonModel],
) -> Result<(Vec<CrossProductNode>, Vec<CrossProductEdge>), IpetError> {
    let entry_block = model.nodes[model.entry].block.clone();
    let Some(start_existing) = initial_progress(runtimes, &entry_block) else {
        return Err(IpetError::Unknown("infeasible-ordered-entry".to_owned()));
    };
    let Some(start_presence) = initial_presence_progress(presence_runtimes, &entry_block) else {
        return Err(IpetError::Unknown("infeasible-presence-entry".to_owned()));
    };
    let start_unordered = initial_cross_unordered_progress(unordered_models, &entry_block);
    let mut start_cross = Vec::with_capacity(automata.len());
    for automaton in automata {
        let Some(state) = initial_cross_state(automaton, &entry_block) else {
            return Err(IpetError::Unknown("infeasible-ordered-entry".to_owned()));
        };
        start_cross.push(state);
    }
    let mut index_by_key: BTreeMap<CrossProductKey, usize> = BTreeMap::new();
    let mut nodes = vec![CrossProductNode {
        model: model.entry,
        existing: start_existing.clone(),
        presence: start_presence.clone(),
        unordered: start_unordered.clone(),
        cross: start_cross.clone(),
    }];
    index_by_key.insert(
        (
            model.entry,
            start_existing,
            start_presence,
            start_unordered,
            start_cross,
        ),
        0,
    );
    let mut edges = Vec::new();
    let mut queue = VecDeque::from([0usize]);
    while let Some(from) = queue.pop_front() {
        let source_model = nodes[from].model;
        let existing = nodes[from].existing.clone();
        let presence = nodes[from].presence.clone();
        let unordered = nodes[from].unordered.clone();
        let cross = nodes[from].cross.clone();
        for &model_edge in &model.outgoing[source_model] {
            let edge = &model.edges[model_edge];
            let Some(next_existing) = advance_existing_on_model(cfg, runtimes, &existing, edge)
            else {
                continue;
            };
            let Some(next_presence) =
                advance_presence_on_model(cfg, presence_runtimes, &presence, edge)
            else {
                continue;
            };
            let Some(next_unordered) =
                advance_cross_unordered(model, program, cfg, unordered_models, &unordered, edge)
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
            let key = (
                edge.target,
                next_existing.clone(),
                next_presence.clone(),
                next_unordered.clone(),
                next_cross.clone(),
            );
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
                    presence: next_presence,
                    unordered: next_unordered,
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

/// Remove product states that cannot reach a function exit. Flow conservation
/// alone permits circulations in such dead states, which would count
/// executions that no complete path can perform.
fn prune_dead_cross_product_nodes(
    model: &ModelGraph,
    nonexit_headers: &BTreeSet<usize>,
    nodes: Vec<CrossProductNode>,
    edges: Vec<CrossProductEdge>,
) -> Result<(Vec<CrossProductNode>, Vec<CrossProductEdge>), IpetError> {
    let mut reverse = vec![Vec::new(); nodes.len()];
    for edge in &edges {
        reverse[edge.to].push(edge.from);
    }
    let mut live = vec![false; nodes.len()];
    let mut queue = VecDeque::new();
    for (index, node) in nodes.iter().enumerate() {
        if model.outgoing[node.model].is_empty() || nonexit_headers.contains(&node.model) {
            live[index] = true;
            queue.push_back(index);
        }
    }
    while let Some(index) = queue.pop_front() {
        for &source in &reverse[index] {
            if !live[source] {
                live[source] = true;
                queue.push_back(source);
            }
        }
    }
    if !live[0] {
        return Err(IpetError::Unknown("cross-function-no-exit".to_owned()));
    }
    let mut index_by_old = vec![usize::MAX; nodes.len()];
    let mut pruned_nodes = Vec::new();
    for (old, node) in nodes.into_iter().enumerate() {
        if live[old] {
            index_by_old[old] = pruned_nodes.len();
            pruned_nodes.push(node);
        }
    }
    let mut pruned_edges = Vec::new();
    for edge in edges {
        let (Some(&from), Some(&to)) = (index_by_old.get(edge.from), index_by_old.get(edge.to))
        else {
            continue;
        };
        if from != usize::MAX && to != usize::MAX {
            pruned_edges.push(CrossProductEdge {
                from,
                to,
                model_edge: edge.model_edge,
            });
        }
    }
    Ok((pruned_nodes, pruned_edges))
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
    presence: &[PresenceAutomaton],
    cross: &[&CrossFunctionConstraint],
    unordered: &[&CrossFunctionConstraint],
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
        unordered,
    )?;
    let runtimes = automaton_runtimes(cfg, automata)?;
    let presence_runtimes = presence_runtimes(cfg, presence)?;
    let cross_automata = cross_automaton_models(&model, cfg, cross)?;
    let unordered_models = cross_unordered_models(&model, cfg, unordered)?;
    let model_loops = build_model_loops(&model, loops);
    let nonexit_headers: BTreeSet<usize> = loops
        .iter()
        .filter(|loop_| !loop_.has_exit)
        .filter_map(|loop_| model.caller_nodes.get(&loop_.header).copied())
        .collect();
    let (product_nodes, product_edges) = build_cross_product_graph(
        &model,
        program,
        cfg,
        &runtimes,
        &presence_runtimes,
        &unordered_models,
        &cross_automata,
    )?;
    let (product_nodes, product_edges) =
        prune_dead_cross_product_nodes(&model, &nonexit_headers, product_nodes, product_edges)?;
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
    constraints.extend(aggregate_conflict_constraints(
        cfg,
        &node_by_block_id,
        &block_expression,
        &edge_expression,
        facts,
        function_id,
        scope,
        &mut vars,
    ));

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
            partitioning: None,
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
            ras_model: None,
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
            None,
            false,
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

struct RasIpetModel {
    entries: usize,
    miss_penalty: u32,
}

impl RasIpetModel {
    fn penalty(&self) -> f64 {
        f64::from(self.miss_penalty)
    }
}

fn build_ras_ipet_model(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    reachable_nodes: &BTreeSet<NodeIndex>,
) -> Option<RasIpetModel> {
    let info = program.ras.as_ref()?;
    let mut has_return = false;
    for node in reachable_nodes {
        if cfg.graph[*node].terminator != crate::cfg::CfgTerminator::Return {
            continue;
        }
        has_return = true;
        let metadata = cfg.graph[*node].ras.as_ref()?;
        if metadata.fallback {
            return None;
        }
    }
    has_return.then(|| RasIpetModel {
        entries: usize::try_from(info.entries).unwrap_or(usize::MAX),
        miss_penalty: info.miss_penalty,
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

#[allow(clippy::too_many_arguments)]
fn state_base_cost(
    block: &CfgBlock,
    node: NodeIndex,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    models: &CacheIpetModels,
    branch: Option<&BranchIpetModel>,
    pipeline_cost: Option<(f64, f64)>,
    btb_model: Option<&BtbIpetModel>,
    ras_model: Option<&RasIpetModel>,
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
    if let Some(model) = ras_model
        && let Some(ras) = &block.ras
    {
        cost -= f64::from(ras.misses_max) * model.penalty();
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
    ras: Option<RasState>,
}

#[derive(Clone)]
struct StateProductNode {
    key: StateProductKey,
    cost: f64,
    exit_instruction: Option<CacheState>,
    exit_data: Option<CacheState>,
    exit_pipeline: Option<PipelineState>,
}

#[derive(Clone)]
struct StateProductEdge {
    from: usize,
    to: usize,
    original: Option<EdgeIndex>,
    branch_cost: f64,
    summary_counts: Option<BTreeMap<BlockId, u64>>,
}

#[allow(clippy::too_many_arguments)]
fn state_product_node(
    cfg: &FunctionCfg,
    key: StateProductKey,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    models: &CacheIpetModels,
    branch: Option<&BranchIpetModel>,
    pipeline_model: Option<&PipelineFunctionModel>,
    btb_model: Option<&BtbIpetModel>,
    ras_model: Option<&RasIpetModel>,
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
    debug_assert_eq!(
        ras_model.is_some(),
        key.ras.is_some(),
        "RAS state/model mismatch"
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
        ras_model,
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
    if let Some(model) = ras_model
        && block.terminator == crate::cfg::CfgTerminator::Return
        && let Some(state) = key.ras.as_ref()
        && state.return_miss()
    {
        cost += model.penalty();
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
    ras_model: Option<&RasIpetModel>,
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
        ras: ras_model.map(|_| RasState::entry()),
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
        ras_model,
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
            let next_ras = if let Some(model) = ras_model {
                let state = key.ras.as_ref()?;
                if edge.weight().kind == crate::cfg::CfgEdgeKind::CallReturn {
                    Some(state.call_return(cfg.graph[target].address, model.entries))
                } else {
                    Some(state.clone())
                }
            } else {
                None
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
                    ras: next_ras.clone(),
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
                        ras_model,
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
                    original: Some(edge.id()),
                    branch_cost: branch_cost + btb_cost,
                    summary_counts: None,
                });
            }
        }
    }
    Some((nodes, edges))
}

struct StatePartitionPlan {
    region: PartitionRegion,
    summaries: Vec<StateSummaryEdge>,
}

struct StateSummaryEdge {
    from: usize,
    to: usize,
    cost: f64,
    counts: BTreeMap<BlockId, u64>,
}

struct StateProductPartition {
    nodes: Vec<StateProductNode>,
    edges: Vec<StateProductEdge>,
    regions: u32,
    summarized_blocks: u32,
}

fn state_partition_eligible(
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> bool {
    if cfg.graph.node_count() > MAX_PARTITION_BLOCKS || analysis.blocked_by_unresolved {
        return false;
    }
    partition_facts_supported(facts, function_id, scope, false, false)
}

struct StateProductView {
    nodes_by_block: BTreeMap<NodeIndex, Vec<usize>>,
    incoming: Vec<Vec<usize>>,
    outgoing: Vec<Vec<usize>>,
}

fn state_product_view(nodes: &[StateProductNode], edges: &[StateProductEdge]) -> StateProductView {
    let mut nodes_by_block: BTreeMap<NodeIndex, Vec<usize>> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        nodes_by_block.entry(node.key.node).or_default().push(index);
    }
    let mut incoming: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    let mut outgoing: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (index, edge) in edges.iter().enumerate() {
        incoming[edge.to].push(index);
        outgoing[edge.from].push(index);
    }
    StateProductView {
        nodes_by_block,
        incoming,
        outgoing,
    }
}

fn select_state_partition_regions(mut candidates: Vec<PartitionRegion>) -> Vec<PartitionRegion> {
    candidates.sort_by(|left, right| {
        right
            .blocks
            .len()
            .cmp(&left.blocks.len())
            .then_with(|| left.entry.index().cmp(&right.entry.index()))
            .then_with(|| left.exit.index().cmp(&right.exit.index()))
    });
    let mut selected: Vec<PartitionRegion> = Vec::new();
    for region in candidates.drain(..) {
        if selected.len() >= usize::try_from(MAX_PARTITION_REGIONS).unwrap_or(usize::MAX) {
            break;
        }
        if selected
            .iter()
            .all(|other| state_partition_regions_compatible(&region, other))
        {
            selected.push(region);
        }
    }
    selected.sort_by(|left, right| {
        left.blocks
            .len()
            .cmp(&right.blocks.len())
            .then_with(|| left.entry.index().cmp(&right.entry.index()))
            .then_with(|| left.exit.index().cmp(&right.exit.index()))
    });
    selected
}

fn state_partition_regions_compatible(left: &PartitionRegion, right: &PartitionRegion) -> bool {
    if left.blocks == right.blocks {
        return false;
    }
    if left.blocks.is_subset(&right.blocks) {
        return state_partition_region_contains(right, left);
    }
    if right.blocks.is_subset(&left.blocks) {
        return state_partition_region_contains(left, right);
    }
    if left.blocks.is_disjoint(&right.blocks) {
        return state_partition_regions_disjoint_safe(left, right);
    }
    false
}

fn state_partition_region_contains(outer: &PartitionRegion, inner: &PartitionRegion) -> bool {
    let entry_kept = inner.entry == outer.entry || !inner.blocks.contains(&outer.entry);
    let exit_kept = inner.exit == outer.exit || outer.blocks.contains(&inner.exit);
    entry_kept && exit_kept && inner.exit != outer.entry
}

fn state_partition_regions_disjoint_safe(left: &PartitionRegion, right: &PartitionRegion) -> bool {
    let left_keeps_right_exit = !left.blocks.contains(&right.exit) || left.entry == right.exit;
    let right_keeps_left_exit = !right.blocks.contains(&left.exit) || right.entry == left.exit;
    left_keeps_right_exit && right_keeps_left_exit
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn partition_state_product_graph(
    cfg: &FunctionCfg,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    function_entry: NodeIndex,
    fact_blocks: &BTreeSet<BlockId>,
    nodes: &[StateProductNode],
    edges: &[StateProductEdge],
    pipeline_model: Option<&PipelineFunctionModel>,
    pipeline_stalls: &BTreeMap<EdgeIndex, f64>,
) -> Option<StateProductPartition> {
    let mut scan_steps = 0_usize;
    let candidates = collect_state_partition_candidates(
        cfg,
        analysis,
        function_entry,
        fact_blocks,
        &mut scan_steps,
    );
    if candidates.is_empty() {
        return None;
    }
    let regions = select_state_partition_regions(candidates);
    if regions.is_empty() {
        return None;
    }
    let mut working_nodes = nodes.to_vec();
    let mut working_edges = edges.to_vec();
    let mut view: Option<StateProductView> = None;
    let mut hidden_blocks: BTreeSet<NodeIndex> = BTreeSet::new();
    let mut summarized = 0_u32;
    for region in regions {
        let summaries = {
            let current =
                view.get_or_insert_with(|| state_product_view(&working_nodes, &working_edges));
            summarize_state_region(
                cfg,
                &region,
                &working_nodes,
                &current.nodes_by_block,
                &current.incoming,
                &current.outgoing,
                &working_edges,
                pipeline_model,
                pipeline_stalls,
            )
        };
        let Some(summaries) = summaries else {
            continue;
        };
        if summaries.is_empty() {
            continue;
        }
        let plan = StatePartitionPlan { region, summaries };
        let hidden: BTreeSet<NodeIndex> = working_nodes
            .iter()
            .filter(|node| {
                plan.region.blocks.contains(&node.key.node) && node.key.node != plan.region.entry
            })
            .map(|node| node.key.node)
            .collect();
        let Some((new_nodes, new_edges)) =
            apply_state_partition_plan(&working_nodes, &working_edges, &plan)
        else {
            continue;
        };
        working_nodes = new_nodes;
        working_edges = new_edges;
        view = None;
        hidden_blocks.extend(hidden);
        summarized = summarized.saturating_add(1);
    }
    if summarized == 0 {
        return None;
    }
    Some(StateProductPartition {
        nodes: working_nodes,
        edges: working_edges,
        regions: summarized,
        summarized_blocks: u32::try_from(hidden_blocks.len()).unwrap_or(u32::MAX),
    })
}

fn apply_state_partition_plan(
    nodes: &[StateProductNode],
    edges: &[StateProductEdge],
    plan: &StatePartitionPlan,
) -> Option<(Vec<StateProductNode>, Vec<StateProductEdge>)> {
    let mut removed_nodes: BTreeSet<usize> = BTreeSet::new();
    let mut entry_sources: BTreeSet<usize> = BTreeSet::new();
    for (index, node) in nodes.iter().enumerate() {
        if node.key.node == plan.region.entry {
            entry_sources.insert(index);
        } else if plan.region.blocks.contains(&node.key.node) {
            removed_nodes.insert(index);
        }
    }
    let kept: Vec<usize> = (0..nodes.len())
        .filter(|index| !removed_nodes.contains(index))
        .collect();
    if kept.first().copied() != Some(0) {
        return None;
    }
    let old_to_new: BTreeMap<usize, usize> = kept
        .iter()
        .enumerate()
        .map(|(new, old)| (*old, new))
        .collect();
    let new_nodes: Vec<StateProductNode> = kept.iter().map(|index| nodes[*index].clone()).collect();
    let mut new_edges: Vec<StateProductEdge> = Vec::new();
    for edge in edges {
        if removed_nodes.contains(&edge.from)
            || removed_nodes.contains(&edge.to)
            || entry_sources.contains(&edge.from)
        {
            continue;
        }
        let from = *old_to_new.get(&edge.from)?;
        let to = *old_to_new.get(&edge.to)?;
        new_edges.push(StateProductEdge {
            from,
            to,
            original: edge.original,
            branch_cost: edge.branch_cost,
            summary_counts: None,
        });
    }
    for summary in &plan.summaries {
        let from = *old_to_new.get(&summary.from)?;
        let to = *old_to_new.get(&summary.to)?;
        new_edges.push(StateProductEdge {
            from,
            to,
            original: None,
            branch_cost: summary.cost,
            summary_counts: Some(summary.counts.clone()),
        });
    }
    Some((new_nodes, new_edges))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn summarize_state_region(
    cfg: &FunctionCfg,
    region: &PartitionRegion,
    nodes: &[StateProductNode],
    nodes_by_block: &BTreeMap<NodeIndex, Vec<usize>>,
    incoming: &[Vec<usize>],
    outgoing: &[Vec<usize>],
    edges: &[StateProductEdge],
    pipeline_model: Option<&PipelineFunctionModel>,
    pipeline_stalls: &BTreeMap<EdgeIndex, f64>,
) -> Option<Vec<StateSummaryEdge>> {
    let mut inside: BTreeSet<usize> = BTreeSet::new();
    for block in &region.blocks {
        if let Some(indices) = nodes_by_block.get(block) {
            inside.extend(indices.iter().copied());
        }
    }
    if inside.is_empty() {
        return None;
    }
    let entry_nodes: Vec<usize> = inside
        .iter()
        .copied()
        .filter(|index| nodes[*index].key.node == region.entry)
        .collect();
    if entry_nodes.is_empty() || entry_nodes.len() > MAX_STATE_PARTITION_ENTRY_STATES {
        return None;
    }
    let entry_set: BTreeSet<usize> = entry_nodes.iter().copied().collect();
    let internal_nodes: Vec<usize> = inside
        .iter()
        .copied()
        .filter(|index| !entry_set.contains(index))
        .collect();
    let exit_nodes: Vec<usize> = nodes_by_block
        .get(&region.exit)
        .into_iter()
        .flatten()
        .copied()
        .filter(|index| {
            incoming[*index]
                .iter()
                .any(|edge| inside.contains(&edges[*edge].from))
        })
        .collect();
    if exit_nodes.is_empty() || exit_nodes.len() > MAX_STATE_PARTITION_EXIT_STATES {
        return None;
    }
    let exit_set: BTreeSet<usize> = exit_nodes.iter().copied().collect();
    for &from in &inside {
        for &edge_index in &outgoing[from] {
            let target = edges[edge_index].to;
            if entry_set.contains(&target) {
                return None;
            }
            if !inside.contains(&target) && !exit_set.contains(&target) {
                return None;
            }
        }
    }
    for &to in &inside {
        for &edge_index in &incoming[to] {
            if !inside.contains(&edges[edge_index].from) && nodes[to].key.node != region.entry {
                return None;
            }
        }
    }

    let mut local_old: Vec<usize> = Vec::new();
    local_old.extend(entry_nodes.iter().copied());
    local_old.extend(internal_nodes.iter().copied());
    local_old.extend(exit_nodes.iter().copied());
    if local_old.len() > MAX_STATE_PARTITION_LOCAL_NODES {
        return None;
    }
    let mut local_index: BTreeMap<usize, usize> = BTreeMap::new();
    for (index, old) in local_old.iter().enumerate() {
        local_index.insert(*old, index);
    }
    let local_count = local_old.len();
    let mut is_entry = vec![false; local_count];
    let mut is_internal = vec![false; local_count];
    let mut is_exit = vec![false; local_count];
    for (index, old) in local_old.iter().enumerate() {
        if entry_set.contains(old) {
            is_entry[index] = true;
        } else if exit_set.contains(old) {
            is_exit[index] = true;
        } else {
            is_internal[index] = true;
        }
    }
    let mut local_outgoing: Vec<Vec<(usize, usize)>> = vec![Vec::new(); local_count];
    for (source, &old) in local_old.iter().enumerate() {
        if is_exit[source] {
            continue;
        }
        for &edge_index in &outgoing[old] {
            let target = edges[edge_index].to;
            let &target_local = local_index.get(&target)?;
            if is_entry[target_local] {
                return None;
            }
            local_outgoing[source].push((target_local, edge_index));
        }
    }
    let mut indegree = vec![0_usize; local_count];
    for list in &local_outgoing {
        for &(target, _) in list {
            indegree[target] = indegree[target].saturating_add(1);
        }
    }
    let mut queue: VecDeque<usize> = indegree
        .iter()
        .enumerate()
        .filter(|(_, degree)| **degree == 0)
        .map(|(index, _)| index)
        .collect();
    let mut topological = Vec::with_capacity(local_count);
    while let Some(source) = queue.pop_front() {
        topological.push(source);
        for &(target, _) in &local_outgoing[source] {
            indegree[target] = indegree[target].saturating_sub(1);
            if indegree[target] == 0 {
                queue.push_back(target);
            }
        }
    }
    if topological.len() != local_count {
        return None;
    }
    let mut reverse: Vec<Vec<usize>> = vec![Vec::new(); local_count];
    for (source, list) in local_outgoing.iter().enumerate() {
        for &(target, _) in list {
            reverse[target].push(source);
        }
    }
    let mut can_reach_exit = vec![false; local_count];
    let mut exit_queue: VecDeque<usize> =
        (0..local_count).filter(|index| is_exit[*index]).collect();
    for &index in &exit_queue {
        can_reach_exit[index] = true;
    }
    while let Some(target) = exit_queue.pop_front() {
        for &source in &reverse[target] {
            if !can_reach_exit[source] {
                can_reach_exit[source] = true;
                exit_queue.push_back(source);
            }
        }
    }

    let mut summaries = Vec::new();
    for &entry_old in &entry_nodes {
        let entry_local = *local_index.get(&entry_old)?;
        let mut best = vec![f64::NEG_INFINITY; local_count];
        let mut predecessor: Vec<Option<(usize, usize)>> = vec![None; local_count];
        best[entry_local] = 0.0;
        for &source in &topological {
            if !best[source].is_finite() {
                continue;
            }
            for &(target, edge_index) in &local_outgoing[source] {
                let mut candidate = best[source]
                    + state_product_edge_cost(&edges[edge_index], pipeline_model, pipeline_stalls);
                if is_internal[target] {
                    candidate += nodes[local_old[target]].cost;
                }
                if candidate.is_finite() && candidate > best[target] + 1e-9 {
                    best[target] = candidate;
                    predecessor[target] = Some((source, edge_index));
                }
            }
        }
        for (index, is_internal_node) in is_internal.iter().enumerate() {
            if *is_internal_node && best[index].is_finite() && !can_reach_exit[index] {
                return None;
            }
        }
        let mut saw_exit = false;
        for &exit_old in &exit_nodes {
            let exit_local = *local_index.get(&exit_old)?;
            if !best[exit_local].is_finite() {
                continue;
            }
            saw_exit = true;
            let mut counts: BTreeMap<BlockId, u64> = BTreeMap::new();
            let mut current = exit_local;
            while let Some((previous, edge_index)) = predecessor[current] {
                if is_internal[current] {
                    let block = &cfg.graph[nodes[local_old[current]].key.node].id;
                    let count = counts.entry(block.clone()).or_default();
                    *count = count.saturating_add(1);
                }
                if let Some(nested) = &edges[edge_index].summary_counts {
                    for (block, count) in nested {
                        let entry = counts.entry(block.clone()).or_default();
                        *entry = entry.saturating_add(*count);
                    }
                }
                current = previous;
            }
            if current != entry_local {
                return None;
            }
            summaries.push(StateSummaryEdge {
                from: entry_old,
                to: exit_old,
                cost: best[exit_local],
                counts,
            });
        }
        if !saw_exit {
            return None;
        }
    }
    Some(summaries)
}

fn state_product_edge_stall(
    edge: &StateProductEdge,
    pipeline_model: Option<&PipelineFunctionModel>,
    pipeline_stalls: &BTreeMap<EdgeIndex, f64>,
) -> f64 {
    if pipeline_model.is_some() {
        return 0.0;
    }
    edge.original
        .and_then(|original| pipeline_stalls.get(&original).copied())
        .unwrap_or(0.0)
}

fn state_product_edge_cost(
    edge: &StateProductEdge,
    pipeline_model: Option<&PipelineFunctionModel>,
    pipeline_stalls: &BTreeMap<EdgeIndex, f64>,
) -> f64 {
    edge.branch_cost + state_product_edge_stall(edge, pipeline_model, pipeline_stalls)
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
    ras_model: Option<&RasIpetModel>,
    allow_partition: bool,
) -> Result<Option<IpetOutcome>, IpetError> {
    let Some((mut product_nodes, mut product_edges)) = build_state_product_graph(
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
        ras_model,
    ) else {
        return Ok(None);
    };

    let mut partitioning = None;
    if allow_partition {
        let analysis = cfg.analyze_graph();
        let fact_blocks = non_loop_fact_blocks(cfg, facts, function_id, scope);
        if state_partition_eligible(cfg, &analysis, facts, function_id, scope)
            && let Some(partition) = partition_state_product_graph(
                cfg,
                &analysis,
                entry,
                &fact_blocks,
                &product_nodes,
                &product_edges,
                pipeline_model,
                pipeline_stalls,
            )
        {
            let mut caveats = vec![
                "State-product SESE regions are summarized by the worst local path from each entry cache/prediction/pipeline/BTB/RAS state to each exit state; entry and exit states remain explicit in the final product graph. Nested regions are summarized innermost first, and their costs and block counts are folded into enclosing summaries.".to_owned(),
                "A region entry state that can reach several exit states may use those exits more freely in the final IPET than in a concrete execution. This over-approximates the monolithic state-product model, so the result remains a safe upper bound but can be larger.".to_owned(),
                "Regions containing loop headers or latches, or ending at a loop header, are left monolithic. Supported branch/call facts and unordered aggregate or presence infeasible-path constraints are applied by the final product model; a region that touches any referenced block is left monolithic. Ordered, cross-function and automaton constraints, or unresolved control flow, disable state-aware partitioning. Block counts inside a summarized region describe one worst-cost local path per entry/exit state and are diagnostic.".to_owned(),
            ];
            if let Some(caveat) = call_site_partition_caveat(scope) {
                caveats.push(caveat);
            }
            if let Some(caveat) = recovered_call_partition_caveat(cfg) {
                caveats.push(caveat);
            }
            partitioning = Some(CfgIpetPartitioningInfo {
                model: STATE_PARTITION_MODEL.to_owned(),
                regions: partition.regions,
                summarized_blocks: partition.summarized_blocks,
                caveats,
            });
            product_nodes = partition.nodes;
            product_edges = partition.edges;
        }
    }

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
        if let Some(original) = edge.original {
            edges_by_original.entry(original).or_default().push(index);
        }
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
    constraints.extend(aggregate_conflict_constraints(
        cfg,
        &node_by_block_id,
        &block_expression,
        &edge_expression,
        facts,
        function_id,
        scope,
        &mut vars,
    ));

    let mut objective = Expression::from(0.0);
    for (index, node) in product_nodes.iter().enumerate() {
        if node.cost != 0.0 {
            objective += node_variables[index] * node.cost;
        }
    }
    for (index, edge) in product_edges.iter().enumerate() {
        let stall = state_product_edge_stall(edge, pipeline_model, pipeline_stalls);
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
    for (index, edge) in product_edges.iter().enumerate() {
        let Some(summary_counts) = &edge.summary_counts else {
            continue;
        };
        let value = solution.value(edge_variables[index]);
        let rounded = value.round();
        if (value - rounded).abs() > 1e-4 {
            partial = true;
        }
        if rounded < 0.0 {
            partial = true;
            continue;
        }
        let executions = rounded as u64;
        if executions == 0 {
            continue;
        }
        for (block, per_entry) in summary_counts {
            let Some(&node) = node_by_block_id.get(block) else {
                continue;
            };
            let scaled = per_entry.saturating_mul(executions);
            let entry = counts.entry(node).or_default();
            *entry = entry
                .checked_add(scaled)
                .ok_or_else(|| IpetError::Unbounded("ipet-solver-bound-saturated".to_owned()))?;
            if *entry >= u64::from(i32::MAX as u32) {
                return Err(IpetError::Unbounded(
                    "ipet-solver-bound-saturated".to_owned(),
                ));
            }
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
            partitioning,
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
            ras_model: ras_model.map(|_| "state-product".to_owned()),
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
    use super::{
        analyze_program, analyze_program_with_branch_prediction, build_cache_ipet_models,
        build_loops, pipeline_edge_stalls, solve_function_with_state_products, solve_simple_ipet,
    };
    use crate::board_profile::BoardProfile;
    use crate::cfg::{
        CfgBlockDraft, CfgCallSite, CfgEdgeDraft, CfgEdgeKind, CfgFunction, CfgInstruction,
        CfgIpetSolution, CfgMemoryAccess, CfgMemoryAccessKind, CfgMemoryResolution,
        CfgPipelineEdgeInfo, CfgPipelineInfo, CfgTerminator, CfgWcetStatus, FunctionCfg,
        ProgramCfg,
    };
    use crate::flow_facts::{
        FactScope, FlowFactDocument, FlowFacts, InfeasibleEnforcement, InfeasibleScope,
        OrderedReset, SpecificIteration,
    };
    use elf2tdg_schema::{Addr, BlockId, CostRange, FunctionId, FunctionKind, Language};
    use petgraph::stable_graph::NodeIndex;
    use std::collections::{BTreeMap, BTreeSet};

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

    fn analyze_with_for(program: &ProgramCfg, text: &str, address: u64) -> (f64, FlowFacts) {
        let mut constrained = program.clone();
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(text, "conflict.ffx").expect("parse");
        facts
            .apply_document(document, program)
            .expect("apply conflict");
        let _ = analyze_program(&mut constrained, &facts);
        let cycles = constrained
            .functions
            .iter()
            .find(|function| function.address == address)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("finite function cycles");
        (cycles, facts)
    }

    fn analyze_baseline_for(program: &ProgramCfg, address: u64) -> f64 {
        let mut program = program.clone();
        let _ = analyze_program(&mut program, &facts());
        program
            .functions
            .iter()
            .find(|function| function.address == address)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("finite function cycles")
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

    fn mixed_unordered_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x9000,
            FunctionCfg::build(
                vec![
                    block(0x9000, CfgTerminator::Fallthrough, 1.0),
                    block(0x9002, CfgTerminator::Branch, 1.0),
                    block(0x9004, CfgTerminator::Fallthrough, 100.0),
                    block(0x9006, CfgTerminator::Fallthrough, 20.0),
                    block(0x9008, CfgTerminator::Fallthrough, 5.0),
                    block(0x900a, CfgTerminator::Branch, 1.0),
                    block(0x900c, CfgTerminator::Branch, 1.0),
                    block(0x900e, CfgTerminator::Fallthrough, 1.0),
                    block(0x9010, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x9000, 0x9002, CfgEdgeKind::Fallthrough),
                    edge(0x9002, 0x9004, CfgEdgeKind::Branch),
                    edge(0x9002, 0x9008, CfgEdgeKind::Fallthrough),
                    edge(0x9004, 0x9006, CfgEdgeKind::Fallthrough),
                    edge(0x9006, 0x900a, CfgEdgeKind::Fallthrough),
                    edge(0x9008, 0x900a, CfgEdgeKind::Fallthrough),
                    edge(0x900a, 0x9002, CfgEdgeKind::Branch),
                    edge(0x900a, 0x900c, CfgEdgeKind::Fallthrough),
                    edge(0x900c, 0x900e, CfgEdgeKind::Branch),
                    edge(0x900c, 0x9010, CfgEdgeKind::Fallthrough),
                    edge(0x900e, 0x9010, CfgEdgeKind::Fallthrough),
                ],
                Some(0x9000),
            ),
        )])
    }

    fn mixed_specific_cross_program() -> ProgramCfg {
        let caller = FunctionCfg::build(
            vec![
                block(0x7600, CfgTerminator::Fallthrough, 1.0),
                block(0x7602, CfgTerminator::Branch, 1.0),
                block(0x7604, CfgTerminator::Fallthrough, 50.0),
                block(0x7606, CfgTerminator::Branch, 1.0),
                call_block(0x7608, 1.0, 0x9000),
                block(0x760a, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x7600, 0x7602, CfgEdgeKind::Fallthrough),
                edge(0x7602, 0x7604, CfgEdgeKind::Branch),
                edge(0x7602, 0x7608, CfgEdgeKind::Fallthrough),
                edge(0x7604, 0x7606, CfgEdgeKind::Fallthrough),
                edge(0x7606, 0x7602, CfgEdgeKind::Branch),
                edge(0x7606, 0x7608, CfgEdgeKind::Fallthrough),
                edge(0x7608, 0x760a, CfgEdgeKind::CallReturn),
            ],
            Some(0x7600),
        );
        let helper = FunctionCfg::build(
            vec![
                block(0x9000, CfgTerminator::Fallthrough, 1.0),
                block(0x9002, CfgTerminator::Return, 1.0),
            ],
            vec![edge(0x9000, 0x9002, CfgEdgeKind::Fallthrough)],
            Some(0x9000),
        );
        ProgramCfg::new(vec![
            named_function(0x7600, "main", caller),
            named_function(0x9000, "helper", helper),
        ])
    }

    fn top_tested_loop_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x7400,
            FunctionCfg::build(
                vec![
                    block(0x7400, CfgTerminator::Fallthrough, 1.0),
                    block(0x7402, CfgTerminator::Branch, 1.0),
                    block(0x7404, CfgTerminator::Fallthrough, 100.0),
                    block(0x7406, CfgTerminator::Branch, 1.0),
                    block(0x7408, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x7400, 0x7402, CfgEdgeKind::Fallthrough),
                    edge(0x7402, 0x7404, CfgEdgeKind::Branch),
                    edge(0x7402, 0x7408, CfgEdgeKind::Fallthrough),
                    edge(0x7404, 0x7406, CfgEdgeKind::Fallthrough),
                    edge(0x7406, 0x7402, CfgEdgeKind::Branch),
                ],
                Some(0x7400),
            ),
        )])
    }

    fn disjoint_loop_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x7100,
            FunctionCfg::build(
                vec![
                    block(0x7100, CfgTerminator::Fallthrough, 1.0),
                    block(0x7102, CfgTerminator::Branch, 1.0),
                    block(0x7104, CfgTerminator::Fallthrough, 100.0),
                    block(0x7106, CfgTerminator::Branch, 1.0),
                    block(0x7108, CfgTerminator::Branch, 1.0),
                    block(0x710a, CfgTerminator::Fallthrough, 200.0),
                    block(0x710c, CfgTerminator::Branch, 1.0),
                    block(0x710e, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x7100, 0x7102, CfgEdgeKind::Fallthrough),
                    edge(0x7102, 0x7104, CfgEdgeKind::Branch),
                    edge(0x7102, 0x7108, CfgEdgeKind::Fallthrough),
                    edge(0x7104, 0x7106, CfgEdgeKind::Fallthrough),
                    edge(0x7106, 0x7102, CfgEdgeKind::Branch),
                    edge(0x7106, 0x7108, CfgEdgeKind::Fallthrough),
                    edge(0x7108, 0x710a, CfgEdgeKind::Branch),
                    edge(0x7108, 0x710e, CfgEdgeKind::Fallthrough),
                    edge(0x710a, 0x710c, CfgEdgeKind::Fallthrough),
                    edge(0x710c, 0x7108, CfgEdgeKind::Branch),
                    edge(0x710c, 0x710e, CfgEdgeKind::Fallthrough),
                ],
                Some(0x7100),
            ),
        )])
    }

    fn named_function(address: u64, name: &str, cfg: FunctionCfg) -> CfgFunction {
        let mut function = function(address, cfg);
        function.primary_name = name.to_owned();
        function
    }

    fn partition_diamond_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x5000,
            FunctionCfg::build(
                vec![
                    block(0x5000, CfgTerminator::Fallthrough, 1.0),
                    block(0x5002, CfgTerminator::Branch, 1.0),
                    block(0x5004, CfgTerminator::Fallthrough, 2.0),
                    block(0x5006, CfgTerminator::Fallthrough, 5.0),
                    block(0x5008, CfgTerminator::Fallthrough, 1.0),
                    block(0x500a, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x5000, 0x5002, CfgEdgeKind::Fallthrough),
                    edge(0x5002, 0x5004, CfgEdgeKind::Branch),
                    edge(0x5002, 0x5006, CfgEdgeKind::Fallthrough),
                    edge(0x5004, 0x5008, CfgEdgeKind::Fallthrough),
                    edge(0x5006, 0x5008, CfgEdgeKind::Fallthrough),
                    edge(0x5008, 0x500a, CfgEdgeKind::Fallthrough),
                ],
                Some(0x5000),
            ),
        )])
    }

    fn fact_partition_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x6000,
            FunctionCfg::build(
                vec![
                    block(0x6000, CfgTerminator::Branch, 1.0),
                    block(0x6002, CfgTerminator::Branch, 1.0),
                    block(0x6004, CfgTerminator::Fallthrough, 10.0),
                    block(0x6006, CfgTerminator::Fallthrough, 1.0),
                    block(0x6008, CfgTerminator::Fallthrough, 1.0),
                    block(0x600a, CfgTerminator::Return, 1.0),
                    block(0x600b, CfgTerminator::Fallthrough, 50.0),
                ],
                vec![
                    edge(0x6000, 0x6002, CfgEdgeKind::Branch),
                    edge(0x6000, 0x600b, CfgEdgeKind::Fallthrough),
                    edge(0x6002, 0x6004, CfgEdgeKind::Branch),
                    edge(0x6002, 0x6006, CfgEdgeKind::Fallthrough),
                    edge(0x6004, 0x6008, CfgEdgeKind::Fallthrough),
                    edge(0x6006, 0x6008, CfgEdgeKind::Fallthrough),
                    edge(0x6008, 0x600a, CfgEdgeKind::Fallthrough),
                    edge(0x600b, 0x600a, CfgEdgeKind::Fallthrough),
                ],
                Some(0x6000),
            ),
        )])
    }

    fn ordered_fact_partition_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x7000,
            FunctionCfg::build(
                vec![
                    block(0x7000, CfgTerminator::Fallthrough, 1.0),
                    block(0x7002, CfgTerminator::Branch, 1.0),
                    block(0x7004, CfgTerminator::Branch, 1.0),
                    block(0x7006, CfgTerminator::Fallthrough, 10.0),
                    block(0x7008, CfgTerminator::Fallthrough, 1.0),
                    block(0x700a, CfgTerminator::Fallthrough, 1.0),
                    block(0x7010, CfgTerminator::Branch, 1.0),
                    block(0x7012, CfgTerminator::Fallthrough, 10.0),
                    block(0x7014, CfgTerminator::Fallthrough, 1.0),
                    block(0x7016, CfgTerminator::Fallthrough, 1.0),
                    block(0x701c, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x7000, 0x7002, CfgEdgeKind::Fallthrough),
                    edge(0x7002, 0x7004, CfgEdgeKind::Branch),
                    edge(0x7002, 0x7010, CfgEdgeKind::Fallthrough),
                    edge(0x7004, 0x7006, CfgEdgeKind::Branch),
                    edge(0x7004, 0x7008, CfgEdgeKind::Fallthrough),
                    edge(0x7006, 0x700a, CfgEdgeKind::Fallthrough),
                    edge(0x7008, 0x700a, CfgEdgeKind::Fallthrough),
                    edge(0x700a, 0x701c, CfgEdgeKind::Fallthrough),
                    edge(0x7010, 0x7012, CfgEdgeKind::Branch),
                    edge(0x7010, 0x7016, CfgEdgeKind::Fallthrough),
                    edge(0x7012, 0x7014, CfgEdgeKind::Fallthrough),
                    edge(0x7014, 0x7010, CfgEdgeKind::Branch),
                    edge(0x7016, 0x701c, CfgEdgeKind::Fallthrough),
                ],
                Some(0x7000),
            ),
        )])
    }

    fn cross_partition_program() -> ProgramCfg {
        let caller_cfg = FunctionCfg::build(
            vec![
                block(0x8000, CfgTerminator::Fallthrough, 1.0),
                block(0x8002, CfgTerminator::Branch, 1.0),
                block(0x8004, CfgTerminator::Branch, 1.0),
                block(0x8006, CfgTerminator::Fallthrough, 1.0),
                block(0x8008, CfgTerminator::Fallthrough, 1.0),
                block(0x800a, CfgTerminator::Fallthrough, 1.0),
                block(0x8010, CfgTerminator::Fallthrough, 50.0),
                call_block(0x8012, 1.0, 0x9000),
                block(0x8014, CfgTerminator::Fallthrough, 1.0),
                block(0x801c, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x8000, 0x8002, CfgEdgeKind::Fallthrough),
                edge(0x8002, 0x8004, CfgEdgeKind::Branch),
                edge(0x8002, 0x8010, CfgEdgeKind::Fallthrough),
                edge(0x8004, 0x8006, CfgEdgeKind::Branch),
                edge(0x8004, 0x8008, CfgEdgeKind::Fallthrough),
                edge(0x8006, 0x800a, CfgEdgeKind::Fallthrough),
                edge(0x8008, 0x800a, CfgEdgeKind::Fallthrough),
                edge(0x800a, 0x801c, CfgEdgeKind::Fallthrough),
                edge(0x8010, 0x8012, CfgEdgeKind::Fallthrough),
                edge(0x8012, 0x8014, CfgEdgeKind::CallReturn),
                edge(0x8014, 0x801c, CfgEdgeKind::Fallthrough),
            ],
            Some(0x8000),
        );
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0x9000, CfgTerminator::Fallthrough, 1.0),
                block(0x9002, CfgTerminator::Fallthrough, 1.0),
                block(0x9004, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x9000, 0x9002, CfgEdgeKind::Fallthrough),
                edge(0x9002, 0x9004, CfgEdgeKind::Fallthrough),
            ],
            Some(0x9000),
        );
        ProgramCfg::new(vec![
            named_function(0x8000, "main", caller_cfg),
            named_function(0x9000, "helper", helper_cfg),
        ])
    }

    fn multi_group_cross_program() -> ProgramCfg {
        let caller_cfg = FunctionCfg::build(
            vec![
                block(0xa000, CfgTerminator::Fallthrough, 1.0),
                block(0xa002, CfgTerminator::Branch, 1.0),
                block(0xa004, CfgTerminator::Branch, 1.0),
                block(0xa006, CfgTerminator::Fallthrough, 1.0),
                block(0xa008, CfgTerminator::Fallthrough, 1.0),
                block(0xa00a, CfgTerminator::Fallthrough, 1.0),
                block(0xa010, CfgTerminator::Fallthrough, 50.0),
                call_block(0xa012, 1.0, 0xb000),
                block(0xa014, CfgTerminator::Fallthrough, 1.0),
                call_block(0xa016, 1.0, 0xb000),
                block(0xa018, CfgTerminator::Fallthrough, 1.0),
                block(0xa01c, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0xa000, 0xa002, CfgEdgeKind::Fallthrough),
                edge(0xa002, 0xa004, CfgEdgeKind::Branch),
                edge(0xa002, 0xa010, CfgEdgeKind::Fallthrough),
                edge(0xa004, 0xa006, CfgEdgeKind::Branch),
                edge(0xa004, 0xa008, CfgEdgeKind::Fallthrough),
                edge(0xa006, 0xa00a, CfgEdgeKind::Fallthrough),
                edge(0xa008, 0xa00a, CfgEdgeKind::Fallthrough),
                edge(0xa00a, 0xa01c, CfgEdgeKind::Fallthrough),
                edge(0xa010, 0xa012, CfgEdgeKind::Fallthrough),
                edge(0xa012, 0xa014, CfgEdgeKind::CallReturn),
                edge(0xa014, 0xa016, CfgEdgeKind::Fallthrough),
                edge(0xa016, 0xa018, CfgEdgeKind::CallReturn),
                edge(0xa018, 0xa01c, CfgEdgeKind::Fallthrough),
            ],
            Some(0xa000),
        );
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0xb000, CfgTerminator::Fallthrough, 1.0),
                block(0xb002, CfgTerminator::Fallthrough, 1.0),
                block(0xb004, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0xb000, 0xb002, CfgEdgeKind::Fallthrough),
                edge(0xb002, 0xb004, CfgEdgeKind::Fallthrough),
            ],
            Some(0xb000),
        );
        ProgramCfg::new(vec![
            named_function(0xa000, "main", caller_cfg),
            named_function(0xb000, "helper", helper_cfg),
        ])
    }

    fn loop_cross_partition_program() -> ProgramCfg {
        let caller_cfg = FunctionCfg::build(
            vec![
                block(0xc000, CfgTerminator::Fallthrough, 1.0),
                block(0xc002, CfgTerminator::Branch, 1.0),
                block(0xc004, CfgTerminator::Branch, 1.0),
                block(0xc006, CfgTerminator::Fallthrough, 1.0),
                block(0xc008, CfgTerminator::Fallthrough, 1.0),
                block(0xc00a, CfgTerminator::Fallthrough, 1.0),
                block(0xc010, CfgTerminator::Branch, 1.0),
                call_block(0xc012, 1.0, 0x9000),
                block(0xc014, CfgTerminator::Branch, 1.0),
                block(0xc016, CfgTerminator::Fallthrough, 1.0),
                block(0xc01c, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0xc000, 0xc002, CfgEdgeKind::Fallthrough),
                edge(0xc002, 0xc004, CfgEdgeKind::Branch),
                edge(0xc002, 0xc010, CfgEdgeKind::Fallthrough),
                edge(0xc004, 0xc006, CfgEdgeKind::Branch),
                edge(0xc004, 0xc008, CfgEdgeKind::Fallthrough),
                edge(0xc006, 0xc00a, CfgEdgeKind::Fallthrough),
                edge(0xc008, 0xc00a, CfgEdgeKind::Fallthrough),
                edge(0xc00a, 0xc01c, CfgEdgeKind::Fallthrough),
                edge(0xc010, 0xc012, CfgEdgeKind::Branch),
                edge(0xc010, 0xc016, CfgEdgeKind::Fallthrough),
                edge(0xc012, 0xc014, CfgEdgeKind::CallReturn),
                edge(0xc014, 0xc010, CfgEdgeKind::Branch),
                edge(0xc016, 0xc01c, CfgEdgeKind::Fallthrough),
            ],
            Some(0xc000),
        );
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0x9000, CfgTerminator::Branch, 1.0),
                block(0x9002, CfgTerminator::Fallthrough, 50.0),
                block(0x9004, CfgTerminator::Fallthrough, 1.0),
                block(0x9006, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x9000, 0x9002, CfgEdgeKind::Branch),
                edge(0x9000, 0x9004, CfgEdgeKind::Fallthrough),
                edge(0x9002, 0x9006, CfgEdgeKind::Fallthrough),
                edge(0x9004, 0x9006, CfgEdgeKind::Fallthrough),
            ],
            Some(0x9000),
        );
        ProgramCfg::new(vec![
            named_function(0xc000, "main", caller_cfg),
            named_function(0x9000, "helper", helper_cfg),
        ])
    }

    fn specific_iteration_cross_program() -> ProgramCfg {
        let caller_cfg = FunctionCfg::build(
            vec![
                block(0xd000, CfgTerminator::Fallthrough, 1.0),
                block(0xd002, CfgTerminator::Branch, 1.0),
                block(0xd004, CfgTerminator::Branch, 1.0),
                block(0xd006, CfgTerminator::Fallthrough, 1.0),
                block(0xd008, CfgTerminator::Fallthrough, 1.0),
                block(0xd00a, CfgTerminator::Fallthrough, 1.0),
                block(0xd010, CfgTerminator::Fallthrough, 1.0),
                call_block(0xd012, 1.0, 0x9000),
                block(0xd014, CfgTerminator::Branch, 1.0),
                block(0xd016, CfgTerminator::Fallthrough, 1.0),
                block(0xd01c, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0xd000, 0xd002, CfgEdgeKind::Fallthrough),
                edge(0xd002, 0xd004, CfgEdgeKind::Branch),
                edge(0xd002, 0xd010, CfgEdgeKind::Fallthrough),
                edge(0xd004, 0xd006, CfgEdgeKind::Branch),
                edge(0xd004, 0xd008, CfgEdgeKind::Fallthrough),
                edge(0xd006, 0xd00a, CfgEdgeKind::Fallthrough),
                edge(0xd008, 0xd00a, CfgEdgeKind::Fallthrough),
                edge(0xd00a, 0xd01c, CfgEdgeKind::Fallthrough),
                edge(0xd010, 0xd012, CfgEdgeKind::Fallthrough),
                edge(0xd012, 0xd014, CfgEdgeKind::CallReturn),
                edge(0xd014, 0xd010, CfgEdgeKind::Branch),
                edge(0xd014, 0xd016, CfgEdgeKind::Fallthrough),
                edge(0xd016, 0xd01c, CfgEdgeKind::Fallthrough),
            ],
            Some(0xd000),
        );
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0x9000, CfgTerminator::Branch, 1.0),
                block(0x9002, CfgTerminator::Fallthrough, 50.0),
                block(0x9004, CfgTerminator::Fallthrough, 1.0),
                block(0x9006, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x9000, 0x9002, CfgEdgeKind::Branch),
                edge(0x9000, 0x9004, CfgEdgeKind::Fallthrough),
                edge(0x9002, 0x9006, CfgEdgeKind::Fallthrough),
                edge(0x9004, 0x9006, CfgEdgeKind::Fallthrough),
            ],
            Some(0x9000),
        );
        ProgramCfg::new(vec![
            named_function(0xd000, "main", caller_cfg),
            named_function(0x9000, "helper", helper_cfg),
        ])
    }

    fn monolithic_top_tested_cross_program() -> ProgramCfg {
        let caller_cfg = FunctionCfg::build(
            vec![
                block(0xe000, CfgTerminator::Fallthrough, 1.0),
                block(0xe002, CfgTerminator::Branch, 1.0),
                call_block(0xe004, 1.0, 0x9000),
                block(0xe006, CfgTerminator::Fallthrough, 1.0),
                block(0xe00a, CfgTerminator::Fallthrough, 1.0),
                block(0xe00c, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0xe000, 0xe002, CfgEdgeKind::Fallthrough),
                edge(0xe002, 0xe004, CfgEdgeKind::Branch),
                edge(0xe002, 0xe00a, CfgEdgeKind::Fallthrough),
                edge(0xe004, 0xe006, CfgEdgeKind::CallReturn),
                edge(0xe006, 0xe002, CfgEdgeKind::Branch),
                edge(0xe00a, 0xe00c, CfgEdgeKind::Fallthrough),
            ],
            Some(0xe000),
        );
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0x9000, CfgTerminator::Branch, 1.0),
                block(0x9002, CfgTerminator::Fallthrough, 50.0),
                block(0x9004, CfgTerminator::Fallthrough, 1.0),
                block(0x9006, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x9000, 0x9002, CfgEdgeKind::Branch),
                edge(0x9000, 0x9004, CfgEdgeKind::Fallthrough),
                edge(0x9002, 0x9006, CfgEdgeKind::Fallthrough),
                edge(0x9004, 0x9006, CfgEdgeKind::Fallthrough),
            ],
            Some(0x9000),
        );
        ProgramCfg::new(vec![
            named_function(0xe000, "main", caller_cfg),
            named_function(0x9000, "helper", helper_cfg),
        ])
    }

    fn analyze_nested_program(program: &ProgramCfg, conflict: &str) -> (f64, FlowFacts) {
        let text = format!(
            r#"
<flowfacts>
  <function name="main">
    {conflict}
  </function>
</flowfacts>
"#
        );
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(&text, "nested-loop.ffx")
            .expect("parse nested loop conflict");
        facts
            .apply_document(document, program)
            .expect("apply nested loop conflict");
        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let cycles = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0xf000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("finite caller cycles");
        (cycles, facts)
    }

    fn nested_loop_ordered_program() -> ProgramCfg {
        let caller_cfg = FunctionCfg::build(
            vec![
                block(0xf000, CfgTerminator::Fallthrough, 1.0),
                block(0xf002, CfgTerminator::Branch, 1.0),
                block(0xf004, CfgTerminator::Fallthrough, 10.0),
                block(0xf006, CfgTerminator::Branch, 1.0),
                call_block(0xf008, 1.0, 0x9000),
                block(0xf00a, CfgTerminator::Branch, 1.0),
                block(0xf00c, CfgTerminator::Fallthrough, 1.0),
                block(0xf020, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0xf000, 0xf002, CfgEdgeKind::Fallthrough),
                edge(0xf002, 0xf004, CfgEdgeKind::Branch),
                edge(0xf002, 0xf020, CfgEdgeKind::Fallthrough),
                edge(0xf004, 0xf006, CfgEdgeKind::Fallthrough),
                edge(0xf006, 0xf008, CfgEdgeKind::Branch),
                edge(0xf006, 0xf00a, CfgEdgeKind::Fallthrough),
                edge(0xf008, 0xf00c, CfgEdgeKind::CallReturn),
                edge(0xf00c, 0xf006, CfgEdgeKind::Branch),
                edge(0xf00a, 0xf002, CfgEdgeKind::Branch),
                edge(0xf00a, 0xf020, CfgEdgeKind::Fallthrough),
            ],
            Some(0xf000),
        );
        let helper_cfg = FunctionCfg::build(
            vec![
                block(0x9000, CfgTerminator::Branch, 1.0),
                block(0x9002, CfgTerminator::Fallthrough, 50.0),
                block(0x9004, CfgTerminator::Fallthrough, 1.0),
                block(0x9006, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x9000, 0x9002, CfgEdgeKind::Branch),
                edge(0x9000, 0x9004, CfgEdgeKind::Fallthrough),
                edge(0x9002, 0x9006, CfgEdgeKind::Fallthrough),
                edge(0x9004, 0x9006, CfgEdgeKind::Fallthrough),
            ],
            Some(0x9000),
        );
        ProgramCfg::new(vec![
            named_function(0xf000, "main", caller_cfg),
            named_function(0x9000, "helper", helper_cfg),
        ])
    }

    fn nested_partition_diamond_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x6000,
            FunctionCfg::build(
                vec![
                    block(0x6000, CfgTerminator::Fallthrough, 1.0),
                    block(0x6002, CfgTerminator::Branch, 1.0),
                    block(0x6004, CfgTerminator::Branch, 1.0),
                    block(0x6006, CfgTerminator::Fallthrough, 5.0),
                    block(0x6008, CfgTerminator::Fallthrough, 2.0),
                    block(0x600a, CfgTerminator::Fallthrough, 7.0),
                    block(0x600c, CfgTerminator::Fallthrough, 1.0),
                    block(0x600e, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x6000, 0x6002, CfgEdgeKind::Fallthrough),
                    edge(0x6002, 0x6004, CfgEdgeKind::Branch),
                    edge(0x6002, 0x6006, CfgEdgeKind::Fallthrough),
                    edge(0x6004, 0x6008, CfgEdgeKind::Branch),
                    edge(0x6004, 0x600a, CfgEdgeKind::Fallthrough),
                    edge(0x6008, 0x600c, CfgEdgeKind::Fallthrough),
                    edge(0x600a, 0x600c, CfgEdgeKind::Fallthrough),
                    edge(0x6006, 0x600c, CfgEdgeKind::Fallthrough),
                    edge(0x600c, 0x600e, CfgEdgeKind::Fallthrough),
                ],
                Some(0x6000),
            ),
        )])
    }

    fn loop_partition_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x7000,
            FunctionCfg::build(
                vec![
                    block(0x7000, CfgTerminator::Fallthrough, 1.0),
                    block(0x7002, CfgTerminator::Branch, 1.0),
                    block(0x7004, CfgTerminator::Branch, 1.0),
                    block(0x7006, CfgTerminator::Fallthrough, 2.0),
                    block(0x7008, CfgTerminator::Fallthrough, 7.0),
                    block(0x700a, CfgTerminator::Fallthrough, 1.0),
                    block(0x700c, CfgTerminator::Fallthrough, 1.0),
                    block(0x700e, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x7000, 0x7002, CfgEdgeKind::Fallthrough),
                    edge(0x7002, 0x7004, CfgEdgeKind::Branch),
                    edge(0x7002, 0x700e, CfgEdgeKind::Fallthrough),
                    edge(0x7004, 0x7006, CfgEdgeKind::Branch),
                    edge(0x7004, 0x7008, CfgEdgeKind::Fallthrough),
                    edge(0x7006, 0x700a, CfgEdgeKind::Fallthrough),
                    edge(0x7008, 0x700a, CfgEdgeKind::Fallthrough),
                    edge(0x700a, 0x700c, CfgEdgeKind::Fallthrough),
                    edge(0x700c, 0x7002, CfgEdgeKind::Branch),
                ],
                Some(0x7000),
            ),
        )])
    }

    fn root_loop_partition_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x8000,
            FunctionCfg::build(
                vec![
                    block(0x8000, CfgTerminator::Branch, 1.0),
                    block(0x8002, CfgTerminator::Fallthrough, 1.0),
                    block(0x8004, CfgTerminator::Fallthrough, 1.0),
                    block(0x8006, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x8000, 0x8002, CfgEdgeKind::Branch),
                    edge(0x8000, 0x8006, CfgEdgeKind::Fallthrough),
                    edge(0x8002, 0x8004, CfgEdgeKind::Fallthrough),
                    edge(0x8004, 0x8000, CfgEdgeKind::Branch),
                ],
                Some(0x8000),
            ),
        )])
    }

    fn call_partition_program() -> ProgramCfg {
        let caller = FunctionCfg::build(
            vec![
                block(0x9000, CfgTerminator::Fallthrough, 1.0),
                block(0x9002, CfgTerminator::Branch, 1.0),
                call_block(0x9004, 2.0, 0x2000),
                block(0x9006, CfgTerminator::Fallthrough, 1.0),
                block(0x9008, CfgTerminator::Return, 1.0),
                block(0x900a, CfgTerminator::Fallthrough, 5.0),
            ],
            vec![
                edge(0x9000, 0x9002, CfgEdgeKind::Fallthrough),
                edge(0x9002, 0x9004, CfgEdgeKind::Branch),
                edge(0x9002, 0x900a, CfgEdgeKind::Fallthrough),
                edge(0x9004, 0x9006, CfgEdgeKind::CallReturn),
                edge(0x9006, 0x9008, CfgEdgeKind::Fallthrough),
                edge(0x900a, 0x9008, CfgEdgeKind::Fallthrough),
            ],
            Some(0x9000),
        );
        straight_callee_program(caller)
    }

    fn simple_partition_objective(program: &ProgramCfg, facts: &FlowFacts) -> f64 {
        simple_partition_objective_with_calls(program, facts, &BTreeMap::new())
    }

    fn simple_partition_objective_with_calls(
        program: &ProgramCfg,
        facts: &FlowFacts,
        call_cycles: &BTreeMap<BlockId, f64>,
    ) -> f64 {
        let function = &program.functions[0];
        let entry = function.cfg.entry.expect("entry");
        solve_simple_ipet(
            &function.cfg,
            entry,
            call_cycles,
            facts,
            &function.id,
            FactScope::Insensitive,
        )
        .expect("simple IPET")
        .objective
    }

    fn partitioned_solution(program: &ProgramCfg, facts: &FlowFacts) -> CfgIpetSolution {
        let mut program = program.clone();
        let _ = analyze_program(&mut program, facts);
        let wcet = program.functions[0].wcet.as_ref().expect("function WCET");
        assert_ne!(wcet.status, CfgWcetStatus::Unbounded);
        wcet.ipet.clone().expect("IPET solution")
    }

    fn state_partition_solution(
        program: &ProgramCfg,
        board: &BoardProfile,
        allow_partition: bool,
    ) -> CfgIpetSolution {
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        state_partition_solution_with_facts(program, &facts, allow_partition)
    }

    fn state_partition_solution_with_facts(
        program: &ProgramCfg,
        facts: &FlowFacts,
        allow_partition: bool,
    ) -> CfgIpetSolution {
        let function = &program.functions[0];
        let entry = function.cfg.entry.expect("entry");
        let analysis = crate::cfg_graph::analyze(&function.cfg);
        let reachable: BTreeSet<NodeIndex> = function
            .cfg
            .blocks_by_address
            .values()
            .copied()
            .filter(|node| analysis.reachable.contains(&function.cfg.graph[*node].id))
            .collect();
        let loops = build_loops(
            &function.cfg,
            entry,
            &analysis,
            facts,
            FactScope::Insensitive,
        )
        .expect("loops");
        let models = build_cache_ipet_models(program, &function.cfg, &reachable);
        let stalls = pipeline_edge_stalls(program, &function.cfg);
        solve_function_with_state_products(
            &function.cfg,
            entry,
            &reachable,
            &BTreeMap::new(),
            facts,
            &function.id,
            FactScope::Insensitive,
            &loops,
            &models,
            None,
            &stalls,
            None,
            None,
            None,
            None,
            None,
            allow_partition,
        )
        .expect("state-product IPET")
        .expect("state product available")
        .solution
    }

    fn cache_partition_diamond_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x1000,
            FunctionCfg::build(
                vec![
                    block(0x1000, CfgTerminator::Fallthrough, 1.0),
                    block(0x1002, CfgTerminator::Branch, 1.0),
                    block(0x1004, CfgTerminator::Fallthrough, 2.0),
                    block(0x1006, CfgTerminator::Fallthrough, 3.0),
                    block(0x1008, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                    edge(0x1002, 0x1004, CfgEdgeKind::Branch),
                    edge(0x1002, 0x1006, CfgEdgeKind::Fallthrough),
                    edge(0x1004, 0x1008, CfgEdgeKind::Fallthrough),
                    edge(0x1006, 0x1008, CfgEdgeKind::Fallthrough),
                ],
                Some(0x1000),
            ),
        )])
    }

    fn cache_loop_body_partition_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x3000,
            FunctionCfg::build(
                vec![
                    block(0x3000, CfgTerminator::Fallthrough, 1.0),
                    block(0x3002, CfgTerminator::Branch, 1.0),
                    block(0x3004, CfgTerminator::Branch, 1.0),
                    block(0x3006, CfgTerminator::Fallthrough, 2.0),
                    block(0x3008, CfgTerminator::Fallthrough, 3.0),
                    block(0x300a, CfgTerminator::Fallthrough, 1.0),
                    block(0x3010, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x3000, 0x3002, CfgEdgeKind::Fallthrough),
                    edge(0x3002, 0x3004, CfgEdgeKind::Branch),
                    edge(0x3002, 0x3010, CfgEdgeKind::Fallthrough),
                    edge(0x3004, 0x3006, CfgEdgeKind::Branch),
                    edge(0x3004, 0x3008, CfgEdgeKind::Fallthrough),
                    edge(0x3006, 0x300a, CfgEdgeKind::Fallthrough),
                    edge(0x3008, 0x300a, CfgEdgeKind::Fallthrough),
                    edge(0x300a, 0x3002, CfgEdgeKind::Branch),
                ],
                Some(0x3000),
            ),
        )])
    }

    fn nested_state_partition_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x4000,
            FunctionCfg::build(
                vec![
                    block(0x4000, CfgTerminator::Fallthrough, 1.0),
                    block(0x4002, CfgTerminator::Branch, 1.0),
                    block(0x4004, CfgTerminator::Branch, 1.0),
                    block(0x4006, CfgTerminator::Fallthrough, 4.0),
                    block(0x4008, CfgTerminator::Fallthrough, 2.0),
                    block(0x400a, CfgTerminator::Fallthrough, 1.0),
                    block(0x400c, CfgTerminator::Fallthrough, 0.5),
                    block(0x4010, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x4000, 0x4002, CfgEdgeKind::Fallthrough),
                    edge(0x4002, 0x4004, CfgEdgeKind::Branch),
                    edge(0x4002, 0x400c, CfgEdgeKind::Fallthrough),
                    edge(0x4004, 0x4006, CfgEdgeKind::Branch),
                    edge(0x4004, 0x4008, CfgEdgeKind::Fallthrough),
                    edge(0x4006, 0x400a, CfgEdgeKind::Fallthrough),
                    edge(0x4008, 0x400a, CfgEdgeKind::Fallthrough),
                    edge(0x400a, 0x4010, CfgEdgeKind::Fallthrough),
                    edge(0x400c, 0x4010, CfgEdgeKind::Fallthrough),
                ],
                Some(0x4000),
            ),
        )])
    }

    fn deeply_nested_state_partition_program() -> ProgramCfg {
        ProgramCfg::new(vec![function(
            0x5000,
            FunctionCfg::build(
                vec![
                    block(0x5000, CfgTerminator::Fallthrough, 1.0),
                    block(0x5002, CfgTerminator::Branch, 1.0),
                    block(0x5004, CfgTerminator::Branch, 1.0),
                    block(0x5006, CfgTerminator::Branch, 1.0),
                    block(0x5008, CfgTerminator::Fallthrough, 5.0),
                    block(0x500a, CfgTerminator::Fallthrough, 1.0),
                    block(0x500c, CfgTerminator::Fallthrough, 1.0),
                    block(0x5010, CfgTerminator::Fallthrough, 1.0),
                    block(0x5014, CfgTerminator::Fallthrough, 0.5),
                    block(0x5020, CfgTerminator::Fallthrough, 0.5),
                    block(0x5028, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x5000, 0x5002, CfgEdgeKind::Fallthrough),
                    edge(0x5002, 0x5004, CfgEdgeKind::Branch),
                    edge(0x5002, 0x5020, CfgEdgeKind::Fallthrough),
                    edge(0x5004, 0x5006, CfgEdgeKind::Branch),
                    edge(0x5004, 0x5014, CfgEdgeKind::Fallthrough),
                    edge(0x5006, 0x5008, CfgEdgeKind::Branch),
                    edge(0x5006, 0x500a, CfgEdgeKind::Fallthrough),
                    edge(0x5008, 0x500c, CfgEdgeKind::Fallthrough),
                    edge(0x500a, 0x500c, CfgEdgeKind::Fallthrough),
                    edge(0x500c, 0x5010, CfgEdgeKind::Fallthrough),
                    edge(0x5014, 0x5010, CfgEdgeKind::Fallthrough),
                    edge(0x5010, 0x5028, CfgEdgeKind::Fallthrough),
                    edge(0x5020, 0x5028, CfgEdgeKind::Fallthrough),
                ],
                Some(0x5000),
            ),
        )])
    }

    fn block_counts(solution: &CfgIpetSolution) -> BTreeMap<&str, u64> {
        solution
            .blocks
            .iter()
            .map(|block| (block.block.as_str(), block.executions))
            .collect()
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

    fn recovered_call_site(site: u64) -> CfgCallSite {
        CfgCallSite {
            site,
            target: None,
            target_function: None,
            direct: false,
            tail: false,
            conditional: false,
            heuristic: true,
            unresolved: true,
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
    fn sese_partition_summarizes_diamond_exactly() {
        let program = partition_diamond_program();
        let facts = facts();
        let baseline = simple_partition_objective(&program, &facts);
        let solution = partitioned_solution(&program, &facts);
        assert_eq!(solution.objective, baseline);
        let partitioning = solution.partitioning.as_ref().expect("partitioning");
        assert_eq!(partitioning.regions, 1);
        assert_eq!(partitioning.summarized_blocks, 3);
        assert_eq!(partitioning.model, "sese-branch-regions");
        let counts = block_counts(&solution);
        assert_eq!(counts.get("bb:0x5002"), Some(&1));
        assert_eq!(counts.get("bb:0x5006"), Some(&1));
        assert!(!counts.contains_key("bb:0x5004"));
        assert!(
            solution
                .blocks
                .iter()
                .all(|block| !block.block.as_str().starts_with("bb:partition:"))
        );
    }

    #[test]
    fn sese_partition_summarizes_nested_regions_exactly() {
        let program = nested_partition_diamond_program();
        let facts = facts();
        let baseline = simple_partition_objective(&program, &facts);
        let solution = partitioned_solution(&program, &facts);
        assert_eq!(solution.objective, baseline);
        let partitioning = solution.partitioning.as_ref().expect("partitioning");
        assert_eq!(partitioning.regions, 2);
        assert_eq!(partitioning.summarized_blocks, 5);
        let counts = block_counts(&solution);
        assert_eq!(counts.get("bb:0x600a"), Some(&1));
        assert!(!counts.contains_key("bb:0x6006"));
        assert!(!counts.contains_key("bb:0x6008"));
    }

    #[test]
    fn sese_partition_handles_a_region_inside_a_loop() {
        let program = loop_partition_program();
        let facts = facts();
        let baseline = simple_partition_objective(&program, &facts);
        let solution = partitioned_solution(&program, &facts);
        assert_eq!(solution.objective, baseline);
        let partitioning = solution.partitioning.as_ref().expect("partitioning");
        assert!(partitioning.regions >= 1);
        assert!(partitioning.summarized_blocks >= 3);
        assert!(
            solution
                .blocks
                .iter()
                .all(|block| !block.block.as_str().starts_with("bb:partition:"))
        );
    }

    #[test]
    fn sese_partition_summarizes_function_entry_region_exactly() {
        let program = diamond_program();
        let facts = facts();
        let baseline = simple_partition_objective(&program, &facts);
        assert_eq!(baseline, 32.0);
        let solution = partitioned_solution(&program, &facts);
        assert_eq!(solution.objective, baseline);
        let partitioning = solution.partitioning.as_ref().expect("partitioning");
        assert_eq!(partitioning.regions, 1);
        assert_eq!(partitioning.summarized_blocks, 4);
        let counts = block_counts(&solution);
        assert_eq!(counts.get("bb:0x1000"), Some(&1));
        assert_eq!(counts.get("bb:0x1002"), Some(&1));
        assert_eq!(counts.get("bb:0x1004"), Some(&1));
        assert!(!counts.contains_key("bb:0x1008"));
        assert_eq!(counts.get("bb:0x1006"), Some(&1));
    }

    #[test]
    fn sese_partition_handles_a_root_loop_region() {
        let program = root_loop_partition_program();
        let facts = facts();
        let baseline = simple_partition_objective(&program, &facts);
        let solution = partitioned_solution(&program, &facts);
        assert_eq!(solution.objective, baseline);
        let partitioning = solution.partitioning.as_ref().expect("partitioning");
        assert_eq!(partitioning.regions, 1);
        assert_eq!(partitioning.summarized_blocks, 3);
        assert!(
            solution
                .blocks
                .iter()
                .all(|block| !block.block.as_str().starts_with("bb:partition:"))
        );
    }

    #[test]
    fn sese_partition_handles_calls() {
        let program = call_partition_program();
        let facts = facts();
        let call_cycles = BTreeMap::from([(BlockId::new("bb:0x9004"), 3.0)]);
        let baseline = simple_partition_objective_with_calls(&program, &facts, &call_cycles);
        let solution = partitioned_solution(&program, &facts);
        assert_eq!(solution.objective, baseline);
        let partitioning = solution.partitioning.as_ref().expect("partitioning");
        assert_eq!(partitioning.regions, 1);
        assert_eq!(partitioning.summarized_blocks, 4);
        let counts = block_counts(&solution);
        assert_eq!(counts.get("bb:0x9004"), Some(&1));
        assert_eq!(counts.get("bb:0x9006"), Some(&1));
        assert!(!counts.contains_key("bb:0x900a"));
        assert!(
            solution
                .blocks
                .iter()
                .all(|block| !block.block.as_str().starts_with("bb:partition:"))
        );
    }

    #[test]
    fn state_partition_summarizes_cache_region_conservatively() {
        let board = cache_board(
            r"
[instruction_cache]
size = 64
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
",
        );
        let mut program = cache_partition_diamond_program();
        prepare_cache_program(&mut program, &board);

        let monolithic = state_partition_solution(&program, &board, false);
        assert!(monolithic.partitioning.is_none());
        assert_eq!(monolithic.cache_model.as_deref(), Some("state-product"));

        let partitioned = state_partition_solution(&program, &board, true);
        let partitioning = partitioned
            .partitioning
            .as_ref()
            .expect("state-product partitioning");
        assert_eq!(partitioning.model, "sese-state-product-regions");
        assert!(partitioning.regions >= 1);
        assert!(partitioning.summarized_blocks >= 1);
        assert_eq!(partitioned.cache_model, monolithic.cache_model);
        assert!(
            partitioned.objective + 1e-6 >= monolithic.objective,
            "state partition {} must not undercut monolithic {}",
            partitioned.objective,
            monolithic.objective
        );
        assert!(
            partitioned
                .blocks
                .iter()
                .any(|block| block.block.as_str() == "bb:0x1006"),
            "internal region block counts must be reconstructed"
        );
    }

    #[test]
    fn state_partition_leaves_loop_header_regions_monolithic() {
        let board = cache_board(
            r"
[instruction_cache]
size = 64
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
",
        );
        let mut program = cache_loop_header_program();
        prepare_cache_program(&mut program, &board);

        let monolithic = state_partition_solution(&program, &board, false);
        let partitioned = state_partition_solution(&program, &board, true);
        assert!(partitioned.partitioning.is_none());
        assert_eq!(partitioned.objective, monolithic.objective);
        assert_eq!(partitioned.cache_model, monolithic.cache_model);
    }

    #[test]
    fn state_partition_summarizes_a_region_inside_a_loop() {
        let board = cache_board(
            r"
[instruction_cache]
size = 64
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
",
        );
        let mut program = cache_loop_body_partition_program();
        prepare_cache_program(&mut program, &board);

        let monolithic = state_partition_solution(&program, &board, false);
        let partitioned = state_partition_solution(&program, &board, true);
        let partitioning = partitioned
            .partitioning
            .as_ref()
            .expect("loop-body state partitioning");
        assert_eq!(partitioning.model, "sese-state-product-regions");
        assert!(partitioning.regions >= 1);
        assert!(
            partitioned.objective + 1e-6 >= monolithic.objective,
            "loop-body state partition {} must not undercut monolithic {}",
            partitioned.objective,
            monolithic.objective
        );
    }

    #[test]
    fn state_partition_summarizes_nested_regions() {
        let board = cache_board(
            r"
[instruction_cache]
size = 64
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
",
        );
        let mut program = nested_state_partition_program();
        prepare_cache_program(&mut program, &board);

        let monolithic = state_partition_solution(&program, &board, false);
        let partitioned = state_partition_solution(&program, &board, true);
        let partitioning = partitioned
            .partitioning
            .as_ref()
            .expect("nested state partitioning");
        assert_eq!(partitioning.model, "sese-state-product-regions");
        assert_eq!(partitioning.regions, 2);
        assert!(partitioning.summarized_blocks >= 5);
        assert!(
            partitioned.objective + 1e-6 >= monolithic.objective,
            "nested state partition {} must not undercut monolithic {}",
            partitioned.objective,
            monolithic.objective
        );
        assert!(
            partitioned
                .blocks
                .iter()
                .any(|block| block.block.as_str() == "bb:0x4006"),
            "nested summary counts must be composed into the outer region"
        );
    }

    #[test]
    fn state_partition_composes_deeply_nested_summaries() {
        let board = cache_board(
            r"
[instruction_cache]
size = 64
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
",
        );
        let mut program = deeply_nested_state_partition_program();
        prepare_cache_program(&mut program, &board);

        let monolithic = state_partition_solution(&program, &board, false);
        let partitioned = state_partition_solution(&program, &board, true);
        let partitioning = partitioned
            .partitioning
            .as_ref()
            .expect("deeply nested state partitioning");
        assert_eq!(partitioning.regions, 3);
        assert!(partitioning.summarized_blocks >= 6);
        assert!(
            partitioned.objective + 1e-6 >= monolithic.objective,
            "deeply nested state partition {} must not undercut monolithic {}",
            partitioned.objective,
            monolithic.objective
        );
        assert!(
            partitioned
                .blocks
                .iter()
                .any(|block| block.block.as_str() == "bb:0x5008"),
            "deepest summary counts must survive two enclosing summaries"
        );
    }

    #[test]
    fn branch_fact_inside_region_keeps_region_monolithic() {
        let program = partition_diamond_program();
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <conditional address="0x5002">
      <case cond="1" executed="false"/>
    </conditional>
  </function>
</flowfacts>
"#,
            "partition-branch.ffx",
        )
        .expect("branch fact");
        facts
            .apply_document(document, &program)
            .expect("apply branch fact");
        let solution = partitioned_solution(&program, &facts);
        assert!(solution.partitioning.is_none());
    }

    #[test]
    fn branch_fact_outside_region_is_enforced_by_partition_parent() {
        let program = fact_partition_program();
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <conditional address="0x6000">
      <case cond="0" executed="false"/>
    </conditional>
  </function>
</flowfacts>
"#,
            "outside-region-branch.ffx",
        )
        .expect("branch fact");
        facts
            .apply_document(document, &program)
            .expect("apply branch fact");

        let baseline = simple_partition_objective(&program, &facts);
        assert_eq!(baseline, 14.0);
        let solution = partitioned_solution(&program, &facts);
        assert_eq!(solution.objective, baseline);
        let partitioning = solution
            .partitioning
            .as_ref()
            .expect("fact-free inner region is partitioned");
        assert_eq!(partitioning.model, "sese-branch-regions");
        assert_eq!(partitioning.regions, 1);
    }

    #[test]
    fn state_partition_enforces_branch_fact_outside_region() {
        let board = cache_board(
            r"
[instruction_cache]
size = 64
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
",
        );
        let mut program = fact_partition_program();
        prepare_cache_program(&mut program, &board);
        let mut facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <conditional address="0x6000">
      <case cond="0" executed="false"/>
    </conditional>
  </function>
</flowfacts>
"#,
            "outside-region-branch.ffx",
        )
        .expect("branch fact");
        facts
            .apply_document(document, &program)
            .expect("apply branch fact");

        let no_fact = state_partition_solution(&program, &board, false);
        let monolithic = state_partition_solution_with_facts(&program, &facts, false);
        let partitioned = state_partition_solution_with_facts(&program, &facts, true);
        assert!(
            monolithic.objective < no_fact.objective,
            "the branch fact must remove the expensive fallthrough path"
        );
        assert!(
            partitioned.objective + 1e-6 >= monolithic.objective,
            "state partition {} must not undercut fact-enforcing monolithic {}",
            partitioned.objective,
            monolithic.objective
        );
        let partitioning = partitioned
            .partitioning
            .as_ref()
            .expect("fact-free state region is partitioned");
        assert_eq!(partitioning.model, "sese-state-product-regions");
        assert!(partitioning.regions >= 1);
    }

    #[test]
    fn ordered_automaton_fact_allows_fact_free_region_partitioning() {
        let program = ordered_fact_partition_program();
        let baseline = analyze_baseline(&program);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x7012"/>
      <block address="0x7014"/>
    </conflict>
  </function>
</flowfacts>
"#,
            "ordered-partition.ffx",
        )
        .expect("ordered conflict");
        facts
            .apply_document(document, &program)
            .expect("apply ordered conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::Function
            }
        ));

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let wcet = analyzed.functions[0].wcet.as_ref().expect("function WCET");
        let constrained = wcet.cycles.expect("finite cycles");
        assert!(
            constrained < baseline,
            "ordered automaton must reduce the objective: {constrained} < {baseline}"
        );
        let solution = wcet.ipet.as_ref().expect("IPET solution");
        let partitioning = solution
            .partitioning
            .as_ref()
            .expect("fact-free diamond region uses ordered partition");
        assert_eq!(partitioning.model, "sese-branch-regions");
        assert!(partitioning.regions >= 1);
        assert!(
            partitioning
                .caveats
                .iter()
                .any(|caveat| caveat.contains("ordered automata"))
        );
    }

    #[test]
    fn cross_function_ordered_fact_allows_fact_free_region_partitioning() {
        let program = cross_partition_program();
        let baseline = analyze_baseline(&program);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x8010"/>
      <call name="helper">
        <block address="0x9002"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
            "cross-partition.ffx",
        )
        .expect("cross-function conflict");
        facts
            .apply_document(document, &program)
            .expect("apply cross-function conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossFunctionAutomaton
        );

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let caller = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0x8000)
            .and_then(|function| function.wcet.as_ref())
            .expect("caller WCET");
        let constrained = caller.cycles.expect("finite cycles");
        assert!(
            constrained < baseline,
            "cross-function automaton must reduce the objective: {constrained} < {baseline}"
        );
        let solution = caller.ipet.as_ref().expect("IPET solution");
        let partitioning = solution
            .partitioning
            .as_ref()
            .expect("fact-free diamond region uses cross-function partition");
        assert_eq!(partitioning.model, "sese-branch-regions");
        assert!(partitioning.regions >= 1);
        assert!(
            partitioning
                .caveats
                .iter()
                .any(|caveat| caveat.contains("cross-function"))
        );
    }

    #[test]
    fn multi_group_cross_function_fact_allows_region_partitioning() {
        let program = multi_group_cross_program();
        let baseline = analyze_baseline(&program);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0xa010"/>
      <call name="helper" address="0xa012">
        <block address="0xb002"/>
      </call>
      <block address="0xa014"/>
      <call name="helper" address="0xa016">
        <block address="0xb004"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
            "multi-group-cross.ffx",
        )
        .expect("multi-group cross-function conflict");
        facts
            .apply_document(document, &program)
            .expect("apply multi-group conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossFunctionAutomaton
        );
        let cross = conflict.cross_function.as_ref().expect("cross constraint");
        assert_eq!(cross.groups.len(), 2);
        assert_eq!(cross.groups[0].slot_start, 1);
        assert_eq!(cross.groups[1].slot_start, 3);
        let info = facts.info();
        assert_eq!(info.conflicts[0].calls.len(), 2);
        assert_eq!(
            info.conflicts[0].call.as_ref().expect("first call").site,
            Addr::new(0xa012)
        );
        assert_eq!(info.conflicts[0].calls[1].site, Addr::new(0xa016));

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let caller = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0xa000)
            .and_then(|function| function.wcet.as_ref())
            .expect("caller WCET");
        let constrained = caller.cycles.expect("finite cycles");
        assert!(
            constrained < baseline,
            "multi-group cross-function automaton must reduce the objective: {constrained} < {baseline}"
        );
        let solution = caller.ipet.as_ref().expect("IPET solution");
        let partitioning = solution
            .partitioning
            .as_ref()
            .expect("fact-free diamond region uses multi-group cross partition");
        assert_eq!(partitioning.model, "sese-branch-regions");
        assert!(partitioning.regions >= 1);
    }

    #[test]
    fn loop_scoped_cross_function_fact_applies_loop_entry_reset() {
        let program = loop_caller_program(true);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x3002">
      <conflict ordered="yes">
        <block address="0x3002"/>
        <call name="helper">
          <block address="0x2004"/>
        </call>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#,
            "loop-cross.ffx",
        )
        .expect("loop cross-function conflict");
        facts
            .apply_document(document, &program)
            .expect("apply loop cross conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(
            conflict.scope,
            Some(InfeasibleScope::Loop {
                header: BlockId::new("bb:0x3002")
            })
        );
        let cross = conflict.cross_function.as_ref().expect("cross constraint");
        assert_eq!(
            cross.reset,
            OrderedReset::LoopEntry {
                header: BlockId::new("bb:0x3002")
            }
        );
        let info = facts.info();
        assert_eq!(info.conflicts[0].scope.as_deref(), Some("loop"));
        assert_eq!(
            info.conflicts[0].loop_header.as_ref().map(BlockId::as_str),
            Some("bb:0x3002")
        );
        let call = info.conflicts[0].call.as_ref().expect("call boundary");
        assert_eq!(call.callee.as_str(), "fn:0x2000");
        assert_eq!(call.block.as_str(), "bb:0x3004");
        assert_eq!(call.continuation.as_str(), "bb:0x3006");
        assert_eq!(
            info.conflicts[0].elements[0]
                .function
                .as_ref()
                .map(FunctionId::as_str),
            Some("fn:0x1000")
        );
        assert_eq!(
            info.conflicts[0].elements[1]
                .function
                .as_ref()
                .map(FunctionId::as_str),
            Some("fn:0x2000")
        );
    }

    #[test]
    fn loop_scoped_cross_function_fact_allows_region_partitioning() {
        let program = loop_cross_partition_program();
        let mut baseline_program = program.clone();
        let _ = analyze_program(&mut baseline_program, &facts());
        let baseline = baseline_program
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("baseline caller cycles");
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <conflict ordered="yes">
        <block address="0xc010"/>
        <call name="helper">
          <block address="0x9000"/>
        </call>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#,
            "loop-cross-partition.ffx",
        )
        .expect("loop cross-function conflict");
        facts
            .apply_document(document, &program)
            .expect("apply loop cross conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        let cross = conflict.cross_function.as_ref().expect("cross constraint");
        assert_eq!(
            cross.reset,
            OrderedReset::LoopEntry {
                header: BlockId::new("bb:0xc010")
            }
        );

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let caller = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .expect("caller WCET");
        let constrained = caller.cycles.expect("finite cycles");
        assert!(
            constrained < baseline,
            "loop-scoped cross automaton must reduce the objective: {constrained} < {baseline}"
        );
        let solution = caller.ipet.as_ref().expect("IPET solution");
        let partitioning = solution
            .partitioning
            .as_ref()
            .expect("fact-free diamond region uses loop-cross partition");
        assert_eq!(partitioning.model, "sese-branch-regions");
        assert!(partitioning.regions >= 1);
    }

    #[test]
    fn loop_scoped_cross_function_sequence_spans_iterations() {
        let program = loop_cross_partition_program();
        let mut baseline_program = program.clone();
        let _ = analyze_program(&mut baseline_program, &facts());
        let baseline = baseline_program
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("baseline caller cycles");
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <conflict ordered="yes">
        <block address="0xc014"/>
        <block address="0xc010"/>
        <call name="helper">
          <block address="0x9000"/>
        </call>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#,
            "loop-cross-span.ffx",
        )
        .expect("loop cross-function conflict");
        facts
            .apply_document(document, &program)
            .expect("apply loop cross conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        let cross = conflict.cross_function.as_ref().expect("cross constraint");
        assert_eq!(
            cross.reset,
            OrderedReset::LoopEntry {
                header: BlockId::new("bb:0xc010")
            }
        );

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let constrained = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("finite caller cycles");
        assert!(
            constrained < baseline,
            "loop-entry reset must allow a sequence across iterations: \
             {constrained} < {baseline}"
        );
    }

    #[test]
    fn iteration_scoped_cross_function_sequence_resets_at_backedges() {
        let program = loop_cross_partition_program();
        let mut baseline_program = program.clone();
        let _ = analyze_program(&mut baseline_program, &facts());
        let baseline = baseline_program
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("baseline caller cycles");
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="*">
        <conflict ordered="yes">
          <block address="0xc014"/>
          <block address="0xc010"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            "iteration-cross-span.ffx",
        )
        .expect("iteration cross-function conflict");
        facts
            .apply_document(document, &program)
            .expect("apply iteration cross conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        let cross = conflict.cross_function.as_ref().expect("cross constraint");
        assert_eq!(
            cross.reset,
            OrderedReset::LoopIteration {
                header: BlockId::new("bb:0xc010")
            }
        );

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let constrained = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("finite caller cycles");
        assert_eq!(
            constrained, baseline,
            "iteration reset must prevent the sequence from spanning iterations"
        );
    }

    #[test]
    fn invalid_loop_scoped_cross_function_shapes_are_ignored() {
        let program = loop_cross_partition_program();
        let (cycles, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="*">
        <conflict ordered="yes">
          <edge src="0xc014" dst="0xc010"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(cycles.is_finite());
        let conflict = &facts.infeasible_paths()[0];
        assert!(!conflict.applied);
        assert!(
            conflict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("loop-backedge element"))
        );
    }

    #[test]
    fn specific_iteration_cross_function_facts_select_the_target_iteration() {
        let program = specific_iteration_cross_program();
        let analyze = |iteration: Option<&str>| -> (f64, FlowFacts, Option<(String, u32)>) {
            let conflict = iteration.map_or_else(String::new, |number| {
                format!(
                    r#"
      <iteration number="{number}">
        <conflict ordered="yes">
          <block address="0xd010"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
"#
                )
            });
            let text = format!(
                r#"
<flowfacts>
  <function name="main">
    <loop address="0xd010" maxcount="1">{conflict}
    </loop>
  </function>
</flowfacts>
"#
            );
            let mut facts = facts();
            let document = FlowFactDocument::parse_text(&text, "specific-iteration.ffx")
                .expect("parse specific iteration conflict");
            facts
                .apply_document(document, &program)
                .expect("apply specific iteration conflict");
            let mut analyzed = program.clone();
            let _ = analyze_program(&mut analyzed, &facts);
            let caller = analyzed
                .functions
                .iter()
                .find(|function| function.address == 0xd000)
                .and_then(|function| function.wcet.as_ref())
                .expect("caller WCET");
            let cycles = caller.cycles.expect("finite caller cycles");
            let partitioning = caller
                .ipet
                .as_ref()
                .and_then(|ipet| ipet.partitioning.as_ref())
                .map(|partitioning| (partitioning.model.clone(), partitioning.regions));
            (cycles, facts, partitioning)
        };

        let (baseline, _, _) = analyze(None);
        let (first, first_facts, first_partitioning) = analyze(Some("1"));
        let (second, second_facts, _) = analyze(Some("2"));
        let (last, last_facts, last_partitioning) = analyze(Some("-1"));
        assert!(
            first < baseline,
            "iteration 1 must remove the expensive loop path: {first} < {baseline}"
        );
        assert_eq!(
            second, baseline,
            "iteration 2 must be vacuous when the loop bound is one"
        );
        assert!(
            last < baseline,
            "last iteration must remove the expensive loop path: {last} < {baseline}"
        );
        let (model, regions) = first_partitioning.expect("iteration 1 partition");
        assert_eq!(model, "sese-branch-regions");
        assert!(regions >= 1);
        let (model, regions) = last_partitioning.expect("last-iteration partition");
        assert_eq!(model, "sese-branch-regions");
        assert!(regions >= 1);

        let cross = first_facts.infeasible_paths()[0]
            .cross_function
            .as_ref()
            .expect("first cross constraint");
        assert_eq!(
            cross.reset,
            OrderedReset::LoopIteration {
                header: BlockId::new("bb:0xd010")
            }
        );
        assert_eq!(cross.specific_iteration, Some(SpecificIteration::Number(1)));
        assert_eq!(first_facts.info().conflicts[0].iteration, Some(1));

        let cross = second_facts.infeasible_paths()[0]
            .cross_function
            .as_ref()
            .expect("second cross constraint");
        assert_eq!(cross.specific_iteration, Some(SpecificIteration::Number(2)));
        assert_eq!(second_facts.info().conflicts[0].iteration, Some(2));

        let cross = last_facts.infeasible_paths()[0]
            .cross_function
            .as_ref()
            .expect("last cross constraint");
        assert_eq!(cross.specific_iteration, Some(SpecificIteration::Last));
        assert_eq!(last_facts.info().conflicts[0].iteration, Some(-1));
    }

    fn cross_automaton_for(
        program: ProgramCfg,
        caller_address: u64,
        header: &str,
        block: &str,
        callee_block: &str,
        number: &str,
    ) -> (
        ProgramCfg,
        FunctionCfg,
        super::ModelGraph,
        super::CrossAutomatonModel,
    ) {
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            &format!(
                r#"
<flowfacts>
  <function name="main">
    <loop address="{header}" maxcount="4">
      <iteration number="{number}">
        <conflict ordered="yes">
          <block address="{block}"/>
          <call name="helper">
            <block address="{callee_block}"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#
            ),
            "specific-iteration.ffx",
        )
        .expect("parse specific iteration conflict");
        facts
            .apply_document(document, &program)
            .expect("apply specific iteration conflict");
        let caller = program
            .functions
            .iter()
            .find(|function| function.address == caller_address)
            .expect("caller");
        let analysis = crate::cfg_graph::analyze(&caller.cfg);
        let reachable: BTreeSet<_> = caller
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
            &BTreeMap::new(),
            &facts,
            &caller.id,
            scope,
            &cross,
            &[],
        )
        .expect("cross model");
        let automaton = super::cross_automaton_models(&model, &caller.cfg, &cross)
            .expect("automata")
            .remove(0);
        let cfg = caller.cfg.clone();
        (program, cfg, model, automaton)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn specific_iteration_cross_automaton_tracks_iterations_and_last_exit() {
        let build = |number: &str| {
            cross_automaton_for(
                specific_iteration_cross_program(),
                0xd000,
                "0xd010",
                "0xd010",
                "0x9000",
                number,
            )
        };

        let find_edge = |model: &super::ModelGraph,
                         predicate: &dyn Fn(&super::ModelEdge) -> bool| {
            model.edges.iter().position(predicate).expect("model edge")
        };
        let caller = |model: &super::ModelGraph, edge: &super::ModelEdge| -> (String, String) {
            (
                model.nodes[edge.source].block.to_string(),
                model.nodes[edge.target].block.to_string(),
            )
        };

        let (program, cfg, model, automaton) = build("2");
        let entry = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::Caller
                && caller(&model, edge) == ("bb:0xd002".to_owned(), "bb:0xd010".to_owned())
        });
        let backedge = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::Caller
                && caller(&model, edge) == ("bb:0xd014".to_owned(), "bb:0xd010".to_owned())
        });
        let enter = find_edge(&model, &|edge| edge.kind == super::ModelEdgeKind::EnterCall);
        let ret = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::ReturnCall
        });
        let mut state = super::initial_cross_state(&automaton, &model.nodes[model.entry].block)
            .expect("initial state");
        let advance = |state: super::CrossState, edge: usize| {
            super::advance_cross_state(
                &model,
                &program,
                &cfg,
                &automaton,
                state,
                &model.edges[edge],
            )
        };
        state = advance(state, entry).expect("entry");
        assert_eq!(state.iteration, 1);
        assert_eq!(state.slot, 0, "iteration 1 is not active for number 2");
        state = advance(state, enter).expect("inactive enter");
        state = advance(state, ret).expect("inactive return");
        assert_eq!(state.sub, 0);
        state = advance(state, backedge).expect("backedge to iteration 2");
        assert_eq!(state.iteration, 2);
        assert_eq!(state.slot, 1, "header starts the target iteration");
        state = advance(state, enter).expect("enter target iteration");
        assert_eq!(state.sub, 1);
        assert!(
            advance(state, ret).is_none(),
            "the target iteration must reject the completed sequence"
        );

        let (program, cfg, model, automaton) = build("-1");
        let entry = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::Caller
                && caller(&model, edge) == ("bb:0xd002".to_owned(), "bb:0xd010".to_owned())
        });
        let backedge = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::Caller
                && caller(&model, edge) == ("bb:0xd014".to_owned(), "bb:0xd010".to_owned())
        });
        let exit = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::Caller
                && caller(&model, edge) == ("bb:0xd014".to_owned(), "bb:0xd016".to_owned())
        });
        let enter = find_edge(&model, &|edge| edge.kind == super::ModelEdgeKind::EnterCall);
        let ret = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::ReturnCall
        });
        let mut state = super::initial_cross_state(&automaton, &model.nodes[model.entry].block)
            .expect("initial state");
        let advance = |state: super::CrossState, edge: usize| {
            super::advance_cross_state(
                &model,
                &program,
                &cfg,
                &automaton,
                state,
                &model.edges[edge],
            )
        };
        state = advance(state, entry).expect("entry");
        state = advance(state, enter).expect("enter");
        state = advance(state, ret).expect("return completes the sequence");
        assert!(state.pending, "last iteration keeps a pending violation");
        state = advance(state, backedge).expect("a backedge clears the pending violation");
        assert!(!state.pending);
        assert_eq!(state.slot, 1, "the next iteration starts at the header");
        state = advance(state, enter).expect("enter last candidate iteration");
        state = advance(state, ret).expect("return completes the sequence again");
        assert!(state.pending);
        assert!(
            advance(state, exit).is_none(),
            "exiting the loop in the violated iteration must reject the path"
        );
    }

    #[test]
    fn last_iteration_cross_function_fact_prunes_a_top_tested_loop() {
        let program = loop_cross_partition_program();
        let analyze = |iteration: Option<&str>| -> (f64, FlowFacts) {
            let conflict = iteration.map_or_else(String::new, |number| {
                format!(
                    r#"
      <iteration number="{number}">
        <conflict ordered="yes">
          <block address="0xc010"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
"#
                )
            });
            let text = format!(
                r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">{conflict}
    </loop>
  </function>
</flowfacts>
"#
            );
            let mut facts = facts();
            let document = FlowFactDocument::parse_text(&text, "last-iteration.ffx")
                .expect("parse last iteration conflict");
            facts
                .apply_document(document, &program)
                .expect("apply last iteration conflict");
            let mut analyzed = program.clone();
            let _ = analyze_program(&mut analyzed, &facts);
            let cycles = analyzed
                .functions
                .iter()
                .find(|function| function.address == 0xc000)
                .and_then(|function| function.wcet.as_ref())
                .and_then(|wcet| wcet.cycles)
                .expect("finite caller cycles");
            (cycles, facts)
        };

        let (baseline, _) = analyze(None);
        let (constrained, facts) = analyze(Some("-1"));
        assert!(
            constrained < baseline,
            "the final body iteration must lose its expensive call: \
             {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(facts.info().conflicts[0].iteration, Some(-1));

        let (above_bound, _) = analyze(Some("5"));
        assert_eq!(
            above_bound, baseline,
            "an iteration beyond the configured loop bound is vacuous"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn last_iteration_cross_function_pending_survives_a_header_exit() {
        let (program, cfg, model, automaton) = cross_automaton_for(
            loop_cross_partition_program(),
            0xc000,
            "0xc010",
            "0xc010",
            "0x9000",
            "-1",
        );
        let find_edge = |model: &super::ModelGraph,
                         predicate: &dyn Fn(&super::ModelEdge) -> bool| {
            model.edges.iter().position(predicate).expect("model edge")
        };
        let caller = |model: &super::ModelGraph, edge: &super::ModelEdge| -> (String, String) {
            (
                model.nodes[edge.source].block.to_string(),
                model.nodes[edge.target].block.to_string(),
            )
        };
        let entry = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::Caller
                && caller(&model, edge) == ("bb:0xc002".to_owned(), "bb:0xc010".to_owned())
        });
        let body = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::Caller
                && caller(&model, edge) == ("bb:0xc010".to_owned(), "bb:0xc012".to_owned())
        });
        let backedge = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::Caller
                && caller(&model, edge) == ("bb:0xc014".to_owned(), "bb:0xc010".to_owned())
        });
        let exit = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::Caller
                && caller(&model, edge) == ("bb:0xc010".to_owned(), "bb:0xc016".to_owned())
        });
        let enter = find_edge(&model, &|edge| edge.kind == super::ModelEdgeKind::EnterCall);
        let ret = find_edge(&model, &|edge| {
            edge.kind == super::ModelEdgeKind::ReturnCall
        });
        let advance = |state: super::CrossState, edge: usize| {
            super::advance_cross_state(
                &model,
                &program,
                &cfg,
                &automaton,
                state,
                &model.edges[edge],
            )
        };
        let completed =
            |advance: &dyn Fn(super::CrossState, usize) -> Option<super::CrossState>| {
                let mut state =
                    super::initial_cross_state(&automaton, &model.nodes[model.entry].block)
                        .expect("initial state");
                for (edge, name) in [(entry, "entry"), (enter, "enter"), (ret, "return")] {
                    state = advance(state, edge).expect(name);
                }
                state
            };

        let state = completed(&advance);
        assert!(state.pending);
        let state = advance(state, backedge).expect("header backedge");
        assert!(
            !state.pending && state.last_pending,
            "the completed iteration must survive a backedge to a header that can exit"
        );
        assert_eq!(
            state.slot, 1,
            "the next header still starts a new candidate sequence"
        );
        assert!(
            advance(state, exit).is_none(),
            "exiting at the header must reject the last completed body"
        );

        let state = completed(&advance);
        let state = advance(state, backedge).expect("header backedge");
        let state = advance(state, body).expect("next body entry");
        assert!(
            !state.pending && !state.last_pending,
            "entering another body clears the previous iteration's completion"
        );
        assert_eq!(state.slot, 1, "header progress carries into the new body");
        let state = advance(state, enter).expect("enter a later iteration");
        assert_eq!(state.sub, 1);
        let state = advance(state, ret).expect("complete the later iteration");
        assert!(state.pending);
        let state = advance(state, backedge).expect("backedge after completion");
        assert!(state.last_pending);
        assert!(
            advance(state, exit).is_none(),
            "the later completed body is the last iteration"
        );
    }

    #[test]
    fn last_iteration_cross_function_fact_prunes_a_monolithic_top_tested_loop() {
        let program = monolithic_top_tested_cross_program();
        let analyze = |iteration: Option<&str>| -> (f64, FlowFacts) {
            let conflict = iteration.map_or_else(String::new, |number| {
                format!(
                    r#"
      <iteration number="{number}">
        <conflict ordered="yes">
          <block address="0xe002"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
"#
                )
            });
            let text = format!(
                r#"
<flowfacts>
  <function name="main">
    <loop address="0xe002">{conflict}
    </loop>
  </function>
</flowfacts>
"#
            );
            let mut facts = facts();
            let document = FlowFactDocument::parse_text(&text, "last.ffx").expect("parse");
            facts.apply_document(document, &program).expect("apply");
            let mut analyzed = program.clone();
            let _ = analyze_program(&mut analyzed, &facts);
            let cycles = analyzed
                .functions
                .iter()
                .find(|function| function.address == 0xe000)
                .and_then(|function| function.wcet.as_ref())
                .and_then(|wcet| wcet.cycles)
                .expect("finite caller cycles");
            (cycles, facts)
        };
        let (baseline, _) = analyze(None);
        let (last, facts) = analyze(Some("-1"));
        assert!(
            last < baseline,
            "the last iteration must prune the monolithic loop: {last} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(facts.info().conflicts[0].iteration, Some(-1));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn specific_iteration_same_function_facts_select_the_target_iteration() {
        let program = loop_program();
        let baseline = analyze_baseline(&program);
        let analyze = |number: &str, ordered: bool| -> (f64, FlowFacts) {
            let ordered = if ordered { "yes" } else { "no" };
            let text = format!(
                r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="{number}">
        <conflict ordered="{ordered}">
          <block address="0x2004"/>
          <block address="0x2006"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#
            );
            let mut facts = facts();
            let document = FlowFactDocument::parse_text(&text, "specific-same.ffx")
                .expect("parse specific same-function conflict");
            facts
                .apply_document(document, &program)
                .expect("apply specific same-function conflict");
            let mut analyzed = program.clone();
            let _ = analyze_program(&mut analyzed, &facts);
            let cycles = analyzed.functions[0]
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.cycles)
                .expect("finite cycles");
            (cycles, facts)
        };

        let (first, first_facts) = analyze("1", true);
        assert!(
            first < baseline,
            "iteration 1 must remove the expensive body path: {first} < {baseline}"
        );
        let conflict = &first_facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopSpecific {
                    iteration: SpecificIteration::Number(1),
                    ..
                }
            }
        ));
        assert_eq!(first_facts.info().conflicts[0].iteration, Some(1));
        assert_eq!(
            first_facts.info().conflicts[0].scope.as_deref(),
            Some("loop")
        );

        let (last, last_facts) = analyze("-1", true);
        assert!(
            last < baseline,
            "the last iteration must remove the expensive body path: {last} < {baseline}"
        );
        assert!(matches!(
            last_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopSpecific {
                    iteration: SpecificIteration::Last,
                    ..
                }
            }
        ));
        assert_eq!(last_facts.info().conflicts[0].iteration, Some(-1));

        let (above_bound, _) = analyze("5", true);
        assert_eq!(
            above_bound, baseline,
            "an iteration beyond the loop bound is vacuous"
        );

        let (unordered, unordered_facts) = analyze("1", false);
        assert!(
            unordered < baseline,
            "iteration 1 unordered presence must remove the body path: \
             {unordered} < {baseline}"
        );
        let conflict = &unordered_facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: Some(SpecificIteration::Number(1)),
                ref header,
            } if header.as_str() == "bb:0x2002"
        ));
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0x2002"
        ));
        assert_eq!(unordered_facts.info().conflicts[0].iteration, Some(1));
        assert_eq!(
            unordered_facts.info().conflicts[0].mode.as_deref(),
            Some("automaton")
        );

        let (unordered_last, unordered_last_facts) = analyze("-1", false);
        assert!(
            unordered_last < baseline,
            "last-iteration unordered presence must remove the body path: \
             {unordered_last} < {baseline}"
        );
        assert!(matches!(
            unordered_last_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: Some(SpecificIteration::Last),
                ..
            }
        ));
        assert_eq!(unordered_last_facts.info().conflicts[0].iteration, Some(-1));

        let (unordered_above_bound, _) = analyze("5", false);
        assert_eq!(
            unordered_above_bound, baseline,
            "an unordered iteration beyond the loop bound is vacuous"
        );
    }

    #[test]
    fn specific_iteration_same_function_fact_allows_region_partitioning() {
        let program = ordered_fact_partition_program();
        let baseline = analyze_baseline(&program);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x7010">
      <iteration number="1">
        <conflict ordered="yes">
          <block address="0x7012"/>
          <block address="0x7014"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            "specific-ordered-partition.ffx",
        )
        .expect("specific ordered conflict");
        facts
            .apply_document(document, &program)
            .expect("apply specific ordered conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopSpecific {
                    iteration: SpecificIteration::Number(1),
                    ..
                }
            }
        ));

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let wcet = analyzed.functions[0].wcet.as_ref().expect("function WCET");
        let constrained = wcet.cycles.expect("finite cycles");
        assert!(
            constrained < baseline,
            "specific ordered automaton must reduce the objective: \
             {constrained} < {baseline}"
        );
        let partitioning = wcet
            .ipet
            .as_ref()
            .and_then(|ipet| ipet.partitioning.as_ref())
            .expect("fact-free diamond region uses specific ordered partition");
        assert_eq!(partitioning.model, "sese-branch-regions");
        assert!(partitioning.regions >= 1);
    }

    #[test]
    fn invalid_cross_iteration_facts_are_ignored() {
        let program = specific_iteration_cross_program();
        for (number, expected) in [
            ("0", "iteration number 0 is unsupported"),
            ("257", "exceeds the analysis limit"),
        ] {
            let text = format!(
                r#"
<flowfacts>
  <function name="main">
    <loop address="0xd010">
      <iteration number="{number}">
        <conflict ordered="yes">
          <block address="0xd010"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#
            );
            let mut facts = facts();
            let document =
                FlowFactDocument::parse_text(&text, "invalid-iteration.ffx").expect("parse");
            facts
                .apply_document(document, &program)
                .expect("apply invalid iteration");
            let conflict = &facts.infeasible_paths()[0];
            assert!(!conflict.applied);
            assert!(
                conflict
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains(expected)),
                "unexpected reason: {:?}",
                conflict.reason
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn nested_loop_ordered_conflicts_select_the_containing_scope() {
        let program = nested_loop_ordered_program();
        let analyze = |conflict: &str| -> (f64, FlowFacts) {
            let text = format!(
                r#"
<flowfacts>
  <function name="main">
    {conflict}
  </function>
</flowfacts>
"#
            );
            let mut facts = facts();
            let document = FlowFactDocument::parse_text(&text, "nested-loop.ffx")
                .expect("parse nested loop conflict");
            facts
                .apply_document(document, &program)
                .expect("apply nested loop conflict");
            let mut analyzed = program.clone();
            let _ = analyze_program(&mut analyzed, &facts);
            let cycles = analyzed
                .functions
                .iter()
                .find(|function| function.address == 0xf000)
                .and_then(|function| function.wcet.as_ref())
                .and_then(|wcet| wcet.cycles)
                .expect("finite caller cycles");
            (cycles, facts)
        };
        let (baseline, _) = analyze("");

        let (outer, outer_facts) = analyze(
            r#"
    <loop address="0xf002">
      <loop address="0xf006">
        <conflict ordered="yes">
          <block address="0xf004"/>
          <block address="0xf008"/>
        </conflict>
      </loop>
    </loop>
"#,
        );
        assert!(
            outer < baseline,
            "elements spanning the inner loop lift to the outer scope: {outer} < {baseline}"
        );
        let conflict = &outer_facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopEntry { ref header }
            } if header.as_str() == "bb:0xf002"
        ));
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0xf002"
        ));

        let (inner, inner_facts) = analyze(
            r#"
    <loop address="0xf002">
      <loop address="0xf006">
        <conflict ordered="yes">
          <block address="0xf008"/>
          <block address="0xf00c"/>
        </conflict>
      </loop>
    </loop>
"#,
        );
        assert!(
            inner < baseline,
            "inner-only elements use the innermost scope: {inner} < {baseline}"
        );
        assert!(matches!(
            inner_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopEntry { ref header }
            } if header.as_str() == "bb:0xf006"
        ));

        let (specific, specific_facts) = analyze(
            r#"
    <loop address="0xf002">
      <loop address="0xf006">
        <iteration number="1">
          <conflict ordered="yes">
            <block address="0xf008"/>
            <block address="0xf00c"/>
          </conflict>
        </iteration>
      </loop>
    </loop>
"#,
        );
        assert!(
            specific < baseline,
            "inner iteration context selects the inner scope: {specific} < {baseline}"
        );
        assert!(matches!(
            specific_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopSpecific {
                    ref header,
                    iteration: SpecificIteration::Number(1)
                }
            } if header.as_str() == "bb:0xf006"
        ));

        let (all, applied_facts) = analyze(
            r#"
    <loop address="0xf002">
      <loop address="0xf006">
        <iteration number="*">
          <conflict ordered="yes">
            <block address="0xf004"/>
            <block address="0xf008"/>
          </conflict>
        </iteration>
      </loop>
    </loop>
"#,
        );
        assert!(
            all < baseline,
            "nested all-iteration mixed ordering must prune the loop: {all} < {baseline}"
        );
        assert!(applied_facts.infeasible_paths()[0].applied);
        assert!(matches!(
            applied_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopIteration { ref header }
            } if header.as_str() == "bb:0xf006"
        ));
    }

    #[test]
    fn nested_loop_unordered_conflicts_use_invocation_presence() {
        let program = nested_loop_ordered_program();
        let baseline = analyze_baseline_for(&program, 0xf000);
        let (constrained, facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <block address="0xf004"/>
      <block address="0xf008"/>
    </conflict>
  </function>
</flowfacts>
"#,
            0xf000,
        );
        assert!(
            constrained < baseline,
            "nested-loop unordered presence must prune the inner path: \
             {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(conflict.presence);
        assert_eq!(conflict.scope, Some(InfeasibleScope::Function));
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Aggregate
        ));
        assert_eq!(facts.info().conflicts[0].scope.as_deref(), Some("function"));
        assert_eq!(facts.info().conflicts[0].mode.as_deref(), Some("aggregate"));
    }

    #[test]
    fn all_iteration_unordered_conflicts_track_nested_loops() {
        let program = nested_loop_ordered_program();
        let baseline = analyze_baseline_for(&program, 0xf000);
        let (constrained, facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xf002">
      <iteration number="*">
        <conflict>
          <block address="0xf004"/>
          <block address="0xf008"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            0xf000,
        );
        assert!(
            constrained < baseline,
            "all-iteration presence must prune the inner call in every iteration: \
             {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: None,
                ref header,
            } if header.as_str() == "bb:0xf002"
        ));
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0xf002"
        ));
        assert_eq!(facts.info().conflicts[0].iteration, None);

        let (inner_under_outer, inner_facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xf002">
      <iteration number="*">
        <conflict>
          <block address="0xf008"/>
          <block address="0xf00c"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            0xf000,
        );
        assert!(
            inner_under_outer < baseline,
            "the declared outer loop must drive nested all-iteration presence: \
             {inner_under_outer} < {baseline}"
        );
        assert!(matches!(
            inner_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: None,
                ref header,
            } if header.as_str() == "bb:0xf002"
        ));
    }

    #[test]
    fn disjoint_loop_unordered_conflicts_use_invocation_presence() {
        let program = disjoint_loop_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <block address="0x7104"/>
      <block address="0x710a"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert!(
            constrained < baseline,
            "disjoint-loop unordered presence must prune one loop body: \
             {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(conflict.presence);
        assert_eq!(conflict.scope, Some(InfeasibleScope::Function));
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Aggregate
        ));
    }

    #[test]
    fn specific_iteration_unordered_prunes_top_tested_loops() {
        let program = top_tested_loop_program();
        let baseline = analyze_baseline(&program);
        let analyze = |number: &str| -> (f64, FlowFacts) {
            analyze_with(
                &program,
                &format!(
                    r#"
<flowfacts>
  <function name="main">
    <loop address="0x7402">
      <iteration number="{number}">
        <conflict>
          <block address="0x7404"/>
          <block address="0x7406"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#
                ),
            )
        };

        let (last, last_facts) = analyze("-1");
        assert!(
            last < baseline,
            "last-iteration unordered presence must forbid the final body: \
             {last} < {baseline}"
        );
        assert!(matches!(
            last_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: Some(SpecificIteration::Last),
                ..
            }
        ));

        let (second, second_facts) = analyze("2");
        assert!(
            second < baseline && second > last,
            "iteration 2 only forbids the second body: {second} < {baseline}"
        );
        assert!(matches!(
            second_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: Some(SpecificIteration::Number(2)),
                ..
            }
        ));
    }

    #[test]
    fn specific_iteration_unordered_tracks_nested_inner_iterations() {
        let program = nested_loop_ordered_program();
        let baseline = analyze_baseline_for(&program, 0xf000);
        let (constrained, conflict_facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xf002">
      <loop address="0xf006">
        <iteration number="1">
          <conflict>
            <block address="0xf008"/>
            <block address="0xf00c"/>
          </conflict>
        </iteration>
      </loop>
    </loop>
  </function>
</flowfacts>
"#,
            0xf000,
        );
        assert!(
            constrained < baseline,
            "inner iteration presence must prune each entry's call: \
             {constrained} < {baseline}"
        );
        let conflict = &conflict_facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: Some(SpecificIteration::Number(1)),
                ref header,
            } if header.as_str() == "bb:0xf006"
        ));
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0xf006"
        ));
    }

    #[test]
    fn specific_iteration_unordered_applies_with_branch_state_models() {
        let board = branch_board(16);
        let prediction = board.branch_prediction().expect("branch profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));

        let mut baseline = top_tested_loop_program();
        let _ = crate::branch_prediction::analyze_program(&mut baseline, prediction);
        let _ = analyze_program_with_branch_prediction(&mut baseline, &facts, Some(prediction));
        let baseline_cycles = baseline.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.cycles)
            .expect("baseline cycles");

        let mut constrained = top_tested_loop_program();
        let _ = crate::branch_prediction::analyze_program(&mut constrained, prediction);
        let mut constrained_facts =
            FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x7402">
      <iteration number="-1">
        <conflict>
          <block address="0x7404"/>
          <block address="0x7406"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            "specific-presence-state.ffx",
        )
        .expect("parse specific presence state conflict");
        constrained_facts
            .apply_document(document, &constrained)
            .expect("apply specific presence state conflict");
        let _ = analyze_program_with_branch_prediction(
            &mut constrained,
            &constrained_facts,
            Some(prediction),
        );
        let wcet = constrained.functions[0]
            .wcet
            .as_ref()
            .expect("constraint WCET");
        let cycles = wcet.cycles.expect("finite cycles");
        assert!(
            cycles < baseline_cycles,
            "specific presence must apply with branch models: {cycles} < {baseline_cycles}"
        );
        assert!(constrained_facts.infeasible_paths()[0].applied);
    }

    #[test]
    fn mixed_specific_iteration_unordered_conflicts_track_outside_presence() {
        let program = loop_program();
        let baseline = analyze_baseline(&program);
        let analyze = |number: &str, outside: &str| -> (f64, FlowFacts) {
            analyze_with(
                &program,
                &format!(
                    r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="{number}">
        <conflict>
          <block address="0x2004"/>
          <block address="{outside}"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#
                ),
            )
        };

        let (first, first_facts) = analyze("1", "0x200c");
        assert!(
            first < baseline,
            "a present outside block must suppress the selected body: \
             {first} < {baseline}"
        );
        let conflict = &first_facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: Some(SpecificIteration::Number(1)),
                ref header,
            } if header.as_str() == "bb:0x2002"
        ));
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0x2002"
        ));

        let (before, before_facts) = analyze("1", "0x2000");
        assert!(
            before < baseline,
            "a present pre-loop block must suppress the selected body: \
             {before} < {baseline}"
        );
        assert!(before_facts.infeasible_paths()[0].applied);

        let (last, last_facts) = analyze("-1", "0x200c");
        assert!(
            last < baseline,
            "last-iteration presence must include outside blocks: {last} < {baseline}"
        );
        assert!(matches!(
            last_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: Some(SpecificIteration::Last),
                ..
            }
        ));
    }

    #[test]
    fn mixed_specific_iteration_unordered_requires_outside_presence() {
        let program = mixed_unordered_program();
        let baseline = analyze_baseline(&program);
        assert_eq!(baseline, 492.0);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x9002">
      <iteration number="1">
        <conflict>
          <block address="0x9004"/>
          <block address="0x900e"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(
            constrained, 491.0,
            "the optional outside block must stay absent; the selected body may repeat"
        );
        assert!(matches!(
            facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: Some(SpecificIteration::Number(1)),
                ..
            }
        ));
    }

    #[test]
    fn nested_loop_cross_function_conflict_selects_the_containing_scope() {
        let program = nested_loop_ordered_program();
        let (baseline, _) = analyze_nested_program(&program, "");
        let (constrained, facts) = analyze_nested_program(
            &program,
            r#"
    <loop address="0xf002">
      <loop address="0xf006">
        <conflict ordered="yes">
          <block address="0xf004"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </loop>
    </loop>
"#,
        );
        assert!(
            constrained < baseline,
            "nested cross-function conflict must use the outer scope: \
             {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossFunctionAutomaton
        );
        let cross = conflict.cross_function.as_ref().expect("cross constraint");
        assert_eq!(
            cross.reset,
            OrderedReset::LoopEntry {
                header: BlockId::new("bb:0xf002")
            }
        );
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0xf002"
        ));
    }

    #[test]
    fn mixed_loop_ordered_conflicts_use_function_scope() {
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
        <block address="0x200c"/>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(
            constrained < baseline,
            "mixed loop/non-loop order must be enforced: {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(conflict.scope, Some(InfeasibleScope::Function));
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::Function
            }
        ));
        assert_eq!(facts.info().conflicts[0].scope.as_deref(), Some("function"));

        let (all, all_facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="*">
        <conflict ordered="yes">
          <block address="0x2004"/>
          <block address="0x200c"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(
            all < baseline,
            "all-iteration mixed ordering must prune the loop: {all} < {baseline}"
        );
        assert!(matches!(
            all_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopIteration { ref header }
            } if header.as_str() == "bb:0x2002"
        ));
        assert!(matches!(
            all_facts.infeasible_paths()[0].scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0x2002"
        ));
    }

    #[test]
    fn mixed_loop_unordered_conflicts_use_presence_indicators() {
        let program = mixed_unordered_program();
        let baseline = analyze_baseline(&program);
        let (optional, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <block address="0x9004"/>
      <block address="0x900e"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(baseline, 492.0);
        assert_eq!(
            optional, 491.0,
            "the loop may repeat when the optional outside block is absent"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(conflict.presence);
        assert_eq!(conflict.scope, Some(InfeasibleScope::Function));
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Aggregate
        ));
        assert_eq!(facts.info().conflicts[0].scope.as_deref(), Some("function"));
        assert_eq!(facts.info().conflicts[0].mode.as_deref(), Some("aggregate"));
        assert_eq!(facts.info().conflicts[0].iteration, None);

        let (mandatory, mandatory_facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <block address="0x9004"/>
      <block address="0x9010"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(
            mandatory, 32.0,
            "a present outside element must suppress the loop element"
        );
        assert!(mandatory_facts.infeasible_paths()[0].presence);

        let (all_iterations, all_facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x9002">
      <iteration number="*">
        <conflict>
          <block address="0x9004"/>
          <block address="0x900e"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(
            all_iterations, 491.0,
            "all-iteration presence must keep the optional outside block absent"
        );
        let conflict = &all_facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: None,
                ref header,
            } if header.as_str() == "bb:0x9002"
        ));
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0x9002"
        ));
        assert_eq!(all_facts.info().conflicts[0].iteration, None);
        assert_eq!(
            all_facts.info().conflicts[0].mode.as_deref(),
            Some("automaton")
        );
    }

    #[test]
    fn mixed_loop_unordered_conflicts_apply_with_ordered_automata() {
        let program = mixed_unordered_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x9004"/>
      <block address="0x9010"/>
    </conflict>
    <conflict>
      <block address="0x9004"/>
      <block address="0x900e"/>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert!(
            constrained < baseline,
            "mixed unordered presence must apply beside ordered automata: \
             {constrained} < {baseline}"
        );
        assert_eq!(facts.infeasible_paths().len(), 2);
        assert!(matches!(
            facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::Automaton { .. }
        ));
        let mixed = &facts.infeasible_paths()[1];
        assert!(mixed.applied);
        assert!(mixed.presence);
        assert_eq!(mixed.scope, Some(InfeasibleScope::Function));
        assert!(matches!(
            mixed.enforcement,
            InfeasibleEnforcement::Aggregate
        ));
    }

    #[test]
    fn mixed_loop_unordered_conflicts_apply_in_branch_state_products() {
        let board = branch_board(256);
        let prediction = board.branch_prediction().expect("branch profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));

        let mut baseline_program = mixed_unordered_program();
        let _ = crate::branch_prediction::analyze_program(&mut baseline_program, prediction);
        let _ =
            analyze_program_with_branch_prediction(&mut baseline_program, &facts, Some(prediction));
        let baseline = baseline_program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.cycles)
            .expect("baseline cycles");

        let mut constrained_program = mixed_unordered_program();
        let _ = crate::branch_prediction::analyze_program(&mut constrained_program, prediction);
        let mut constrained_facts =
            FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <block address="0x9004"/>
      <block address="0x900e"/>
    </conflict>
  </function>
</flowfacts>
"#,
            "mixed-state-product.ffx",
        )
        .expect("parse mixed state-product conflict");
        constrained_facts
            .apply_document(document, &constrained_program)
            .expect("apply mixed state-product conflict");
        let _ = analyze_program_with_branch_prediction(
            &mut constrained_program,
            &constrained_facts,
            Some(prediction),
        );
        let wcet = constrained_program.functions[0]
            .wcet
            .as_ref()
            .expect("constraint WCET");
        let constrained = wcet.cycles.expect("finite cycles");
        assert!(
            constrained < baseline,
            "mixed presence must apply in branch state products: {constrained} < {baseline}"
        );
        assert_eq!(
            wcet.ipet
                .as_ref()
                .and_then(|ipet| ipet.branch_model.as_deref()),
            Some("state-product")
        );
        assert!(constrained_facts.infeasible_paths()[0].presence);
    }

    #[test]
    fn mixed_loop_cross_function_conflict_uses_function_scope() {
        let program = loop_cross_partition_program();
        let baseline = analyze_baseline_for(&program, 0xc000);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <conflict ordered="yes">
        <call name="helper">
          <block address="0x9000"/>
        </call>
        <block address="0xc01c"/>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#,
            "mixed-cross.ffx",
        )
        .expect("mixed cross conflict");
        facts
            .apply_document(document, &program)
            .expect("apply mixed cross conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert_eq!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossFunctionAutomaton
        );
        let cross = conflict.cross_function.as_ref().expect("cross constraint");
        assert_eq!(cross.reset, OrderedReset::Function);
        assert_eq!(conflict.scope, Some(InfeasibleScope::CrossFunction));

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let constrained = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("finite caller cycles");
        assert!(
            constrained < baseline,
            "mixed cross-function order must be enforced: {constrained} < {baseline}"
        );
    }

    #[test]
    fn mixed_loop_unordered_conflicts_apply_with_cross_function_automata() {
        let program = loop_cross_partition_program();
        let baseline = analyze_baseline_for(&program, 0xc000);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <conflict ordered="yes">
        <call name="helper">
          <block address="0x9000"/>
        </call>
        <block address="0xc01c"/>
      </conflict>
    </loop>
    <conflict>
      <block address="0xc012"/>
      <block address="0xc016"/>
    </conflict>
  </function>
</flowfacts>
"#,
            "mixed-cross-state.ffx",
        )
        .expect("parse mixed cross state conflict");
        facts
            .apply_document(document, &program)
            .expect("apply mixed cross state conflict");
        assert_eq!(facts.infeasible_paths().len(), 2);
        assert!(facts.infeasible_paths().iter().any(|conflict| matches!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossFunctionAutomaton
        )));
        let mixed = facts
            .infeasible_paths()
            .iter()
            .find(|conflict| conflict.presence)
            .expect("mixed presence constraint");
        assert!(mixed.applied);
        assert_eq!(mixed.scope, Some(InfeasibleScope::Function));
        assert!(matches!(
            mixed.enforcement,
            InfeasibleEnforcement::Aggregate
        ));

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let constrained = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("finite cycles");
        assert!(
            constrained < baseline,
            "mixed presence must apply beside cross-function automata: \
             {constrained} < {baseline}"
        );
    }

    #[test]
    fn specific_iteration_unordered_applies_with_cross_function_automata() {
        let program = loop_cross_partition_program();
        let baseline = analyze_baseline_for(&program, 0xc000);
        let cross_text = r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="2">
        <conflict ordered="yes">
          <block address="0xc010"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#;
        let (cross, _) = analyze_with_for(&program, cross_text, 0xc000);
        assert!(cross < baseline, "cross order must prune an iteration path");

        let both_text = r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="2">
        <conflict ordered="yes">
          <block address="0xc010"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
      <iteration number="1">
        <conflict>
          <block address="0xc012"/>
          <block address="0xc014"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#;
        let (both, facts) = analyze_with_for(&program, both_text, 0xc000);
        assert!(
            both < cross,
            "specific unordered presence must combine with cross automata: \
             {both} < {cross}"
        );
        let presence = facts
            .infeasible_paths()
            .iter()
            .find(|conflict| {
                matches!(
                    conflict.enforcement,
                    InfeasibleEnforcement::PresenceAutomaton { .. }
                )
            })
            .expect("presence automaton");
        assert!(presence.applied);

        let mixed_text = r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="2">
        <conflict ordered="yes">
          <block address="0xc010"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
      <iteration number="1">
        <conflict>
          <block address="0xc012"/>
          <block address="0xc01c"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#;
        let (mixed, mixed_facts) = analyze_with_for(&program, mixed_text, 0xc000);
        assert!(
            mixed < cross,
            "outside-block presence must combine with cross automata: {mixed} < {cross}"
        );
        assert!(mixed_facts.infeasible_paths().iter().any(|conflict| {
            matches!(
                conflict.enforcement,
                InfeasibleEnforcement::PresenceAutomaton {
                    iteration: Some(SpecificIteration::Number(1)),
                    ..
                }
            )
        }));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn specific_iteration_mixed_loop_ordered_conflicts_use_the_selected_iteration() {
        let program = loop_program();
        let baseline = analyze_baseline(&program);
        let analyze = |text: &str| -> (f64, FlowFacts) { analyze_with(&program, text) };

        let (first, first_facts) = analyze(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="1">
        <conflict ordered="yes">
          <block address="0x2004"/>
          <block address="0x200c"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(
            first < baseline,
            "mixed iteration 1 ordering must prune the loop path: {first} < {baseline}"
        );
        let conflict = &first_facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopSpecific {
                    ref header,
                    iteration: SpecificIteration::Number(1)
                }
            } if header.as_str() == "bb:0x2002"
        ));
        assert_eq!(first_facts.info().conflicts[0].iteration, Some(1));

        let (last, last_facts) = analyze(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="-1">
        <conflict ordered="yes">
          <block address="0x2004"/>
          <block address="0x200c"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(
            last < baseline,
            "mixed last-iteration ordering must prune the loop path: {last} < {baseline}"
        );
        assert_eq!(last_facts.info().conflicts[0].iteration, Some(-1));

        let (before, _) = analyze(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="1">
        <conflict ordered="yes">
          <block address="0x2000"/>
          <block address="0x2004"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(
            before < baseline,
            "outside-before progress must survive loop entry: {before} < {baseline}"
        );

        let (all, all_facts) = analyze(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x2002">
      <iteration number="*">
        <conflict ordered="yes">
          <block address="0x2004"/>
          <block address="0x200c"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
        );
        assert!(
            all < baseline,
            "all-iteration mixed ordering must prune the loop: {all} < {baseline}"
        );
        assert!(all_facts.infeasible_paths()[0].applied);
        assert!(matches!(
            all_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::Automaton {
                reset: OrderedReset::LoopIteration { ref header }
            } if header.as_str() == "bb:0x2002"
        ));
    }

    #[test]
    fn specific_iteration_mixed_loop_cross_function_conflict_uses_the_selected_iteration() {
        let program = loop_cross_partition_program();
        let baseline = analyze_baseline_for(&program, 0xc000);
        let analyze = |number: &str| -> (f64, FlowFacts) {
            let text = format!(
                r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="{number}">
        <conflict ordered="yes">
          <call name="helper">
            <block address="0x9000"/>
          </call>
          <block address="0xc01c"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#
            );
            let mut facts = facts();
            let document = FlowFactDocument::parse_text(&text, "mixed-specific-cross.ffx")
                .expect("parse mixed specific cross conflict");
            facts
                .apply_document(document, &program)
                .expect("apply mixed specific cross conflict");
            let mut analyzed = program.clone();
            let _ = analyze_program(&mut analyzed, &facts);
            let cycles = analyzed
                .functions
                .iter()
                .find(|function| function.address == 0xc000)
                .and_then(|function| function.wcet.as_ref())
                .and_then(|wcet| wcet.cycles)
                .expect("finite caller cycles");
            (cycles, facts)
        };

        let (first, first_facts) = analyze("1");
        assert!(
            first < baseline,
            "mixed specific cross ordering must prune the loop path: {first} < {baseline}"
        );
        let conflict = &first_facts.infeasible_paths()[0];
        assert!(conflict.applied);
        let cross = conflict.cross_function.as_ref().expect("cross constraint");
        assert_eq!(
            cross.reset,
            OrderedReset::LoopIteration {
                header: BlockId::new("bb:0xc010")
            }
        );
        assert_eq!(cross.specific_iteration, Some(SpecificIteration::Number(1)));
        assert_eq!(first_facts.info().conflicts[0].iteration, Some(1));

        let (last, last_facts) = analyze("-1");
        assert!(
            last < baseline,
            "mixed last-iteration cross ordering must prune the loop: {last} < {baseline}"
        );
        assert_eq!(last_facts.info().conflicts[0].iteration, Some(-1));

        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="1">
        <conflict ordered="yes">
          <block address="0xc000"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            "mixed-specific-before.ffx",
        )
        .expect("parse mixed specific outside-before conflict");
        facts
            .apply_document(document, &program)
            .expect("apply mixed specific outside-before conflict");
        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let before = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("finite caller cycles");
        assert!(
            before < baseline,
            "outside-before cross progress must survive loop entry: {before} < {baseline}"
        );
    }

    #[test]
    fn all_iteration_mixed_loop_cross_function_conflict_uses_the_iteration_scope() {
        let program = loop_cross_partition_program();
        let baseline = analyze_baseline_for(&program, 0xc000);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="*">
        <conflict ordered="yes">
          <call name="helper">
            <block address="0x9000"/>
          </call>
          <block address="0xc01c"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            "all-mixed-cross.ffx",
        )
        .expect("all-iteration mixed cross conflict");
        facts
            .apply_document(document, &program)
            .expect("apply all-iteration mixed cross conflict");
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        let cross = conflict.cross_function.as_ref().expect("cross constraint");
        assert_eq!(
            cross.reset,
            OrderedReset::LoopIteration {
                header: BlockId::new("bb:0xc010")
            }
        );
        assert_eq!(cross.specific_iteration, None);
        assert_eq!(facts.info().conflicts[0].iteration, None);
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0xc010"
        ));

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let constrained = analyzed
            .functions
            .iter()
            .find(|function| function.address == 0xc000)
            .and_then(|function| function.wcet.as_ref())
            .and_then(|wcet| wcet.cycles)
            .expect("finite caller cycles");
        assert!(
            constrained < baseline,
            "all-iteration mixed cross ordering must prune the loop: \
             {constrained} < {baseline}"
        );
    }

    #[test]
    fn recovered_calls_stay_partial_with_exact_partitioning() {
        let mut program = partition_diamond_program();
        program.functions[0]
            .cfg
            .recovered_calls
            .push(recovered_call_site(0x5fff));
        let facts = facts();
        let baseline = simple_partition_objective(&program, &facts);

        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let wcet = analyzed.functions[0].wcet.as_ref().expect("function WCET");
        assert_eq!(wcet.status, CfgWcetStatus::Partial);
        assert_eq!(wcet.unresolved_calls, 1);
        let solution = wcet.ipet.clone().expect("partitioned IPET solution");
        let partitioning = solution
            .partitioning
            .as_ref()
            .expect("exact partitioning despite recovered call");
        assert_eq!(partitioning.model, "sese-branch-regions");
        assert_eq!(solution.objective, baseline);
        assert!(
            partitioning
                .caveats
                .iter()
                .any(|caveat| caveat.contains("recovered call site"))
        );
    }

    #[test]
    fn recovered_calls_stay_partial_with_state_partitioning() {
        let board = cache_board(
            r"
[instruction_cache]
size = 64
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
",
        );
        let mut program = cache_partition_diamond_program();
        prepare_cache_program(&mut program, &board);
        program.functions[0]
            .cfg
            .recovered_calls
            .push(recovered_call_site(0x1fff));

        let monolithic = state_partition_solution(&program, &board, false);
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &facts);
        let wcet = analyzed.functions[0].wcet.as_ref().expect("function WCET");
        assert_eq!(wcet.status, CfgWcetStatus::Partial);
        assert_eq!(wcet.unresolved_calls, 1);
        let solution = wcet.ipet.clone().expect("partitioned IPET solution");
        let partitioning = solution
            .partitioning
            .as_ref()
            .expect("state partitioning despite recovered call");
        assert_eq!(partitioning.model, "sese-state-product-regions");
        assert!(
            solution.objective + 1e-6 >= monolithic.objective,
            "state partition {} must not undercut monolithic {}",
            solution.objective,
            monolithic.objective
        );
        assert!(
            partitioning
                .caveats
                .iter()
                .any(|caveat| caveat.contains("recovered call site"))
        );
    }

    #[test]
    fn call_site_sensitive_partition_uses_per_site_loop_bounds() {
        let mut root_function = function(
            0x1000,
            FunctionCfg::build(
                vec![
                    call_block(0x1000, 1.0, 0x4000),
                    call_block(0x1002, 1.0, 0x4000),
                    block(0x1004, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x1000, 0x1002, CfgEdgeKind::CallReturn),
                    edge(0x1002, 0x1004, CfgEdgeKind::CallReturn),
                ],
                Some(0x1000),
            ),
        );
        root_function.primary_name = "caller".to_owned();
        root_function.demangled_name = None;
        let mut helper_function = function(
            0x4000,
            FunctionCfg::build(
                vec![
                    block(0x4000, CfgTerminator::Branch, 1.0),
                    block(0x4002, CfgTerminator::Jump, 10.0),
                    block(0x4004, CfgTerminator::Return, 1.0),
                ],
                vec![
                    edge(0x4000, 0x4002, CfgEdgeKind::Branch),
                    edge(0x4000, 0x4004, CfgEdgeKind::Fallthrough),
                    edge(0x4002, 0x4000, CfgEdgeKind::Jump),
                ],
                Some(0x4000),
            ),
        );
        helper_function.primary_name = "helper".to_owned();
        helper_function.demangled_name = None;

        let program = ProgramCfg::new(vec![root_function, helper_function]);
        let mut facts = facts();
        let document = FlowFactDocument::parse_text(
            r#"
<flowfacts>
  <function name="caller">
    <call name="helper" address="0x1000">
      <loop address="0x4000" maxcount="2"/>
    </call>
    <call name="helper" address="0x1002">
      <loop address="0x4000" maxcount="5"/>
    </call>
  </function>
</flowfacts>
"#,
            "call-site.ffx",
        )
        .expect("call-site flow facts");
        facts
            .apply_document(document, &program)
            .expect("apply call-site facts");
        assert!(facts.has_call_site_contexts());

        let mut program = program;
        let _ = analyze_program(&mut program, &facts);
        let root_wcet = program
            .functions
            .iter()
            .find(|function| function.address == 0x1000)
            .and_then(|function| function.wcet.as_ref())
            .expect("caller WCET");
        let helper_wcet = program
            .functions
            .iter()
            .find(|function| function.address == 0x4000)
            .and_then(|function| function.wcet.as_ref())
            .expect("callee WCET");
        assert_eq!(root_wcet.cycles, Some(62.0));
        assert_eq!(helper_wcet.cycles, Some(46.0));
        let partitioning = helper_wcet
            .ipet
            .as_ref()
            .and_then(|ipet| ipet.partitioning.as_ref())
            .expect("call-site-sensitive callee partition");
        assert_eq!(partitioning.model, "sese-branch-regions");
        assert!(
            partitioning
                .caveats
                .iter()
                .any(|caveat| caveat.contains("call-site-sensitive"))
        );
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
        assert!(!conflict.presence);
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
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::PresenceAutomaton {
                iteration: None,
                ref header,
            } if header.as_str() == "bb:0x2002"
        ));
        let mut analyzed = program.clone();
        let _ = analyze_program(&mut analyzed, &exit_facts);
        let cycles = analyzed.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.cycles)
            .expect("finite cycles");
        assert!(
            cycles < baseline,
            "a loop-exit edge participates in all-iteration presence: {cycles} < {baseline}"
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
            &[],
        )
        .expect("cross model");
        let automata =
            super::cross_automaton_models(&model, &caller.cfg, &cross).expect("automata");
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
        assert_eq!(state.slot, automaton.groups[0].start);
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
                .is_some_and(|reason| reason.contains("repeats call site"))
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
    fn ras_state_product_models_return_after_entry_eviction() {
        let board = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:ipet-ras-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[return_address_stack]
entries = 1
miss_penalty = 2
max_states = 16

[wcet]
default_loop_bound = 4
auto_loop_bounds = false
"#,
        )
        .expect("valid RAS profile");
        let ras_profile = board.return_address_stack().expect("RAS profile");
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        let cfg = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Fallthrough, 1.0),
                block(0x1002, CfgTerminator::Call, 1.0),
                block(0x1004, CfgTerminator::Return, 1.0),
            ],
            vec![
                edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                edge(0x1002, 0x1004, CfgEdgeKind::CallReturn),
            ],
            Some(0x1000),
        );
        let mut program = ProgramCfg::new(vec![function(0x1000, cfg)]);
        let info = crate::ras::analyze_program(&mut program, ras_profile);
        program.ras = Some(info);
        let _ = analyze_program(&mut program, &facts);
        let ipet = program.functions[0]
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .expect("RAS IPET");
        assert_eq!(ipet.ras_model.as_deref(), Some("state-product"));
        assert!(ipet.objective > 0.0);
        let return_block =
            &program.functions[0].cfg.graph[program.functions[0].cfg.blocks_by_address[&0x1004]];
        let ras = return_block.ras.as_ref().expect("RAS metadata");
        assert_eq!(ras.misses_max, 1);
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
    fn cross_function_unordered_group_must_match_one_invocation() {
        let program = two_call_branching_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <block address="0x1000"/>
      <call name="helper" address="0x1002">
        <block address="0x2004"/>
        <block address="0x2006"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert_eq!(
            constrained, baseline,
            "callee elements in alternative branches cannot complete one invocation"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossUnorderedPresence
        ));
    }

    #[test]
    fn cross_function_unordered_multiple_groups_require_all_calls() {
        let program = multi_group_cross_program();
        let baseline = analyze_baseline(&program);
        let (constrained, facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <call name="helper" address="0xa012">
        <block address="0xb002"/>
      </call>
      <call name="helper" address="0xa016">
        <block address="0xb002"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert!(
            constrained < baseline,
            "both call groups together must be infeasible: {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossUnorderedPresence
        ));
        assert_eq!(
            conflict
                .cross_function
                .as_ref()
                .map(|cross| cross.groups.len()),
            Some(2)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn loop_scoped_cross_function_unordered_presence_prunes_body() {
        let program = loop_cross_partition_program();
        let baseline = analyze_baseline_for(&program, 0xc000);
        let (constrained, facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <conflict>
        <block address="0xc010"/>
        <call name="helper">
          <block address="0x9000"/>
        </call>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#,
            0xc000,
        );
        assert!(
            constrained < baseline,
            "loop-scoped caller and call presence must prune the body: \
             {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossUnorderedPresence
        ));
        assert!(matches!(
            conflict.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0xc010"
        ));
        assert_eq!(facts.info().conflicts[0].scope.as_deref(), Some("loop"));

        let (outside, outside_facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <conflict>
        <block address="0xc016"/>
        <call name="helper">
          <block address="0x9000"/>
        </call>
      </conflict>
    </loop>
  </function>
</flowfacts>
"#,
            0xc000,
        );
        assert_eq!(outside, baseline);
        assert!(!outside_facts.infeasible_paths()[0].applied);
        assert!(
            outside_facts.infeasible_paths()[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("outside the selected loop"))
        );

        let analyze_iteration = |number: &str| -> (f64, FlowFacts) {
            analyze_with_for(
                &program,
                &format!(
                    r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="{number}">
        <conflict>
          <block address="0xc010"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#
                ),
                0xc000,
            )
        };

        let (first, first_facts) = analyze_iteration("1");
        assert!(
            first < baseline,
            "iteration 1 cross-function presence must prune the body: \
             {first} < {baseline}"
        );
        assert!(matches!(
            first_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::CrossUnorderedPresence
        ));
        assert_eq!(first_facts.info().conflicts[0].iteration, Some(1));

        let (second, second_facts) = analyze_iteration("2");
        assert!(
            second < baseline && second > first,
            "iteration 2 only forbids the second body: {second} < {baseline}"
        );
        assert_eq!(second_facts.info().conflicts[0].iteration, Some(2));

        let (last, last_facts) = analyze_iteration("-1");
        assert!(
            last < baseline,
            "last-iteration cross-function presence must prune the body: \
             {last} < {baseline}"
        );
        assert_eq!(last_facts.info().conflicts[0].iteration, Some(-1));

        let (above_bound, _) = analyze_iteration("5");
        assert_eq!(
            above_bound, baseline,
            "a cross-function iteration above the loop bound is vacuous"
        );

        let (all_iterations, all_facts) = analyze_iteration("*");
        assert!(
            all_iterations < baseline,
            "all-iteration cross-function presence must prune the body: \
             {all_iterations} < {baseline}"
        );
        assert!(all_facts.infeasible_paths()[0].applied);
        assert!(matches!(
            all_facts.infeasible_paths()[0].enforcement,
            InfeasibleEnforcement::CrossUnorderedPresence
        ));
        assert_eq!(all_facts.info().conflicts[0].iteration, None);

        let (mixed_all, mixed_all_facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="*">
        <conflict>
          <block address="0xc016"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            0xc000,
        );
        assert!(
            mixed_all < baseline,
            "all-iteration mixed presence must include outside blocks: \
             {mixed_all} < {baseline}"
        );
        assert!(mixed_all_facts.infeasible_paths()[0].applied);
        assert_eq!(mixed_all_facts.info().conflicts[0].iteration, None);

        let (mixed_iteration, mixed_facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="1">
        <conflict>
          <block address="0xc016"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            0xc000,
        );
        assert!(
            mixed_iteration < baseline,
            "outside caller presence must combine with selected-iteration groups: \
             {mixed_iteration} < {baseline}"
        );
        let mixed = &mixed_facts.infeasible_paths()[0];
        assert!(mixed.applied);
        assert!(matches!(
            mixed.enforcement,
            InfeasibleEnforcement::CrossUnorderedPresence
        ));
        assert!(matches!(
            mixed.scope,
            Some(InfeasibleScope::Loop { ref header }) if header.as_str() == "bb:0xc010"
        ));
        assert_eq!(mixed_facts.info().conflicts[0].iteration, Some(1));

        let (mixed_last, mixed_last_facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0xc010">
      <iteration number="-1">
        <conflict>
          <block address="0xc016"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            0xc000,
        );
        assert!(
            mixed_last < baseline,
            "last-iteration mixed presence must include outside blocks: \
             {mixed_last} < {baseline}"
        );
        assert_eq!(mixed_last_facts.info().conflicts[0].iteration, Some(-1));
    }

    #[test]
    fn mixed_specific_cross_unordered_tracks_outside_call_groups() {
        let program = mixed_specific_cross_program();
        let baseline = analyze_baseline_for(&program, 0x7600);
        let (constrained, facts) = analyze_with_for(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x7602">
      <iteration number="1">
        <conflict>
          <block address="0x7604"/>
          <call name="helper">
            <block address="0x9000"/>
          </call>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            0x7600,
        );
        assert!(
            constrained < baseline,
            "an outside call group must complete the selected-iteration conflict: \
             {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossUnorderedPresence
        ));
        assert_eq!(facts.info().conflicts[0].iteration, Some(1));
    }

    #[test]
    fn cross_function_unordered_presence_prunes_caller_paths() {
        let program = branch_caller_program();
        let baseline = analyze_baseline(&program);
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
        assert!(
            constrained < baseline,
            "caller presence and a matching callee group must be exclusive: \
             {constrained} < {baseline}"
        );
        let conflict = &facts.infeasible_paths()[0];
        assert!(conflict.applied);
        assert!(matches!(
            conflict.enforcement,
            InfeasibleEnforcement::CrossUnorderedPresence
        ));
        assert_eq!(conflict.scope, Some(InfeasibleScope::CrossFunction));
        assert_eq!(
            facts.info().conflicts[0].scope.as_deref(),
            Some("cross-function")
        );
        assert_eq!(facts.info().conflicts[0].mode.as_deref(), Some("automaton"));
        assert_eq!(facts.info().conflicts[0].iteration, None);

        let (after_call, after_facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <block address="0x1008"/>
      <call name="helper">
        <block address="0x2002"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert!(
            after_call < baseline,
            "the call continuation must join the caller presence set: \
             {after_call} < {baseline}"
        );
        assert!(after_facts.infeasible_paths()[0].applied);

        let (entry, entry_facts) = analyze_with(
            &program,
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <block address="0x1004"/>
      <call name="helper">
        <block address="0x2000"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
        );
        assert!(
            entry < baseline,
            "a callee entry block must count as group presence: {entry} < {baseline}"
        );
        assert!(entry_facts.infeasible_paths()[0].applied);
    }
}
