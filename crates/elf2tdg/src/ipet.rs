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

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use good_lp::{
    Expression, ProblemVariables, Solution, SolutionStatus, SolverModel, Variable, constraint,
};
use petgraph::algo::tarjan_scc;
use petgraph::graph::DiGraph;
use petgraph::stable_graph::{EdgeIndex, NodeIndex};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};

use elf2tdg_schema::{BlockId, FunctionId};

use crate::cfg::{
    CfgFunction, CfgFunctionWcet, CfgIpetBlockCount, CfgIpetSolution, CfgWcetInfo, CfgWcetStatus,
    FunctionCfg, ProgramCfg,
};
use crate::flow_facts::{
    BranchOutcome, FactScope, FlowFacts, InfeasibleElement, InfeasibleEnforcement, InfeasibleScope,
    OrderedReset,
};
use crate::wcet::{
    CallContext, VersionSummaries, aggregate_context_summaries, build_call_info_with,
    callee_context, frequency_hz, function_call_targets, plan_contexts, root_results, time_ns,
    unbounded_summary, unknown_summary,
};

pub(crate) const MODEL_NAME: &str = "cfg-ipet";
const SOLVER_NAME: &str = "microlp";
const MAX_MODEL_VARIABLES: usize = 500_000;

/// Runs IPET over the program and attaches per-function results.
#[must_use]
#[allow(clippy::too_many_lines)]
pub(crate) fn analyze_program(program: &mut ProgramCfg, facts: &FlowFacts) -> CfgWcetInfo {
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
                    function,
                    |target| resolver.summary(target),
                    facts,
                    FactScope::Context(context),
                    frequency_hz,
                );
                versions.insert((function.id.clone(), context.clone()), summary.clone());
                context_summaries.push(summary);
            }
            if let Some(summary) = aggregate_context_summaries(&context_summaries) {
                aggregates.insert(function.id.clone(), summary);
            }
        } else {
            summaries[index] = Some(analyze_function(
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
            "Cache, branch-prediction and data-memory results are local and not path-sensitive."
                .to_owned(),
            "Interrupts, DMA, bus contention, multi-core interference and concurrency are not modeled."
                .to_owned(),
        ],
    };
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
            "Infeasible-path conflicts use aggregate constraints when their scope is unordered and structurally enforceable. Ordered conflicts use aggregate reduction when reachability forces the order, otherwise a product sequence-progress automaton for function, loop or per-iteration scope; cross-function, specific-iteration and duplicate-edge conflicts are skipped with warnings, and automaton state-cap overflow makes the function unknown."
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

fn analyze_function<'a, F>(
    function: &CfgFunction,
    summary_for: F,
    facts: &FlowFacts,
    scope: FactScope<'_>,
    frequency_hz: Option<u64>,
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
        &function.cfg,
        entry,
        &analysis,
        &reachable_nodes,
        &call_info.block_cycles,
        facts,
        &function.id,
        scope,
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

enum IpetError {
    Unbounded(String),
    Unknown(String),
}

struct IpetOutcome {
    solution: CfgIpetSolution,
    partial: bool,
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn solve_function(
    cfg: &FunctionCfg,
    entry: NodeIndex,
    analysis: &crate::cfg_graph::CfgGraphAnalysis,
    reachable_nodes: &BTreeSet<NodeIndex>,
    call_cycles: &BTreeMap<NodeIndex, f64>,
    facts: &FlowFacts,
    function_id: &FunctionId,
    scope: FactScope<'_>,
) -> Result<IpetOutcome, IpetError> {
    let loops = build_loops(cfg, entry, analysis, facts, scope)?;
    let automata = ordered_automata(facts, function_id, scope);
    if !automata.is_empty() {
        return solve_function_with_automata(
            cfg,
            entry,
            reachable_nodes,
            call_cycles,
            facts,
            function_id,
            scope,
            &loops,
            &automata,
        );
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

    let objective = objective(cfg, &block_vars, call_cycles);
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
    Ok(IpetOutcome {
        solution: CfgIpetSolution {
            solver: SOLVER_NAME.to_owned(),
            status: status.to_owned(),
            objective,
            blocks,
        },
        partial,
    })
}

fn objective(
    cfg: &FunctionCfg,
    block_vars: &BTreeMap<NodeIndex, Variable>,
    call_cycles: &BTreeMap<NodeIndex, f64>,
) -> Expression {
    let mut objective = Expression::from(0.0);
    for (node, var) in block_vars {
        let block = &cfg.graph[*node];
        let base = block.cycles.map_or(0.0, |cycles| cycles.max);
        let call = call_cycles.get(node).copied().unwrap_or(0.0);
        objective += *var * (base + call);
    }
    objective
}

struct LoopModel {
    header: NodeIndex,
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
        loops.push(LoopModel {
            header,
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
        let block = &cfg.graph[node.original];
        let base = block.cycles.map_or(0.0, |cycles| cycles.max);
        let call = call_cycles.get(&node.original).copied().unwrap_or(0.0);
        objective += node_variables[index] * (base + call);
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
            None => {}
        }
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
            blocks,
        },
        partial,
    })
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
    use super::analyze_program;
    use crate::board_profile::BoardProfile;
    use crate::cfg::{
        CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgFunction, CfgInstruction, CfgTerminator,
        FunctionCfg, ProgramCfg,
    };
    use crate::flow_facts::{
        FlowFactDocument, FlowFacts, InfeasibleEnforcement, InfeasibleScope, OrderedReset,
    };
    use elf2tdg_schema::{CostRange, FunctionId, FunctionKind, Language};

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
}
