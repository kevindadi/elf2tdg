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

use std::collections::{BTreeMap, BTreeSet};

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
use crate::flow_facts::{BranchOutcome, FactScope, FlowFacts};
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
