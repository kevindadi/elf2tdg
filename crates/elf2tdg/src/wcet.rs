//! CFG-based worst-case execution-time analysis.
//!
//! The analysis computes a longest path through each function CFG using block
//! cycle upper bounds. Natural loops are bounded from flow facts (board profile
//! or imported F4/FFX); a loop without a configured bound makes the containing
//! function unbounded.
//! Interprocedural call costs are computed bottom-up over call-graph SCCs.
//! Recursive SCCs are reported as unbounded.

use std::collections::{BTreeMap, BTreeSet};

use petgraph::algo::tarjan_scc;
use petgraph::graph::DiGraph;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};

use elf2tdg_schema::{BlockId, FunctionId};

use crate::board_profile::WcetProfile;
use crate::cfg::{
    CfgCallSite, CfgFunction, CfgFunctionWcet, CfgRoot, CfgWcetInfo, CfgWcetRoot, CfgWcetStatus,
    FunctionCfg, ProgramCfg,
};
use crate::cfg_graph::CfgGraphAnalysis;
use crate::flow_facts::FlowFacts;

const MODEL_NAME: &str = "cfg-longest-path";

/// Convenience wrapper used by the unit tests.
#[cfg(test)]
#[must_use]
pub(crate) fn analyze_program(program: &mut ProgramCfg, profile: &WcetProfile) -> CfgWcetInfo {
    let facts = FlowFacts::from_wcet_profile(profile);
    analyze_program_with_facts(program, profile, &facts)
}

/// Runs WCET analysis over the program with explicit flow facts.
#[must_use]
#[allow(clippy::too_many_lines)]
pub(crate) fn analyze_program_with_facts(
    program: &mut ProgramCfg,
    profile: &WcetProfile,
    facts: &FlowFacts,
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
    let mut summaries: Vec<Option<CfgFunctionWcet>> = vec![None; program.functions.len()];
    for component in components {
        let recursive = component.len() > 1
            || component
                .first()
                .is_some_and(|node| call_graph.find_edge(*node, *node).is_some());
        if recursive {
            for node in component {
                let index = call_graph[node];
                summaries[index] = Some(unbounded_summary("recursive-call-cycle", 0, 0));
            }
            continue;
        }
        let Some(&node) = component.first() else {
            continue;
        };
        let index = call_graph[node];
        summaries[index] = Some(analyze_function(
            &program.functions[index],
            &index_by_id,
            &summaries,
            facts,
            profile.max_states(),
            frequency_hz,
        ));
    }

    let roots = root_results(&program.roots, &index_by_id, &summaries);
    let mut info = CfgWcetInfo {
        model: MODEL_NAME.to_owned(),
        default_loop_bound: facts.default_loop_bound(),
        max_states: profile.max_states(),
        frequency_hz,
        solver: None,
        flow_facts: Some(facts.info()),
        functions_analyzed: 0,
        functions_partial: 0,
        functions_unbounded: 0,
        functions_unknown: 0,
        roots,
        caveats: vec![
            "WCET is a CFG longest-path estimate over modeled block upper bounds, not a hardware proof."
                .to_owned(),
            "Loops require a bound from the board profile, an imported F4/FFX file or a recognized counted-loop pattern; unresolved loops make the containing function unbounded. Automatic inference accepts only canonical counted loops with a constant initializer, one constant self-update, one conditional exit and no calls on the relevant paths."
                .to_owned(),
            "Recursive call-graph SCCs are reported as unbounded."
                .to_owned(),
            "Unresolved calls, calls to functions without local code, unresolved control flow or missing block timing produce partial results."
                .to_owned(),
            "Loop bounds are not path-sensitive; inner-loop counters reset on outer backedges, but loops re-entered without an outer backedge share one visit budget."
                .to_owned(),
            "Cache, branch-prediction and data-memory results are local and not context-sensitive across call paths."
                .to_owned(),
            "Interrupts, DMA, bus contention, multi-core interference and concurrency are not modeled."
                .to_owned(),
        ],
    };
    if facts.has_non_loop_facts() {
        info.caveats.push(
            "Branch and call flow facts are enforced only by the IPET backend; longest-path ignores them and remains a conservative overestimate."
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

pub(crate) fn frequency_hz(program: &ProgramCfg) -> Option<u64> {
    let timing = program.timing.as_ref()?;
    let domain = timing.default_frequency_domain.as_ref()?;
    timing.frequency_domain(domain).map(|domain| domain.hz)
}

pub(crate) fn function_call_targets(cfg: &FunctionCfg) -> BTreeSet<FunctionId> {
    let analysis = crate::cfg_graph::analyze(cfg);
    let reachable: BTreeSet<BlockId> = analysis.reachable.into_iter().collect();
    let mut targets = BTreeSet::new();
    for node in cfg.blocks_by_address.values() {
        let block = &cfg.graph[*node];
        if !reachable.contains(&block.id) {
            continue;
        }
        for call in &block.calls {
            collect_call_targets(call, &mut targets);
        }
    }
    targets
}

fn collect_call_targets(call: &CfgCallSite, targets: &mut BTreeSet<FunctionId>) {
    if call.null_target {
        return;
    }
    if let Some(target) = &call.target_function {
        targets.insert(target.clone());
    }
    for candidate in &call.candidates {
        if let Some(target) = &candidate.target_function {
            targets.insert(target.clone());
        }
    }
}

fn analyze_function(
    function: &CfgFunction,
    index_by_id: &BTreeMap<FunctionId, usize>,
    summaries: &[Option<CfgFunctionWcet>],
    facts: &FlowFacts,
    max_states: usize,
    frequency_hz: Option<u64>,
) -> CfgFunctionWcet {
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
    let mut partial = analysis.blocked_by_unresolved;
    if reachable_nodes
        .iter()
        .any(|node| function.cfg.graph[*node].cycles.is_none())
    {
        partial = true;
    }
    let loops = match build_loop_context(&function.cfg, &analysis, facts) {
        Ok(context) => context,
        Err(reason) => return unbounded_summary(&reason, 0, 0),
    };
    let call_info = match build_call_info(&function.cfg, &reachable_nodes, index_by_id, summaries) {
        Ok(info) => info,
        Err(reason) => return unbounded_summary(&reason, 0, 0),
    };
    partial |= call_info.partial || loops.nonterminating_bounded;
    let partial_reason = if loops.nonterminating_bounded {
        "non-terminating-loop-bounded"
    } else {
        "incomplete-call-or-control-flow-model"
    };
    let path = match longest_path(
        &function.cfg,
        entry,
        &loops,
        &call_info.block_cycles,
        max_states,
    ) {
        Ok(path) => path,
        Err(WcetPathError::StateLimit) => {
            return unknown_summary(
                "state-limit",
                call_info.unresolved_calls,
                call_info.external_calls,
            );
        }
        Err(WcetPathError::UnsupportedCycle) => {
            return unbounded_summary(
                "unsupported-cycle",
                call_info.unresolved_calls,
                call_info.external_calls,
            );
        }
    };
    let time_ns = path.cycles_time_ns(frequency_hz);
    CfgFunctionWcet {
        status: if partial {
            CfgWcetStatus::Partial
        } else {
            CfgWcetStatus::Bounded
        },
        cycles: Some(path.cycles),
        time_ns,
        path: path.path,
        reason: partial.then(|| partial_reason.to_owned()),
        unresolved_calls: call_info.unresolved_calls,
        external_calls: call_info.external_calls,
        ipet: None,
    }
}

#[allow(clippy::cast_precision_loss)]
pub(crate) fn time_ns(cycles: f64, frequency_hz: Option<u64>) -> Option<f64> {
    frequency_hz
        .filter(|hz| *hz > 0)
        .map(|hz| cycles * 1_000_000_000.0 / hz as f64)
}

#[derive(Clone)]
struct PathCost {
    cycles: f64,
    path: Vec<BlockId>,
}

impl PathCost {
    fn cycles_time_ns(&self, frequency_hz: Option<u64>) -> Option<f64> {
        time_ns(self.cycles, frequency_hz)
    }
}

struct LoopContext {
    bounds: Vec<u32>,
    backedges: BTreeMap<(NodeIndex, NodeIndex), Vec<usize>>,
    reset_on_backedge: Vec<Vec<usize>>,
    nonterminating_bounded: bool,
}

fn build_loop_context(
    cfg: &FunctionCfg,
    analysis: &CfgGraphAnalysis,
    facts: &FlowFacts,
) -> Result<LoopContext, String> {
    let node_by_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let mut bounds = Vec::new();
    let mut backedges: BTreeMap<(NodeIndex, NodeIndex), Vec<usize>> = BTreeMap::new();
    let mut loop_blocks = BTreeSet::new();
    let mut loop_block_sets = Vec::new();
    let mut headers = Vec::new();
    let mut nonterminating_bounded = false;
    for loop_ in &analysis.loops {
        let Some(&header_node) = node_by_id.get(&loop_.header) else {
            return Err("loop-header-missing".to_owned());
        };
        let header_address = cfg.graph[header_node].address;
        let bound = facts
            .bound_for(header_address)
            .ok_or_else(|| format!("loop-unbounded:0x{header_address:x}"))?;
        let loop_set: BTreeSet<BlockId> = loop_.blocks.iter().cloned().collect();
        let has_exit = cfg.graph.edge_references().any(|edge| {
            loop_set.contains(&cfg.graph[edge.source()].id)
                && !loop_set.contains(&cfg.graph[edge.target()].id)
        });
        if !has_exit {
            if !facts.bound_nonterminating_loops() {
                return Err(format!("non-terminating-loop:0x{header_address:x}"));
            }
            nonterminating_bounded = true;
        }
        let index = bounds.len();
        bounds.push(bound);
        loop_blocks.extend(loop_.blocks.iter().cloned());
        loop_block_sets.push(loop_set);
        headers.push(loop_.header.clone());
        for backedge in &loop_.backedges {
            let Some(&from) = node_by_id.get(&backedge.from) else {
                return Err("loop-latch-missing".to_owned());
            };
            let Some(&to) = node_by_id.get(&backedge.to) else {
                return Err("loop-header-missing".to_owned());
            };
            backedges.entry((from, to)).or_default().push(index);
        }
    }
    for scc in &analysis.sccs {
        if scc.cyclic && !scc.blocks.iter().all(|block| loop_blocks.contains(block)) {
            return Err("unsupported-cycle".to_owned());
        }
    }
    let mut reset_on_backedge = vec![Vec::new(); bounds.len()];
    for outer in 0..bounds.len() {
        for (inner, header) in headers.iter().enumerate() {
            if outer != inner && loop_block_sets[outer].contains(header) {
                reset_on_backedge[outer].push(inner);
            }
        }
    }
    Ok(LoopContext {
        bounds,
        backedges,
        reset_on_backedge,
        nonterminating_bounded,
    })
}

#[derive(Clone, Copy)]
enum WcetPathError {
    StateLimit,
    UnsupportedCycle,
}

struct PathContext<'a> {
    cfg: &'a FunctionCfg,
    loops: &'a LoopContext,
    block_cycles: &'a BTreeMap<NodeIndex, f64>,
    max_states: usize,
    memo: BTreeMap<(NodeIndex, Vec<u32>), PathCost>,
    visiting: BTreeSet<(NodeIndex, Vec<u32>)>,
}

fn longest_path(
    cfg: &FunctionCfg,
    entry: NodeIndex,
    loops: &LoopContext,
    block_cycles: &BTreeMap<NodeIndex, f64>,
    max_states: usize,
) -> Result<PathCost, WcetPathError> {
    let mut context = PathContext {
        cfg,
        loops,
        block_cycles,
        max_states,
        memo: BTreeMap::new(),
        visiting: BTreeSet::new(),
    };
    let counts = vec![0; loops.bounds.len()];
    context.longest(entry, &counts)
}

impl PathContext<'_> {
    fn longest(&mut self, node: NodeIndex, counts: &[u32]) -> Result<PathCost, WcetPathError> {
        let key = (node, counts.to_vec());
        if let Some(cached) = self.memo.get(&key) {
            return Ok(cached.clone());
        }
        if !self.visiting.insert(key.clone()) {
            return Err(WcetPathError::UnsupportedCycle);
        }
        if self.memo.len() >= self.max_states {
            self.visiting.remove(&key);
            return Err(WcetPathError::StateLimit);
        }
        let block = &self.cfg.graph[node];
        let mut block_cost = block.cycles.map_or(0.0, |cycles| cycles.max);
        block_cost += self.block_cycles.get(&node).copied().unwrap_or(0.0);
        let mut edges: Vec<(NodeIndex, crate::cfg::CfgEdge)> = self
            .cfg
            .graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .map(|edge| (edge.target(), edge.weight().clone()))
            .collect();
        edges.sort_by_key(|(target, _)| (self.cfg.graph[*target].address, target.index()));
        let mut best: Option<PathCost> = None;
        for (target, _) in edges {
            let mut next_counts = counts.to_vec();
            let mut allowed = true;
            if let Some(loop_indices) = self.loops.backedges.get(&(node, target)) {
                for loop_index in loop_indices {
                    let next = next_counts[*loop_index].saturating_add(1);
                    if next >= self.loops.bounds[*loop_index] {
                        allowed = false;
                        break;
                    }
                    next_counts[*loop_index] = next;
                    for inner in &self.loops.reset_on_backedge[*loop_index] {
                        next_counts[*inner] = 0;
                    }
                }
            }
            if !allowed {
                continue;
            }
            let child = self.longest(target, &next_counts)?;
            let candidate = PathCost {
                cycles: block_cost + child.cycles,
                path: std::iter::once(block.id.clone())
                    .chain(child.path)
                    .collect(),
            };
            if best
                .as_ref()
                .is_none_or(|current| candidate.cycles > current.cycles)
            {
                best = Some(candidate);
            }
        }
        let result = best.unwrap_or_else(|| PathCost {
            cycles: block_cost,
            path: vec![block.id.clone()],
        });
        self.visiting.remove(&key);
        self.memo.insert(key, result.clone());
        Ok(result)
    }
}

pub(crate) struct CallInfo {
    pub(crate) block_cycles: BTreeMap<NodeIndex, f64>,
    pub(crate) partial: bool,
    pub(crate) unresolved_calls: u32,
    pub(crate) external_calls: u32,
}

pub(crate) fn build_call_info(
    cfg: &FunctionCfg,
    reachable_nodes: &BTreeSet<NodeIndex>,
    index_by_id: &BTreeMap<FunctionId, usize>,
    summaries: &[Option<CfgFunctionWcet>],
) -> Result<CallInfo, String> {
    let mut block_cycles = BTreeMap::new();
    let mut partial = !cfg.recovered_calls.is_empty();
    let mut unresolved_calls = u32::try_from(cfg.recovered_calls.len()).unwrap_or(u32::MAX);
    let mut external_calls = 0_u32;
    for node in reachable_nodes {
        let block = &cfg.graph[*node];
        let mut block_total = 0.0_f64;
        for call in &block.calls {
            if call.null_target {
                continue;
            }
            let mut targets = BTreeSet::new();
            collect_call_targets(call, &mut targets);
            let mut local_count = 0_usize;
            let mut missing = false;
            let mut call_total = 0.0_f64;
            for target in targets {
                let Some(&callee_index) = index_by_id.get(&target) else {
                    missing = true;
                    continue;
                };
                local_count += 1;
                let Some(Some(summary)) = summaries.get(callee_index) else {
                    missing = true;
                    continue;
                };
                match summary.status {
                    CfgWcetStatus::Unbounded => {
                        return Err("callee-unbounded".to_owned());
                    }
                    CfgWcetStatus::Unknown => {
                        missing = true;
                    }
                    CfgWcetStatus::Bounded | CfgWcetStatus::Partial => {
                        if summary.status == CfgWcetStatus::Partial {
                            partial = true;
                        }
                        if let Some(cycles) = summary.cycles {
                            call_total = call_total.max(cycles);
                        }
                    }
                }
            }
            if local_count == 0 {
                if call.unresolved {
                    unresolved_calls = unresolved_calls.saturating_add(1);
                    partial = true;
                } else {
                    external_calls = external_calls.saturating_add(1);
                    partial = true;
                }
            } else if missing {
                external_calls = external_calls.saturating_add(1);
                partial = true;
            }
            if call.unresolved || call.heuristic {
                partial = true;
            }
            block_total += call_total;
        }
        if block_total > 0.0 {
            block_cycles.insert(*node, block_total);
        }
    }
    Ok(CallInfo {
        block_cycles,
        partial,
        unresolved_calls,
        external_calls,
    })
}

pub(crate) fn unbounded_summary(
    reason: &str,
    unresolved_calls: u32,
    external_calls: u32,
) -> CfgFunctionWcet {
    CfgFunctionWcet {
        status: CfgWcetStatus::Unbounded,
        cycles: None,
        time_ns: None,
        path: Vec::new(),
        reason: Some(reason.to_owned()),
        unresolved_calls,
        external_calls,
        ipet: None,
    }
}

pub(crate) fn unknown_summary(
    reason: &str,
    unresolved_calls: u32,
    external_calls: u32,
) -> CfgFunctionWcet {
    CfgFunctionWcet {
        status: CfgWcetStatus::Unknown,
        cycles: None,
        time_ns: None,
        path: Vec::new(),
        reason: Some(reason.to_owned()),
        unresolved_calls,
        external_calls,
        ipet: None,
    }
}

pub(crate) fn root_results(
    roots: &[CfgRoot],
    index_by_id: &BTreeMap<FunctionId, usize>,
    summaries: &[Option<CfgFunctionWcet>],
) -> Vec<CfgWcetRoot> {
    roots
        .iter()
        .map(|root| {
            let summary = index_by_id
                .get(&root.function)
                .and_then(|index| summaries.get(*index))
                .and_then(Option::as_ref);
            match summary {
                Some(summary) => CfgWcetRoot {
                    function: root.function.clone(),
                    kind: root.kind,
                    name: root.name.clone(),
                    status: summary.status,
                    cycles: summary.cycles,
                    time_ns: summary.time_ns,
                    path: summary.path.clone(),
                },
                None => CfgWcetRoot {
                    function: root.function.clone(),
                    kind: root.kind,
                    name: root.name.clone(),
                    status: CfgWcetStatus::Unknown,
                    cycles: None,
                    time_ns: None,
                    path: Vec::new(),
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::analyze_program;
    use crate::board_profile::{BoardProfile, WcetProfile};
    use crate::cfg::{
        CfgBlockDraft, CfgCallSite, CfgEdgeDraft, CfgEdgeKind, CfgFunction, CfgInstruction,
        CfgRoot, CfgRootKind, CfgTerminator, CfgWcetStatus, FunctionCfg, ProgramCfg,
    };
    use elf2tdg_schema::{Confidence, CostRange, FunctionId, FunctionKind, Language};

    fn wcet_profile(extra: &str) -> WcetProfile {
        let text = format!(
            r#"
schema_version = 2
id = "board:wcet-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[wcet]
max_states = 1000
{extra}
"#
        );
        BoardProfile::parse_toml(&text)
            .expect("valid WCET profile")
            .wcet()
            .expect("WCET profile")
            .clone()
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

    fn block(
        address: u64,
        terminator: CfgTerminator,
        cycles: f64,
        calls: Vec<CfgCallSite>,
    ) -> CfgBlockDraft {
        CfgBlockDraft {
            address,
            size: 2,
            instructions: vec![instruction(address, terminator, cycles)],
            calls,
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
            primary_name: format!("fn_0x{address:x}"),
            demangled_name: None,
            symbols: Vec::new(),
            language: Language::C,
            kind: FunctionKind::Normal,
            address,
            size: 0x20,
            section: ".text".to_owned(),
            source: None,
            inline_frames: Vec::new(),
            noreturn: None,
            cfg,
            wcet: None,
        }
    }

    fn root(function: &CfgFunction) -> CfgRoot {
        CfgRoot {
            function: function.id.clone(),
            kind: CfgRootKind::Startup,
            name: Some("reset".to_owned()),
            vector: None,
            irq: None,
            confidence: Confidence::High,
        }
    }

    fn call(target: &CfgFunction, site: u64) -> CfgCallSite {
        CfgCallSite {
            site,
            target: Some(target.address),
            target_function: Some(target.id.clone()),
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

    #[test]
    fn chooses_the_most_expensive_acyclic_path() {
        let cfg = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Branch, 1.0, Vec::new()),
                block(0x1002, CfgTerminator::Return, 10.0, Vec::new()),
                block(0x1004, CfgTerminator::Return, 5.0, Vec::new()),
            ],
            vec![
                edge(0x1000, 0x1002, CfgEdgeKind::Branch),
                edge(0x1000, 0x1004, CfgEdgeKind::Fallthrough),
            ],
            Some(0x1000),
        );
        let function = function(0x1000, cfg);
        let mut program = ProgramCfg::new(vec![function]);
        program.roots = vec![root(&program.functions[0])];
        let info = analyze_program(&mut program, &wcet_profile(""));
        assert_eq!(info.functions_analyzed, 1);
        let wcet = program.functions[0].wcet.as_ref().expect("function WCET");
        assert_eq!(wcet.status, CfgWcetStatus::Bounded);
        assert_eq!(wcet.cycles, Some(11.0));
        assert_eq!(info.roots.len(), 1);
        assert_eq!(info.roots[0].cycles, Some(11.0));
        assert_eq!(wcet.path.len(), 2);
    }

    #[test]
    fn applies_loop_bounds_and_reports_unbounded_without_one() {
        let cfg = FunctionCfg::build(
            vec![
                block(0x2000, CfgTerminator::Branch, 1.0, Vec::new()),
                block(0x2002, CfgTerminator::Return, 2.0, Vec::new()),
            ],
            vec![
                edge(0x2000, 0x2000, CfgEdgeKind::Branch),
                edge(0x2000, 0x2002, CfgEdgeKind::Fallthrough),
            ],
            Some(0x2000),
        );
        let mut bounded = ProgramCfg::new(vec![function(0x2000, cfg.clone())]);
        let info = analyze_program(&mut bounded, &wcet_profile("default_loop_bound = 3"));
        assert_eq!(info.functions_analyzed, 1);
        let wcet = bounded.functions[0].wcet.as_ref().expect("function WCET");
        assert_eq!(wcet.status, CfgWcetStatus::Bounded);
        assert_eq!(wcet.cycles, Some(5.0));
        assert_eq!(wcet.path.len(), 4);

        let mut unbounded = ProgramCfg::new(vec![function(0x2000, cfg)]);
        let info = analyze_program(&mut unbounded, &wcet_profile(""));
        assert_eq!(info.functions_unbounded, 1);
        let wcet = unbounded.functions[0].wcet.as_ref().expect("function WCET");
        assert_eq!(wcet.status, CfgWcetStatus::Unbounded);
        assert_eq!(wcet.reason.as_deref(), Some("loop-unbounded:0x2000"));
    }

    #[test]
    fn reports_non_terminating_loops_as_unbounded() {
        let cfg = FunctionCfg::build(
            vec![block(0x2400, CfgTerminator::Jump, 1.0, Vec::new())],
            vec![edge(0x2400, 0x2400, CfgEdgeKind::Jump)],
            Some(0x2400),
        );
        let mut program = ProgramCfg::new(vec![function(0x2400, cfg)]);
        let info = analyze_program(&mut program, &wcet_profile("default_loop_bound = 4"));
        assert_eq!(info.functions_unbounded, 1);
        let wcet = program.functions[0].wcet.as_ref().expect("WCET");
        assert_eq!(wcet.status, CfgWcetStatus::Unbounded);
        assert_eq!(wcet.reason.as_deref(), Some("non-terminating-loop:0x2400"));
    }

    #[test]
    fn can_explicitly_bound_a_nonterminating_loop() {
        let cfg = FunctionCfg::build(
            vec![block(0x2600, CfgTerminator::Jump, 1.0, Vec::new())],
            vec![edge(0x2600, 0x2600, CfgEdgeKind::Jump)],
            Some(0x2600),
        );
        let mut program = ProgramCfg::new(vec![function(0x2600, cfg)]);
        let info = analyze_program(
            &mut program,
            &wcet_profile("default_loop_bound = 4\nbound_nonterminating_loops = true"),
        );
        assert_eq!(info.functions_partial, 1);
        let wcet = program.functions[0].wcet.as_ref().expect("WCET");
        assert_eq!(wcet.status, CfgWcetStatus::Partial);
        assert_eq!(wcet.cycles, Some(4.0));
        assert_eq!(wcet.reason.as_deref(), Some("non-terminating-loop-bounded"));
    }

    #[test]
    fn adds_callee_wcet_to_call_blocks() {
        let leaf = function(
            0x3000,
            FunctionCfg::build(
                vec![block(0x3000, CfgTerminator::Return, 20.0, Vec::new())],
                Vec::new(),
                Some(0x3000),
            ),
        );
        let caller_fn = function(
            0x2800,
            FunctionCfg::build(
                vec![block(
                    0x2800,
                    CfgTerminator::Return,
                    1.0,
                    vec![call(&leaf, 0x2800), call(&leaf, 0x2801)],
                )],
                Vec::new(),
                Some(0x2800),
            ),
        );
        let mut program = ProgramCfg::new(vec![caller_fn, leaf]);
        let info = analyze_program(&mut program, &wcet_profile(""));
        assert_eq!(info.functions_analyzed, 2);
        let root = program
            .functions
            .iter()
            .find(|function| function.address == 0x2800)
            .and_then(|function| function.wcet.as_ref())
            .expect("caller WCET");
        assert_eq!(root.cycles, Some(41.0));
    }

    #[test]
    fn reports_recursive_calls_and_unresolved_calls() {
        let cfg = FunctionCfg::build(
            vec![block(
                0x4000,
                CfgTerminator::Return,
                1.0,
                vec![CfgCallSite {
                    site: 0x4000,
                    target: Some(0x4000),
                    target_function: Some(FunctionId::new("fn:0x4000")),
                    direct: true,
                    tail: false,
                    conditional: false,
                    heuristic: false,
                    unresolved: false,
                    null_target: false,
                    noreturn: false,
                    candidates: Vec::new(),
                }],
            )],
            Vec::new(),
            Some(0x4000),
        );
        let mut recursive = ProgramCfg::new(vec![function(0x4000, cfg)]);
        let info = analyze_program(&mut recursive, &wcet_profile(""));
        assert_eq!(info.functions_unbounded, 1);
        let wcet = recursive.functions[0].wcet.as_ref().expect("WCET");
        assert_eq!(wcet.status, CfgWcetStatus::Unbounded);
        assert_eq!(wcet.reason.as_deref(), Some("recursive-call-cycle"));

        let cfg = FunctionCfg::build(
            vec![block(
                0x5000,
                CfgTerminator::Return,
                1.0,
                vec![CfgCallSite {
                    site: 0x5000,
                    target: None,
                    target_function: None,
                    direct: false,
                    tail: false,
                    conditional: false,
                    heuristic: false,
                    unresolved: true,
                    null_target: false,
                    noreturn: false,
                    candidates: Vec::new(),
                }],
            )],
            Vec::new(),
            Some(0x5000),
        );
        let mut partial = ProgramCfg::new(vec![function(0x5000, cfg)]);
        let info = analyze_program(&mut partial, &wcet_profile(""));
        assert_eq!(info.functions_partial, 1);
        let wcet = partial.functions[0].wcet.as_ref().expect("WCET");
        assert_eq!(wcet.status, CfgWcetStatus::Partial);
        assert_eq!(wcet.cycles, Some(1.0));
        assert_eq!(wcet.unresolved_calls, 1);
    }
}
