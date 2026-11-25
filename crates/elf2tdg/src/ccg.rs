//! Cache conflict graph (CCG) construction and IPET flow constraints.
//!
//! For each cache set, the graph contains a node for every `(basic block,
//! cache line)` pair, plus a source and sink.  Edges connect consecutive
//! accesses to the set along the CFG, including accesses carried across blocks
//! that do not touch the set.  A unit of flow enters the source, visits the
//! access nodes and exits through the sink; loops let one entry produce the
//! block execution counts of the IPET solution.
//!
//! At a node, incoming flow from the same cache line is a guaranteed hit:
//! accesses to other sets cannot evict the line, and an immediate same-line
//! predecessor means the line was just loaded or hit.  Incoming flow from a
//! different line is conservatively treated as a miss, even when an
//! associative cache could still retain the line.  This makes the model a safe
//! over-approximation of misses while retaining the flow correlations that the
//! aggregate conflict bounds cannot express.
//!
//! The model is instruction-cache only.  It is not built for functions with
//! call-return edges or unresolved control flow, because those introduce cold
//! cache barriers or missing successors.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use good_lp::{Expression, ProblemVariables, Variable, constraint};
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};

use crate::cache_state::{CacheGeometry, instruction_accesses};
use crate::cfg::{CfgEdgeKind, FunctionCfg, ProgramCfg};

/// Local CCG source node.
const SOURCE: usize = 0;
/// Local CCG sink node.
const SINK: usize = 1;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CcgNode {
    block: NodeIndex,
    line: u64,
    accesses: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct CcgSet {
    nodes: Vec<CcgNode>,
    edges: Vec<(usize, usize)>,
}

#[derive(Clone, Debug)]
pub(crate) struct CcgModel {
    miss_penalty: u32,
    sets: Vec<CcgSet>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CcgApplication {
    pub(crate) variables: usize,
    pub(crate) constraints: usize,
    pub(crate) sets: usize,
    pub(crate) nodes: usize,
    pub(crate) edges: usize,
}

impl CcgModel {
    pub(crate) fn miss_penalty(&self) -> u32 {
        self.miss_penalty
    }

    pub(crate) fn variable_count(&self) -> usize {
        self.sets
            .iter()
            .map(|set| set.nodes.len().saturating_add(set.edges.len()))
            .fold(0, usize::saturating_add)
    }
}

/// Builds the instruction-cache CCG for one function, when the CFG has no
/// call-return barriers or unresolved control flow.
#[allow(clippy::too_many_lines)]
pub(crate) fn build(
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    reachable: &BTreeSet<NodeIndex>,
) -> Option<CcgModel> {
    let info = program.cache.as_ref()?;
    if !info.invalidate_on_call || info.sets == 0 || info.line_bytes == 0 {
        return None;
    }
    let graph = crate::cfg_graph::analyze(cfg);
    if graph.blocked_by_unresolved {
        return None;
    }
    let entry = cfg.entry?;
    if !reachable.contains(&entry) {
        return None;
    }
    if cfg.graph.edge_references().any(|edge| {
        edge.weight().kind == CfgEdgeKind::CallReturn
            && reachable.contains(&edge.source())
            && reachable.contains(&edge.target())
    }) {
        return None;
    }
    if !reachable
        .iter()
        .all(|node| cfg.graph[*node].cache.is_some())
    {
        return None;
    }
    let mut order: Vec<NodeIndex> = reachable.iter().copied().collect();
    order.sort_by_key(|node| (cfg.graph[*node].address, node.index()));
    let terminals: BTreeSet<NodeIndex> = order
        .iter()
        .copied()
        .filter(|node| {
            !cfg.graph
                .edges_directed(*node, petgraph::Direction::Outgoing)
                .any(|edge| reachable.contains(&edge.target()))
        })
        .collect();
    if terminals.is_empty() {
        return None;
    }
    let geometry = CacheGeometry {
        line_bytes: u64::from(info.line_bytes),
        sets: info.sets,
        ways: usize::try_from(info.ways).unwrap_or(usize::MAX),
    };
    let mut sequences: BTreeMap<NodeIndex, BTreeMap<u64, Vec<u64>>> = BTreeMap::new();
    let mut sets = BTreeSet::new();
    for node in &order {
        let mut by_set: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for access in instruction_accesses(&cfg.graph[*node], geometry) {
            let set = access.line % info.sets;
            by_set.entry(set).or_default().push(access.line);
            sets.insert(set);
        }
        if !by_set.is_empty() {
            sequences.insert(*node, by_set);
        }
    }
    let mut ccg_sets = Vec::new();
    for set in sets {
        let mut nodes = Vec::new();
        let mut node_by_block_line: BTreeMap<(NodeIndex, u64), usize> = BTreeMap::new();
        let mut first_by_block: BTreeMap<NodeIndex, usize> = BTreeMap::new();
        let mut last_by_block: BTreeMap<NodeIndex, usize> = BTreeMap::new();
        for node in &order {
            let Some(sequence) = sequences.get(node).and_then(|m| m.get(&set)) else {
                continue;
            };
            let mut seen = BTreeSet::new();
            for line in sequence {
                if seen.insert(*line) {
                    let id = nodes.len() + 2;
                    nodes.push(CcgNode {
                        block: *node,
                        line: geometry.line_address(*line),
                        accesses: 0,
                    });
                    node_by_block_line.insert((*node, *line), id);
                }
            }
            let mut counts: BTreeMap<u64, u32> = BTreeMap::new();
            for line in sequence {
                *counts.entry(*line).or_insert(0) += 1;
            }
            for (line, count) in counts {
                let id = node_by_block_line[&(*node, line)];
                nodes[id - 2].accesses = count;
            }
            let first = node_by_block_line[&(*node, sequence[0])];
            let last = node_by_block_line[&(*node, *sequence.last()?)];
            first_by_block.insert(*node, first);
            last_by_block.insert(*node, last);
        }
        if nodes.is_empty() {
            return None;
        }
        let mut edges: BTreeSet<(usize, usize)> = BTreeSet::new();
        for node in &order {
            let Some(sequence) = sequences.get(node).and_then(|m| m.get(&set)) else {
                continue;
            };
            for pair in sequence.windows(2) {
                let from = node_by_block_line[&(*node, pair[0])];
                let to = node_by_block_line[&(*node, pair[1])];
                edges.insert((from, to));
            }
        }
        let mut in_last: BTreeMap<NodeIndex, BTreeSet<usize>> = BTreeMap::new();
        in_last.entry(entry).or_default().insert(SOURCE);
        let mut queue = VecDeque::from([entry]);
        while let Some(block) = queue.pop_front() {
            let incoming = in_last.get(&block).cloned().unwrap_or_default();
            if incoming.is_empty() {
                continue;
            }
            let successors: Vec<NodeIndex> = cfg
                .graph
                .edges_directed(block, petgraph::Direction::Outgoing)
                .map(|edge| edge.target())
                .filter(|target| reachable.contains(target))
                .collect();
            if let Some(&first) = first_by_block.get(&block) {
                for prev in &incoming {
                    edges.insert((*prev, first));
                }
                let last = last_by_block[&block];
                for &target in &successors {
                    let target_in_last = in_last.entry(target).or_default();
                    if let Some(&target_first) = first_by_block.get(&target) {
                        edges.insert((last, target_first));
                    }
                    if target_in_last.insert(last) {
                        queue.push_back(target);
                    }
                }
                if successors.is_empty() {
                    edges.insert((last, SINK));
                }
            } else {
                for &target in &successors {
                    let target_in_last = in_last.entry(target).or_default();
                    for prev in &incoming {
                        if let Some(&target_first) = first_by_block.get(&target) {
                            edges.insert((*prev, target_first));
                        }
                        if target_in_last.insert(*prev) {
                            queue.push_back(target);
                        }
                    }
                }
                if successors.is_empty() {
                    for prev in &incoming {
                        edges.insert((*prev, SINK));
                    }
                }
            }
        }
        let node_count = nodes.len() + 2;
        let mut outgoing = vec![Vec::new(); node_count];
        let mut incoming = vec![Vec::new(); node_count];
        for (from, to) in &edges {
            outgoing[*from].push(*to);
            incoming[*to].push(*from);
        }
        let mut reachable_from_source = vec![false; node_count];
        reachable_from_source[SOURCE] = true;
        let mut work = vec![SOURCE];
        while let Some(node) = work.pop() {
            for target in &outgoing[node] {
                if !reachable_from_source[*target] {
                    reachable_from_source[*target] = true;
                    work.push(*target);
                }
            }
        }
        let mut reaches_sink = vec![false; node_count];
        reaches_sink[SINK] = true;
        let mut work = vec![SINK];
        while let Some(node) = work.pop() {
            for source in &incoming[node] {
                if !reaches_sink[*source] {
                    reaches_sink[*source] = true;
                    work.push(*source);
                }
            }
        }
        if (0..node_count).any(|node| !reachable_from_source[node] || !reaches_sink[node]) {
            // A partial graph would leave block cache costs subtracted without
            // corresponding miss variables.  Fall back to another model.
            return None;
        }
        ccg_sets.push(CcgSet {
            nodes,
            edges: edges.into_iter().collect(),
        });
    }
    if ccg_sets.is_empty() {
        None
    } else {
        Some(CcgModel {
            miss_penalty: info.miss_penalty,
            sets: ccg_sets,
        })
    }
}

/// Adds the CCG flow variables, flow conservation, hit/miss constraints and
/// objective terms to one IPET model.
pub(crate) fn add_constraints(
    vars: &mut ProblemVariables,
    model: &CcgModel,
    block_execution: &dyn Fn(NodeIndex) -> Expression,
    constraints: &mut Vec<good_lp::Constraint>,
    objective: &mut Expression,
) -> CcgApplication {
    let mut application = CcgApplication {
        sets: model.sets.len(),
        ..CcgApplication::default()
    };
    for set in &model.sets {
        let edge_variables: Vec<Variable> = set
            .edges
            .iter()
            .map(|_| vars.add(good_lp::variable().integer().min(0.0)))
            .collect();
        application.variables = application.variables.saturating_add(edge_variables.len());
        application.edges = application.edges.saturating_add(set.edges.len());
        application.nodes = application.nodes.saturating_add(set.nodes.len());
        let mut incoming = vec![Vec::new(); set.nodes.len() + 2];
        let mut outgoing = vec![Vec::new(); set.nodes.len() + 2];
        for (index, (from, to)) in set.edges.iter().enumerate() {
            outgoing[*from].push(index);
            incoming[*to].push(index);
        }
        for node in 2..set.nodes.len() + 2 {
            let data = &set.nodes[node - 2];
            let executions = block_execution(data.block);
            let accesses = executions * f64::from(data.accesses);
            let mut in_flow = Expression::from(0.0);
            let mut same_line = Expression::from(0.0);
            for edge in &incoming[node] {
                let variable = edge_variables[*edge];
                in_flow += variable;
                let (from, _) = set.edges[*edge];
                if from >= 2 && set.nodes[from - 2].line == data.line {
                    same_line += variable;
                }
            }
            let mut out_flow = Expression::from(0.0);
            for edge in &outgoing[node] {
                out_flow += edge_variables[*edge];
            }
            constraints.push(constraint::eq(in_flow - accesses.clone(), 0.0));
            constraints.push(constraint::eq(out_flow - accesses.clone(), 0.0));
            let miss = vars.add(good_lp::variable().integer().min(0.0));
            application.variables = application.variables.saturating_add(1);
            application.constraints = application.constraints.saturating_add(2);
            constraints.push(constraint::eq(miss + same_line - accesses, 0.0));
            application.constraints = application.constraints.saturating_add(1);
            *objective += miss * f64::from(model.miss_penalty);
        }
        let mut source_out = Expression::from(0.0);
        for edge in &outgoing[SOURCE] {
            source_out += edge_variables[*edge];
        }
        constraints.push(constraint::eq(source_out, 1.0));
        let mut sink_in = Expression::from(0.0);
        for edge in &incoming[SINK] {
            sink_in += edge_variables[*edge];
        }
        constraints.push(constraint::eq(sink_in, 1.0));
        application.constraints = application.constraints.saturating_add(2);
    }
    application
}
