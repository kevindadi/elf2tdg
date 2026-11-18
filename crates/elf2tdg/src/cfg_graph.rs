//! Structural CFG analysis and conservative normalization.
//!
//! The analysis is non-destructive: reachability, SCCs, natural loops,
//! dominators and post-dominators are reported using stable block IDs. The
//! normalization pass removes blocks proven unreachable from the entry and
//! merges contiguous fallthrough-only blocks. Functions with an unresolved
//! control transfer keep their unreachable blocks, because an unknown jump may
//! target any address.

use std::collections::{BTreeMap, BTreeSet};

use elf2tdg_schema::{BlockId, CostRange};
use petgraph::algo::tarjan_scc;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};

use crate::cfg::{CfgEdge, CfgEdgeKind, CfgTerminator, FunctionCfg};

/// Result of non-destructive CFG structure analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgGraphAnalysis {
    /// Blocks reachable from the function entry.
    pub reachable: Vec<BlockId>,
    /// Blocks not reachable from the function entry.
    pub unreachable: Vec<BlockId>,
    /// Strongly connected components, ordered by lowest address.
    pub sccs: Vec<CfgScc>,
    /// Natural loops discovered from dominator backedges.
    pub loops: Vec<CfgLoop>,
    /// Blocks dominating each reachable block, including the block itself.
    pub dominators: BTreeMap<BlockId, Vec<BlockId>>,
    /// Immediate dominator for each reachable non-entry block.
    pub immediate_dominators: BTreeMap<BlockId, BlockId>,
    /// Blocks post-dominating each reachable block, including the block itself.
    pub post_dominators: BTreeMap<BlockId, Vec<BlockId>>,
    /// Immediate post-dominator, when a unique real block exists.
    pub immediate_post_dominators: BTreeMap<BlockId, BlockId>,
    /// A reachable block has an unresolved control transfer. Unreachable
    /// minimization must be treated as unsafe in this function.
    pub blocked_by_unresolved: bool,
}

impl CfgGraphAnalysis {
    /// Returns whether any SCC is cyclic.
    #[must_use]
    pub fn has_cycles(&self) -> bool {
        self.sccs.iter().any(|scc| scc.cyclic)
    }
}

/// One strongly connected component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgScc {
    /// Blocks in address order.
    pub blocks: Vec<BlockId>,
    /// Whether the component contains a cycle.
    pub cyclic: bool,
    /// Whether the component is reachable from the entry.
    pub reachable: bool,
}

/// A natural loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgLoop {
    /// Loop header.
    pub header: BlockId,
    /// Header and all blocks in the natural loop.
    pub blocks: Vec<BlockId>,
    /// Backedge latches.
    pub latches: Vec<BlockId>,
    /// Backedges, each from a latch to the header.
    pub backedges: Vec<CfgBackedge>,
}

/// One loop backedge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgBackedge {
    /// Latch block.
    pub from: BlockId,
    /// Loop header.
    pub to: BlockId,
}

/// Why unreachable-block removal was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgNormalizationSkip {
    /// The function has no entry block.
    NoEntry,
    /// A reachable block has unresolved control flow.
    UnresolvedControlFlow,
}

/// One fallthrough-block merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgBlockMerge {
    /// Block that was folded into another block.
    pub from: BlockId,
    /// Surviving block.
    pub into: BlockId,
}

/// Result of [`normalize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgNormalization {
    /// Unreachable blocks removed from the graph.
    pub removed_unreachable: Vec<BlockId>,
    /// Fallthrough merges performed.
    pub merged: Vec<CfgBlockMerge>,
    /// Reason unreachable removal was not attempted.
    pub skip_reason: Option<CfgNormalizationSkip>,
}

impl CfgNormalization {
    /// Returns whether normalization changed the graph.
    #[must_use]
    pub fn changed(&self) -> bool {
        !self.removed_unreachable.is_empty() || !self.merged.is_empty()
    }
}

/// Analyzes reachability, SCCs, loops and dominator relations.
#[must_use]
pub fn analyze(cfg: &FunctionCfg) -> CfgGraphAnalysis {
    let reachable = reachable_nodes(cfg);
    let reachable_ids = block_ids(cfg, reachable.iter().copied());
    let unreachable_ids = block_ids(
        cfg,
        cfg.graph
            .node_indices()
            .filter(|node| !reachable.contains(node)),
    );
    let blocked_by_unresolved = reachable.iter().any(|node| {
        cfg.graph
            .node_weight(*node)
            .is_some_and(|block| block.terminator == CfgTerminator::Unresolved)
    });
    let sccs = strongly_connected_components(cfg, &reachable);
    let dominator_nodes = dominator_sets(cfg, cfg.entry, &reachable);
    let dominators = dominator_id_sets(cfg, &dominator_nodes);
    let immediate_dominators = immediate_dominators(cfg, &dominator_nodes);
    let loops = natural_loops(cfg, &reachable, &dominator_nodes);
    let (post_dominators, immediate_post_dominators) = post_dominator_sets(cfg, &reachable);
    CfgGraphAnalysis {
        reachable: reachable_ids,
        unreachable: unreachable_ids,
        sccs,
        loops,
        dominators,
        immediate_dominators,
        post_dominators,
        immediate_post_dominators,
        blocked_by_unresolved,
    }
}

/// Removes proven-unreachable blocks and merges contiguous fallthrough blocks.
///
/// Unreachable removal is skipped when the function has no entry or when a
/// reachable unresolved control transfer exists. Merging is still safe in
/// both cases because it only follows a proven fallthrough edge.
pub fn normalize(cfg: &mut FunctionCfg) -> CfgNormalization {
    let analysis = analyze(cfg);
    let mut result = CfgNormalization {
        removed_unreachable: Vec::new(),
        merged: Vec::new(),
        skip_reason: None,
    };
    if !analysis.unreachable.is_empty() {
        if cfg.entry.is_none() {
            result.skip_reason = Some(CfgNormalizationSkip::NoEntry);
        } else if analysis.blocked_by_unresolved {
            result.skip_reason = Some(CfgNormalizationSkip::UnresolvedControlFlow);
        } else {
            remove_blocks(cfg, &analysis.unreachable);
            result.removed_unreachable = analysis.unreachable;
        }
    }
    loop {
        if merge_one_fallthrough(cfg, &mut result.merged) {
            continue;
        }
        break;
    }
    result
}

fn reachable_nodes(cfg: &FunctionCfg) -> BTreeSet<NodeIndex> {
    let Some(entry) = cfg.entry else {
        return BTreeSet::new();
    };
    let mut reachable = BTreeSet::new();
    let mut pending = vec![entry];
    while let Some(node) = pending.pop() {
        if !reachable.insert(node) {
            continue;
        }
        pending.extend(
            cfg.graph
                .neighbors_directed(node, petgraph::Direction::Outgoing),
        );
    }
    reachable
}

fn block_ids(cfg: &FunctionCfg, nodes: impl IntoIterator<Item = NodeIndex>) -> Vec<BlockId> {
    let mut nodes: Vec<NodeIndex> = nodes
        .into_iter()
        .filter(|node| cfg.graph.contains_node(*node))
        .collect();
    nodes.sort_by_key(|node| cfg.graph[*node].address);
    nodes
        .into_iter()
        .map(|node| cfg.graph[node].id.clone())
        .collect()
}

fn strongly_connected_components(
    cfg: &FunctionCfg,
    reachable: &BTreeSet<NodeIndex>,
) -> Vec<CfgScc> {
    let mut components: Vec<(u64, CfgScc)> = tarjan_scc(&cfg.graph)
        .into_iter()
        .map(|nodes| {
            let cyclic = nodes.len() > 1
                || nodes
                    .first()
                    .is_some_and(|node| cfg.graph.find_edge(*node, *node).is_some());
            let reachable_component = nodes.iter().any(|node| reachable.contains(node));
            let lowest = nodes
                .iter()
                .map(|node| cfg.graph[*node].address)
                .min()
                .unwrap_or(0);
            (
                lowest,
                CfgScc {
                    blocks: block_ids(cfg, nodes),
                    cyclic,
                    reachable: reachable_component,
                },
            )
        })
        .collect();
    components.sort_by_key(|(address, _)| *address);
    components
        .into_iter()
        .map(|(_, component)| component)
        .collect()
}

fn dominator_sets(
    cfg: &FunctionCfg,
    entry: Option<NodeIndex>,
    reachable: &BTreeSet<NodeIndex>,
) -> BTreeMap<NodeIndex, BTreeSet<NodeIndex>> {
    let Some(entry) = entry else {
        return BTreeMap::new();
    };
    if !reachable.contains(&entry) {
        return BTreeMap::new();
    }
    let mut dominators: BTreeMap<NodeIndex, BTreeSet<NodeIndex>> = reachable
        .iter()
        .map(|node| (*node, reachable.clone()))
        .collect();
    dominators.insert(entry, BTreeSet::from([entry]));
    loop {
        let mut changed = false;
        for node in reachable {
            if *node == entry {
                continue;
            }
            let predecessors: BTreeSet<NodeIndex> = cfg
                .graph
                .neighbors_directed(*node, petgraph::Direction::Incoming)
                .filter(|predecessor| reachable.contains(predecessor))
                .collect();
            let mut next = BTreeSet::new();
            let mut predecessors = predecessors.into_iter();
            if let Some(first) = predecessors.next()
                && let Some(first_set) = dominators.get(&first)
            {
                next.clone_from(first_set);
                for predecessor in predecessors {
                    if let Some(previous) = dominators.get(&predecessor) {
                        next = next.intersection(previous).copied().collect();
                    }
                }
            }
            next.insert(*node);
            if dominators.get(node) != Some(&next) {
                dominators.insert(*node, next);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    dominators
}

fn dominator_id_sets(
    cfg: &FunctionCfg,
    dominators: &BTreeMap<NodeIndex, BTreeSet<NodeIndex>>,
) -> BTreeMap<BlockId, Vec<BlockId>> {
    dominators
        .iter()
        .map(|(node, set)| {
            (
                cfg.graph[*node].id.clone(),
                block_ids(cfg, set.iter().copied()),
            )
        })
        .collect()
}

fn immediate_dominators(
    cfg: &FunctionCfg,
    dominators: &BTreeMap<NodeIndex, BTreeSet<NodeIndex>>,
) -> BTreeMap<BlockId, BlockId> {
    let mut immediate = BTreeMap::new();
    for (node, set) in dominators {
        let mut candidates: Vec<NodeIndex> = set
            .iter()
            .copied()
            .filter(|candidate| candidate != node)
            .collect();
        candidates.sort_by_key(|candidate| dominators.get(candidate).map_or(0, BTreeSet::len));
        if let Some(candidate) = candidates.last() {
            immediate.insert(
                cfg.graph[*node].id.clone(),
                cfg.graph[*candidate].id.clone(),
            );
        }
    }
    immediate
}

fn natural_loops(
    cfg: &FunctionCfg,
    reachable: &BTreeSet<NodeIndex>,
    dominators: &BTreeMap<NodeIndex, BTreeSet<NodeIndex>>,
) -> Vec<CfgLoop> {
    struct LoopDraft {
        blocks: BTreeSet<NodeIndex>,
        latches: BTreeSet<NodeIndex>,
        backedges: BTreeSet<(NodeIndex, NodeIndex)>,
    }
    let mut loops: BTreeMap<NodeIndex, LoopDraft> = BTreeMap::new();
    for edge in cfg.graph.edge_references() {
        let (from, to) = (edge.source(), edge.target());
        if !reachable.contains(&from)
            || !reachable.contains(&to)
            || !dominators.get(&from).is_some_and(|set| set.contains(&to))
        {
            continue;
        }
        let draft = loops.entry(to).or_insert_with(|| LoopDraft {
            blocks: BTreeSet::from([to]),
            latches: BTreeSet::new(),
            backedges: BTreeSet::new(),
        });
        draft.latches.insert(from);
        draft.backedges.insert((from, to));
        let mut blocks = BTreeSet::from([to]);
        let mut pending = vec![from];
        while let Some(node) = pending.pop() {
            if node == to || !blocks.insert(node) {
                continue;
            }
            for predecessor in cfg
                .graph
                .neighbors_directed(node, petgraph::Direction::Incoming)
            {
                if reachable.contains(&predecessor) {
                    pending.push(predecessor);
                }
            }
        }
        draft.blocks.extend(blocks);
    }
    let mut result: Vec<(u64, CfgLoop)> = loops
        .into_iter()
        .map(|(header, draft)| {
            (
                cfg.graph[header].address,
                CfgLoop {
                    header: cfg.graph[header].id.clone(),
                    blocks: block_ids(cfg, draft.blocks),
                    latches: block_ids(cfg, draft.latches),
                    backedges: draft
                        .backedges
                        .into_iter()
                        .map(|(from, to)| CfgBackedge {
                            from: cfg.graph[from].id.clone(),
                            to: cfg.graph[to].id.clone(),
                        })
                        .collect(),
                },
            )
        })
        .collect();
    result.sort_by_key(|(address, _)| *address);
    result.into_iter().map(|(_, loop_info)| loop_info).collect()
}

fn post_dominator_sets(
    cfg: &FunctionCfg,
    reachable: &BTreeSet<NodeIndex>,
) -> (BTreeMap<BlockId, Vec<BlockId>>, BTreeMap<BlockId, BlockId>) {
    if reachable.is_empty() {
        return (BTreeMap::new(), BTreeMap::new());
    }
    let nodes: Vec<NodeIndex> = reachable.iter().copied().collect();
    let indices: BTreeMap<NodeIndex, usize> = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (*node, index))
        .collect();
    let virtual_exit = nodes.len();
    let mut successors = vec![Vec::new(); nodes.len() + 1];
    let mut has_exit = false;
    for (index, node) in nodes.iter().enumerate() {
        let mut node_successors: BTreeSet<usize> = cfg
            .graph
            .neighbors_directed(*node, petgraph::Direction::Outgoing)
            .filter_map(|successor| indices.get(&successor).copied())
            .collect();
        if node_successors.is_empty() {
            node_successors.insert(virtual_exit);
            has_exit = true;
        }
        successors[index] = node_successors.into_iter().collect();
    }
    if !has_exit {
        return (BTreeMap::new(), BTreeMap::new());
    }
    let all: BTreeSet<usize> = (0..=nodes.len()).collect();
    let mut post: Vec<BTreeSet<usize>> = nodes.iter().map(|_| all.clone()).collect();
    post.push(BTreeSet::from([virtual_exit]));
    loop {
        let mut changed = false;
        for index in 0..nodes.len() {
            let mut node_successors = successors[index].iter();
            let mut next = match node_successors.next() {
                Some(successor) => post[*successor].clone(),
                None => BTreeSet::new(),
            };
            for successor in node_successors {
                next = next.intersection(&post[*successor]).copied().collect();
            }
            next.insert(index);
            if post[index] != next {
                post[index] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut result = BTreeMap::new();
    let mut immediate = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        let set: Vec<BlockId> = block_ids(
            cfg,
            post[index]
                .iter()
                .filter(|candidate| **candidate != virtual_exit)
                .map(|candidate| nodes[*candidate]),
        );
        let mut real_candidates: Vec<usize> = post[index]
            .iter()
            .copied()
            .filter(|candidate| candidate != &index && candidate != &virtual_exit)
            .collect();
        real_candidates.sort_by_key(|candidate| post[*candidate].len());
        if let Some(candidate) = real_candidates.last() {
            immediate.insert(
                cfg.graph[*node].id.clone(),
                cfg.graph[nodes[*candidate]].id.clone(),
            );
        }
        result.insert(cfg.graph[*node].id.clone(), set);
    }
    (result, immediate)
}

fn remove_blocks(cfg: &mut FunctionCfg, ids: &[BlockId]) {
    let nodes: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let to_remove: BTreeSet<NodeIndex> =
        ids.iter().filter_map(|id| nodes.get(id).copied()).collect();
    for node in &to_remove {
        cfg.graph.remove_node(*node);
    }
    cfg.blocks_by_address
        .retain(|_, node| !to_remove.contains(node));
}

fn merge_one_fallthrough(cfg: &mut FunctionCfg, merged: &mut Vec<CfgBlockMerge>) -> bool {
    let nodes: Vec<NodeIndex> = cfg.blocks_by_address.values().copied().collect();
    for source in nodes {
        if !cfg.graph.contains_node(source) {
            continue;
        }
        let outgoing: Vec<(NodeIndex, CfgEdge)> = cfg
            .graph
            .edges_directed(source, petgraph::Direction::Outgoing)
            .map(|edge| (edge.target(), edge.weight().clone()))
            .collect();
        if outgoing.len() != 1 {
            continue;
        }
        let (target, edge) = &outgoing[0];
        if edge.kind != CfgEdgeKind::Fallthrough
            || cfg.graph[source].terminator != CfgTerminator::Fallthrough
            || Some(*target) == cfg.entry
            || *target == source
        {
            continue;
        }
        let incoming: Vec<NodeIndex> = cfg
            .graph
            .edges_directed(*target, petgraph::Direction::Incoming)
            .map(|edge| edge.source())
            .collect();
        if incoming.len() != 1 || incoming[0] != source {
            continue;
        }
        let Some(end) = cfg.graph[source]
            .address
            .checked_add(cfg.graph[source].size)
        else {
            continue;
        };
        if cfg.graph[*target].address != end {
            continue;
        }
        let target_block = cfg.graph[*target].clone();
        let target_edges: Vec<(NodeIndex, CfgEdge)> = cfg
            .graph
            .edges_directed(*target, petgraph::Direction::Outgoing)
            .map(|edge| (edge.target(), edge.weight().clone()))
            .collect();
        {
            let source_block = &mut cfg.graph[source];
            source_block.instructions.extend(target_block.instructions);
            source_block.calls.extend(target_block.calls);
            source_block.calls.sort_by_key(|call| call.site);
            source_block.size = source_block.size.saturating_add(target_block.size);
            source_block.cycles = merge_cycles(source_block.cycles, target_block.cycles);
            source_block.cache = None;
            source_block.data_cache = None;
            source_block.terminator = target_block.terminator;
        }
        cfg.graph.remove_node(*target);
        cfg.blocks_by_address.remove(&target_block.address);
        for (to, edge) in target_edges {
            cfg.graph.add_edge(source, to, edge);
        }
        merged.push(CfgBlockMerge {
            from: target_block.id,
            into: cfg.graph[source].id.clone(),
        });
        return true;
    }
    false
}

fn merge_cycles(left: Option<CostRange>, right: Option<CostRange>) -> Option<CostRange> {
    match (left, right) {
        (Some(left), Some(right)) => {
            Some(CostRange::new(left.min + right.min, left.max + right.max))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{CfgNormalizationSkip, analyze, normalize};
    use crate::cfg::{
        CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgInstruction, CfgTerminator, FunctionCfg,
    };

    fn instruction(address: u64) -> CfgInstruction {
        CfgInstruction {
            address,
            size: 4,
            bytes: vec![0; 4],
            mnemonic: "nop".to_owned(),
            operands: String::new(),
            text: "nop".to_owned(),
            is_call: false,
            is_jump: false,
            is_return: false,
            is_conditional: false,
            direct_target: None,
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: None,
            source: None,
        }
    }

    fn block(address: u64, terminator: CfgTerminator) -> CfgBlockDraft {
        let mut instruction = instruction(address);
        match terminator {
            CfgTerminator::Return => instruction.is_return = true,
            CfgTerminator::Branch => {
                instruction.is_jump = true;
                instruction.is_conditional = true;
            }
            CfgTerminator::Jump | CfgTerminator::Unresolved => instruction.is_jump = true,
            CfgTerminator::Call | CfgTerminator::NoreturnCall => instruction.is_call = true,
            CfgTerminator::Fallthrough => {}
        }
        CfgBlockDraft {
            address,
            size: 4,
            instructions: vec![instruction],
            calls: Vec::new(),
            cycles: None,
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

    fn loop_cfg() -> FunctionCfg {
        FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Branch),
                block(0x1004, CfgTerminator::Branch),
                block(0x1008, CfgTerminator::Jump),
                block(0x1010, CfgTerminator::Return),
            ],
            vec![
                edge(0x1000, 0x1004, CfgEdgeKind::Branch),
                edge(0x1000, 0x1010, CfgEdgeKind::Branch),
                edge(0x1004, 0x1008, CfgEdgeKind::Branch),
                edge(0x1004, 0x1010, CfgEdgeKind::Branch),
                edge(0x1008, 0x1004, CfgEdgeKind::Jump),
            ],
            Some(0x1000),
        )
    }

    #[test]
    fn finds_sccs_dominators_and_loops() {
        let cfg = loop_cfg();
        let analysis = analyze(&cfg);
        assert_eq!(analysis.reachable.len(), 4);
        assert_eq!(analysis.unreachable.as_slice(), []);
        assert!(!analysis.blocked_by_unresolved);
        assert_eq!(analysis.sccs.iter().filter(|scc| scc.cyclic).count(), 1);
        let loop_info = analysis.loops.first().expect("loop");
        assert_eq!(loop_info.header.as_str(), "bb:0x1004");
        assert_eq!(
            loop_info
                .blocks
                .iter()
                .map(elf2tdg_schema::BlockId::as_str)
                .collect::<Vec<_>>(),
            vec!["bb:0x1004", "bb:0x1008"]
        );
        assert_eq!(loop_info.latches[0].as_str(), "bb:0x1008");
        assert_eq!(
            analysis
                .dominators
                .get(&elf2tdg_schema::BlockId::new("bb:0x1008"))
                .expect("body dominators")
                .len(),
            3
        );
        assert_eq!(
            analysis
                .immediate_dominators
                .get(&elf2tdg_schema::BlockId::new("bb:0x1008"))
                .map(elf2tdg_schema::BlockId::as_str),
            Some("bb:0x1004")
        );
        assert!(
            analysis
                .post_dominators
                .contains_key(&elf2tdg_schema::BlockId::new("bb:0x1010"))
        );
    }

    #[test]
    fn normalizes_unreachable_and_fallthrough_blocks() {
        let mut cfg = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Fallthrough),
                block(0x1004, CfgTerminator::Return),
                block(0x1020, CfgTerminator::Return),
            ],
            vec![edge(0x1000, 0x1004, CfgEdgeKind::Fallthrough)],
            Some(0x1000),
        );
        let report = normalize(&mut cfg);
        assert_eq!(report.removed_unreachable.len(), 1);
        assert_eq!(report.removed_unreachable[0].as_str(), "bb:0x1020");
        assert_eq!(report.merged.len(), 1);
        assert_eq!(cfg.blocks_by_address.len(), 1);
        let block = cfg
            .blocks_by_address
            .values()
            .map(|node| &cfg.graph[*node])
            .next()
            .expect("merged block");
        assert_eq!(block.address, 0x1000);
        assert_eq!(block.size, 8);
        assert_eq!(block.instructions.len(), 2);
        assert_eq!(block.terminator, CfgTerminator::Return);
        assert_eq!(cfg.graph.edge_count(), 0);
        cfg.ensure_valid().expect("normalized CFG must validate");
    }

    #[test]
    fn keeps_unreachable_blocks_after_unresolved_jump() {
        let mut cfg = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Unresolved),
                block(0x1020, CfgTerminator::Return),
            ],
            Vec::new(),
            Some(0x1000),
        );
        let report = normalize(&mut cfg);
        assert_eq!(
            report.skip_reason,
            Some(CfgNormalizationSkip::UnresolvedControlFlow)
        );
        assert_eq!(report.removed_unreachable.as_slice(), []);
        assert_eq!(cfg.blocks_by_address.len(), 2);
    }
}
