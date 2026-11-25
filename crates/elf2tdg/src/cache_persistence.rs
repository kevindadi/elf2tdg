//! Per-line cache persistence and first-miss classification.
//!
//! The instruction- and data-cache analyses already enumerate the concrete
//! LRU states reaching each block.  This module reuses those states to decide
//! whether a cache line can be evicted between two loop entries.  A line is
//! first-miss when, after it is loaded, the modeled loop never evicts it
//! again: IPET can then charge at most one miss per line per loop entry
//! instead of the per-block worst case on every iteration.
//!
//! The analysis works per cache line, so a loop may have a persistent line
//! even when its total working set does not fit in one set.  This is the
//! line-split view used by the IPET cache model.
//!
//! The proof is deliberately local. It does not model inter-function state,
//! prefetch, dirty-line writeback or aliasing beyond the concrete line
//! addresses recorded by the cache analyses.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use petgraph::stable_graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};

use elf2tdg_schema::{Addr, BlockId, FunctionId};

use crate::cache_state::{CacheAccess, CacheAccessKind, CacheGeometry, CacheState, simulate};
use crate::cfg::{CfgCachePersistenceRegion, CfgEdgeKind, FunctionCfg};

/// Upper bound on the state exploration used for one natural loop.
const MAX_LINE_SPLIT_STATES: usize = 100_000;

/// One natural loop with cache lines that are never evicted after a load.
#[derive(Clone, Debug)]
pub(crate) struct PersistenceRegion {
    /// Loop header.
    pub(crate) header: BlockId,
    /// Reachable blocks in the natural loop.
    pub(crate) blocks: Vec<NodeIndex>,
    /// Persistent line start addresses.
    pub(crate) lines: BTreeSet<u64>,
}

/// Line-split persistence result for one function.
#[derive(Clone, Debug, Default)]
pub(crate) struct PersistenceAnalysis {
    /// Natural loops inspected for this function.
    pub(crate) loops_analyzed: u32,
    /// Loops with at least one persistent line.
    pub(crate) loops_persistent: u32,
    /// Persistent loop regions.
    pub(crate) regions: Vec<PersistenceRegion>,
}

impl PersistenceAnalysis {
    /// Returns whether no loop met the persistence proof.
    pub(crate) fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}

#[derive(Clone, Copy, Debug)]
enum AccessMode {
    Instruction,
    Data { write_allocate: bool },
}

impl AccessMode {
    fn data(self) -> Option<bool> {
        match self {
            Self::Instruction => None,
            Self::Data { write_allocate } => Some(write_allocate),
        }
    }
}

/// Classifies persistent instruction-cache lines from the concrete states
/// produced by the instruction-cache analysis.
pub(crate) fn instruction_from_states(
    cfg: &FunctionCfg,
    entry_states: &BTreeMap<NodeIndex, BTreeSet<CacheState>>,
    accesses: &BTreeMap<NodeIndex, Vec<CacheAccess>>,
    geometry: CacheGeometry,
    max_states: usize,
) -> PersistenceAnalysis {
    analyze_with_states(
        cfg,
        entry_states,
        accesses,
        geometry,
        AccessMode::Instruction,
        max_states,
    )
}

/// Classifies persistent data-cache lines from the concrete states produced
/// by the data-cache analysis.
pub(crate) fn data_from_states(
    cfg: &FunctionCfg,
    entry_states: &BTreeMap<NodeIndex, BTreeSet<CacheState>>,
    accesses: &BTreeMap<NodeIndex, Vec<CacheAccess>>,
    geometry: CacheGeometry,
    write_allocate: bool,
    max_states: usize,
) -> PersistenceAnalysis {
    analyze_with_states(
        cfg,
        entry_states,
        accesses,
        geometry,
        AccessMode::Data { write_allocate },
        max_states,
    )
}

#[allow(clippy::too_many_lines)]
fn analyze_with_states(
    cfg: &FunctionCfg,
    entry_states: &BTreeMap<NodeIndex, BTreeSet<CacheState>>,
    accesses: &BTreeMap<NodeIndex, Vec<CacheAccess>>,
    geometry: CacheGeometry,
    kind: AccessMode,
    max_states: usize,
) -> PersistenceAnalysis {
    if geometry.sets == 0 || geometry.ways == 0 || geometry.line_bytes == 0 {
        return PersistenceAnalysis::default();
    }
    let graph = crate::cfg_graph::analyze(cfg);
    let reachable: BTreeSet<BlockId> = graph.reachable.iter().cloned().collect();
    let node_by_id: BTreeMap<BlockId, NodeIndex> = cfg
        .blocks_by_address
        .values()
        .map(|node| (cfg.graph[*node].id.clone(), *node))
        .collect();
    let mut result = PersistenceAnalysis::default();
    for loop_ in &graph.loops {
        result.loops_analyzed = result.loops_analyzed.saturating_add(1);
        let blocks: Vec<NodeIndex> = loop_
            .blocks
            .iter()
            .filter_map(|block| node_by_id.get(block).copied())
            .collect();
        if blocks.is_empty()
            || blocks
                .iter()
                .any(|node| !reachable.contains(&cfg.graph[*node].id))
        {
            continue;
        }
        let Some(header) = node_by_id.get(&loop_.header).copied() else {
            continue;
        };
        let node_set: BTreeSet<NodeIndex> = blocks.iter().copied().collect();
        if cfg.graph.edge_references().any(|edge| {
            let source_in = node_set.contains(&edge.source());
            let target_in = node_set.contains(&edge.target());
            (edge.weight().kind == CfgEdgeKind::CallReturn && source_in)
                || (target_in && !source_in && edge.target() != header)
        }) {
            // Calls reset the modeled state, and a non-header outside entry
            // makes the loop multi-entry: a line could be evicted between
            // entries without the header-entry count seeing it.
            continue;
        }
        if kind.data().is_some()
            && blocks.iter().any(|node| {
                cfg.graph[*node]
                    .data_cache
                    .as_ref()
                    .is_some_and(|cache| cache.unresolved_memory_accesses > 0)
            })
        {
            continue;
        }
        let Some(header_states) = entry_states.get(&header) else {
            continue;
        };
        if header_states.is_empty() {
            continue;
        }
        let (candidate_lines, written_lines) = loop_lines(accesses, &blocks);
        let candidate_lines: BTreeSet<u64> = candidate_lines
            .into_iter()
            .filter(|line| {
                !kind
                    .data()
                    .is_some_and(|write_allocate| !write_allocate && written_lines.contains(line))
            })
            .collect();
        if candidate_lines.is_empty() {
            continue;
        }
        let state_limit = max_states
            .saturating_mul(blocks.len().max(1))
            .clamp(256, MAX_LINE_SPLIT_STATES);
        let mut persistent = candidate_lines.clone();
        let mut processed: BTreeSet<(NodeIndex, CacheState)> = BTreeSet::new();
        let mut queue: VecDeque<(NodeIndex, CacheState)> = header_states
            .iter()
            .cloned()
            .map(|state| (header, state))
            .collect();
        while let Some((node, state)) = queue.pop_front() {
            if processed.len() >= state_limit {
                persistent.clear();
                break;
            }
            if !processed.insert((node, state.clone())) {
                continue;
            }
            let block_accesses = accesses.get(&node).map_or(&[][..], Vec::as_slice);
            let failed: Vec<u64> = persistent
                .iter()
                .copied()
                .filter(|line| !block_preserves_line(block_accesses, &state, geometry, kind, *line))
                .collect();
            for line in failed {
                persistent.remove(&line);
            }
            if persistent.is_empty() {
                break;
            }
            let simulation = simulate(
                block_accesses,
                &state,
                geometry,
                kind.data().unwrap_or(true),
            );
            for edge in cfg
                .graph
                .edges_directed(node, petgraph::Direction::Outgoing)
            {
                if node_set.contains(&edge.target()) {
                    queue.push_back((edge.target(), simulation.state.clone()));
                }
            }
        }
        if persistent.is_empty() {
            continue;
        }
        result.loops_persistent = result.loops_persistent.saturating_add(1);
        result.regions.push(PersistenceRegion {
            header: cfg.graph[header].id.clone(),
            blocks,
            lines: persistent
                .into_iter()
                .map(|line| geometry.line_address(line))
                .collect(),
        });
    }
    result
}

fn loop_lines(
    accesses: &BTreeMap<NodeIndex, Vec<CacheAccess>>,
    blocks: &[NodeIndex],
) -> (BTreeSet<u64>, BTreeSet<u64>) {
    let mut lines = BTreeSet::new();
    let mut written = BTreeSet::new();
    for node in blocks {
        if let Some(block_accesses) = accesses.get(node) {
            for access in block_accesses {
                lines.insert(access.line);
                if matches!(
                    access.kind,
                    CacheAccessKind::Write | CacheAccessKind::ReadWrite
                ) {
                    written.insert(access.line);
                }
            }
        }
    }
    (lines, written)
}

fn block_preserves_line(
    accesses: &[CacheAccess],
    state: &CacheState,
    geometry: CacheGeometry,
    kind: AccessMode,
    line: u64,
) -> bool {
    let mut state = state.clone();
    let mut misses = 0_u32;
    for access in accesses {
        let before = state.contains(line, geometry.sets);
        apply_access(&mut state, access, geometry, kind);
        let after = state.contains(line, geometry.sets);
        if access.line == line {
            if !before {
                if !access_allocates(access.kind, kind) {
                    return false;
                }
                misses = misses.saturating_add(1);
                if misses > 1 {
                    return false;
                }
            }
        } else if before && !after {
            return false;
        }
        if before && !after {
            return false;
        }
    }
    true
}

fn access_allocates(kind: CacheAccessKind, mode: AccessMode) -> bool {
    match kind {
        CacheAccessKind::Fetch | CacheAccessKind::Read | CacheAccessKind::ReadWrite => true,
        CacheAccessKind::Write => mode.data().is_none_or(|write_allocate| write_allocate),
    }
}

fn apply_access(
    state: &mut CacheState,
    access: &CacheAccess,
    geometry: CacheGeometry,
    mode: AccessMode,
) {
    let write_allocate = mode.data().unwrap_or(true);
    match access.kind {
        CacheAccessKind::Fetch | CacheAccessKind::Read | CacheAccessKind::ReadWrite => {
            state.access(access.line, geometry.ways, geometry.sets);
        }
        CacheAccessKind::Write if write_allocate => {
            state.access(access.line, geometry.ways, geometry.sets);
        }
        CacheAccessKind::Write => {
            state.write_no_allocate(access.line, geometry.sets);
        }
    }
}

/// Builds the schema record for one persistence region.
pub(crate) fn region_info(
    function: &FunctionId,
    region: &PersistenceRegion,
) -> CfgCachePersistenceRegion {
    CfgCachePersistenceRegion {
        function: function.clone(),
        header: region.header.clone(),
        blocks: u32::try_from(region.blocks.len()).unwrap_or(u32::MAX),
        lines: region.lines.iter().copied().map(Addr::new).collect(),
    }
}

/// Caveats shared by the instruction- and data-cache persistence records.
pub(crate) fn caveats(data_cache: bool) -> Vec<String> {
    let mut caveats = vec![
        "Line splitting classifies each cache line separately from the concrete states reaching a natural loop; a line is first-miss when the modeled loop never evicts it after it is loaded.".to_owned(),
        "Line-split persistence is proved per natural loop from concrete line addresses; inter-function cache state, prefetch and address aliasing are not modeled, and loops with call-return edges, non-header entries or state-limit overflow are not classified.".to_owned(),
    ];
    if data_cache {
        caveats.push(
            "With write_allocate = false, lines with any store are not claimed first-miss; non-allocating store misses can repeat every iteration.".to_owned(),
        );
    }
    caveats
}

#[cfg(test)]
mod tests {
    use super::{AccessMode, block_preserves_line, data_from_states, instruction_from_states};
    use crate::cache_state::{CacheAccess, CacheAccessKind, CacheGeometry};
    use crate::cfg::{
        CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgInstruction, CfgTerminator, FunctionCfg,
    };
    use elf2tdg_schema::CostRange;
    use std::collections::{BTreeMap, BTreeSet};

    fn instruction(address: u64) -> CfgInstruction {
        CfgInstruction {
            address,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "nop".to_owned(),
            operands: String::new(),
            text: "nop".to_owned(),
            is_call: false,
            is_jump: true,
            is_return: false,
            is_conditional: false,
            direct_target: None,
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            source: None,
        }
    }

    fn block(address: u64, terminator: CfgTerminator) -> CfgBlockDraft {
        CfgBlockDraft {
            address,
            size: 2,
            instructions: vec![instruction(address)],
            calls: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
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

    fn node(cfg: &FunctionCfg, address: u64) -> petgraph::stable_graph::NodeIndex {
        cfg.blocks_by_address[&address]
    }

    fn line_access(line: u64) -> CacheAccess {
        CacheAccess {
            line,
            kind: CacheAccessKind::Fetch,
        }
    }

    fn geometry(ways: usize) -> CacheGeometry {
        CacheGeometry {
            line_bytes: 16,
            sets: 1,
            ways,
        }
    }

    #[test]
    fn a_line_persists_even_when_the_loop_working_set_is_too_large() {
        let cfg = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Fallthrough),
                block(0x1002, CfgTerminator::Branch),
                block(0x1004, CfgTerminator::Jump),
                block(0x1006, CfgTerminator::Jump),
            ],
            vec![
                edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                edge(0x1002, 0x1004, CfgEdgeKind::Fallthrough),
                edge(0x1002, 0x1006, CfgEdgeKind::Branch),
                edge(0x1004, 0x1000, CfgEdgeKind::Jump),
                edge(0x1006, 0x1000, CfgEdgeKind::Jump),
            ],
            Some(0x1000),
        );
        let header = node(&cfg, 0x1000);
        let a = node(&cfg, 0x1002);
        let b = node(&cfg, 0x1004);
        let c = node(&cfg, 0x1006);
        let geometry = geometry(2);
        let cold = geometry.cold();
        let mut warm_a = cold.clone();
        warm_a.access(0, geometry.ways, geometry.sets);
        warm_a.access(1, geometry.ways, geometry.sets);
        let mut warm_b = cold.clone();
        warm_b.access(0, geometry.ways, geometry.sets);
        warm_b.access(2, geometry.ways, geometry.sets);
        let entry_states = BTreeMap::from([
            (header, BTreeSet::from([cold, warm_a, warm_b])),
            (a, BTreeSet::from([geometry.cold()])),
            (b, BTreeSet::from([geometry.cold()])),
            (c, BTreeSet::from([geometry.cold()])),
        ]);
        let accesses = BTreeMap::from([
            (header, Vec::new()),
            (a, vec![line_access(0)]),
            (b, vec![line_access(1)]),
            (c, vec![line_access(2)]),
        ]);
        let result = instruction_from_states(&cfg, &entry_states, &accesses, geometry, 16);
        assert_eq!(result.regions.len(), 1);
        assert!(result.regions[0].lines.contains(&0));
        assert!(!result.regions[0].lines.contains(&1));
        assert!(!result.regions[0].lines.contains(&2));
    }

    #[test]
    fn call_return_edges_block_line_persistence() {
        let cfg = FunctionCfg::build(
            vec![
                block(0x1000, CfgTerminator::Jump),
                block(0x1002, CfgTerminator::Return),
            ],
            vec![edge(0x1000, 0x1000, CfgEdgeKind::CallReturn)],
            Some(0x1000),
        );
        let header = node(&cfg, 0x1000);
        let geometry = geometry(2);
        let mut warm = geometry.cold();
        warm.access(0, geometry.ways, geometry.sets);
        let entry_states = BTreeMap::from([(header, BTreeSet::from([geometry.cold(), warm]))]);
        let accesses = BTreeMap::from([(header, vec![line_access(0)])]);
        assert!(
            instruction_from_states(&cfg, &entry_states, &accesses, geometry, 16)
                .regions
                .is_empty()
        );
    }

    #[test]
    fn non_allocating_write_lines_are_not_first_miss() {
        let cfg = FunctionCfg::build(
            vec![block(0x1000, CfgTerminator::Jump)],
            vec![edge(0x1000, 0x1000, CfgEdgeKind::Jump)],
            Some(0x1000),
        );
        let header = node(&cfg, 0x1000);
        let geometry = geometry(2);
        let mut warm = geometry.cold();
        warm.access(0, geometry.ways, geometry.sets);
        warm.access(1, geometry.ways, geometry.sets);
        let entry_states = BTreeMap::from([(header, BTreeSet::from([geometry.cold(), warm]))]);
        let accesses = BTreeMap::from([(
            header,
            vec![
                CacheAccess {
                    line: 0,
                    kind: CacheAccessKind::Write,
                },
                CacheAccess {
                    line: 1,
                    kind: CacheAccessKind::Read,
                },
            ],
        )]);
        let result = data_from_states(&cfg, &entry_states, &accesses, geometry, false, 16);
        assert_eq!(result.regions.len(), 1);
        assert!(!result.regions[0].lines.contains(&geometry.line_address(0)));
        assert!(result.regions[0].lines.contains(&geometry.line_address(1)));
    }

    #[test]
    fn a_line_present_at_entry_must_survive_the_block() {
        let geometry = geometry(2);
        let mut state = geometry.cold();
        state.access(0, geometry.ways, geometry.sets);
        let accesses = [line_access(1), line_access(2)];
        assert!(!block_preserves_line(
            &accesses,
            &state,
            geometry,
            AccessMode::Instruction,
            0
        ));
    }
}
