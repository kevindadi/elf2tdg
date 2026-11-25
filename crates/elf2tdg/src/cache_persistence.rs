//! Cache-line persistence classification for LRU instruction and data caches.
//!
//! Persistence is proved with a per-set working-set check over a natural loop:
//! when the distinct lines accessed by the loop in each cache set fit in the
//! configured associativity, and the loop contains no call-return
//! invalidation, a line loaded by the loop remains resident until the loop is
//! left. IPET can then charge at most one miss per line per loop entry instead
//! of the per-block worst case on every iteration.
//!
//! The proof is deliberately local. It does not model inter-function state,
//! prefetch, dirty-line writeback or aliasing beyond the concrete line
//! addresses recorded by the cache analyses.

use std::collections::{BTreeMap, BTreeSet};

use petgraph::stable_graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};

use elf2tdg_schema::{Addr, BlockId, FunctionId};

use crate::cache_state::CacheGeometry;
use crate::cfg::{CfgCachePersistenceRegion, CfgEdgeKind, FunctionCfg};

/// One natural loop in which a set of lines is persistent.
#[derive(Clone, Debug)]
pub(crate) struct PersistenceRegion {
    /// Loop header.
    pub(crate) header: BlockId,
    /// Reachable blocks in the natural loop.
    pub(crate) blocks: Vec<NodeIndex>,
    /// Persistent line start addresses.
    pub(crate) lines: BTreeSet<u64>,
}

/// Persistence result for one function.
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
struct LineUse {
    accesses: u32,
    reads: u32,
    writes: u32,
}

#[derive(Clone, Copy, Debug)]
enum AccessKind {
    Instruction,
    Data { write_allocate: bool },
}

impl AccessKind {
    fn data(self) -> Option<bool> {
        match self {
            Self::Instruction => None,
            Self::Data { write_allocate } => Some(write_allocate),
        }
    }
}

/// Classifies persistent instruction-cache lines in every natural loop of `cfg`.
pub(crate) fn instruction(cfg: &FunctionCfg, geometry: CacheGeometry) -> PersistenceAnalysis {
    analyze(cfg, geometry, AccessKind::Instruction)
}

/// Classifies persistent data-cache lines in every natural loop of `cfg`.
pub(crate) fn data(
    cfg: &FunctionCfg,
    geometry: CacheGeometry,
    write_allocate: bool,
) -> PersistenceAnalysis {
    analyze(cfg, geometry, AccessKind::Data { write_allocate })
}

fn analyze(cfg: &FunctionCfg, geometry: CacheGeometry, kind: AccessKind) -> PersistenceAnalysis {
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
        let Some(uses) = loop_line_uses(cfg, &blocks, kind) else {
            continue;
        };
        let mut per_set: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for (line, use_) in &uses {
            if kind
                .data()
                .is_some_and(|write_allocate| !write_allocate && use_.reads == 0)
            {
                // A store miss does not install a line when allocation is
                // disabled, so a purely written line does not occupy a way.
                continue;
            }
            let set = (line / geometry.line_bytes) % geometry.sets;
            per_set.entry(set).or_default().insert(*line);
        }
        if per_set.values().any(|lines| lines.len() > geometry.ways) {
            continue;
        }
        let lines: BTreeSet<u64> = uses
            .iter()
            .filter(|(_, use_)| {
                !kind
                    .data()
                    .is_some_and(|write_allocate| !write_allocate && use_.writes > 0)
            })
            .map(|(line, _)| *line)
            .collect();
        if lines.is_empty() {
            continue;
        }
        result.loops_persistent = result.loops_persistent.saturating_add(1);
        result.regions.push(PersistenceRegion {
            header: cfg.graph[header].id.clone(),
            blocks,
            lines,
        });
    }
    result
}

fn loop_line_uses(
    cfg: &FunctionCfg,
    blocks: &[NodeIndex],
    kind: AccessKind,
) -> Option<BTreeMap<u64, LineUse>> {
    let mut uses: BTreeMap<u64, LineUse> = BTreeMap::new();
    for node in blocks {
        let block = &cfg.graph[*node];
        match kind {
            AccessKind::Instruction => {
                let cache = block.cache.as_ref()?;
                if cache.fallback {
                    return None;
                }
                for line in &cache.lines {
                    let entry = uses.entry(line.line.get()).or_insert(LineUse {
                        accesses: 0,
                        reads: 0,
                        writes: 0,
                    });
                    entry.accesses = entry.accesses.saturating_add(line.accesses);
                }
            }
            AccessKind::Data { .. } => {
                let cache = block.data_cache.as_ref()?;
                if cache.fallback || cache.unresolved_memory_accesses > 0 {
                    return None;
                }
                for line in &cache.lines {
                    let entry = uses.entry(line.line.get()).or_insert(LineUse {
                        accesses: 0,
                        reads: 0,
                        writes: 0,
                    });
                    entry.accesses = entry.accesses.saturating_add(line.accesses);
                    entry.reads = entry.reads.saturating_add(line.reads);
                    entry.writes = entry.writes.saturating_add(line.writes);
                }
            }
        }
    }
    Some(uses)
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
        "Persistence uses a per-set working-set check: a line is persistent in a natural loop when the loop's distinct lines per set fit in the cache and the loop contains no call-return invalidation.".to_owned(),
        "Persistence is proved per natural loop from concrete line addresses; inter-function cache state, prefetch, line splitting and address aliasing are not modeled.".to_owned(),
    ];
    if data_cache {
        caveats.push(
            "With write_allocate = false, purely written lines do not occupy a way and lines with any write are not claimed persistent; non-allocating store misses can repeat every iteration.".to_owned(),
        );
    }
    caveats
}

#[cfg(test)]
mod tests {
    use super::{AccessKind, analyze};
    use crate::cache_state::CacheGeometry;
    use crate::cfg::{
        CfgBlockCache, CfgBlockCacheLine, CfgBlockDataCache, CfgBlockDataCacheLine, CfgBlockDraft,
        CfgCacheLineClass, CfgEdgeDraft, CfgEdgeKind, CfgInstruction, CfgTerminator, FunctionCfg,
    };
    use elf2tdg_schema::{Addr, CostRange};

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

    fn loop_cfg() -> FunctionCfg {
        FunctionCfg::build(
            vec![CfgBlockDraft {
                address: 0x1000,
                size: 2,
                instructions: vec![instruction(0x1000)],
                calls: Vec::new(),
                cycles: Some(CostRange::exact(1.0)),
                terminator: CfgTerminator::Jump,
            }],
            vec![CfgEdgeDraft {
                from: 0x1000,
                to: 0x1000,
                kind: CfgEdgeKind::Jump,
                site: 0x1000,
                conditional: false,
            }],
            Some(0x1000),
        )
    }

    fn set_icache(cfg: &mut FunctionCfg, lines: &[(u64, u32)]) {
        let node = cfg.blocks_by_address[&0x1000];
        let total = lines.iter().map(|(_, misses)| *misses).sum();
        let lines = lines
            .iter()
            .map(|(line, misses)| CfgBlockCacheLine {
                line: Addr::new(*line),
                accesses: 1,
                classification: CfgCacheLineClass::MayHit,
                hits_min: 0,
                hits_max: 0,
                misses_min: *misses,
                misses_max: *misses,
            })
            .collect();
        cfg.graph[node].cache = Some(CfgBlockCache {
            fetches: 1,
            misses_min: 0,
            misses_max: total,
            entry_states: 2,
            fallback: false,
            lines,
        });
    }

    fn set_dcache(cfg: &mut FunctionCfg, lines: &[(u64, u32, u32)]) {
        let node = cfg.blocks_by_address[&0x1000];
        let total = lines.iter().map(|(_, _, misses)| *misses).sum();
        let lines = lines
            .iter()
            .map(|(line, reads, writes)| CfgBlockDataCacheLine {
                line: Addr::new(*line),
                accesses: reads + writes,
                reads: *reads,
                writes: *writes,
                classification: CfgCacheLineClass::MayHit,
                hits_min: 0,
                hits_max: 0,
                misses_min: *reads + *writes,
                misses_max: *reads + *writes,
            })
            .collect();
        cfg.graph[node].data_cache = Some(CfgBlockDataCache {
            memory_accesses: 1,
            resolved_memory_accesses: 1,
            unresolved_memory_accesses: 0,
            line_accesses: 1,
            misses_min: 0,
            misses_max: total,
            entry_states: 2,
            fallback: false,
            lines,
        });
    }

    fn geometry(ways: usize) -> CacheGeometry {
        CacheGeometry {
            line_bytes: 16,
            sets: 1,
            ways,
        }
    }

    #[test]
    fn working_set_must_fit_the_cache_set() {
        let mut cfg = loop_cfg();
        set_icache(&mut cfg, &[(0x1000, 1), (0x1010, 1)]);
        assert_eq!(
            analyze(&cfg, geometry(2), AccessKind::Instruction)
                .regions
                .len(),
            1
        );
        assert!(
            analyze(&cfg, geometry(1), AccessKind::Instruction)
                .regions
                .is_empty()
        );
    }

    #[test]
    fn call_return_edges_block_loop_persistence() {
        let mut cfg = loop_cfg();
        set_icache(&mut cfg, &[(0x1000, 1)]);
        let edge = cfg.graph.edge_weights_mut().next().expect("edge");
        edge.kind = CfgEdgeKind::CallReturn;
        assert!(
            analyze(&cfg, geometry(2), AccessKind::Instruction)
                .regions
                .is_empty()
        );
    }

    #[test]
    fn non_allocating_write_lines_are_not_persistent() {
        let mut cfg = loop_cfg();
        set_dcache(&mut cfg, &[(0x2000, 1, 0), (0x2010, 0, 1)]);
        let analysis = analyze(
            &cfg,
            geometry(2),
            AccessKind::Data {
                write_allocate: false,
            },
        );
        assert_eq!(analysis.regions.len(), 1);
        assert!(analysis.regions[0].lines.contains(&0x2000));
        assert!(!analysis.regions[0].lines.contains(&0x2010));
        assert!(
            analyze(
                &cfg,
                geometry(2),
                AccessKind::Data {
                    write_allocate: true
                }
            )
            .regions[0]
                .lines
                .contains(&0x2010)
        );
    }
}
