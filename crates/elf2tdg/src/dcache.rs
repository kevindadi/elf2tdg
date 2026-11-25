//! Data-cache analysis.
//!
//! The analysis simulates the modeled LRU data cache along each function CFG.
//! Each function starts from a cold cache. Distinct concrete cache states
//! reaching a block are tracked up to a configured limit; if the limit is
//! exceeded, the function falls back to an all-miss bound for the resolved
//! accesses.
//!
//! Only accesses whose addresses are statically resolved are modeled. Stack,
//! indexed and otherwise unknown accesses are counted in the metadata but do
//! not contribute miss penalties. Call-return edges can conservatively clear
//! the modeled state because callee data accesses are outside this local
//! analysis.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use petgraph::Direction;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::EdgeRef;

use elf2tdg_schema::{Addr, CostRange};

use crate::board_profile::DataCacheProfile;
use crate::cache_state::{
    CacheAccess, CacheAccessKind, CacheGeometry, CacheSimulation, CacheState, simulate,
};
use crate::cfg::{
    CfgBlockDataCache, CfgBlockDataCacheLine, CfgCacheLineClass, CfgDataCacheInfo, CfgEdgeKind,
    FunctionCfg, ProgramCfg,
};

struct CacheModel {
    sets: u64,
    ways: usize,
    line_bytes: u64,
    miss_penalty: u32,
    write_allocate: bool,
    invalidate_on_call: bool,
    max_states: usize,
}

impl CacheModel {
    fn from_profile(profile: &DataCacheProfile) -> Self {
        Self {
            sets: profile.sets(),
            ways: usize::try_from(profile.ways()).unwrap_or(usize::MAX),
            line_bytes: u64::from(profile.line_bytes()),
            miss_penalty: profile.miss_penalty(),
            write_allocate: profile.write_allocate(),
            invalidate_on_call: profile.invalidate_on_call(),
            max_states: profile.max_states(),
        }
    }

    fn geometry(&self) -> CacheGeometry {
        CacheGeometry {
            line_bytes: self.line_bytes,
            sets: self.sets,
            ways: self.ways,
        }
    }

    fn line_address(&self, line: u64) -> u64 {
        self.geometry().line_address(line)
    }

    fn cold_state(&self) -> CacheState {
        self.geometry().cold()
    }
}

struct AccessTrace {
    lines: Vec<CacheAccess>,
    memory_accesses: u32,
    resolved_memory_accesses: u32,
    unresolved_memory_accesses: u32,
}

impl AccessTrace {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            memory_accesses: 0,
            resolved_memory_accesses: 0,
            unresolved_memory_accesses: 0,
        }
    }

    fn add(&mut self, access: &crate::cfg::CfgMemoryAccess, geometry: CacheGeometry) {
        self.memory_accesses = self.memory_accesses.saturating_add(1);
        let Some(address) = access.address else {
            self.unresolved_memory_accesses = self.unresolved_memory_accesses.saturating_add(1);
            return;
        };
        self.resolved_memory_accesses = self.resolved_memory_accesses.saturating_add(1);
        let width = u64::from(access.width.max(1));
        let first = geometry.line_of(address.get());
        let last = geometry.line_of(address.get().saturating_add(width.saturating_sub(1)));
        for line in first..=last {
            self.lines.push(CacheAccess {
                line,
                kind: access.kind.into(),
            });
        }
    }

    fn line_accesses(&self) -> u32 {
        u32::try_from(self.lines.len()).unwrap_or(u32::MAX)
    }
}

fn block_accesses(block: &crate::cfg::CfgBlock, geometry: CacheGeometry) -> AccessTrace {
    let mut trace = AccessTrace::new();
    for instruction in &block.instructions {
        for access in &instruction.memory_accesses {
            trace.add(access, geometry);
        }
    }
    trace
}

/// Runs data-cache analysis over every function in `program`.
///
/// The analysis mutates block cycle ranges by adding modeled miss penalties and
/// attaches per-block data-cache metadata. It returns program-level metadata.
#[must_use]
pub(crate) fn analyze_program(
    program: &mut ProgramCfg,
    profile: &DataCacheProfile,
) -> CfgDataCacheInfo {
    let model = CacheModel::from_profile(profile);
    let mut info = CfgDataCacheInfo {
        model: format!("data-{}", profile.replacement_name()),
        size: profile.size(),
        line_bytes: profile.line_bytes(),
        ways: profile.ways(),
        sets: profile.sets(),
        miss_penalty: profile.miss_penalty(),
        write_allocate: profile.write_allocate(),
        entry_state: "cold-per-function".to_owned(),
        invalidate_on_call: profile.invalidate_on_call(),
        max_states: profile.max_states(),
        memory_accesses: 0,
        resolved_memory_accesses: 0,
        unresolved_memory_accesses: 0,
        line_accesses: 0,
        functions_analyzed: 0,
        functions_fallback: 0,
        blocks_analyzed: 0,
        blocks_fallback: 0,
        caveats: vec![
            "Data-cache analysis assumes a cold cache at each function entry.".to_owned(),
            "Only statically resolved data addresses are modeled; unresolved stack, indexed and register-dependent accesses are counted but excluded from miss penalties and state propagation, so modeled hits remain optimistic."
                .to_owned(),
            "Base-register address recovery is bounded and not path-sensitive."
                .to_owned(),
            "All resolved addresses are treated as cacheable; memory-region cacheability attributes are not modeled."
                .to_owned(),
            "Dirty-line writeback, store buffers, prefetch and inter-function data-cache state are not modeled."
                .to_owned(),
            "Miss penalties are added to the base block cost; configured fetch wait states are not replaced."
                .to_owned(),
        ],
    };
    for function in &mut program.functions {
        if function.cfg.blocks_by_address.is_empty() {
            continue;
        }
        let result = analyze_function(&mut function.cfg, &model);
        info.memory_accesses = info.memory_accesses.saturating_add(result.memory_accesses);
        info.resolved_memory_accesses = info
            .resolved_memory_accesses
            .saturating_add(result.resolved_memory_accesses);
        info.unresolved_memory_accesses = info
            .unresolved_memory_accesses
            .saturating_add(result.unresolved_memory_accesses);
        info.line_accesses = info.line_accesses.saturating_add(result.line_accesses);
        if result.fallback {
            info.functions_fallback = info.functions_fallback.saturating_add(1);
            info.blocks_fallback = info.blocks_fallback.saturating_add(result.blocks);
        } else {
            info.functions_analyzed = info.functions_analyzed.saturating_add(1);
            info.blocks_analyzed = info.blocks_analyzed.saturating_add(result.blocks);
        }
    }
    info
}

struct FunctionResult {
    fallback: bool,
    blocks: u32,
    memory_accesses: u32,
    resolved_memory_accesses: u32,
    unresolved_memory_accesses: u32,
    line_accesses: u32,
}

impl FunctionResult {
    fn empty() -> Self {
        Self {
            fallback: false,
            blocks: 0,
            memory_accesses: 0,
            resolved_memory_accesses: 0,
            unresolved_memory_accesses: 0,
            line_accesses: 0,
        }
    }
}

#[allow(clippy::too_many_lines)]
fn analyze_function(cfg: &mut FunctionCfg, model: &CacheModel) -> FunctionResult {
    let Some(entry) = cfg.entry else {
        return FunctionResult::empty();
    };
    let nodes: Vec<NodeIndex> = cfg.blocks_by_address.values().copied().collect();
    let geometry = model.geometry();
    let traces: BTreeMap<NodeIndex, AccessTrace> = nodes
        .iter()
        .map(|node| (*node, block_accesses(&cfg.graph[*node], geometry)))
        .collect();
    let mut entry_states: BTreeMap<NodeIndex, BTreeSet<CacheState>> = BTreeMap::new();
    let mut results: BTreeMap<NodeIndex, Vec<CacheSimulation>> = BTreeMap::new();
    let mut processed: BTreeSet<(NodeIndex, CacheState)> = BTreeSet::new();
    let mut queue: VecDeque<(NodeIndex, CacheState)> = VecDeque::new();
    let cold = model.cold_state();
    entry_states.entry(entry).or_default().insert(cold.clone());
    queue.push_back((entry, cold));

    while let Some((node, state)) = queue.pop_front() {
        if !processed.insert((node, state.clone())) {
            continue;
        }
        let trace = traces.get(&node).expect("trace for CFG node");
        let result = simulate(&trace.lines, &state, geometry, model.write_allocate);
        results.entry(node).or_default().push(result.clone());
        for edge in cfg.graph.edges_directed(node, Direction::Outgoing) {
            let target = edge.target();
            let next = if edge.weight().kind == CfgEdgeKind::CallReturn && model.invalidate_on_call
            {
                model.cold_state()
            } else {
                result.state.clone()
            };
            let target_states = entry_states.entry(target).or_default();
            if target_states.len() >= model.max_states && !target_states.contains(&next) {
                return fallback_function(cfg, &traces, model);
            }
            if target_states.insert(next.clone()) {
                queue.push_back((target, next));
            }
        }
    }

    let mut summary = FunctionResult::empty();
    for node in nodes {
        let Some(node_results) = results.get(&node) else {
            continue;
        };
        let Some(trace) = traces.get(&node) else {
            continue;
        };
        let misses_min = node_results
            .iter()
            .map(|result| result.misses)
            .min()
            .unwrap_or(0);
        let misses_max = node_results
            .iter()
            .map(|result| result.misses)
            .max()
            .unwrap_or(0);
        let (access_counts, read_counts, write_counts) = line_counts(trace);
        let lines = line_metadata(
            node_results,
            &access_counts,
            &read_counts,
            &write_counts,
            model,
            false,
        );
        let line_accesses = trace.line_accesses();
        let block = &mut cfg.graph[node];
        block.data_cache = Some(CfgBlockDataCache {
            memory_accesses: trace.memory_accesses,
            resolved_memory_accesses: trace.resolved_memory_accesses,
            unresolved_memory_accesses: trace.unresolved_memory_accesses,
            line_accesses,
            misses_min,
            misses_max,
            entry_states: u32::try_from(node_results.len()).unwrap_or(u32::MAX),
            fallback: false,
            lines,
        });
        add_penalty(
            &mut block.cycles,
            misses_min,
            misses_max,
            model.miss_penalty,
        );
        summary.blocks = summary.blocks.saturating_add(1);
        summary.memory_accesses = summary
            .memory_accesses
            .saturating_add(trace.memory_accesses);
        summary.resolved_memory_accesses = summary
            .resolved_memory_accesses
            .saturating_add(trace.resolved_memory_accesses);
        summary.unresolved_memory_accesses = summary
            .unresolved_memory_accesses
            .saturating_add(trace.unresolved_memory_accesses);
        summary.line_accesses = summary.line_accesses.saturating_add(line_accesses);
    }
    summary
}

fn line_counts(
    trace: &AccessTrace,
) -> (BTreeMap<u64, u32>, BTreeMap<u64, u32>, BTreeMap<u64, u32>) {
    let mut accesses = BTreeMap::new();
    let mut reads = BTreeMap::new();
    let mut writes = BTreeMap::new();
    for access in &trace.lines {
        *accesses.entry(access.line).or_insert(0) += 1;
        match access.kind {
            CacheAccessKind::Read => {
                *reads.entry(access.line).or_insert(0) += 1;
            }
            CacheAccessKind::Write => {
                *writes.entry(access.line).or_insert(0) += 1;
            }
            CacheAccessKind::ReadWrite => {
                *reads.entry(access.line).or_insert(0) += 1;
                *writes.entry(access.line).or_insert(0) += 1;
            }
            CacheAccessKind::Fetch => {}
        }
    }
    (accesses, reads, writes)
}

fn line_metadata(
    results: &[CacheSimulation],
    access_counts: &BTreeMap<u64, u32>,
    read_counts: &BTreeMap<u64, u32>,
    write_counts: &BTreeMap<u64, u32>,
    model: &CacheModel,
    fallback: bool,
) -> Vec<CfgBlockDataCacheLine> {
    if fallback {
        return access_counts
            .iter()
            .map(|(line, accesses)| CfgBlockDataCacheLine {
                line: Addr::new(model.line_address(*line)),
                accesses: *accesses,
                reads: read_counts.get(line).copied().unwrap_or(0),
                writes: write_counts.get(line).copied().unwrap_or(0),
                classification: CfgCacheLineClass::AlwaysMiss,
                hits_min: 0,
                hits_max: 0,
                misses_min: *accesses,
                misses_max: *accesses,
            })
            .collect();
    }
    let mut hits: BTreeMap<u64, (u32, u32)> = BTreeMap::new();
    for result in results {
        for line in access_counts.keys() {
            let value = result.hits_by_line.get(line).copied().unwrap_or(0);
            let entry = hits.entry(*line).or_insert((u32::MAX, 0));
            entry.0 = entry.0.min(value);
            entry.1 = entry.1.max(value);
        }
    }
    access_counts
        .iter()
        .map(|(line, accesses)| {
            let (hits_min, hits_max) = hits.get(line).copied().unwrap_or((0, 0));
            CfgBlockDataCacheLine {
                line: Addr::new(model.line_address(*line)),
                accesses: *accesses,
                reads: read_counts.get(line).copied().unwrap_or(0),
                writes: write_counts.get(line).copied().unwrap_or(0),
                classification: if hits_min == *accesses {
                    CfgCacheLineClass::AlwaysHit
                } else if hits_max == 0 {
                    CfgCacheLineClass::AlwaysMiss
                } else {
                    CfgCacheLineClass::MayHit
                },
                hits_min,
                hits_max,
                misses_min: accesses.saturating_sub(hits_max),
                misses_max: accesses.saturating_sub(hits_min),
            }
        })
        .collect()
}

fn fallback_function(
    cfg: &mut FunctionCfg,
    traces: &BTreeMap<NodeIndex, AccessTrace>,
    model: &CacheModel,
) -> FunctionResult {
    let reachable_ids: BTreeSet<_> = crate::cfg_graph::analyze(cfg)
        .reachable
        .into_iter()
        .collect();
    let reachable: Vec<NodeIndex> = cfg
        .blocks_by_address
        .values()
        .copied()
        .filter(|node| reachable_ids.contains(&cfg.graph[*node].id))
        .collect();
    let mut summary = FunctionResult {
        fallback: true,
        ..FunctionResult::empty()
    };
    for node in reachable {
        let Some(trace) = traces.get(&node) else {
            continue;
        };
        let (access_counts, read_counts, write_counts) = line_counts(trace);
        let lines = line_metadata(
            &[],
            &access_counts,
            &read_counts,
            &write_counts,
            model,
            true,
        );
        let line_accesses = trace.line_accesses();
        let block = &mut cfg.graph[node];
        block.data_cache = Some(CfgBlockDataCache {
            memory_accesses: trace.memory_accesses,
            resolved_memory_accesses: trace.resolved_memory_accesses,
            unresolved_memory_accesses: trace.unresolved_memory_accesses,
            line_accesses,
            misses_min: line_accesses,
            misses_max: line_accesses,
            entry_states: 0,
            fallback: true,
            lines,
        });
        add_penalty(
            &mut block.cycles,
            line_accesses,
            line_accesses,
            model.miss_penalty,
        );
        summary.blocks = summary.blocks.saturating_add(1);
        summary.memory_accesses = summary
            .memory_accesses
            .saturating_add(trace.memory_accesses);
        summary.resolved_memory_accesses = summary
            .resolved_memory_accesses
            .saturating_add(trace.resolved_memory_accesses);
        summary.unresolved_memory_accesses = summary
            .unresolved_memory_accesses
            .saturating_add(trace.unresolved_memory_accesses);
        summary.line_accesses = summary.line_accesses.saturating_add(line_accesses);
    }
    summary
}

#[allow(clippy::cast_precision_loss)]
fn add_penalty(
    cycles: &mut Option<CostRange>,
    misses_min: u32,
    misses_max: u32,
    miss_penalty: u32,
) {
    let Some(cycles) = cycles else {
        return;
    };
    cycles.min += f64::from(misses_min.saturating_mul(miss_penalty));
    cycles.max += f64::from(misses_max.saturating_mul(miss_penalty));
}

#[cfg(test)]
mod tests {
    use super::{CacheModel, analyze_function};
    use crate::board_profile::BoardProfile;
    use crate::cfg::{
        CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgInstruction, CfgMemoryAccess,
        CfgMemoryAccessKind, CfgMemoryResolution, CfgTerminator, FunctionCfg,
    };
    use elf2tdg_schema::{Addr, CostRange};

    fn model(write_allocate: bool) -> CacheModel {
        let profile = BoardProfile::parse_toml(&format!(
            r#"
schema_version = 2
id = "board:dcache-test"
arch = "thumb"
cpu = "cortex-m7"

[data_cache]
size = 64
line_bytes = 32
ways = 2
miss_penalty = 10
write_allocate = {write_allocate}
max_states = 16
"#
        ))
        .expect("valid data-cache profile");
        CacheModel::from_profile(profile.data_cache().expect("data-cache profile"))
    }

    fn access(kind: CfgMemoryAccessKind, address: Option<u64>) -> CfgMemoryAccess {
        CfgMemoryAccess {
            kind,
            address: address.map(Addr::new),
            width: 4,
            resolution: if address.is_some() {
                CfgMemoryResolution::Direct
            } else {
                CfgMemoryResolution::Unresolved
            },
            base: None,
            index: None,
            disp: 0,
        }
    }

    fn instruction(address: u64, accesses: Vec<CfgMemoryAccess>) -> CfgInstruction {
        CfgInstruction {
            address,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "ldr".to_owned(),
            operands: String::new(),
            text: "ldr".to_owned(),
            is_call: false,
            is_jump: false,
            is_return: false,
            is_conditional: false,
            direct_target: None,
            indirect: None,
            memory_accesses: accesses,
            cycles: Some(CostRange::exact(1.0)),
            source: None,
        }
    }

    fn loop_cfg(accesses: Vec<CfgMemoryAccess>) -> FunctionCfg {
        FunctionCfg::build(
            vec![CfgBlockDraft {
                address: 0x1000,
                size: 2,
                instructions: vec![instruction(0x1000, accesses)],
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

    #[test]
    fn classifies_cold_and_warm_loop_accesses() {
        let model = model(true);
        let mut cfg = loop_cfg(vec![access(CfgMemoryAccessKind::Read, Some(0x1000))]);
        let result = analyze_function(&mut cfg, &model);
        assert!(!result.fallback);
        let block = cfg
            .blocks_by_address
            .values()
            .map(|node| &cfg.graph[*node])
            .next()
            .expect("block");
        let cache = block.data_cache.as_ref().expect("data-cache result");
        assert_eq!(cache.memory_accesses, 1);
        assert_eq!(cache.resolved_memory_accesses, 1);
        assert_eq!(cache.unresolved_memory_accesses, 0);
        assert_eq!(cache.entry_states, 2);
        assert_eq!(cache.misses_min, 0);
        assert_eq!(cache.misses_max, 1);
        assert_eq!(
            cache.lines[0].classification,
            crate::cfg::CfgCacheLineClass::MayHit
        );
        let cycles = block.cycles.expect("block cycles");
        assert_eq!(cycles.min, 1.0);
        assert_eq!(cycles.max, 11.0);
    }

    #[test]
    fn write_miss_allocation_changes_later_read_cost() {
        let mut allocating = loop_cfg(vec![
            access(CfgMemoryAccessKind::Write, Some(0x1000)),
            access(CfgMemoryAccessKind::Read, Some(0x1000)),
        ]);
        let result = analyze_function(&mut allocating, &model(true));
        assert!(!result.fallback);
        let block = allocating
            .blocks_by_address
            .values()
            .map(|node| &allocating.graph[*node])
            .next()
            .expect("block");
        assert_eq!(block.data_cache.as_ref().expect("cache").misses_max, 1);
        assert_eq!(block.data_cache.as_ref().expect("cache").lines[0].reads, 1);
        assert_eq!(block.data_cache.as_ref().expect("cache").lines[0].writes, 1);

        let mut non_allocating = loop_cfg(vec![
            access(CfgMemoryAccessKind::Write, Some(0x1000)),
            access(CfgMemoryAccessKind::Read, Some(0x1000)),
        ]);
        analyze_function(&mut non_allocating, &model(false));
        let block = non_allocating
            .blocks_by_address
            .values()
            .map(|node| &non_allocating.graph[*node])
            .next()
            .expect("block");
        assert_eq!(block.data_cache.as_ref().expect("cache").misses_max, 2);
    }

    #[test]
    fn reports_unresolved_accesses_without_penalizing_them() {
        let mut cfg = loop_cfg(vec![access(CfgMemoryAccessKind::Read, None)]);
        let result = analyze_function(&mut cfg, &model(true));
        assert!(!result.fallback);
        let block = cfg
            .blocks_by_address
            .values()
            .map(|node| &cfg.graph[*node])
            .next()
            .expect("block");
        let cache = block.data_cache.as_ref().expect("cache");
        assert_eq!(cache.memory_accesses, 1);
        assert_eq!(cache.resolved_memory_accesses, 0);
        assert_eq!(cache.unresolved_memory_accesses, 1);
        assert_eq!(cache.misses_max, 0);
        assert_eq!(block.cycles.expect("cycles").max, 1.0);
    }
}
