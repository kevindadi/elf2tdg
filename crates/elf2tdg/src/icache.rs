//! Instruction-cache analysis.
//!
//! The analysis simulates the modeled LRU instruction cache along each
//! function CFG. Each function starts from a cold cache. Distinct concrete
//! cache states reaching a block are tracked up to a configured limit; if the
//! limit is exceeded, the function falls back to an all-miss upper bound.
//!
//! Call-return edges can invalidate the modeled state because the callee's
//! instruction footprint is outside this intra-function analysis. The result
//! is a local fetch-cost estimate, not a whole-program cache bound.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use petgraph::Direction;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::EdgeRef;

use elf2tdg_schema::{Addr, CostRange};

use crate::board_profile::InstructionCacheProfile;
use crate::cfg::{
    CfgBlockCache, CfgBlockCacheLine, CfgCacheInfo, CfgEdgeKind, FunctionCfg, ProgramCfg,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CacheState {
    sets: Vec<Vec<u64>>,
}

impl CacheState {
    fn cold(set_count: usize) -> Self {
        Self {
            sets: vec![Vec::new(); set_count],
        }
    }

    fn access(&mut self, line: u64, ways: usize, set_count: u64) -> bool {
        let set = usize::try_from(line % set_count).unwrap_or(0);
        let lines = &mut self.sets[set];
        if let Some(position) = lines.iter().position(|cached| *cached == line) {
            lines.remove(position);
            lines.insert(0, line);
            true
        } else {
            lines.insert(0, line);
            lines.truncate(ways);
            false
        }
    }
}

struct CacheModel {
    sets: u64,
    ways: usize,
    line_bytes: u64,
    miss_penalty: u32,
    invalidate_on_call: bool,
    max_states: usize,
}

impl CacheModel {
    fn from_profile(profile: &InstructionCacheProfile) -> Self {
        Self {
            sets: profile.sets(),
            ways: usize::try_from(profile.ways()).unwrap_or(usize::MAX),
            line_bytes: u64::from(profile.line_bytes()),
            miss_penalty: profile.miss_penalty(),
            invalidate_on_call: profile.invalidate_on_call(),
            max_states: profile.max_states(),
        }
    }

    fn line_of(&self, address: u64) -> u64 {
        address / self.line_bytes
    }

    fn line_address(&self, line: u64) -> u64 {
        line.saturating_mul(self.line_bytes)
    }

    fn cold_state(&self) -> CacheState {
        CacheState::cold(usize::try_from(self.sets).unwrap_or(usize::MAX))
    }
}

#[derive(Clone)]
struct StateResult {
    state: CacheState,
    misses: u32,
    hits_by_line: BTreeMap<u64, u32>,
}

fn block_line_accesses(block: &crate::cfg::CfgBlock, model: &CacheModel) -> Vec<u64> {
    let mut accesses = Vec::new();
    for instruction in &block.instructions {
        if instruction.size == 0 {
            continue;
        }
        let first = model.line_of(instruction.address);
        let last = model.line_of(
            instruction
                .address
                .saturating_add(u64::from(instruction.size).saturating_sub(1)),
        );
        for line in first..=last {
            accesses.push(line);
        }
    }
    accesses
}

fn simulate(accesses: &[u64], state: &CacheState, model: &CacheModel) -> StateResult {
    let mut state = state.clone();
    let mut misses = 0_u32;
    let mut hits_by_line = BTreeMap::new();
    for line in accesses {
        let hit = state.access(*line, model.ways, model.sets);
        if hit {
            *hits_by_line.entry(*line).or_insert(0) += 1;
        } else {
            misses = misses.saturating_add(1);
        }
    }
    StateResult {
        state,
        misses,
        hits_by_line,
    }
}

/// Runs instruction-cache analysis over every function in `program`.
///
/// The analysis mutates block cycle ranges by adding modeled miss penalties and
/// attaches per-block cache metadata. It returns program-level cache metadata.
#[must_use]
pub(crate) fn analyze_program(
    program: &mut ProgramCfg,
    profile: &InstructionCacheProfile,
) -> CfgCacheInfo {
    let model = CacheModel::from_profile(profile);
    let mut info = CfgCacheInfo {
        model: format!("instruction-{}", profile.replacement_name()),
        size: profile.size(),
        line_bytes: profile.line_bytes(),
        ways: profile.ways(),
        sets: profile.sets(),
        miss_penalty: profile.miss_penalty(),
        entry_state: "cold".to_owned(),
        invalidate_on_call: profile.invalidate_on_call(),
        max_states: profile.max_states(),
        functions_analyzed: 0,
        functions_fallback: 0,
        blocks_analyzed: 0,
        blocks_fallback: 0,
        caveats: vec![
            "Instruction-cache analysis assumes a cold cache at each function entry.".to_owned(),
            "Prefetch, data caches, bus contention and inter-function cache state are not modeled."
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
}

#[allow(clippy::too_many_lines)]
fn analyze_function(cfg: &mut FunctionCfg, model: &CacheModel) -> FunctionResult {
    let Some(entry) = cfg.entry else {
        return FunctionResult {
            fallback: false,
            blocks: 0,
        };
    };
    let nodes: Vec<NodeIndex> = cfg.blocks_by_address.values().copied().collect();
    let accesses: BTreeMap<NodeIndex, Vec<u64>> = nodes
        .iter()
        .map(|node| (*node, block_line_accesses(&cfg.graph[*node], model)))
        .collect();
    let mut entry_states: BTreeMap<NodeIndex, BTreeSet<CacheState>> = BTreeMap::new();
    let mut results: BTreeMap<NodeIndex, Vec<StateResult>> = BTreeMap::new();
    let mut processed: BTreeSet<(NodeIndex, CacheState)> = BTreeSet::new();
    let mut queue: VecDeque<(NodeIndex, CacheState)> = VecDeque::new();
    let cold = model.cold_state();
    entry_states.entry(entry).or_default().insert(cold.clone());
    queue.push_back((entry, cold));

    while let Some((node, state)) = queue.pop_front() {
        if !processed.insert((node, state.clone())) {
            continue;
        }
        let block_accesses = accesses.get(&node).map_or(&[][..], Vec::as_slice);
        let result = simulate(block_accesses, &state, model);
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
                return fallback_function(cfg, &accesses, model);
            }
            if target_states.insert(next.clone()) {
                queue.push_back((target, next));
            }
        }
    }

    let mut block_count = 0_u32;
    for node in nodes {
        let Some(node_results) = results.get(&node) else {
            continue;
        };
        let Some(block_accesses) = accesses.get(&node) else {
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
        let mut access_counts: BTreeMap<u64, u32> = BTreeMap::new();
        for line in block_accesses {
            *access_counts.entry(*line).or_insert(0) += 1;
        }
        let mut hits: BTreeMap<u64, (u32, u32)> = BTreeMap::new();
        for result in node_results {
            for line in access_counts.keys() {
                let value = result.hits_by_line.get(line).copied().unwrap_or(0);
                let entry = hits.entry(*line).or_insert((u32::MAX, 0));
                entry.0 = entry.0.min(value);
                entry.1 = entry.1.max(value);
            }
        }
        let lines = access_counts
            .iter()
            .map(|(line, accesses)| {
                let (hits_min, hits_max) = hits.get(line).copied().unwrap_or((0, 0));
                CfgBlockCacheLine {
                    line: Addr::new(model.line_address(*line)),
                    accesses: *accesses,
                    classification: if hits_min == *accesses {
                        crate::cfg::CfgCacheLineClass::AlwaysHit
                    } else if hits_max == 0 {
                        crate::cfg::CfgCacheLineClass::AlwaysMiss
                    } else {
                        crate::cfg::CfgCacheLineClass::MayHit
                    },
                    hits_min,
                    hits_max,
                    misses_min: accesses.saturating_sub(hits_max),
                    misses_max: accesses.saturating_sub(hits_min),
                }
            })
            .collect();
        let block = &mut cfg.graph[node];
        block.cache = Some(CfgBlockCache {
            fetches: u32::try_from(block_accesses.len()).unwrap_or(u32::MAX),
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
        block_count = block_count.saturating_add(1);
    }
    FunctionResult {
        fallback: false,
        blocks: block_count,
    }
}

fn fallback_function(
    cfg: &mut FunctionCfg,
    accesses: &BTreeMap<NodeIndex, Vec<u64>>,
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
    let mut blocks = 0_u32;
    for node in reachable {
        let Some(line_accesses) = accesses.get(&node) else {
            continue;
        };
        let mut access_counts: BTreeMap<u64, u32> = BTreeMap::new();
        for line in line_accesses {
            *access_counts.entry(*line).or_insert(0) += 1;
        }
        let lines = access_counts
            .iter()
            .map(|(line, accesses)| CfgBlockCacheLine {
                line: Addr::new(model.line_address(*line)),
                accesses: *accesses,
                classification: crate::cfg::CfgCacheLineClass::AlwaysMiss,
                hits_min: 0,
                hits_max: 0,
                misses_min: *accesses,
                misses_max: *accesses,
            })
            .collect();
        let fetches = u32::try_from(line_accesses.len()).unwrap_or(u32::MAX);
        let block = &mut cfg.graph[node];
        block.cache = Some(CfgBlockCache {
            fetches,
            misses_min: fetches,
            misses_max: fetches,
            entry_states: 0,
            fallback: true,
            lines,
        });
        add_penalty(&mut block.cycles, fetches, fetches, model.miss_penalty);
        blocks = blocks.saturating_add(1);
    }
    FunctionResult {
        fallback: true,
        blocks,
    }
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
    use super::{CacheModel, CacheState, analyze_function};
    use crate::board_profile::BoardProfile;
    use crate::cfg::{
        CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgInstruction, CfgTerminator, FunctionCfg,
    };
    use elf2tdg_schema::CostRange;

    fn model() -> CacheModel {
        let profile = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:icache-test"
arch = "thumb"
cpu = "cortex-m7"

[instruction_cache]
size = 32
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 16
"#,
        )
        .expect("valid cache profile");
        CacheModel::from_profile(profile.instruction_cache().expect("cache profile"))
    }

    #[test]
    fn lru_access_classifies_hits_and_misses() {
        let model = model();
        let mut state = CacheState::cold(usize::try_from(model.sets).expect("sets"));
        assert!(!state.access(0, model.ways, model.sets));
        assert!(!state.access(1, model.ways, model.sets));
        assert!(!state.access(2, model.ways, model.sets));
        assert!(!state.access(0, model.ways, model.sets));
        assert!(!state.access(1, model.ways, model.sets));
    }

    fn instruction(address: u64, is_jump: bool) -> CfgInstruction {
        CfgInstruction {
            address,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "b".to_owned(),
            operands: String::new(),
            text: "b".to_owned(),
            is_call: false,
            is_jump,
            is_return: false,
            is_conditional: false,
            direct_target: None,
            indirect: None,
            cycles: Some(CostRange::exact(1.0)),
            source: None,
        }
    }

    #[test]
    fn analyzes_loop_states_and_penalties() {
        let model = model();
        let mut cfg = FunctionCfg::build(
            vec![CfgBlockDraft {
                address: 0x1000,
                size: 2,
                instructions: vec![instruction(0x1000, true)],
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
        );
        let result = analyze_function(&mut cfg, &model);
        assert!(!result.fallback);
        let block = cfg
            .blocks_by_address
            .values()
            .map(|node| &cfg.graph[*node])
            .next()
            .expect("block");
        let cache = block.cache.as_ref().expect("cache result");
        assert_eq!(cache.entry_states, 2, "cold miss and warm hit states");
        assert_eq!(cache.misses_min, 0);
        assert_eq!(cache.misses_max, 1);
        let cycles = block.cycles.expect("block cycles");
        assert_eq!(cycles.min, 1.0);
        assert_eq!(cycles.max, 11.0);
    }
}
