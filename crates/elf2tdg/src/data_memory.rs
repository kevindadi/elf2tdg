//! Region-based data-memory latency analysis.
//!
//! Each resolved data access is mapped to the configured memory regions. The
//! wait cycles are based on the region's data bus width and per-read/write
//! wait-state counts. Unresolved accesses and accesses outside all configured
//! regions are reported but do not add cycles.

use std::collections::BTreeMap;

use elf2tdg_schema::CostRange;

use crate::board_profile::{BoardProfile, MemoryRegion};
use crate::cfg::{
    CfgBlockDataMemory, CfgDataMemoryInfo, CfgDataMemoryRegion, CfgMemoryAccess,
    CfgMemoryAccessKind, FunctionCfg, ProgramCfg,
};

struct DataMemoryModel<'a> {
    regions: &'a [MemoryRegion],
}

#[derive(Default)]
struct RegionContribution {
    accesses: u32,
    bytes: u64,
    read_wait_cycles: u32,
    write_wait_cycles: u32,
}

#[derive(Default)]
struct AccessTiming {
    resolved: bool,
    mapped: bool,
    unmapped: bool,
    read_wait_cycles: u32,
    write_wait_cycles: u32,
    regions: BTreeMap<usize, RegionContribution>,
}

impl DataMemoryModel<'_> {
    fn access(&self, access: &CfgMemoryAccess) -> AccessTiming {
        let Some(address) = access.address else {
            return AccessTiming::default();
        };
        let mut timing = AccessTiming {
            resolved: true,
            ..AccessTiming::default()
        };
        let start = address.get();
        let width = u64::from(access.width.max(1));
        let end = start.saturating_add(width);
        let reads = matches!(
            access.kind,
            CfgMemoryAccessKind::Read | CfgMemoryAccessKind::ReadWrite
        );
        let writes = matches!(
            access.kind,
            CfgMemoryAccessKind::Write | CfgMemoryAccessKind::ReadWrite
        );
        let mut cursor = start;
        while cursor < end {
            let Some((index, region)) = self
                .regions
                .iter()
                .enumerate()
                .find(|(_, region)| region.contains(cursor))
            else {
                timing.unmapped = true;
                cursor = cursor.saturating_add(1);
                continue;
            };
            timing.mapped = true;
            let region_end = region.end().unwrap_or(u64::MAX);
            let fragment_end = end.min(region_end);
            let bytes = fragment_end.saturating_sub(cursor);
            let transactions = bytes.div_ceil(u64::from(region.data_width_bytes()));
            let contribution = timing.regions.entry(index).or_default();
            contribution.accesses = contribution.accesses.saturating_add(1);
            contribution.bytes = contribution.bytes.saturating_add(bytes);
            if reads {
                let cycles = transactions.saturating_mul(u64::from(region.data_read_wait_states()));
                let cycles = u32::try_from(cycles).unwrap_or(u32::MAX);
                contribution.read_wait_cycles =
                    contribution.read_wait_cycles.saturating_add(cycles);
                timing.read_wait_cycles = timing.read_wait_cycles.saturating_add(cycles);
            }
            if writes {
                let cycles =
                    transactions.saturating_mul(u64::from(region.data_write_wait_states()));
                let cycles = u32::try_from(cycles).unwrap_or(u32::MAX);
                contribution.write_wait_cycles =
                    contribution.write_wait_cycles.saturating_add(cycles);
                timing.write_wait_cycles = timing.write_wait_cycles.saturating_add(cycles);
            }
            cursor = fragment_end;
        }
        timing
    }
}

struct BlockSummary {
    data_memory: CfgBlockDataMemory,
}

fn analyze_block(
    block: &crate::cfg::CfgBlock,
    model: &DataMemoryModel<'_>,
) -> Option<BlockSummary> {
    let mut accesses = 0_u32;
    let mut resolved = 0_u32;
    let mut unresolved = 0_u32;
    let mut mapped = 0_u32;
    let mut unmapped = 0_u32;
    let mut read_wait_cycles = 0_u32;
    let mut write_wait_cycles = 0_u32;
    let mut regions: BTreeMap<usize, RegionContribution> = BTreeMap::new();
    for instruction in &block.instructions {
        for access in &instruction.memory_accesses {
            accesses = accesses.saturating_add(1);
            let timing = model.access(access);
            if !timing.resolved {
                unresolved = unresolved.saturating_add(1);
                continue;
            }
            resolved = resolved.saturating_add(1);
            if timing.mapped {
                mapped = mapped.saturating_add(1);
            }
            if timing.unmapped {
                unmapped = unmapped.saturating_add(1);
            }
            read_wait_cycles = read_wait_cycles.saturating_add(timing.read_wait_cycles);
            write_wait_cycles = write_wait_cycles.saturating_add(timing.write_wait_cycles);
            for (index, contribution) in timing.regions {
                let entry = regions.entry(index).or_default();
                entry.accesses = entry.accesses.saturating_add(contribution.accesses);
                entry.bytes = entry.bytes.saturating_add(contribution.bytes);
                entry.read_wait_cycles = entry
                    .read_wait_cycles
                    .saturating_add(contribution.read_wait_cycles);
                entry.write_wait_cycles = entry
                    .write_wait_cycles
                    .saturating_add(contribution.write_wait_cycles);
            }
        }
    }
    if accesses == 0 {
        return None;
    }
    let mut region_views: Vec<CfgDataMemoryRegion> = regions
        .into_iter()
        .filter_map(|(index, contribution)| {
            model.regions.get(index).map(|region| CfgDataMemoryRegion {
                region: region.name().to_owned(),
                kind: region.kind_name().to_owned(),
                accesses: contribution.accesses,
                bytes: contribution.bytes,
                read_wait_cycles: contribution.read_wait_cycles,
                write_wait_cycles: contribution.write_wait_cycles,
            })
        })
        .collect();
    region_views.sort_by(|left, right| left.region.cmp(&right.region));
    let wait_cycles = read_wait_cycles.saturating_add(write_wait_cycles);
    Some(BlockSummary {
        data_memory: CfgBlockDataMemory {
            accesses,
            resolved_accesses: resolved,
            unresolved_accesses: unresolved,
            mapped_accesses: mapped,
            unmapped_accesses: unmapped,
            read_wait_cycles,
            write_wait_cycles,
            wait_cycles,
            regions: region_views,
        },
    })
}

struct FunctionResult {
    analyzed: bool,
    accesses: u32,
    resolved_accesses: u32,
    unresolved_accesses: u32,
    mapped_accesses: u32,
    unmapped_accesses: u32,
    read_wait_cycles: u32,
    write_wait_cycles: u32,
    blocks: u32,
}

impl FunctionResult {
    fn empty() -> Self {
        Self {
            analyzed: false,
            accesses: 0,
            resolved_accesses: 0,
            unresolved_accesses: 0,
            mapped_accesses: 0,
            unmapped_accesses: 0,
            read_wait_cycles: 0,
            write_wait_cycles: 0,
            blocks: 0,
        }
    }
}

fn analyze_function(cfg: &mut FunctionCfg, model: &DataMemoryModel<'_>) -> FunctionResult {
    let nodes: Vec<_> = cfg.blocks_by_address.values().copied().collect();
    let mut summary = FunctionResult::empty();
    for node in nodes {
        let Some(block_summary) = analyze_block(&cfg.graph[node], model) else {
            continue;
        };
        let data_memory = block_summary.data_memory;
        let block = &mut cfg.graph[node];
        add_penalty(&mut block.cycles, data_memory.wait_cycles);
        block.data_memory = Some(data_memory.clone());
        summary.analyzed = true;
        summary.blocks = summary.blocks.saturating_add(1);
        summary.accesses = summary.accesses.saturating_add(data_memory.accesses);
        summary.resolved_accesses = summary
            .resolved_accesses
            .saturating_add(data_memory.resolved_accesses);
        summary.unresolved_accesses = summary
            .unresolved_accesses
            .saturating_add(data_memory.unresolved_accesses);
        summary.mapped_accesses = summary
            .mapped_accesses
            .saturating_add(data_memory.mapped_accesses);
        summary.unmapped_accesses = summary
            .unmapped_accesses
            .saturating_add(data_memory.unmapped_accesses);
        summary.read_wait_cycles = summary
            .read_wait_cycles
            .saturating_add(data_memory.read_wait_cycles);
        summary.write_wait_cycles = summary
            .write_wait_cycles
            .saturating_add(data_memory.write_wait_cycles);
    }
    summary
}

/// Runs data-memory latency analysis over every function in `program`.
///
/// The analysis adds region wait cycles to block cycle ranges and attaches
/// per-block and per-region access metadata.
#[must_use]
pub(crate) fn analyze_program(
    program: &mut ProgramCfg,
    profile: &BoardProfile,
) -> CfgDataMemoryInfo {
    let model = DataMemoryModel {
        regions: profile.data_memory_regions(),
    };
    let mut info = CfgDataMemoryInfo {
        model: "region-data-wait-states".to_owned(),
        functions_analyzed: 0,
        blocks_analyzed: 0,
        accesses: 0,
        resolved_accesses: 0,
        unresolved_accesses: 0,
        mapped_accesses: 0,
        unmapped_accesses: 0,
        read_wait_cycles: 0,
        write_wait_cycles: 0,
        wait_cycles: 0,
        caveats: vec![
            "Only statically resolved data addresses are modeled; unresolved stack, indexed and register-dependent accesses are counted but excluded from wait cycles."
                .to_owned(),
            "Wait states are charged per data_width_bytes transaction; bus contention, arbitration, outstanding requests, write buffers, prefetch and cache hit/miss effects are not modeled."
                .to_owned(),
            "Register-derived addresses use bounded backward recovery and are not path-sensitive."
                .to_owned(),
            "If [data_cache] is also enabled, data-cache miss penalties and data-memory wait cycles are additive and can double-count memory latency."
                .to_owned(),
            "An access spanning memory regions is split at region boundaries."
                .to_owned(),
        ],
    };
    for function in &mut program.functions {
        if function.cfg.blocks_by_address.is_empty() {
            continue;
        }
        let result = analyze_function(&mut function.cfg, &model);
        if !result.analyzed {
            continue;
        }
        info.functions_analyzed = info.functions_analyzed.saturating_add(1);
        info.blocks_analyzed = info.blocks_analyzed.saturating_add(result.blocks);
        info.accesses = info.accesses.saturating_add(result.accesses);
        info.resolved_accesses = info
            .resolved_accesses
            .saturating_add(result.resolved_accesses);
        info.unresolved_accesses = info
            .unresolved_accesses
            .saturating_add(result.unresolved_accesses);
        info.mapped_accesses = info.mapped_accesses.saturating_add(result.mapped_accesses);
        info.unmapped_accesses = info
            .unmapped_accesses
            .saturating_add(result.unmapped_accesses);
        info.read_wait_cycles = info
            .read_wait_cycles
            .saturating_add(result.read_wait_cycles);
        info.write_wait_cycles = info
            .write_wait_cycles
            .saturating_add(result.write_wait_cycles);
        info.wait_cycles = info
            .wait_cycles
            .saturating_add(result.read_wait_cycles)
            .saturating_add(result.write_wait_cycles);
    }
    info
}

#[allow(clippy::cast_precision_loss)]
fn add_penalty(cycles: &mut Option<CostRange>, wait_cycles: u32) {
    let Some(cycles) = cycles else {
        return;
    };
    let cycles_added = f64::from(wait_cycles);
    cycles.min += cycles_added;
    cycles.max += cycles_added;
}

#[cfg(test)]
mod tests {
    use super::{DataMemoryModel, analyze_function};
    use crate::board_profile::BoardProfile;
    use crate::cfg::{
        CfgBlockDraft, CfgInstruction, CfgMemoryAccess, CfgMemoryAccessKind, CfgMemoryResolution,
        CfgTerminator, FunctionCfg,
    };
    use elf2tdg_schema::{Addr, CostRange};

    fn profile() -> &'static str {
        r#"
schema_version = 2
id = "board:data-memory-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[[memory]]
name = "sram"
start = 0x2000_0000
size = 0x1000
kind = "ram"
data_width_bytes = 4
data_read_wait_states = 2
data_write_wait_states = 3

[[memory]]
name = "flash"
start = 0x0800_0000
size = 0x1000
kind = "flash"
data_width_bytes = 4
data_read_wait_states = 5
data_write_wait_states = 5
"#
    }

    fn access(kind: CfgMemoryAccessKind, address: Option<u64>, width: u32) -> CfgMemoryAccess {
        CfgMemoryAccess {
            kind,
            address: address.map(Addr::new),
            width,
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

    fn cfg(accesses: Vec<CfgMemoryAccess>) -> FunctionCfg {
        let instruction = CfgInstruction {
            address: 0x1000,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: "ldr".to_owned(),
            operands: String::new(),
            text: "ldr".to_owned(),
            is_call: false,
            is_jump: false,
            is_return: true,
            is_conditional: false,
            direct_target: None,
            indirect: None,
            memory_accesses: accesses,
            cycles: Some(CostRange::exact(1.0)),
            source: None,
        };
        FunctionCfg::build(
            vec![CfgBlockDraft {
                address: 0x1000,
                size: 2,
                instructions: vec![instruction],
                calls: Vec::new(),
                cycles: Some(CostRange::exact(1.0)),
                terminator: CfgTerminator::Return,
            }],
            Vec::new(),
            Some(0x1000),
        )
    }

    #[test]
    fn charges_region_transactions_and_splits_boundaries() {
        let profile = BoardProfile::parse_toml(profile()).expect("profile");
        let model = DataMemoryModel {
            regions: profile.data_memory_regions(),
        };
        let mut cfg = cfg(vec![
            access(CfgMemoryAccessKind::Read, Some(0x2000_0000), 8),
            access(CfgMemoryAccessKind::Write, Some(0x2000_0000), 4),
            access(CfgMemoryAccessKind::ReadWrite, Some(0x0800_0000), 4),
            access(CfgMemoryAccessKind::Read, None, 4),
            access(CfgMemoryAccessKind::Read, Some(0x3000_0000), 4),
        ]);
        let result = analyze_function(&mut cfg, &model);
        assert!(result.analyzed);
        assert_eq!(result.accesses, 5);
        assert_eq!(result.resolved_accesses, 4);
        assert_eq!(result.unresolved_accesses, 1);
        assert_eq!(result.mapped_accesses, 3);
        assert_eq!(result.unmapped_accesses, 1);
        // SRAM: read 8B = 2 transactions * 2, write 4B = 1 * 3.
        // Flash: read+write 4B = 1 * 5 + 1 * 5.
        assert_eq!(result.read_wait_cycles, 4 + 5);
        assert_eq!(result.write_wait_cycles, 3 + 5);
        let block = &cfg.graph[cfg.entry.expect("entry")];
        let data_memory = block.data_memory.as_ref().expect("data memory");
        assert_eq!(data_memory.wait_cycles, 17);
        assert_eq!(block.cycles.expect("cycles").min, 18.0);
        assert_eq!(block.cycles.expect("cycles").max, 18.0);
        assert_eq!(data_memory.regions.len(), 2);
    }

    #[test]
    fn splits_an_access_at_a_region_boundary() {
        let profile = BoardProfile::parse_toml(
            r#"
schema_version = 2
id = "board:data-memory-boundary"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[[memory]]
name = "low"
start = 0x2000_0000
size = 4
kind = "ram"
data_width_bytes = 4
data_read_wait_states = 1

[[memory]]
name = "high"
start = 0x2000_0004
size = 4
kind = "ram"
data_width_bytes = 4
data_read_wait_states = 2
"#,
        )
        .expect("profile");
        let model = DataMemoryModel {
            regions: profile.data_memory_regions(),
        };
        let mut cfg = cfg(vec![access(
            CfgMemoryAccessKind::Read,
            Some(0x2000_0000),
            8,
        )]);
        let result = analyze_function(&mut cfg, &model);
        assert_eq!(result.read_wait_cycles, 3);
        let block = &cfg.graph[cfg.entry.expect("entry")];
        assert_eq!(
            block
                .data_memory
                .as_ref()
                .expect("data memory")
                .regions
                .len(),
            2
        );
    }
}
