//! Multicore shared-resource interference budget analysis.
//!
//! This first model is deliberately simple and auditable: the profile supplies
//! a worst-case interference budget per data read, data write and instruction
//! fetch. Every decoded event is charged, including unresolved stack/register
//! accesses, so the budget must cover the worst-case access mix. The model does
//! not attempt to reconstruct bus arbitration schedules or other cores'
//! workloads.

use elf2tdg_schema::CostRange;

use crate::board_profile::MulticoreProfile;
use crate::cfg::{CfgBlockMulticore, CfgMemoryAccessKind, CfgMulticoreInfo, ProgramCfg};

/// Runs the access-budget interference analysis over every function.
#[must_use]
pub(crate) fn analyze_program(
    program: &mut ProgramCfg,
    profile: &MulticoreProfile,
) -> CfgMulticoreInfo {
    let read_budget = profile.data_read_interference_cycles();
    let write_budget = profile.data_write_interference_cycles();
    let fetch_budget = profile.instruction_fetch_interference_cycles();
    let mut info = CfgMulticoreInfo {
        model: profile.model().to_owned(),
        cores: profile.cores(),
        core_id: profile.core_id(),
        confidence: profile.confidence(),
        data_read_interference_cycles: read_budget,
        data_write_interference_cycles: write_budget,
        instruction_fetch_interference_cycles: fetch_budget,
        functions_analyzed: 0,
        blocks_analyzed: 0,
        data_read_accesses: 0,
        data_write_accesses: 0,
        instruction_fetches: 0,
        interference_cycles: 0,
        caveats: {
            let mut caveats = vec![
                "Multicore interference is modeled as a per-access and per-fetch budget supplied by [multicore]; arbitration schedules, shared caches, DMA, memory-controller queues and the other cores' actual workloads are not modeled."
                    .to_owned(),
                "Every decoded data access is charged, including unresolved stack/register accesses; the budget must cover the worst-case access mix."
                    .to_owned(),
                "Instruction fetches are charged once per decoded instruction."
                    .to_owned(),
            ];
            caveats.extend(profile.caveats().iter().cloned());
            caveats
        },
    };

    for function in &mut program.functions {
        let nodes: Vec<_> = function.cfg.blocks_by_address.values().copied().collect();
        let mut function_analyzed = false;
        for node in nodes {
            let block = &mut function.cfg.graph[node];
            if block.instructions.is_empty() {
                continue;
            }
            let mut reads = 0_u32;
            let mut writes = 0_u32;
            let mut fetches = 0_u32;
            for instruction in &block.instructions {
                fetches = fetches.saturating_add(1);
                for access in &instruction.memory_accesses {
                    match access.kind {
                        CfgMemoryAccessKind::Read => {
                            reads = reads.saturating_add(1);
                        }
                        CfgMemoryAccessKind::Write => {
                            writes = writes.saturating_add(1);
                        }
                        CfgMemoryAccessKind::ReadWrite => {
                            reads = reads.saturating_add(1);
                            writes = writes.saturating_add(1);
                        }
                    }
                }
            }
            let interference = reads
                .saturating_mul(read_budget)
                .saturating_add(writes.saturating_mul(write_budget))
                .saturating_add(fetches.saturating_mul(fetch_budget));
            add_penalty(&mut block.cycles, interference);
            block.multicore = Some(CfgBlockMulticore {
                data_read_accesses: reads,
                data_write_accesses: writes,
                instruction_fetches: fetches,
                interference_cycles: interference,
            });
            function_analyzed = true;
            info.blocks_analyzed = info.blocks_analyzed.saturating_add(1);
            info.data_read_accesses = info.data_read_accesses.saturating_add(reads);
            info.data_write_accesses = info.data_write_accesses.saturating_add(writes);
            info.instruction_fetches = info.instruction_fetches.saturating_add(fetches);
            info.interference_cycles = info.interference_cycles.saturating_add(interference);
        }
        if function_analyzed {
            info.functions_analyzed = info.functions_analyzed.saturating_add(1);
        }
    }
    info
}

fn add_penalty(cycles: &mut Option<CostRange>, added: u32) {
    if added == 0 {
        return;
    }
    let added = f64::from(added);
    if let Some(cycles) = cycles {
        cycles.min += added;
        cycles.max += added;
    }
}
