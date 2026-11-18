//! Data-memory latency profile integration coverage.

use std::collections::BTreeMap;
use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg_schema::BlockId;

#[test]
#[allow(clippy::too_many_lines)]
fn applies_data_memory_wait_cycles() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf =
        manifest.join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    let profile_path = manifest.join("../../examples/profiles/cortex-m7-data-memory.toml");
    if !elf.exists() || !profile_path.exists() {
        return;
    }
    let image = loader::load(&elf).expect("example ELF must load");
    let memory_profile = BoardProfile::load(&profile_path).expect("profile must load");
    let profile_text = std::fs::read_to_string(&profile_path).expect("profile text");
    let without_memory = profile_text
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            !line.starts_with("data_width_bytes")
                && !line.starts_with("data_read_wait_states")
                && !line.starts_with("data_write_wait_states")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let base_profile = BoardProfile::parse_toml(&without_memory).expect("base profile");
    let base = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(base_profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("base analysis");
    let delayed = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(memory_profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("data-memory analysis");
    base.cfg.ensure_valid().expect("base CFG");
    delayed.cfg.ensure_valid().expect("delayed CFG");

    let info = delayed.cfg.data_memory.as_ref().expect("data-memory info");
    assert_eq!(info.model, "region-data-wait-states");
    assert!(info.functions_analyzed > 0);
    assert!(info.blocks_analyzed > 0);
    assert!(info.accesses > 0);
    assert!(info.resolved_accesses > 0);
    assert!(info.unresolved_accesses > 0);
    assert!(info.mapped_accesses > 0);
    assert!(info.wait_cycles > 0);
    assert_eq!(
        info.wait_cycles,
        info.read_wait_cycles.saturating_add(info.write_wait_cycles)
    );
    assert!(base.cfg.data_memory.is_none());

    let base_costs = block_costs(&base.cfg);
    let mut blocks = 0_u32;
    let mut total_wait_cycles = 0_u32;
    let mut saw_region = false;
    for function in &delayed.cfg.functions {
        for node in function.cfg.blocks_by_address.values() {
            let block = &function.cfg.graph[*node];
            let Some(data_memory) = &block.data_memory else {
                continue;
            };
            blocks += 1;
            total_wait_cycles = total_wait_cycles.saturating_add(data_memory.wait_cycles);
            assert_eq!(
                data_memory.wait_cycles,
                data_memory
                    .read_wait_cycles
                    .saturating_add(data_memory.write_wait_cycles)
            );
            assert_eq!(
                data_memory.accesses,
                data_memory
                    .resolved_accesses
                    .saturating_add(data_memory.unresolved_accesses)
            );
            saw_region |= !data_memory.regions.is_empty();
            let base_cycles = base_costs.get(&block.id).expect("base block");
            if let Some(cycles) = block.cycles {
                let expected_min = base_cycles.min + f64::from(data_memory.wait_cycles);
                let expected_max = base_cycles.max + f64::from(data_memory.wait_cycles);
                assert!((cycles.min - expected_min).abs() < 1e-6);
                assert!((cycles.max - expected_max).abs() < 1e-6);
            }
        }
    }
    assert_eq!(blocks, info.blocks_analyzed);
    assert_eq!(total_wait_cycles, info.wait_cycles);
    assert!(saw_region, "at least one access must map to a region");

    let json = cfg::render_json(&delayed.cfg, None, false).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("CFG JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert_eq!(document["data_memory"]["model"], "region-data-wait-states");
    assert!(document["data_memory"]["wait_cycles"].as_u64().unwrap_or(0) > 0);
    assert!(
        document["functions"]
            .as_array()
            .is_some_and(|functions| functions.iter().any(|function| {
                function["blocks"].as_array().is_some_and(|blocks| {
                    blocks.iter().any(|block| {
                        block["data_memory"].is_object()
                            && block["data_memory"]["regions"]
                                .as_array()
                                .is_some_and(|regions| {
                                    !regions.is_empty()
                                        && regions.iter().all(|region| {
                                            region["region"].is_string()
                                                && region["kind"].is_string()
                                        })
                                })
                    })
                })
            }))
    );
}

fn block_costs(program: &cfg::ProgramCfg) -> BTreeMap<BlockId, elf2tdg_schema::CostRange> {
    let mut costs = BTreeMap::new();
    for function in &program.functions {
        for node in function.cfg.blocks_by_address.values() {
            let block = &function.cfg.graph[*node];
            if let Some(cycles) = block.cycles {
                costs.insert(block.id.clone(), cycles);
            }
        }
    }
    costs
}
