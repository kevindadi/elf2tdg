//! Full pipeline + memory + cache + branch + WCET integration coverage.

use std::collections::BTreeMap;
use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg_schema::BlockId;

#[test]
#[allow(clippy::too_many_lines)]
fn composes_all_analysis_models() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf =
        manifest.join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    let baseline_path = manifest.join("../../examples/profiles/cortex-m4-pipeline.toml");
    let full_path = manifest.join("../../examples/profiles/cortex-m4-full-stack.toml");
    if !elf.exists() || !baseline_path.exists() || !full_path.exists() {
        return;
    }
    let image = loader::load(&elf).expect("example ELF must load");
    let baseline_profile = BoardProfile::load(&baseline_path).expect("baseline profile");
    let full_profile = BoardProfile::load(&full_path).expect("full-stack profile");
    let baseline = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(baseline_profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("baseline analysis");
    let full = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(full_profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("full-stack analysis");
    baseline.cfg.ensure_valid().expect("baseline CFG");
    full.cfg.ensure_valid().expect("full-stack CFG");

    let icache = full.cfg.cache.as_ref().expect("instruction cache");
    let dcache = full.cfg.data_cache.as_ref().expect("data cache");
    let branch = full
        .cfg
        .branch_prediction
        .as_ref()
        .expect("branch prediction");
    let data_memory = full.cfg.data_memory.as_ref().expect("data memory");
    let wcet = full.cfg.wcet.as_ref().expect("WCET");
    assert!(icache.functions_analyzed > 0);
    assert!(dcache.functions_analyzed > 0);
    assert!(branch.branches_analyzed > 0);
    assert!(data_memory.wait_cycles > 0);
    assert!(wcet.functions_analyzed > 0);
    assert!(!wcet.roots.is_empty());
    assert!(baseline.cfg.cache.is_none());
    assert!(baseline.cfg.data_cache.is_none());
    assert!(baseline.cfg.branch_prediction.is_none());
    assert!(baseline.cfg.data_memory.is_none());

    let baseline_costs = block_costs(&baseline.cfg);
    let mut saw_instruction_cache = false;
    let mut saw_data_cache = false;
    let mut saw_branch = false;
    let mut saw_memory = false;
    for function in &full.cfg.functions {
        for node in function.cfg.blocks_by_address.values() {
            let block = &function.cfg.graph[*node];
            let base = baseline_costs.get(&block.id).expect("baseline block");
            let icache_penalty = block.cache.as_ref().map_or(0.0, |cache| {
                f64::from(cache.misses_min * icache.miss_penalty)
            });
            let dcache_penalty = block.data_cache.as_ref().map_or(0.0, |cache| {
                f64::from(cache.misses_min * dcache.miss_penalty)
            });
            let branch_penalty = block.branch_prediction.as_ref().map_or(0.0, |prediction| {
                f64::from(prediction.mispredicts_min * branch.mispredict_penalty)
            });
            let memory_penalty = block
                .data_memory
                .as_ref()
                .map_or(0.0, |memory| f64::from(memory.wait_cycles));
            let expected_min =
                base.min + icache_penalty + dcache_penalty + branch_penalty + memory_penalty;
            let icache_penalty_max = block.cache.as_ref().map_or(0.0, |cache| {
                f64::from(cache.misses_max * icache.miss_penalty)
            });
            let dcache_penalty_max = block.data_cache.as_ref().map_or(0.0, |cache| {
                f64::from(cache.misses_max * dcache.miss_penalty)
            });
            let branch_penalty_max = block.branch_prediction.as_ref().map_or(0.0, |prediction| {
                f64::from(prediction.mispredicts_max * branch.mispredict_penalty)
            });
            let expected_max = base.max
                + icache_penalty_max
                + dcache_penalty_max
                + branch_penalty_max
                + memory_penalty;
            let cycles = block.cycles.expect("block cycles");
            assert!((cycles.min - expected_min).abs() < 1e-6, "{} min", block.id);
            assert!((cycles.max - expected_max).abs() < 1e-6, "{} max", block.id);
            saw_instruction_cache |= block.cache.is_some();
            saw_data_cache |= block.data_cache.is_some();
            saw_branch |= block.branch_prediction.is_some();
            saw_memory |= block.data_memory.is_some();
        }
    }
    assert!(saw_instruction_cache && saw_data_cache && saw_branch && saw_memory);

    let extras = &full.cfg.timing.as_ref().expect("timing").models[0]
        .params
        .extras;
    assert_eq!(
        extras.get("board_profile_pipeline").map(String::as_str),
        Some("cortex-m4-resource-dependency-model")
    );
    assert!(extras.contains_key("board_profile_instruction_cache"));
    assert!(extras.contains_key("board_profile_data_cache"));
    assert!(extras.contains_key("board_profile_branch_prediction"));
    assert!(extras.contains_key("board_profile_data_memory"));
    assert!(extras.contains_key("board_profile_wcet"));

    let json = cfg::render_json(&full.cfg, None, false).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("CFG JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    for field in [
        "cache",
        "data_cache",
        "branch_prediction",
        "data_memory",
        "wcet",
    ] {
        assert!(document[field].is_object(), "missing {field}");
    }
    assert!(
        document["functions"]
            .as_array()
            .is_some_and(|functions| functions.iter().any(|function| {
                function["wcet"].is_object() && function["wcet"]["status"].is_string()
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
