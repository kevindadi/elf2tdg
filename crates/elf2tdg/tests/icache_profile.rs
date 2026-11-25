//! Instruction-cache profile integration coverage.

use std::collections::BTreeMap;
use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg_schema::BlockId;

#[test]
#[allow(clippy::too_many_lines)]
fn applies_instruction_cache_penalties() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf =
        manifest.join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    let profile_path = manifest.join("../../examples/profiles/cortex-m7-icache.toml");
    if !elf.exists() || !profile_path.exists() {
        return;
    }
    let image = loader::load(&elf).expect("example ELF must load");
    let cache_profile = BoardProfile::load(&profile_path).expect("cache profile must load");
    let profile_text = std::fs::read_to_string(&profile_path).expect("profile text");
    let without_cache = profile_text
        .split("[instruction_cache]")
        .next()
        .expect("profile prefix");
    let base_profile = BoardProfile::parse_toml(without_cache).expect("base profile");
    let base = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(base_profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("base analysis");
    let cached = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(cache_profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("cache analysis");
    base.cfg.ensure_valid().expect("base CFG");
    cached.cfg.ensure_valid().expect("cached CFG");

    let info = cached.cfg.cache.as_ref().expect("cache metadata");
    assert_eq!(info.size, 16_384);
    assert_eq!(info.line_bytes, 32);
    assert_eq!(info.ways, 4);
    assert_eq!(info.miss_penalty, 20);
    assert!(info.functions_analyzed > 0);
    assert!(info.blocks_analyzed > 0);
    assert_eq!(info.persistence.model, "instruction-working-set-lru");
    assert!(info.persistence.loops_analyzed >= info.persistence.loops_persistent);
    assert!(base.cfg.cache.is_none());

    let base_costs = block_costs(&base.cfg);
    let mut saw_penalty = false;
    let mut saw_misses = false;
    let mut saw_hits = false;
    let mut saw_line_class = false;
    for function in &cached.cfg.functions {
        for node in function.cfg.blocks_by_address.values() {
            let block = &function.cfg.graph[*node];
            let Some(cache_block) = &block.cache else {
                continue;
            };
            assert!(cache_block.entry_states > 0);
            saw_misses |= cache_block.misses_max > 0;
            saw_hits |= cache_block
                .lines
                .iter()
                .any(|line| line.classification == cfg::CfgCacheLineClass::AlwaysHit);
            saw_line_class |= cache_block.lines.iter().all(|line| {
                matches!(
                    line.classification,
                    cfg::CfgCacheLineClass::AlwaysHit
                        | cfg::CfgCacheLineClass::AlwaysMiss
                        | cfg::CfgCacheLineClass::MayHit
                )
            });
            let base_cycles = base_costs.get(&block.id).expect("base block");
            if let Some(cycles) = block.cycles {
                let expected_min =
                    base_cycles.min + f64::from(cache_block.misses_min * info.miss_penalty);
                let expected_max =
                    base_cycles.max + f64::from(cache_block.misses_max * info.miss_penalty);
                assert!((cycles.min - expected_min).abs() < 1e-6);
                assert!((cycles.max - expected_max).abs() < 1e-6);
                saw_penalty |= cache_block.misses_max > 0;
            }
        }
    }
    assert!(saw_misses, "example code must contain cache misses");
    assert!(saw_penalty, "cache misses must add cycle penalties");
    assert!(saw_hits, "some analyzed line must always hit");
    assert!(saw_line_class, "every line must have a classification");

    let json = cfg::render_json(&cached.cfg, None, false).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("CFG JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert_eq!(document["cache"]["miss_penalty"], 20);
    assert_eq!(
        document["cache"]["persistence"]["model"],
        "instruction-working-set-lru"
    );
    assert_eq!(
        document["cache"]["persistence"]["loops_analyzed"],
        info.persistence.loops_analyzed
    );
    assert!(
        document["functions"]
            .as_array()
            .is_some_and(|functions| functions.iter().any(|function| {
                function["blocks"].as_array().is_some_and(|blocks| {
                    blocks.iter().any(|block| {
                        block["cache"].is_object()
                            && block["cache"]["lines"].as_array().is_some_and(|lines| {
                                lines.iter().all(|line| {
                                    line["classification"].as_str().is_some_and(|class| {
                                        matches!(class, "always-hit" | "always-miss" | "may-hit")
                                    })
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
