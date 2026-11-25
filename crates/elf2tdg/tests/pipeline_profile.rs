//! Cortex-M4 pipeline-profile integration coverage.

use std::collections::BTreeMap;
use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg::ProgramCfg;
use elf2tdg::loader;
use elf2tdg_schema::{BlockId, FrequencySource};

#[test]
#[allow(clippy::too_many_lines)]
fn applies_cortex_m4_pipeline_profile() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf =
        manifest.join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    let profile_path = manifest.join("../../examples/profiles/cortex-m4-pipeline.toml");
    if !elf.exists() || !profile_path.exists() {
        return;
    }
    let image = loader::load(&elf).expect("example ELF must load");
    let profile = BoardProfile::load(&profile_path).expect("pipeline profile must load");
    let base = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            cpu: Some("cortex-m4".to_owned()),
            ..AnalysisOptions::default()
        },
    )
    .expect("default analysis must succeed");
    let profiled = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("pipeline analysis must succeed");
    base.cfg.ensure_valid().expect("default CFG must validate");
    profiled
        .cfg
        .ensure_valid()
        .expect("pipeline CFG must validate");

    let timing = profiled.cfg.timing.as_ref().expect("CFG timing metadata");
    let model = timing.models.first().expect("timing model");
    assert_eq!(
        model
            .params
            .extras
            .get("board_profile_pipeline")
            .map(String::as_str),
        Some("cortex-m4-resource-dependency-model")
    );
    assert_eq!(
        model
            .params
            .extras
            .get("board_profile_pipeline_instruction_overrides")
            .map(String::as_str),
        Some("1")
    );
    assert!(
        model
            .caveats
            .iter()
            .any(|caveat| caveat.contains("resource/dependency model")),
        "pipeline caveat must be recorded"
    );
    assert!(
        model
            .caveats
            .iter()
            .any(|caveat| caveat.contains("state table")),
        "pipeline limitations must be explicit"
    );

    let core = timing
        .frequency_domains
        .iter()
        .find(|domain| domain.id.as_str() == "clk:core")
        .expect("core frequency domain");
    assert_eq!(core.hz, 168_000_000);
    assert_eq!(core.source, FrequencySource::BoardProfile);

    assert!(
        !profiled
            .cfg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "timing-unknown-instruction"),
        "example instructions are all recognized"
    );

    let base_costs = block_costs(&base.cfg);
    let mut saw_changed_cost = false;
    let mut saw_time = false;
    for function in &profiled.cfg.functions {
        for node in function.cfg.blocks_by_address.values() {
            let block = &function.cfg.graph[*node];
            let Some(cycles) = block.cycles else {
                continue;
            };
            saw_time = true;
            if let Some(base_cycles) = base_costs.get(&block.id) {
                saw_changed_cost |= (cycles.min - *base_cycles).abs() > f64::EPSILON;
            }
        }
    }
    assert!(
        saw_changed_cost,
        "pipeline scheduling must change at least one block"
    );
    assert!(saw_time, "profile clock must produce wall-clock times");
}

fn block_costs(program: &ProgramCfg) -> BTreeMap<BlockId, f64> {
    let mut costs = BTreeMap::new();
    for function in &program.functions {
        for node in function.cfg.blocks_by_address.values() {
            let block = &function.cfg.graph[*node];
            if let Some(cycles) = block.cycles {
                costs.insert(block.id.clone(), cycles.min);
            }
        }
    }
    costs
}
