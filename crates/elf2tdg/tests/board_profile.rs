//! Board-profile integration coverage on the Cortex-M0 example image.

use std::collections::BTreeMap;
use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg::ProgramCfg;
use elf2tdg::loader;
use elf2tdg_schema::{BlockId, FrequencySource};

#[test]
#[allow(clippy::too_many_lines)]
fn applies_board_profile_timing_and_provenance() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf = manifest.join("../../examples/cortex-m0-isr/artifacts/cortex-m0-isr.elf");
    let profile_path = manifest.join("../../examples/profiles/cortex-m0-isr.toml");
    if !elf.exists() || !profile_path.exists() {
        return;
    }
    let image = loader::load(&elf).expect("example ELF must load");
    let profile = BoardProfile::load(&profile_path).expect("example profile must load");
    let base = analyze_with_cfg(&image, &AnalysisOptions::default())
        .expect("default analysis must succeed");
    let profiled = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile.clone()),
            ..AnalysisOptions::default()
        },
    )
    .expect("profiled analysis must succeed");
    profiled
        .cfg
        .ensure_valid()
        .expect("profiled CFG must validate");
    base.cfg.ensure_valid().expect("default CFG must validate");

    let timing = profiled.cfg.timing.as_ref().expect("CFG timing metadata");
    let model = timing.models.first().expect("timing model");
    assert_eq!(
        model
            .params
            .extras
            .get("board_profile_id")
            .map(String::as_str),
        Some(profile.id())
    );
    assert_eq!(
        model
            .params
            .extras
            .get("board_profile_sha256")
            .map(String::as_str),
        profile.sha256()
    );
    assert_eq!(model.params.flash_wait_states, Some(1));
    assert_eq!(
        model
            .params
            .extras
            .get("board_profile_instruction_cost_overrides")
            .map(String::as_str),
        Some("1")
    );

    let core = timing
        .frequency_domains
        .iter()
        .find(|domain| domain.id.as_str() == "clk:core")
        .expect("core frequency domain");
    assert_eq!(core.hz, 48_000_000);
    assert_eq!(core.source, FrequencySource::BoardProfile);
    assert_eq!(
        timing
            .default_frequency_domain
            .as_ref()
            .map(elf2tdg_schema::FrequencyDomainId::as_str),
        Some("clk:core")
    );

    assert!(
        profiled
            .cfg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "timing-board-profile"),
        "profile provenance diagnostic"
    );
    assert!(
        profiled
            .cfg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "frequency-from-board-profile"),
        "frequency provenance diagnostic"
    );
    assert!(
        !profiled
            .cfg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "timing-unknown-instruction"),
        "example instructions are all recognized"
    );

    let base_costs = block_costs(&base.cfg);
    let mut saw_higher_cost = false;
    let mut saw_cycles = false;
    for function in &profiled.cfg.functions {
        for node in function.cfg.blocks_by_address.values() {
            let block = &function.cfg.graph[*node];
            let Some(cycles) = block.cycles else {
                continue;
            };
            saw_cycles = true;
            if let Some(base_cycles) = base_costs.get(&block.id) {
                assert!(
                    cycles.min >= *base_cycles,
                    "profile fetch costs must not lower block {}",
                    block.id
                );
                saw_higher_cost |= cycles.min > *base_cycles;
            }
        }
    }
    assert!(
        saw_higher_cost,
        "profile fetch costs must change at least one block"
    );
    assert!(saw_cycles, "profile clock must produce block cycle costs");
    let core = timing
        .frequency_domains
        .iter()
        .find(|domain| domain.id.as_str() == "clk:core")
        .expect("core frequency domain");
    assert_eq!(core.hz, 48_000_000);
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
