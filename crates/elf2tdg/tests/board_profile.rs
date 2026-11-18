//! Board-profile integration coverage on the Cortex-M0 example image.

use std::collections::BTreeMap;
use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
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
        .tdg
        .ensure_valid()
        .expect("profiled TDG must validate");
    base.tdg.ensure_valid().expect("default TDG must validate");

    let timing = &profiled.tdg.timing;
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
            .tdg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "timing-board-profile"),
        "profile provenance diagnostic"
    );
    assert!(
        profiled
            .tdg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "frequency-from-board-profile"),
        "frequency provenance diagnostic"
    );
    assert!(
        !profiled
            .tdg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "timing-unknown-instruction"),
        "example instructions are all recognized"
    );

    let base_costs = block_costs(&base.tdg);
    let mut saw_higher_cost = false;
    let mut saw_time = false;
    for function in &profiled.tdg.functions {
        for block in &function.blocks {
            let Some(timing) = &block.timing else {
                continue;
            };
            saw_time |= timing.time_ns.is_some();
            if let Some(time_ns) = &timing.time_ns {
                let hz = 48_000_000.0;
                let expected_min = timing.cycles.min * 1_000_000_000.0 / hz;
                assert!((time_ns.min - expected_min).abs() < 1e-6);
            }
            if let Some(base_cycles) = base_costs.get(&block.id) {
                assert!(
                    timing.cycles.min >= *base_cycles,
                    "profile fetch costs must not lower block {}",
                    block.id
                );
                saw_higher_cost |= timing.cycles.min > *base_cycles;
            }
        }
    }
    assert!(
        saw_higher_cost,
        "profile fetch costs must change at least one block"
    );
    assert!(saw_time, "profile clock must produce wall-clock times");
}

fn block_costs(tdg: &elf2tdg_schema::Tdg) -> BTreeMap<BlockId, f64> {
    let mut costs = BTreeMap::new();
    for function in &tdg.functions {
        for block in &function.blocks {
            if let Some(timing) = &block.timing {
                costs.insert(block.id.clone(), timing.cycles.min);
            }
        }
    }
    costs
}
