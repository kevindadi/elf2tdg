//! Multicore access-budget interference coverage.

use std::path::{Path, PathBuf};

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg::text_report;

fn fixture_elf() -> Option<PathBuf> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cortex_m0/firmware.elf");
    path.exists().then_some(path)
}

fn profile(multicore: bool) -> BoardProfile {
    let extra = if multicore {
        r"
[multicore]
cores = 4
core_id = 1
data_read_interference_cycles = 8
data_write_interference_cycles = 9
instruction_fetch_interference_cycles = 2
"
    } else {
        ""
    };
    BoardProfile::parse_toml(&format!(
        r#"
schema_version = 2
id = "board:multicore-test"
arch = "thumb"
cpu = "cortex-m0"

[clocks.core]
hz = 48_000_000
{extra}
"#
    ))
    .expect("valid profile")
}

#[test]
fn charges_access_budget_and_records_metadata() {
    let Some(path) = fixture_elf() else {
        eprintln!("skipping multicore test: fixture is absent");
        return;
    };
    let image = loader::load(&path).expect("fixture must load");
    let base = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile(false)),
            ..AnalysisOptions::default()
        },
    )
    .expect("baseline analysis");
    let with_multicore = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile(true)),
            ..AnalysisOptions::default()
        },
    )
    .expect("multicore analysis");
    assert!(base.cfg.multicore.is_none());

    let info = with_multicore
        .cfg
        .multicore
        .as_ref()
        .expect("multicore info");
    assert_eq!(info.model, "access-budget");
    assert_eq!(info.cores, 4);
    assert_eq!(info.core_id, 1);
    assert_eq!(info.data_read_interference_cycles, 8);
    assert_eq!(info.data_write_interference_cycles, 9);
    assert_eq!(info.instruction_fetch_interference_cycles, 2);
    assert!(info.functions_analyzed > 0);
    assert!(info.blocks_analyzed > 0);
    assert!(info.instruction_fetches > 0);
    assert!(info.interference_cycles > 0);
    assert!(
        info.caveats
            .iter()
            .any(|caveat| caveat.contains("arbitration"))
    );

    let timing = with_multicore.cfg.timing.as_ref().expect("timing");
    assert_eq!(
        timing.models[0]
            .params
            .extras
            .get("board_profile_multicore_cores")
            .map(String::as_str),
        Some("4")
    );

    let base_main = base.cfg.select(Some("main")).expect("main")[0];
    let multi_main = with_multicore.cfg.select(Some("main")).expect("main")[0];
    let mut checked = 0_usize;
    for node in multi_main.cfg.blocks_by_address.values() {
        let multi_block = &multi_main.cfg.graph[*node];
        let Some(annotation) = multi_block.multicore.as_ref() else {
            continue;
        };
        let expected = annotation
            .data_read_accesses
            .saturating_mul(8)
            .saturating_add(annotation.data_write_accesses.saturating_mul(9))
            .saturating_add(annotation.instruction_fetches.saturating_mul(2));
        assert_eq!(annotation.interference_cycles, expected);
        assert_eq!(
            annotation.instruction_fetches,
            u32::try_from(multi_block.instructions.len()).unwrap_or(u32::MAX)
        );

        let base_block =
            &base_main.cfg.graph[base_main.cfg.blocks_by_address[&multi_block.address]];
        let base_cycles = base_block.cycles.expect("base cycles");
        let multi_cycles = multi_block.cycles.expect("multicore cycles");
        assert_eq!(multi_cycles.min, base_cycles.min + f64::from(expected));
        assert_eq!(multi_cycles.max, base_cycles.max + f64::from(expected));
        checked += 1;
    }
    assert!(checked > 0, "main should have analyzed blocks");

    let json = cfg::render_json(&with_multicore.cfg, Some("main"), false).expect("JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert_eq!(document["multicore"]["model"], "access-budget");
    assert_eq!(document["multicore"]["cores"], 4);
    assert!(
        document["functions"]
            .as_array()
            .is_some_and(|functions| functions.iter().any(|function| {
                function["blocks"]
                    .as_array()
                    .is_some_and(|blocks| blocks.iter().any(|block| block["multicore"].is_object()))
            }))
    );

    let text =
        text_report::render_text(&with_multicore.cfg, Some("main"), false).expect("text report");
    assert!(text.contains("multicore interference: access-budget"));
    assert!(text.contains("multicore:"));
    assert!(text.contains("interference cycle(s)"));
}
