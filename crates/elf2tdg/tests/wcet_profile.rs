//! WCET profile integration coverage.

use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg;
use elf2tdg::loader;

#[test]
#[allow(clippy::too_many_lines)]
fn computes_root_and_function_wcet() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf =
        manifest.join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    let profile_path = manifest.join("../../examples/profiles/cortex-m7-wcet.toml");
    if !elf.exists() || !profile_path.exists() {
        return;
    }
    let image = loader::load(&elf).expect("example ELF must load");
    let profile = BoardProfile::load(&profile_path).expect("profile must load");
    let output = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("WCET analysis");
    output.cfg.ensure_valid().expect("CFG");

    let info = output.cfg.wcet.as_ref().expect("WCET metadata");
    assert_eq!(info.model, "cfg-longest-path");
    assert_eq!(info.default_loop_bound, Some(4));
    assert_eq!(info.max_states, 20_000);
    assert!(info.frequency_hz.is_some());
    assert!(info.functions_analyzed > 0);
    assert!(info.functions_partial > 0);
    assert!(info.functions_unbounded > 0);
    assert!(!info.roots.is_empty());

    let bounded_root = info
        .roots
        .iter()
        .find(|root| root.cycles.is_some())
        .expect("at least one finite root estimate");
    assert!(matches!(
        bounded_root.status,
        cfg::CfgWcetStatus::Bounded | cfg::CfgWcetStatus::Partial
    ));
    assert!(bounded_root.cycles.is_some_and(|cycles| cycles > 0.0));
    assert!(bounded_root.time_ns.is_some_and(|time| time > 0.0));
    assert_ne!(bounded_root.path.len(), 0);
    assert!(
        info.roots
            .iter()
            .any(|root| root.status == cfg::CfgWcetStatus::Unbounded)
    );

    let function = output
        .cfg
        .functions
        .iter()
        .find(|function| function.wcet.is_some())
        .expect("function WCET");
    let wcet = function.wcet.as_ref().expect("WCET");
    assert!(!wcet.path.is_empty() || wcet.status != cfg::CfgWcetStatus::Bounded);

    let json = cfg::render_json(&output.cfg, None, false).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("CFG JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert_eq!(document["wcet"]["model"], "cfg-longest-path");
    assert_eq!(document["wcet"]["default_loop_bound"], 4);
    assert!(
        document["wcet"]["roots"]
            .as_array()
            .is_some_and(|roots| roots.iter().any(|root| {
                matches!(root["status"].as_str(), Some("bounded" | "partial"))
                    && root["cycles"].as_f64().is_some_and(|cycles| cycles > 0.0)
                    && root["path"].is_array()
            }))
    );
    assert!(
        document["functions"]
            .as_array()
            .is_some_and(|functions| functions.iter().any(|function| {
                function["wcet"].is_object() && function["wcet"]["status"].is_string()
            }))
    );
}
