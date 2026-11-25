//! WCET profile integration coverage.

use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, PathAnalysis, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg::text_report;

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

#[test]
fn branch_state_ipet_is_recorded_in_the_pipeline() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf = manifest.join("../../tests/fixtures/cortex_m0/firmware.elf");
    if !elf.exists() {
        return;
    }
    let profile = BoardProfile::parse_toml(
        r#"
schema_version = 2
id = "board:branch-integration"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 48_000_000

[branch_prediction]
model = "bimodal"
mispredict_penalty = 3
initial_state = "weakly-not-taken"
max_states = 128

[wcet]
default_loop_bound = 4
bound_nonterminating_loops = true
auto_loop_bounds = false
"#,
    )
    .expect("valid branch profile");
    let image = loader::load(&elf).expect("fixture ELF must load");
    let output = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            path_analysis: PathAnalysis::Ipet,
            ..AnalysisOptions::default()
        },
    )
    .expect("branch-aware IPET analysis");
    assert!(output.cfg.branch_prediction.is_some());
    assert!(output.cfg.functions.iter().any(|function| {
        function
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .and_then(|ipet| ipet.branch_model.as_deref())
            .is_some_and(|model| matches!(model, "state-product" | "interprocedural-state-product"))
    }));
    let json = cfg::render_json(&output.cfg, None, false).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("CFG JSON");
    assert!(document["functions"].as_array().is_some_and(|functions| {
        functions.iter().any(|function| {
            matches!(
                function["wcet"]["ipet"]["branch_model"].as_str(),
                Some("state-product" | "interprocedural-state-product")
            )
        })
    }));
    let text = text_report::render_text(&output.cfg, None, false).expect("text report");
    assert!(text.contains("ipet branch model"));
}

#[test]
fn pipeline_state_product_is_recorded_in_the_pipeline() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf = manifest.join("../../tests/fixtures/cortex_m0/firmware.elf");
    if !elf.exists() {
        return;
    }
    let profile = BoardProfile::parse_toml(
        r#"
schema_version = 2
id = "board:pipeline-integration"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 48_000_000

[pipeline]
issue_width = 2
branch_penalty = 2

[pipeline.resources]
alu = 2
load_store = 1

[[pipeline.instructions]]
mnemonic = "ldr"
resources = ["load_store"]
latency = 1
occupancy = 4

[wcet]
default_loop_bound = 4
bound_nonterminating_loops = true
auto_loop_bounds = false
"#,
    )
    .expect("valid pipeline profile");
    let image = loader::load(&elf).expect("fixture ELF must load");
    let output = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            path_analysis: PathAnalysis::Ipet,
            ..AnalysisOptions::default()
        },
    )
    .expect("pipeline-aware IPET analysis");
    let pipeline = output.cfg.pipeline.as_ref().expect("pipeline metadata");
    assert_eq!(pipeline.model, "cortex-m4-edge-context");
    assert!(!pipeline.edges.is_empty());
    assert!(pipeline.edges.iter().all(|edge| edge.stall_cycles > 0.0));
    let timing = output.cfg.timing.as_ref().expect("timing metadata");
    assert_eq!(
        timing.models[0].determinism,
        elf2tdg_schema::Determinism::Statistical
    );
    assert_eq!(
        timing.models[0]
            .params
            .extras
            .get("board_profile_pipeline_issue_width")
            .map(String::as_str),
        Some("2")
    );
    assert_eq!(
        timing.models[0]
            .params
            .extras
            .get("board_profile_pipeline_resources")
            .map(String::as_str),
        Some("alu=2,load_store=1")
    );
    assert!(output.cfg.functions.iter().any(|function| {
        function
            .wcet
            .as_ref()
            .and_then(|wcet| wcet.ipet.as_ref())
            .and_then(|ipet| ipet.pipeline_model.as_deref())
            == Some("state-product")
    }));
    let json = cfg::render_json(&output.cfg, None, false).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("CFG JSON");
    assert_eq!(document["pipeline"]["model"], "cortex-m4-edge-context");
    assert!(document["functions"].as_array().is_some_and(|functions| {
        functions
            .iter()
            .any(|function| function["wcet"]["ipet"]["pipeline_model"] == "state-product")
    }));
    let text = text_report::render_text(&output.cfg, None, false).expect("text report");
    assert!(text.contains("pipeline: cortex-m4-edge-context"));
    assert!(text.contains("ipet pipeline model state-product"));
}

#[test]
fn cache_state_ipet_is_recorded_in_the_pipeline() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf = manifest.join("../../tests/fixtures/cortex_m0/firmware.elf");
    if !elf.exists() {
        return;
    }
    let profile = BoardProfile::parse_toml(
        r#"
schema_version = 2
id = "board:ipet-cache-integration"
arch = "thumb"
cpu = "cortex-m4"

[clocks.core]
hz = 48_000_000

[instruction_cache]
size = 1024
line_bytes = 16
ways = 2
miss_penalty = 10
max_states = 128

[wcet]
default_loop_bound = 4
bound_nonterminating_loops = true
auto_loop_bounds = false
"#,
    )
    .expect("valid cache profile");
    let image = loader::load(&elf).expect("fixture ELF must load");
    let output = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            path_analysis: PathAnalysis::Ipet,
            ..AnalysisOptions::default()
        },
    )
    .expect("cache-aware IPET analysis");
    assert!(output.cfg.cache.is_some());
    let wcet = output.cfg.wcet.as_ref().expect("WCET metadata");
    assert!(
        wcet.caveats
            .iter()
            .any(|caveat| caveat.contains("Cache-state IPET"))
    );
    assert!(
        output.cfg.functions.iter().any(|function| {
            function
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.ipet.as_ref())
                .and_then(|ipet| ipet.cache_model.as_deref())
                == Some("state-product")
        }),
        "at least one complete cache analysis should use the state product"
    );
    let json = cfg::render_json(&output.cfg, None, false).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("CFG JSON");
    assert!(document["functions"].as_array().is_some_and(|functions| {
        functions
            .iter()
            .any(|function| function["wcet"]["ipet"]["cache_model"] == "state-product")
    }));
    let text = text_report::render_text(&output.cfg, None, false).expect("text report");
    assert!(text.contains("ipet cache model"));
}
