//! IPET path-analysis integration coverage.

use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, PathAnalysis, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg::text_report;

fn example_elf() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    path.exists().then_some(path)
}

fn wcet_profile() -> Option<PathBuf> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/profiles/cortex-m7-wcet.toml");
    path.exists().then_some(path)
}

#[test]
fn ipet_produces_solver_results_and_flow_facts() {
    let (Some(elf), Some(profile_path)) = (example_elf(), wcet_profile()) else {
        eprintln!("skipping IPET test: example ELF or profile is absent");
        return;
    };
    let image = loader::load(&elf).expect("example ELF must load");
    let profile = BoardProfile::load(&profile_path).expect("profile must load");
    let output = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            path_analysis: PathAnalysis::Ipet,
            ..AnalysisOptions::default()
        },
    )
    .expect("IPET analysis");
    output.cfg.ensure_valid().expect("CFG");

    let info = output.cfg.wcet.as_ref().expect("WCET metadata");
    assert_eq!(info.model, "cfg-ipet");
    assert_eq!(info.solver.as_deref(), Some("microlp"));
    let facts = info.flow_facts.as_ref().expect("flow facts");
    assert_eq!(facts.default_loop_bound, Some(4));
    assert!(facts.bound_nonterminating_loops);
    assert!(info.functions_analyzed > 0);
    assert!(!info.roots.is_empty());

    let sensor = output
        .cfg
        .functions
        .iter()
        .find(|function| {
            elf2tdg::rules::normalize_crate_hashes(&function.primary_name)
                .contains("TaskStorage<rust_concurrency::__sensor_task_task")
        })
        .expect("sensor poll function");
    let wcet = sensor.wcet.as_ref().expect("sensor WCET");
    let ipet = wcet.ipet.as_ref().expect("IPET solution");
    assert_eq!(ipet.solver, "microlp");
    assert_eq!(ipet.status, "optimal");
    assert!(ipet.objective > 0.0);
    assert_eq!(wcet.cycles, Some(ipet.objective));
    assert!(!ipet.blocks.is_empty());
    assert_eq!(
        ipet.blocks
            .iter()
            .map(|block| block.executions)
            .sum::<u64>(),
        4,
        "sensor poll should execute its four basic blocks once"
    );

    let hard_fault = output
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name == "HardFault")
        .expect("HardFault function");
    let hard_fault_wcet = hard_fault.wcet.as_ref().expect("HardFault WCET");
    assert_eq!(hard_fault_wcet.status, cfg::CfgWcetStatus::Partial);
    let hard_fault_ipet = hard_fault_wcet.ipet.as_ref().expect("HardFault IPET");
    assert!(hard_fault_wcet.cycles.is_some_and(|cycles| cycles > 0.0));
    assert!(
        hard_fault_ipet
            .blocks
            .iter()
            .any(|block| block.executions == 4),
        "the default loop bound should appear in the self-loop solution"
    );

    assert!(
        output.cfg.functions.iter().any(|function| function
            .wcet
            .as_ref()
            .is_some_and(|wcet| wcet.status == cfg::CfgWcetStatus::Unbounded)),
        "the irreducible Executor loop must remain unbounded"
    );

    let json = cfg::render_json(&output.cfg, None, false).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("CFG JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert_eq!(document["wcet"]["model"], "cfg-ipet");
    assert_eq!(document["wcet"]["solver"], "microlp");
    assert!(document["wcet"]["flow_facts"].is_object());
    assert!(
        document["functions"]
            .as_array()
            .is_some_and(|functions| functions.iter().any(|function| {
                function["wcet"]["ipet"]["blocks"].is_array()
                    && function["wcet"]["ipet"]["solver"] == "microlp"
            }))
    );
}

#[test]
fn ipet_is_visible_in_the_text_report_and_cli() {
    let (Some(elf), Some(profile_path)) = (example_elf(), wcet_profile()) else {
        return;
    };
    let image = loader::load(&elf).expect("example ELF must load");
    let profile = BoardProfile::load(&profile_path).expect("profile must load");
    let output = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            path_analysis: PathAnalysis::Ipet,
            ..AnalysisOptions::default()
        },
    )
    .expect("IPET analysis");
    let text =
        text_report::render_text(&output.cfg, Some("sensor_task"), true).expect("text report");
    for expected in [
        "model          cfg-ipet",
        "solver         microlp",
        "flow facts",
        "ipet solver",
        "ipet status",
        "ipet block counts:",
    ] {
        assert!(text.contains(expected), "missing {expected:?}");
    }

    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&elf)
        .arg("--board-profile")
        .arg(&profile_path)
        .args([
            "--path-analysis",
            "ipet",
            "--view",
            "cfg",
            "--format",
            "text",
            "--function",
            "sensor_task",
        ])
        .output()
        .expect("run IPET CLI");
    assert!(status.status.success());
    let stdout = String::from_utf8(status.stdout).expect("UTF-8 output");
    assert!(stdout.contains("cfg-ipet"));
    assert!(stdout.contains("ipet solver"));

    let unsafe_run = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&elf)
        .arg("--board-profile")
        .arg(&profile_path)
        .args([
            "--path-analysis",
            "ipet",
            "--require-safe",
            "--view",
            "cfg",
            "--format",
            "text",
            "--function",
            "sensor_task",
        ])
        .output()
        .expect("run safe-checked IPET CLI");
    assert!(!unsafe_run.status.success());
    let stderr = String::from_utf8(unsafe_run.stderr).expect("UTF-8 stderr");
    assert!(stderr.contains("WCET safety check failed"));
}
