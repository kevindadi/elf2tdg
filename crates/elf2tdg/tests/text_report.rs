//! Human-readable CFG/WCET report coverage.

use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::loader;
use elf2tdg::text_report;

fn fixture_elf() -> Option<PathBuf> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cortex_m0/firmware.elf");
    path.exists().then_some(path)
}

fn example_elf() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    path.exists().then_some(path)
}

#[test]
fn renders_readable_cfg_for_main() {
    let Some(path) = fixture_elf() else {
        eprintln!("skipping text report test: Cortex-M0 fixture is absent");
        return;
    };
    let image = loader::load(&path).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let text = text_report::render_text(&analysis.cfg, Some("main"), true)
        .expect("text report must render");
    for expected in [
        "elf2tdg CFG report",
        "execution roots",
        "interprocedural call graph",
        "function main",
        "block bb:",
        "terminator=",
        "push {r4, lr}",
        "sensor_task",
        "wcet",
        "not analyzed",
    ] {
        assert!(text.contains(expected), "missing {expected:?}");
    }
    assert!(!text.contains("\"cfg_schema_version\""));
}

#[test]
fn renders_wcet_details_from_a_profile() {
    let Some(path) = example_elf() else {
        eprintln!("skipping WCET text report test: example ELF is absent");
        return;
    };
    let profile_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/profiles/cortex-m7-wcet.toml");
    if !profile_path.exists() {
        return;
    }
    let image = loader::load(&path).expect("example ELF must load");
    let profile = BoardProfile::load(&profile_path).expect("profile must load");
    let analysis = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("analysis must succeed");
    let text = text_report::render_text(&analysis.cfg, Some("sensor_task"), true)
        .expect("text report must render");
    for expected in [
        "model          cfg-longest-path",
        "root estimates:",
        "cycle(s)",
        "wcet",
        "sensor_task",
        "analysis models",
    ] {
        assert!(text.contains(expected), "missing {expected:?}");
    }
}

#[test]
fn text_format_and_compact_instructions_work_from_the_cli() {
    let Some(fixture) = fixture_elf() else {
        eprintln!("skipping text CLI test: Cortex-M0 fixture is absent");
        return;
    };
    let directory =
        std::env::temp_dir().join(format!("elf2tdg-text-report-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("temp directory");
    let full = directory.join("main.txt");
    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .args([
            "--view",
            "cfg",
            "--format",
            "text",
            "--function",
            "main",
            "--output",
        ])
        .arg(&full)
        .status()
        .expect("run text report");
    assert!(status.success());
    let text = std::fs::read_to_string(&full).expect("text report file");
    assert!(text.contains("push {r4, lr}"));

    let compact = directory.join("main-compact.txt");
    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .args([
            "--view",
            "cfg",
            "--format",
            "text",
            "--function",
            "main",
            "--no-cfg-instructions",
            "--output",
        ])
        .arg(&compact)
        .status()
        .expect("run compact text report");
    assert!(status.success());
    let compact_text = std::fs::read_to_string(&compact).expect("compact text report");
    assert!(compact_text.contains("omitted by --no-cfg-instructions"));
    assert!(!compact_text.contains("push {r4, lr}"));

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn list_passes_works_without_an_input_elf() {
    let plain = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg("--list-passes")
        .output()
        .expect("run pass listing");
    assert!(plain.status.success());
    let plain = String::from_utf8(plain.stdout).expect("UTF-8 output");
    for expected in [
        "frontend.cfg-recovery",
        "timing.instruction-cost",
        "analysis.instruction-cache",
        "wcet.longest-path",
        "wcet.ipet",
    ] {
        assert!(plain.contains(expected), "missing {expected:?}");
    }
    assert!(plain.contains("no [wcet] section in the board profile"));

    let profile = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/profiles/cortex-m4-full-stack.toml");
    if !profile.exists() {
        return;
    }
    let with_profile = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg("--list-passes")
        .arg("--board-profile")
        .arg(&profile)
        .output()
        .expect("run pass listing with profile");
    assert!(with_profile.status.success());
    let with_profile = String::from_utf8(with_profile.stdout).expect("UTF-8 output");
    for expected in [
        "[instruction_cache] is present in the board profile",
        "[data_cache] is present in the board profile",
        "[branch_prediction] is present in the board profile",
        "selected --path-analysis longest-path",
        "select --path-analysis ipet",
    ] {
        assert!(with_profile.contains(expected), "missing {expected:?}");
    }

    let with_ipet = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg("--list-passes")
        .arg("--board-profile")
        .arg(&profile)
        .args(["--path-analysis", "ipet"])
        .output()
        .expect("run IPET pass listing");
    assert!(with_ipet.status.success());
    let with_ipet = String::from_utf8(with_ipet.stdout).expect("UTF-8 output");
    for expected in [
        "selected --path-analysis ipet",
        "select --path-analysis longest-path",
    ] {
        assert!(with_ipet.contains(expected), "missing {expected:?}");
    }
}
