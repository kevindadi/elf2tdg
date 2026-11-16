//! CLI coverage for the CFG view.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

fn fixture_elf() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/cortex_m0/firmware.elf");
    path.exists().then_some(path)
}

fn temp_dir(name: &str) -> Option<(PathBuf, PathBuf)> {
    let fixture = fixture_elf()?;
    let directory =
        std::env::temp_dir().join(format!("elf2tdg-cfg-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("temp directory");
    Some((fixture, directory))
}

fn run_cfg(fixture: &Path, format: &str, output: &Path, no_instructions: bool) -> ExitStatus {
    let mut command = Command::new(env!("CARGO_BIN_EXE_elf2tdg"));
    command
        .arg(fixture)
        .args(["--view", "cfg", "--format", format, "--function", "main"]);
    if no_instructions {
        command.arg("--no-cfg-instructions");
    }
    command
        .arg("--output")
        .arg(output)
        .status()
        .expect("run CFG command")
}

#[test]
fn cli_exports_cfg_json_and_dot_with_instructions() {
    let Some((fixture, directory)) = temp_dir("full") else {
        eprintln!("skipping CFG CLI test: fixture is absent");
        return;
    };
    let json_path = directory.join("main.json");
    assert!(run_cfg(&fixture, "json", &json_path, false).success());
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).expect("CFG JSON"))
            .expect("parse CFG JSON");
    assert_eq!(json["cfg_schema_version"], "1.0");
    assert_eq!(json["functions"][0]["primary_name"], "main");
    assert!(json["functions"][0]["blocks"][0]["instructions"][0]["bytes"].is_string());

    let dot_path = directory.join("main.dot");
    assert!(run_cfg(&fixture, "dot", &dot_path, false).success());
    let dot = std::fs::read_to_string(&dot_path).expect("CFG DOT");
    assert!(dot.contains("digraph cfg"));
    assert!(dot.contains("bb:"));
    assert!(
        dot.contains("push {r4, lr}"),
        "DOT labels should carry assembly by default"
    );

    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .args(["--view", "cfg", "--format", "json"])
        .output()
        .expect("run CFG without selector");
    assert!(
        status.status.success(),
        "CFG should default to functions reachable from main"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn cli_defaults_to_system_reachability_and_all_functions_is_opt_in() {
    let Some((fixture, directory)) = temp_dir("reachable") else {
        eprintln!("skipping CFG CLI test: fixture is absent");
        return;
    };
    let default_path = directory.join("reachable.json");
    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .args(["--view", "cfg", "--format", "json", "--output"])
        .arg(&default_path)
        .status()
        .expect("run default CFG");
    assert!(status.success());
    let default: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&default_path).expect("reachable CFG"))
            .expect("parse reachable CFG");
    let default_names: Vec<&str> = default["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|function| function["primary_name"].as_str().expect("name"))
        .collect();
    assert!(default_names.contains(&"main"));
    assert!(default_names.contains(&"sensor_task"));
    assert!(default_names.contains(&"USART1_IRQHandler"));
    assert!(default_names.contains(&"Reset_Handler"));
    assert!(!default_names.contains(&"Default_Handler"));

    let all_path = directory.join("all.json");
    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .args([
            "--view",
            "cfg",
            "--format",
            "json",
            "--all-functions",
            "--output",
        ])
        .arg(&all_path)
        .status()
        .expect("run full CFG");
    assert!(status.success());
    let all: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&all_path).expect("full CFG"))
            .expect("parse full CFG");
    let all_names: Vec<&str> = all["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|function| function["primary_name"].as_str().expect("name"))
        .collect();
    assert!(all_names.contains(&"USART1_IRQHandler"));
    assert!(all_names.contains(&"Default_Handler"));
    assert!(all_names.len() > default_names.len());

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn cli_reachable_from_selects_a_custom_root() {
    let Some((fixture, directory)) = temp_dir("custom-root") else {
        eprintln!("skipping CFG CLI test: fixture is absent");
        return;
    };
    let json_path = directory.join("sensor-task.json");
    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .args([
            "--view",
            "cfg",
            "--format",
            "json",
            "--reachable-from",
            "sensor_task",
            "--output",
        ])
        .arg(&json_path)
        .status()
        .expect("run reachable CFG");
    assert!(status.success());
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).expect("reachable CFG JSON"))
            .expect("parse reachable CFG JSON");
    let names: Vec<&str> = value["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|function| function["primary_name"].as_str().expect("name"))
        .collect();
    assert!(names.contains(&"sensor_task"));
    assert!(names.contains(&"delay"));
    assert!(!names.contains(&"main"));

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn cli_can_omit_cfg_instructions_from_json_and_dot() {
    let Some((fixture, directory)) = temp_dir("compact") else {
        eprintln!("skipping CFG CLI test: fixture is absent");
        return;
    };
    let json_path = directory.join("main-compact.json");
    assert!(run_cfg(&fixture, "json", &json_path, true).success());
    let compact: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).expect("compact CFG JSON"))
            .expect("parse compact CFG JSON");
    assert!(
        compact["functions"][0]["blocks"][0]
            .get("instructions")
            .is_none(),
        "instructions should be omitted"
    );

    let dot_path = directory.join("main-compact.dot");
    assert!(run_cfg(&fixture, "dot", &dot_path, true).success());
    let compact_dot = std::fs::read_to_string(&dot_path).expect("compact CFG DOT");
    assert!(compact_dot.contains("2 insn"));
    assert!(
        !compact_dot.contains("push {r4, lr}"),
        "DOT labels should omit assembly when requested"
    );

    let _ = std::fs::remove_dir_all(&directory);
}
