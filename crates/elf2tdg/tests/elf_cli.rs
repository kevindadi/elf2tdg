//! CLI coverage for the loader-backed ELF Mermaid view.

use std::path::PathBuf;
use std::process::Command;

fn fixture_elf() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/cortex_m0/firmware.elf");
    path.exists().then_some(path)
}

#[test]
fn cli_renders_elf_layout_as_mermaid_by_default() {
    let Some(fixture) = fixture_elf() else {
        eprintln!("skipping ELF view test: fixture is absent");
        return;
    };
    let directory = std::env::temp_dir().join(format!("elf2tdg-elf-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("temp directory");
    let output = directory.join("layout.mmd");

    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .args(["--view", "elf", "--output"])
        .arg(&output)
        .status()
        .expect("run ELF view");
    assert!(status.success());
    let mermaid = std::fs::read_to_string(&output).expect("ELF Mermaid output");
    assert!(mermaid.contains("flowchart TB"));
    assert!(mermaid.contains("classDef segmentRx"));
    assert!(mermaid.contains("LOAD (PT_LOAD)"));
    assert!(mermaid.contains(".isr_vector"));
    assert!(mermaid.contains(".text"));
    assert!(mermaid.contains("insnCall"));
    assert!(mermaid.contains("Legend"));

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn cli_limits_elf_instructions_and_rejects_non_mermaid_formats() {
    let Some(fixture) = fixture_elf() else {
        eprintln!("skipping ELF view test: fixture is absent");
        return;
    };
    let directory = std::env::temp_dir().join(format!("elf2tdg-elf-limit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("temp directory");
    let output = directory.join("layout.mmd");

    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .args(["--view", "elf", "--elf-max-insns", "1", "--output"])
        .arg(&output)
        .status()
        .expect("run limited ELF view");
    assert!(status.success());
    let mermaid = std::fs::read_to_string(&output).expect("limited ELF Mermaid");
    assert!(mermaid.contains("truncated after 1 instruction"));

    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .args(["--view", "elf", "--format", "json"])
        .output()
        .expect("run unsupported ELF format");
    assert!(!status.status.success());
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert!(stderr.contains("only --format mermaid"), "{stderr}");

    let _ = std::fs::remove_dir_all(&directory);
}
