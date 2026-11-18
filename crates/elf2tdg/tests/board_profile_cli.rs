//! CLI coverage for board-profile loading and error reporting.

use std::path::PathBuf;
use std::process::Command;

fn example_paths() -> Option<(PathBuf, PathBuf)> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let elf = manifest.join("../../examples/cortex-m0-isr/artifacts/cortex-m0-isr.elf");
    let profile = manifest.join("../../examples/profiles/cortex-m0-isr.toml");
    (elf.exists() && profile.exists()).then_some((elf, profile))
}

fn output_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "elf2tdg-board-cli-{}-{name}.json",
        std::process::id()
    ))
}

#[test]
#[allow(clippy::too_many_lines)]
fn cli_applies_board_profile_and_rejects_cpu_conflict() {
    let Some((elf, profile)) = example_paths() else {
        eprintln!("skipping board-profile CLI test: examples are absent");
        return;
    };
    let output = output_path("applied");
    let output_result = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&elf)
        .arg("--board-profile")
        .arg(&profile)
        .arg("--output")
        .arg(&output)
        .output()
        .expect("run profiled analysis");
    assert!(
        output_result.status.success(),
        "profiled CLI failed: {}",
        String::from_utf8_lossy(&output_result.stderr)
    );
    let tdg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output).expect("TDG JSON"))
            .expect("parse TDG JSON");
    let extras = &tdg["timing"]["models"][0]["params"]["extras"];
    assert_eq!(extras["board_profile_id"], "board:cortex-m0-isr");
    assert!(
        extras["board_profile_sha256"]
            .as_str()
            .is_some_and(|h| h.len() == 64)
    );
    assert_eq!(
        tdg["timing"]["frequency_domains"][0]["source"],
        "board-profile"
    );

    let conflict = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&elf)
        .arg("--board-profile")
        .arg(&profile)
        .args(["--cpu", "cortex-m4", "--output"])
        .arg(output_path("conflict"))
        .output()
        .expect("run conflicting analysis");
    assert!(!conflict.status.success());
    assert!(
        String::from_utf8_lossy(&conflict.stderr).contains("conflicts with board profile"),
        "conflict stderr: {}",
        String::from_utf8_lossy(&conflict.stderr)
    );

    let elf_view = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&elf)
        .args(["--view", "elf", "--board-profile"])
        .arg(&profile)
        .output()
        .expect("run ELF view with profile");
    assert!(!elf_view.status.success());
    assert!(
        String::from_utf8_lossy(&elf_view.stderr)
            .contains("only supported for TDG and CFG analysis"),
        "ELF-view stderr: {}",
        String::from_utf8_lossy(&elf_view.stderr)
    );

    let _ = std::fs::remove_file(output);
    let _ = std::fs::remove_file(output_path("conflict"));
}
