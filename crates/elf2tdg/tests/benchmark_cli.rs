//! End-to-end coverage for the benchmark harness binary.

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn benchmark_cli_runs_longest_path_and_ipet() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf = manifest.join("../../tests/fixtures/cortex_m0/firmware.elf");
    let profile = manifest.join("../../benchmarks/profiles/cortex-m0-benchmark.toml");
    if !elf.exists() || !profile.exists() {
        eprintln!("skipping benchmark CLI test: fixtures are absent");
        return;
    }
    let directory = std::env::temp_dir().join(format!("elf2tdg-bench-cli-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("create benchmark temp dir");
    let suite = directory.join("suite.toml");
    let json = directory.join("report.json");
    let markdown = directory.join("report.md");
    fs::write(
        &suite,
        format!(
            "schema_version = 1\n\n[[case]]\nid = \"fixture\"\nelf = '{}'\nprofile = '{}'\nanalyses = [\"longest-path\", \"ipet\"]\n\n[case.reference]\nbackend = \"ipet\"\nsource = \"fixture-reference\"\ncycles = 1.0\n",
            elf.display(),
            profile.display()
        ),
    )
    .expect("write suite");
    let output = Command::new(env!("CARGO_BIN_EXE_elf2tdg-bench"))
        .arg("--suite")
        .arg(&suite)
        .arg("--json")
        .arg(&json)
        .arg("--markdown")
        .arg(&markdown)
        .arg("--fail-on-error")
        .output()
        .expect("run benchmark binary");
    assert!(
        output.status.success(),
        "benchmark failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&json).expect("read JSON report"))
            .expect("parse JSON report");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["cases"][0]["id"], "fixture");
    let analyses = report["cases"][0]["analyses"]
        .as_array()
        .expect("analysis array");
    assert_eq!(analyses.len(), 2);
    for analysis in analyses {
        assert_eq!(analysis["status"], "ok");
        assert!(
            analysis["wcet"]["max_root_cycles"]
                .as_f64()
                .is_some_and(|cycles| cycles > 0.0)
        );
        assert_eq!(analysis["timing"]["determinism"], "bounded");
    }
    assert_eq!(analyses[1]["reference"]["source"], "fixture-reference");
    assert!(
        analyses[1]["reference"]["measured_cycles"]
            .as_f64()
            .is_some_and(|cycles| cycles > 0.0)
    );
    assert_eq!(report["summary"]["analyses_error"], 0);
    let markdown_text = fs::read_to_string(&markdown).expect("read Markdown report");
    assert!(markdown_text.contains("| fixture | ipet | ok |"));
    let _ = fs::remove_dir_all(&directory);
}
