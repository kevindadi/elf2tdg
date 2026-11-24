//! F4 and FFX flow-fact import coverage.

use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, AnalysisOutput, PathAnalysis, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg::text_report;

fn fixture_elf() -> Option<PathBuf> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cortex_m0/firmware.elf");
    path.exists().then_some(path)
}

fn profile_text(extra: &str) -> String {
    format!(
        r#"
schema_version = 2
id = "board:flow-import-test"
arch = "thumb"
cpu = "cortex-m0"

[clocks.core]
hz = 48_000_000

[wcet]
default_loop_bound = 4
bound_nonterminating_loops = true
{extra}
"#
    )
}

fn profile(extra: &str) -> BoardProfile {
    BoardProfile::parse_toml(&profile_text(extra)).expect("valid profile")
}

fn analyze(
    flow_fact_paths: Vec<PathBuf>,
    profile: BoardProfile,
    path_analysis: PathAnalysis,
) -> AnalysisOutput {
    let image = loader::load(&fixture_elf().expect("fixture")).expect("load ELF");
    analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            path_analysis,
            flow_fact_paths,
            ..AnalysisOptions::default()
        },
    )
    .expect("analysis")
}

fn temp_file(name: &str, content: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("elf2tdg-flow-facts-{}-{name}", std::process::id()));
    std::fs::write(&path, content).expect("write flow-fact file");
    path
}

fn assert_loop(output: &AnalysisOutput, header: u64, bound: u32, source_fragment: &str) {
    let info = output.cfg.wcet.as_ref().expect("WCET info");
    let facts = info.flow_facts.as_ref().expect("flow facts");
    assert!(facts.source.contains(source_fragment), "{:?}", facts.source);
    let loop_ = facts
        .loops
        .iter()
        .find(|loop_| loop_.header.get() == header)
        .expect("imported loop bound");
    assert_eq!(loop_.bound, bound);
    assert!(loop_.source.contains(source_fragment), "{:?}", loop_.source);
}

#[test]
fn imports_f4_address_function_offset_and_source_line() {
    let Some(_) = fixture_elf() else {
        eprintln!("skipping flow-fact test: fixture is absent");
        return;
    };

    let address = temp_file("address.ff", "loop 0x0800_013e 7;\n");
    let output = analyze(vec![address.clone()], profile(""), PathAnalysis::Ipet);
    assert_loop(&output, 0x0800_013e, 7, "address.ff");

    let offset = temp_file("offset.ff", "loop \"main\" + 0x6 max 9 total 9;\n");
    let output = analyze(vec![offset.clone()], profile(""), PathAnalysis::Ipet);
    assert_loop(&output, 0x0800_013e, 9, "offset.ff");

    let source = temp_file(
        "source.ff",
        "loop \"main.c\":29 max 3 total 3 in \"main\";\n",
    );
    let output = analyze(vec![source.clone()], profile(""), PathAnalysis::Ipet);
    assert_loop(&output, 0x0800_013e, 3, "source.ff");

    let _ = std::fs::remove_file(address);
    let _ = std::fs::remove_file(offset);
    let _ = std::fs::remove_file(source);
}

#[test]
fn imports_ffx_source_and_offsets() {
    let Some(_) = fixture_elf() else {
        return;
    };
    let ffx = temp_file(
        "source.ffx",
        r#"
<flowfacts>
  <function name="main">
    <loop source="main.c" line="29" maxcount="3" totalcount="3"/>
  </function>
</flowfacts>
"#,
    );
    let output = analyze(vec![ffx.clone()], profile(""), PathAnalysis::Ipet);
    assert_loop(&output, 0x0800_013e, 3, "source.ffx");

    let offset = temp_file(
        "offset.ffx",
        r#"
<flowfacts>
  <function name="main">
    <loop offset="0x6" max="5"/>
  </function>
</flowfacts>
"#,
    );
    let output = analyze(vec![offset.clone()], profile(""), PathAnalysis::Ipet);
    assert_loop(&output, 0x0800_013e, 5, "offset.ffx");

    let _ = std::fs::remove_file(ffx);
    let _ = std::fs::remove_file(offset);
}

#[test]
fn imported_bounds_merge_conservatively_and_apply_to_longest_path() {
    let Some(_) = fixture_elf() else {
        return;
    };
    let lower = temp_file("lower.ff", "loop 0x0800_013e 5;\n");
    let output = analyze(
        vec![lower.clone()],
        profile(
            r"
[[wcet.loop_bounds]]
header = 0x0800_013e
bound = 10
",
        ),
        PathAnalysis::Ipet,
    );
    assert_loop(&output, 0x0800_013e, 10, "board-profile [wcet]");
    assert!(
        output
            .cfg
            .wcet
            .as_ref()
            .expect("WCET")
            .caveats
            .iter()
            .any(|caveat| caveat.contains("keeping the larger bound"))
    );

    let longest_path = analyze(vec![lower.clone()], profile(""), PathAnalysis::LongestPath);
    assert_eq!(
        longest_path.cfg.wcet.as_ref().expect("WCET").model,
        "cfg-longest-path"
    );
    assert_loop(&longest_path, 0x0800_013e, 5, "lower.ff");

    let _ = std::fs::remove_file(lower);
}

#[test]
fn context_specific_facts_are_reported() {
    let Some(_) = fixture_elf() else {
        return;
    };
    let ffx = temp_file(
        "context.ffx",
        r#"
<flowfacts>
  <function name="main">
    <call name="main">
      <loop source="main.c" line="29" maxcount="2"/>
    </call>
  </function>
</flowfacts>
"#,
    );
    let output = analyze(vec![ffx.clone()], profile(""), PathAnalysis::Ipet);
    assert_loop(&output, 0x0800_013e, 2, "context.ffx");
    assert!(
        output
            .cfg
            .wcet
            .as_ref()
            .expect("WCET")
            .caveats
            .iter()
            .any(|caveat| caveat.contains("context-insensitively"))
    );
    let _ = std::fs::remove_file(ffx);
}

#[allow(clippy::too_many_lines)]
#[test]
fn imports_ffx_branch_and_call_facts() {
    let Some(_) = fixture_elf() else {
        return;
    };
    let baseline = analyze(Vec::new(), profile(""), PathAnalysis::Ipet);
    let baseline_delay = baseline
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name == "delay")
        .and_then(|function| function.wcet.as_ref())
        .and_then(|wcet| wcet.cycles)
        .expect("baseline delay WCET");
    let baseline_main = baseline
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name == "main")
        .and_then(|function| function.wcet.as_ref())
        .and_then(|wcet| wcet.cycles)
        .expect("baseline main WCET");

    let branch = temp_file(
        "branch.ffx",
        r#"
<flowfacts>
  <conditional>
    <condition address="0x0800_00f6"/>
    <case cond="1" executed="false"/>
  </conditional>
</flowfacts>
"#,
    );
    let output = analyze(vec![branch.clone()], profile(""), PathAnalysis::Ipet);
    let facts = output
        .cfg
        .wcet
        .as_ref()
        .expect("WCET")
        .flow_facts
        .as_ref()
        .expect("flow facts");
    let branch_fact = facts
        .branches
        .iter()
        .find(|fact| fact.site.get() == 0x0800_00f6)
        .expect("imported branch fact");
    assert_eq!(branch_fact.outcome, "taken");
    assert_eq!(branch_fact.max_count, 0);
    assert!(branch_fact.source.contains("branch.ffx"));
    let tightened_delay = output
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name == "delay")
        .and_then(|function| function.wcet.as_ref())
        .and_then(|wcet| wcet.cycles)
        .expect("branch-constrained delay WCET");
    assert!(
        tightened_delay < baseline_delay,
        "branch fact must tighten WCET: {tightened_delay} < {baseline_delay}"
    );
    let json = cfg::render_json(&output.cfg, None, false).expect("CFG JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        value["wcet"]["flow_facts"]["branches"][0]["outcome"],
        "taken"
    );
    let text = text_report::render_text(&output.cfg, None, false).expect("text report");
    assert!(text.contains("branch fact"));

    let call = temp_file(
        "call.ffx",
        r#"
<flowfacts>
  <call name="delay" address="0x0800_0140" numcall="1"/>
</flowfacts>
"#,
    );
    let output = analyze(vec![call.clone()], profile(""), PathAnalysis::Ipet);
    let facts = output
        .cfg
        .wcet
        .as_ref()
        .expect("WCET")
        .flow_facts
        .as_ref()
        .expect("flow facts");
    let call_fact = facts
        .calls
        .iter()
        .find(|fact| fact.site.get() == 0x0800_0140)
        .expect("imported call fact");
    assert_eq!(call_fact.max_count, 1);
    assert!(call_fact.source.contains("call.ffx"));
    let tightened_main = output
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name == "main")
        .and_then(|function| function.wcet.as_ref())
        .and_then(|wcet| wcet.cycles)
        .expect("call-constrained main WCET");
    assert!(
        tightened_main < baseline_main,
        "call fact must tighten WCET: {tightened_main} < {baseline_main}"
    );
    let json = cfg::render_json(&output.cfg, None, false).expect("CFG JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["wcet"]["flow_facts"]["calls"][0]["max_count"], 1);
    let text = text_report::render_text(&output.cfg, None, false).expect("text report");
    assert!(text.contains("call fact"));

    let _ = std::fs::remove_file(branch);
    let _ = std::fs::remove_file(call);
}

#[test]
fn context_specific_non_loop_facts_are_ignored_conservatively() {
    let Some(_) = fixture_elf() else {
        return;
    };
    let ffx = temp_file(
        "context-branch.ffx",
        r#"
<flowfacts>
  <function name="main">
    <call name="delay">
      <conditional address="0x0800_00e4">
        <case cond="1" executed="false"/>
      </conditional>
    </call>
  </function>
</flowfacts>
"#,
    );
    let output = analyze(vec![ffx.clone()], profile(""), PathAnalysis::Ipet);
    let wcet = output.cfg.wcet.as_ref().expect("WCET");
    let facts = wcet.flow_facts.as_ref().expect("flow facts");
    assert!(facts.branches.is_empty());
    assert!(
        wcet.caveats
            .iter()
            .any(|caveat| caveat.contains("context-specific branch fact"))
    );
    let _ = std::fs::remove_file(ffx);
}

#[test]
fn longest_path_reports_ignored_non_loop_facts() {
    let Some(_) = fixture_elf() else {
        return;
    };
    let ffx = temp_file(
        "longest-branch.ffx",
        r#"
<flowfacts>
  <conditional address="0x0800_00e4">
    <case cond="1" executed="false"/>
  </conditional>
</flowfacts>
"#,
    );
    let output = analyze(vec![ffx.clone()], profile(""), PathAnalysis::LongestPath);
    let wcet = output.cfg.wcet.as_ref().expect("WCET");
    assert!(
        wcet.caveats
            .iter()
            .any(|caveat| caveat.contains("enforced only by the IPET"))
    );
    let _ = std::fs::remove_file(ffx);
}

#[test]
fn flowfacts_require_a_wcet_profile() {
    let Some(fixture) = fixture_elf() else {
        return;
    };
    let board = BoardProfile::parse_toml(
        r#"
schema_version = 2
id = "board:no-wcet"
arch = "thumb"
cpu = "cortex-m0"

[clocks.core]
hz = 48_000_000
"#,
    )
    .expect("valid profile");
    let flowfacts = temp_file("no-wcet.ff", "loop 0x0800_013e 3;\n");
    let image = loader::load(&fixture).expect("load ELF");
    let error = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(board),
            flow_fact_paths: vec![flowfacts.clone()],
            ..AnalysisOptions::default()
        },
    )
    .expect_err("flow facts without [wcet] must fail");
    assert!(error.to_string().contains("flow-fact files require"));
    let _ = std::fs::remove_file(flowfacts);
}

#[test]
fn cli_accepts_flowfacts_files() {
    let Some(fixture) = fixture_elf() else {
        return;
    };
    let profile_path = temp_file("cli.toml", &profile_text(""));
    let flowfacts = temp_file("cli.ff", "loop 0x0800_013e 6;\n");
    let output_path = std::env::temp_dir().join(format!(
        "elf2tdg-flow-facts-{}-cli.json",
        std::process::id()
    ));
    let status = Command::new(env!("CARGO_BIN_EXE_elf2tdg"))
        .arg(&fixture)
        .arg("--board-profile")
        .arg(&profile_path)
        .arg("--flowfacts")
        .arg(&flowfacts)
        .args(["--path-analysis", "ipet", "--format", "json", "--output"])
        .arg(&output_path)
        .status()
        .expect("run flow-fact CLI");
    assert!(status.success());
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&output_path).expect("JSON output"))
            .expect("valid JSON");
    assert!(
        document["wcet"]["flow_facts"]["source"]
            .as_str()
            .is_some_and(|source| source.contains("cli.ff"))
    );
    assert_eq!(
        document["wcet"]["flow_facts"]["loops"][0]["bound"],
        serde_json::json!(6)
    );
    let _ = std::fs::remove_file(profile_path);
    let _ = std::fs::remove_file(flowfacts);
    let _ = std::fs::remove_file(output_path);
}
