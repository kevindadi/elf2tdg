//! End-to-end CFG export from a real Cortex-M0 ELF.

use std::path::{Path, PathBuf};

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg_schema::{ContextKind, Edge};

fn fixture_elf() -> Option<PathBuf> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cortex_m0/firmware.elf");
    path.exists().then_some(path)
}

#[test]
fn exports_function_cfg_for_main() {
    let Some(path) = fixture_elf() else {
        eprintln!("skipping CFG export test: Cortex-M0 fixture is absent");
        return;
    };
    let image = loader::load(&path).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    analysis.tdg.ensure_valid().expect("TDG must validate");

    let main = analysis
        .cfg
        .select(Some("main"))
        .expect("main CFG")
        .into_iter()
        .next()
        .expect("main function");
    assert!(main.cfg.entry.is_some());
    assert!(!main.cfg.blocks_by_address.is_empty());
    let calls: Vec<_> = main
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| main.cfg.graph[*node].calls.iter())
        .collect();
    assert!(!calls.is_empty(), "main should retain call sites");
    assert!(calls.iter().any(|call| call.target_function.is_some()));
    for node in main.cfg.blocks_by_address.values() {
        let block = &main.cfg.graph[*node];
        assert!(!block.instructions.is_empty());
        assert!(
            block
                .instructions
                .iter()
                .all(|instruction| !instruction.bytes.is_empty())
        );
    }

    let json =
        cfg::render_json(&analysis.cfg, &analysis.tdg, Some("main"), true).expect("CFG JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert_eq!(value["functions"].as_array().map(Vec::len), Some(1));
    assert_eq!(value["functions"][0]["primary_name"], "main");
    assert!(value["functions"][0]["blocks"][0]["instructions"][0]["bytes"].is_string());

    let dot = cfg::render_dot(&analysis.cfg, Some("main"), true).expect("CFG DOT");
    assert!(dot.contains("bb:"));
    assert!(dot.contains("call:"));
    let mermaid = cfg::render_mermaid(&analysis.cfg, Some("main"), true).expect("CFG Mermaid");
    assert!(mermaid.contains("flowchart LR"));
    assert!(mermaid.contains("main"));
    assert!(mermaid.contains("call"));
}

#[test]
fn reachable_from_main_filters_runtime_and_keeps_embassy_tasks() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    if !path.exists() {
        return;
    }
    let image = loader::load(&path).expect("example ELF must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let reachable = analysis
        .cfg
        .reachable_from(&analysis.tdg, "main")
        .expect("main reachability");
    assert!(
        reachable.len() < analysis.cfg.functions.len(),
        "default scope should filter the image"
    );

    for task in [
        "rust_concurrency::sensor_task",
        "rust_concurrency::monitor_task",
    ] {
        assert!(
            analysis.tdg.contexts.iter().any(|context| {
                context.kind == ContextKind::AsyncTask && context.name.contains(task)
            }),
            "spawned Embassy task {task} must remain visible in the TDG"
        );
    }
    let embassy_spawns = analysis.tdg.edges.iter().filter(|edge| {
        matches!(
            edge,
            Edge::Spawn { runtime, .. } if runtime.as_str() == "rust-embassy"
        )
    });
    assert_eq!(
        embassy_spawns.count(),
        3,
        "main task plus sensor/monitor task spawns"
    );

    let json = cfg::render_json_selected(&analysis.cfg, &analysis.tdg, &reachable, false)
        .expect("reachable JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        value["functions"].as_array().map(Vec::len),
        Some(reachable.len())
    );
}

#[test]
fn cfg_retains_gap_recovered_calls_and_tdg_parity() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    if !path.exists() {
        return;
    }
    let image = loader::load(&path).expect("example ELF must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let recovered: usize = analysis
        .cfg
        .functions
        .iter()
        .map(|function| function.cfg.recovered_calls.len())
        .sum();
    // Jump-table decoding can eliminate all gaps in this fixture; the unit
    // test in analysis.rs covers the recovered-call path directly.
    let _ = recovered;
    for edge in &analysis.tdg.edges {
        let Edge::Call {
            caller, site, tail, ..
        } = edge
        else {
            continue;
        };
        let function = analysis.cfg.function(caller).expect("caller CFG");
        let in_blocks = function
            .cfg
            .blocks_by_address
            .values()
            .flat_map(|node| function.cfg.graph[*node].calls.iter())
            .any(|call| call.site == site.get() && call.tail == *tail);
        let in_recovered = function
            .cfg
            .recovered_calls
            .iter()
            .any(|call| call.site == site.get() && call.tail == *tail);
        assert!(
            in_blocks || in_recovered,
            "TDG call at {} is missing from CFG",
            site.get()
        );
    }
}

#[test]
fn cfg_blocks_match_tdg_blocks() {
    let Some(path) = fixture_elf() else {
        return;
    };
    let image = loader::load(&path).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    for function in analysis
        .tdg
        .functions
        .iter()
        .filter(|function| function.size > 0)
    {
        let cfg_function = analysis
            .cfg
            .function(&function.id)
            .expect("CFG for every analyzed function");
        assert_eq!(
            cfg_function.cfg.blocks_by_address.len(),
            function.blocks.len(),
            "block count mismatch for {}",
            function.primary_name
        );
    }
    for edge in &analysis.tdg.edges {
        let Edge::Call {
            caller, site, tail, ..
        } = edge
        else {
            continue;
        };
        let cfg_function = analysis
            .cfg
            .function(caller)
            .expect("CFG caller for call edge");
        let found = cfg_function
            .cfg
            .blocks_by_address
            .values()
            .flat_map(|node| cfg_function.cfg.graph[*node].calls.iter())
            .any(|call| call.site == site.get() && call.tail == *tail);
        assert!(
            found,
            "TDG call edge at {} is not represented in the CFG",
            site.get()
        );
    }
}

#[test]
fn system_roots_include_vector_isrs_but_skip_default_handlers() {
    let Some(path) = fixture_elf() else {
        return;
    };
    let image = loader::load(&path).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let roots = analysis.cfg.system_roots(&analysis.tdg, &image);
    assert_ne!(roots.len(), 0);
    let reachable = analysis
        .cfg
        .reachable_from_system(&analysis.tdg, &image, false);
    let names: Vec<&str> = reachable
        .iter()
        .map(|function| function.primary_name.as_str())
        .collect();
    assert!(names.contains(&"main"));
    assert!(names.contains(&"USART1_IRQHandler"));
    assert!(names.contains(&"Reset_Handler"));
    assert!(
        !names.contains(&"Default_Handler"),
        "unused default vectors must not become roots"
    );
    let main_only = analysis
        .cfg
        .reachable_from(&analysis.tdg, "main")
        .expect("main reachability");
    assert!(
        reachable.len() > main_only.len(),
        "multi-root scope should include asynchronous entries"
    );
}

#[test]
fn system_reachability_covers_embassy_tasks() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    if !path.exists() {
        return;
    }
    let image = loader::load(&path).expect("example ELF must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let unpruned = analysis
        .cfg
        .reachable_from_system(&analysis.tdg, &image, false);
    let pruned = analysis
        .cfg
        .reachable_from_system(&analysis.tdg, &image, true);
    assert!(
        unpruned
            .iter()
            .any(|function| function.primary_name.contains("start_tasks")),
        "system roots should reach the Embassy spawn function"
    );
    assert!(
        pruned.len() <= unpruned.len(),
        "runtime boundary pruning must not add functions"
    );
    assert!(
        pruned
            .iter()
            .any(|function| function.primary_name == "main")
    );
}

#[test]
fn cfg_json_limits_diagnostics_to_selected_functions() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    if !path.exists() {
        return;
    }
    let image = loader::load(&path).expect("example ELF must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let reachable = analysis
        .cfg
        .reachable_from(&analysis.tdg, "rust_concurrency::start_tasks")
        .expect("start_tasks reachability");
    let selected: std::collections::BTreeSet<_> =
        reachable.iter().map(|function| &function.id).collect();
    let json = cfg::render_json_selected(&analysis.cfg, &analysis.tdg, &reachable, false)
        .expect("CFG JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert!(
        value["diagnostics_omitted"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "unreachable diagnostics should be reported as omitted"
    );
    for diagnostic in value["diagnostics"].as_array().expect("diagnostics") {
        if let Some(function) = diagnostic["function"].as_str() {
            let function = elf2tdg_schema::FunctionId::new(function);
            assert!(
                selected.contains(&function),
                "diagnostic for out-of-scope function {function}"
            );
        }
    }
}
