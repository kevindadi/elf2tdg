//! End-to-end CFG export from a real Cortex-M0 ELF.

use std::path::{Path, PathBuf};

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg;
use elf2tdg::cfg::CfgConcurrencyKind;
use elf2tdg::loader;

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
    analysis.cfg.ensure_valid().expect("CFG must validate");

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

    let json = cfg::render_json(&analysis.cfg, Some("main"), true).expect("CFG JSON");
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
        .reachable_from("main")
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
            analysis.cfg.roots.iter().any(|root| {
                root.kind == elf2tdg::cfg::CfgRootKind::Task
                    && root.name.as_deref().is_some_and(|name| name.contains(task))
            }),
            "spawned Embassy task {task} must remain a CFG root"
        );
    }
    let embassy_spawns = analysis
        .cfg
        .concurrency
        .iter()
        .filter(|site| {
            matches!(
                &site.operation,
                CfgConcurrencyKind::Spawn { runtime, .. } if runtime.as_str() == "rust-embassy"
            )
        })
        .count();
    assert_eq!(
        embassy_spawns, 3,
        "main task plus sensor/monitor task spawns"
    );

    let json = cfg::render_json_selected(&analysis.cfg, &reachable, false).expect("reachable JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        value["functions"].as_array().map(Vec::len),
        Some(reachable.len())
    );
}

#[test]
fn cfg_call_graph_is_consistent() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    if !path.exists() {
        return;
    }
    let image = loader::load(&path).expect("example ELF must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    assert!(!analysis.cfg.calls.is_empty());
    for call in &analysis.cfg.calls {
        assert!(analysis.cfg.function(&call.caller).is_some());
        if let Some(callee) = &call.callee {
            assert!(analysis.cfg.function(callee).is_some());
        }
        for candidate in &call.candidates {
            assert!(analysis.cfg.function(candidate).is_some());
        }
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
    let roots = analysis.cfg.system_roots(&image);
    assert_ne!(roots.len(), 0);
    let reachable = analysis.cfg.reachable_from_system(&image, false);
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
        .reachable_from("main")
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
    let unpruned = analysis.cfg.reachable_from_system(&image, false);
    let pruned = analysis.cfg.reachable_from_system(&image, true);
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
        .reachable_from("rust_concurrency::start_tasks")
        .expect("start_tasks reachability");
    let selected: std::collections::BTreeSet<_> =
        reachable.iter().map(|function| &function.id).collect();
    let json = cfg::render_json_selected(&analysis.cfg, &reachable, false).expect("CFG JSON");
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
