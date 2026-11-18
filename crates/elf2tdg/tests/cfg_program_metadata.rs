//! CFG-native program metadata and self-contained CFG JSON output.

use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg::{self, CfgRootKind};
use elf2tdg::loader;

#[test]
fn cortex_cfg_carries_roots_calls_and_analysis_metadata() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/cortex-m0-isr/artifacts/cortex-m0-isr.elf");
    if !path.exists() {
        return;
    }
    let image = loader::load(&path).expect("example ELF must load");
    let analysis = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            cpu: Some("cortex-m0".to_owned()),
            frequency_hz: Some(48_000_000),
            ..AnalysisOptions::default()
        },
    )
    .expect("analysis must succeed");

    assert!(analysis.cfg.image.is_some(), "CFG must own image metadata");
    assert!(
        analysis.cfg.timing.is_some(),
        "CFG must own timing metadata"
    );
    assert!(
        analysis
            .cfg
            .timing
            .as_ref()
            .is_some_and(|timing| !timing.models.is_empty()),
        "CFG timing metadata must describe the selected model"
    );
    assert!(
        analysis
            .cfg
            .roots
            .iter()
            .any(|root| root.kind == CfgRootKind::Startup)
    );
    assert!(
        analysis
            .cfg
            .roots
            .iter()
            .any(|root| root.kind == CfgRootKind::Main)
    );
    assert!(
        analysis.cfg.roots.iter().any(|root| {
            root.kind == CfgRootKind::Isr && root.vector == Some(53) && root.irq == Some(37)
        }),
        "ISR vector metadata must survive in the CFG"
    );
    assert!(!analysis.cfg.calls.is_empty());
    for call in &analysis.cfg.calls {
        assert!(analysis.cfg.function(&call.caller).is_some());
        if let Some(callee) = &call.callee {
            assert!(analysis.cfg.function(callee).is_some());
        }
    }

    let selected = analysis
        .cfg
        .select(Some("main"))
        .expect("CFG selector must work without external graph data");
    assert_eq!(selected[0].primary_name, "main");
    let json =
        cfg::render_json(&analysis.cfg, Some("main"), false).expect("self-contained CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("parse CFG JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert!(document["image"].is_object());
    assert!(document["timing"].is_object());
    assert!(
        document["roots"]
            .as_array()
            .is_some_and(|roots| !roots.is_empty())
    );
    assert!(
        document["calls"]
            .as_array()
            .is_some_and(|calls| !calls.is_empty())
    );
}

#[test]
fn rust_cfg_carries_task_aliases_and_concurrency_annotations() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    if !path.exists() {
        return;
    }
    let image = loader::load(&path).expect("example ELF must load");
    let analysis = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            cpu: Some("cortex-m4".to_owned()),
            frequency_hz: Some(168_000_000),
            ..AnalysisOptions::default()
        },
    )
    .expect("analysis must succeed");

    assert!(
        analysis
            .cfg
            .roots
            .iter()
            .any(|root| root.kind == CfgRootKind::Task)
    );
    let selected = analysis
        .cfg
        .select(Some("sensor_task"))
        .expect("task alias selection");
    assert_eq!(selected.len(), 1);
    assert!(selected[0].primary_name.contains("sensor_task"));
    assert!(
        analysis
            .cfg
            .concurrency
            .iter()
            .any(|site| matches!(site.operation, cfg::CfgConcurrencyKind::Spawn { .. })),
        "spawn annotations must live in the CFG"
    );

    let json = cfg::render_json(&analysis.cfg, None, false).expect("self-contained CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("parse CFG JSON");
    assert!(
        document["concurrency"]
            .as_array()
            .is_some_and(|sites| !sites.is_empty())
    );
}
