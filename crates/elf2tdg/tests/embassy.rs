//! End-to-end Embassy task detection in a no-std Cortex-M image.
//!
//! The fixture is the checked-in `rust-concurrency` example ELF. It targets
//! `thumbv7em-none-eabi`, links `cortex-m-rt` and `embassy-executor`, and has
//! no `std` dependency.

use std::path::{Path, PathBuf};

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg::{self, CfgNoreturnReason};
use elf2tdg::loader::{self, ArchKind};
use elf2tdg_schema::{Confidence, ContextKind, Edge, FunctionKind, SpawnTarget};

fn example_elf() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    path.exists().then_some(path)
}

#[test]
#[allow(clippy::too_many_lines)]
fn recovers_embassy_task_contexts_and_spawns() {
    let Some(path) = example_elf() else {
        return;
    };
    let image = loader::load(&path).expect("example ELF must load");
    assert_eq!(image.arch, ArchKind::Thumb);
    assert!(!image.vector_table.is_empty(), "Cortex-M vector table");

    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let tdg = &analysis.tdg;
    tdg.ensure_valid().expect("TDG must validate");

    assert!(
        !tdg.functions
            .iter()
            .any(|function| function.primary_name.starts_with("std::")),
        "the fixture must not contain std runtime functions"
    );
    assert!(
        !tdg.contexts
            .iter()
            .any(|context| context.name.contains("std::thread")),
        "std::thread is outside the supported no_std profile"
    );
    assert!(
        tdg.locks.is_empty(),
        "the example has no locking dependency"
    );

    let async_tasks: Vec<_> = tdg
        .contexts
        .iter()
        .filter(|context| context.kind == ContextKind::AsyncTask)
        .collect();
    assert_eq!(async_tasks.len(), 3, "main plus sensor/monitor tasks");
    for task in ["app_main", "sensor_task", "monitor_task"] {
        assert!(
            async_tasks
                .iter()
                .any(|context| context.name.contains(task)),
            "missing async task context for {task}"
        );
    }

    let main = tdg
        .contexts
        .iter()
        .find(|context| context.kind == ContextKind::Main)
        .expect("main context");
    let app_main = async_tasks
        .iter()
        .find(|context| context.name.contains("app_main"))
        .expect("Embassy main task");
    assert_eq!(
        app_main
            .parent
            .as_ref()
            .map(elf2tdg_schema::ContextId::as_str),
        Some(main.id.as_str()),
        "the Embassy main task should be rooted in the Cortex-M main context"
    );
    for task in ["sensor_task", "monitor_task"] {
        let context = async_tasks
            .iter()
            .find(|context| context.name.contains(task))
            .expect("task context");
        assert_eq!(
            context
                .parent
                .as_ref()
                .map(elf2tdg_schema::ContextId::as_str),
            Some(app_main.id.as_str()),
            "{task} should be spawned from the Embassy main task"
        );
        let entry = tdg
            .functions
            .iter()
            .find(|function| function.id == context.entry)
            .expect("task entry function");
        assert!(entry.primary_name.contains("TaskStorage<"));
        assert!(entry.primary_name.ends_with("::poll"));
    }

    for (selector, task) in [
        ("rust_concurrency::app_main", "__app_main_task"),
        ("app_main", "__app_main_task"),
        ("rust_concurrency::sensor_task", "__sensor_task_task"),
        ("sensor_task", "__sensor_task_task"),
        ("rust_concurrency::monitor_task", "__monitor_task_task"),
        ("monitor_task", "__monitor_task_task"),
    ] {
        let selected = analysis
            .cfg
            .select_with_tdg(&analysis.tdg, Some(selector))
            .unwrap_or_else(|error| panic!("{selector}: {error}"));
        assert_eq!(selected.len(), 1, "{selector}");
        assert!(
            selected[0].primary_name.contains("TaskStorage<"),
            "{selector} should map to the task poll entry, got {}",
            selected[0].primary_name
        );
        assert!(
            selected[0].primary_name.contains(task),
            "{selector} should map to {task}, got {}",
            selected[0].primary_name
        );
    }

    let reachable = analysis
        .cfg
        .reachable_from(&analysis.tdg, "sensor_task")
        .expect("task reachability");
    assert!(reachable.iter().any(|function| {
        function.primary_name.contains("TaskStorage<")
            && function.primary_name.contains("__sensor_task_task")
    }));

    let rendered = cfg::render_json(&analysis.cfg, &analysis.tdg, Some("sensor_task"), false)
        .expect("task selector JSON");
    let rendered: serde_json::Value = serde_json::from_str(&rendered).expect("valid CFG JSON");
    assert!(
        rendered["functions"][0]["primary_name"]
            .as_str()
            .is_some_and(
                |name| name.contains("TaskStorage<") && name.contains("__sensor_task_task")
            )
    );

    let dot = cfg::render_dot_with_tdg(&analysis.cfg, &analysis.tdg, Some("sensor_task"), false)
        .expect("task selector DOT");
    assert!(dot.contains("TaskStorage<"));
    let mermaid =
        cfg::render_mermaid_with_tdg(&analysis.cfg, &analysis.tdg, Some("sensor_task"), false)
            .expect("task selector Mermaid");
    assert!(mermaid.contains("TaskStorage<"));

    let spawns: Vec<&Edge> = tdg
        .edges
        .iter()
        .filter(|edge| matches!(edge, Edge::Spawn { .. }))
        .collect();
    assert_eq!(spawns.len(), 3, "Embassy main, sensor and monitor spawns");
    for edge in &spawns {
        let Edge::Spawn {
            runtime,
            api,
            name,
            target: SpawnTarget::Context { entry, .. },
            ..
        } = edge
        else {
            panic!("expected a resolved Embassy spawn, got {edge:?}");
        };
        assert_eq!(runtime.as_str(), "rust-embassy");
        assert_eq!(api.as_str(), "embassy::Spawner::spawn");
        assert!(name.as_deref().is_some_and(|name| !name.contains("std::")));
        let entry = tdg
            .functions
            .iter()
            .find(|function| &function.id == entry)
            .expect("spawn entry function");
        assert_eq!(entry.kind, FunctionKind::Normal);
        assert!(entry.primary_name.contains("TaskStorage<"));
    }

    let isr_contexts: Vec<_> = tdg
        .contexts
        .iter()
        .filter(|context| context.kind == ContextKind::Isr)
        .collect();
    assert_eq!(isr_contexts.len(), 1, "only HardFault is a real vector");
    assert_eq!(isr_contexts[0].name, "HardFault");

    assert!(
        !tdg.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "unresolved-indirect-call"),
        "the executor task poll dispatch should have bounded targets"
    );
    let candidate_diagnostic = tdg
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "resolved-indirect-call-candidates")
        .expect("multi-target resolution diagnostic");
    let site = candidate_diagnostic.site.expect("candidate call site");
    let candidate_edges: Vec<_> = tdg
        .edges
        .iter()
        .filter_map(|edge| match edge {
            Edge::Call {
                site: edge_site,
                direct: false,
                confidence: Confidence::Low,
                callee,
                ..
            } if *edge_site == site => Some(callee),
            _ => None,
        })
        .collect();
    assert_eq!(candidate_edges.len(), 4, "three task polls + poll_exited");
    for callee in &candidate_edges {
        let target = tdg
            .functions
            .iter()
            .find(|function| &function.id == *callee)
            .expect("candidate target function");
        assert!(
            target.primary_name.contains("TaskStorage<")
                || target.primary_name.ends_with("poll_exited"),
            "unexpected candidate target: {}",
            target.primary_name
        );
    }

    let executor = analysis
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name.contains("Executor>::run"))
        .expect("Embassy executor function");
    assert_eq!(
        executor.noreturn,
        Some(CfgNoreturnReason::ControlFlow),
        "the executor event loop never returns"
    );
    let panic = analysis
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name.contains("::panicking::panic_fmt"))
        .expect("core panic entry point");
    assert_eq!(panic.noreturn, Some(CfgNoreturnReason::Api));
    let cfg_candidates: Vec<_> = executor
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| executor.cfg.graph[*node].calls.iter())
        .filter(|call| call.site == site.get())
        .collect();
    assert_eq!(cfg_candidates.len(), 1, "one call instruction");
    let call_site = cfg_candidates[0];
    assert!(!call_site.unresolved && call_site.heuristic);
    assert!(call_site.target.is_none());
    assert_eq!(call_site.candidates.len(), 4, "four candidate targets");
    assert!(
        call_site
            .candidates
            .iter()
            .all(|candidate| candidate.target_function.is_some() && candidate.target != 0)
    );
}
