//! End-to-end Embassy task detection in a no-std Cortex-M image.
//!
//! The fixture is the checked-in `rust-concurrency` example ELF. It targets
//! `thumbv7em-none-eabi`, links `cortex-m-rt` and `embassy-executor`, and has
//! no `std` dependency.

use std::path::{Path, PathBuf};

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg::{self, CfgConcurrencyKind, CfgNoreturnReason, CfgRootKind};
use elf2tdg::loader::{self, ArchKind};
use elf2tdg_schema::{Confidence, FunctionKind};

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
    analysis.cfg.ensure_valid().expect("CFG must validate");

    assert!(
        !analysis
            .cfg
            .functions
            .iter()
            .any(|function| function.primary_name.starts_with("std::")),
        "the fixture must not contain std runtime functions"
    );
    assert!(
        !analysis
            .cfg
            .aliases
            .iter()
            .any(|alias| alias.name.contains("std::thread")),
        "std::thread is outside the supported no_std profile"
    );
    assert!(
        analysis.cfg.locks.is_empty(),
        "the example has no locking dependency"
    );

    let async_tasks: Vec<_> = analysis
        .cfg
        .roots
        .iter()
        .filter(|root| root.kind == CfgRootKind::Task)
        .collect();
    assert_eq!(async_tasks.len(), 3, "main plus sensor/monitor tasks");
    for task in ["app_main", "sensor_task", "monitor_task"] {
        assert!(
            async_tasks
                .iter()
                .any(|root| { root.name.as_deref().is_some_and(|name| name.contains(task)) }),
            "missing async task root for {task}"
        );
    }
    for root in &async_tasks {
        let entry = analysis
            .cfg
            .function(&root.function)
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
            .select(Some(selector))
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
        .reachable_from("sensor_task")
        .expect("task reachability");
    assert!(reachable.iter().any(|function| {
        function.primary_name.contains("TaskStorage<")
            && function.primary_name.contains("__sensor_task_task")
    }));

    let rendered =
        cfg::render_json(&analysis.cfg, Some("sensor_task"), false).expect("task selector JSON");
    let rendered: serde_json::Value = serde_json::from_str(&rendered).expect("valid CFG JSON");
    assert!(
        rendered["functions"][0]["primary_name"]
            .as_str()
            .is_some_and(
                |name| name.contains("TaskStorage<") && name.contains("__sensor_task_task")
            )
    );

    let dot =
        cfg::render_dot(&analysis.cfg, Some("sensor_task"), false).expect("task selector DOT");
    assert!(dot.contains("TaskStorage<"));
    let mermaid = cfg::render_mermaid(&analysis.cfg, Some("sensor_task"), false)
        .expect("task selector Mermaid");
    assert!(mermaid.contains("TaskStorage<"));

    let spawns: Vec<_> = analysis
        .cfg
        .concurrency
        .iter()
        .filter(|site| matches!(&site.operation, CfgConcurrencyKind::Spawn { .. }))
        .collect();
    assert_eq!(spawns.len(), 3, "Embassy main, sensor and monitor spawns");
    for site in &spawns {
        let CfgConcurrencyKind::Spawn {
            runtime,
            api,
            name,
            entry: Some(entry),
            ..
        } = &site.operation
        else {
            panic!(
                "expected a resolved Embassy spawn, got {:?}",
                site.operation
            );
        };
        assert_eq!(runtime.as_str(), "rust-embassy");
        assert_eq!(api.as_str(), "embassy::Spawner::spawn");
        assert!(name.as_deref().is_some_and(|name| !name.contains("std::")));
        let entry = analysis.cfg.function(entry).expect("spawn entry function");
        assert_eq!(entry.kind, FunctionKind::Normal);
        assert!(entry.primary_name.contains("TaskStorage<"));
    }

    let isr_roots: Vec<_> = analysis
        .cfg
        .roots
        .iter()
        .filter(|root| root.kind == CfgRootKind::Isr)
        .collect();
    assert_eq!(isr_roots.len(), 1, "only HardFault is a real vector");
    assert_eq!(isr_roots[0].name.as_deref(), Some("HardFault"));

    assert!(
        !analysis
            .cfg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "unresolved-indirect-call"),
        "the executor task poll dispatch should have bounded targets"
    );
    let candidate_diagnostic = analysis
        .cfg
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "resolved-indirect-call-candidates")
        .expect("multi-target resolution diagnostic");
    let site = candidate_diagnostic.site.expect("candidate call site");
    let candidate_edges: Vec<_> = analysis
        .cfg
        .calls
        .iter()
        .filter(|call| call.site == site && !call.direct && call.confidence == Confidence::Low)
        .filter_map(|call| call.callee.as_ref())
        .collect();
    assert_eq!(candidate_edges.len(), 4, "three task polls + poll_exited");
    for callee in &candidate_edges {
        let target = analysis
            .cfg
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
