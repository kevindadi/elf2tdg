//! End-to-end Rust concurrency detection.
//!
//! Compiles a small `std::thread`/`thread::scope` program with the host rustc
//! and checks that M1 recovers real thread contexts, spawn/join edges and a
//! structured scope. Skips when rustc is unavailable.

use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::loader;
use elf2tdg::output::{self, GraphOptions};
use elf2tdg_schema::{ContextKind, Edge, JoinTarget, ScopeKind, SpawnTarget};

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rust_threads/main.rs")
}

fn build_fixture() -> Option<PathBuf> {
    build_fixture_at("0")
}

fn build_fixture_at(opt_level: &str) -> Option<PathBuf> {
    let rustc_available = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?
        .status
        .success();
    if !rustc_available {
        eprintln!("skipping Rust thread fixture: rustc is not available");
        return None;
    }
    let directory = std::env::temp_dir().join(format!(
        "elf2tdg-rust-threads-{}-o{opt_level}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let binary = directory.join("rust_threads");
    let status = Command::new("rustc")
        .arg("--edition=2021")
        .args(["-C", &format!("opt-level={opt_level}"), "-g", "-o"])
        .arg(&binary)
        .arg(source())
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping Rust thread fixture: compilation failed");
        None
    }
}

#[test]
fn detects_rust_thread_spawn_join_and_scope() {
    let Some(binary) = build_fixture() else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    tdg.ensure_valid().expect("TDG must validate");

    let thread_context = tdg
        .contexts
        .iter()
        .find(|context| context.kind == ContextKind::Thread)
        .expect("thread context");
    assert!(
        thread_context.name.contains("{closure#0}"),
        "unexpected thread name: {}",
        thread_context.name
    );
    assert!(
        thread_context
            .parent
            .as_ref()
            .is_some_and(|parent| parent.as_str() == "ctx:main"),
        "thread parent should be main"
    );

    let scoped_context = tdg
        .contexts
        .iter()
        .find(|context| context.kind == ContextKind::ScopedThread)
        .expect("scoped thread context");
    assert!(scoped_context.name.contains("{closure#"));

    let spawns: Vec<&Edge> = tdg
        .edges
        .iter()
        .filter(|edge| matches!(edge, Edge::Spawn { .. }))
        .collect();
    assert_eq!(spawns.len(), 2, "expected two resolved Rust spawns");
    for edge in &spawns {
        let Edge::Spawn {
            runtime,
            target: SpawnTarget::Context { entry, .. },
            ..
        } = edge
        else {
            panic!("expected a resolved spawn context, got {edge:?}");
        };
        assert_eq!(runtime.as_str(), "rust-std");
        let entry = tdg
            .functions
            .iter()
            .find(|function| &function.id == entry)
            .expect("spawn entry function");
        assert!(entry.primary_name.contains("{closure#"));
    }

    let join = tdg
        .edges
        .iter()
        .find_map(|edge| match edge {
            Edge::Join {
                target,
                from_context,
                ..
            } => Some((target, from_context)),
            _ => None,
        })
        .expect("join edge");
    assert!(matches!(join.0, JoinTarget::Context { .. }));
    assert_eq!(
        join.1.as_ref().map(elf2tdg_schema::ContextId::as_str),
        Some("ctx:main")
    );

    let scope = tdg.scopes.first().expect("structured scope");
    assert_eq!(scope.kind, ScopeKind::RustThreadScope);
    assert_eq!(scope.entering_context.as_str(), "ctx:main");
    assert_eq!(scope.members.len(), 1, "scope should own the scoped spawn");

    let dot = output::render_dot(&tdg);
    assert!(dot.contains("thread scope"));
    assert!(dot.contains("member"));
    let mermaid = output::render_mermaid(&tdg);
    assert!(mermaid.contains("thread scope"));
    assert!(mermaid.contains("member"));

    let concurrency_dot = output::render_dot_with(&tdg, GraphOptions::concurrency_with_legend());
    assert!(concurrency_dot.contains("concurrency projection"));
    assert!(concurrency_dot.contains("cluster_legend"));
    assert!(
        !concurrency_dot.contains("[label=\"call\""),
        "{concurrency_dot}"
    );
    let concurrency_mermaid =
        output::render_mermaid_with(&tdg, GraphOptions::concurrency_with_legend());
    assert!(concurrency_mermaid.contains("subgraph Legend"));
    assert!(
        !concurrency_mermaid.contains("fillcolor"),
        "{concurrency_mermaid}"
    );
    assert!(
        !concurrency_mermaid.contains("[label="),
        "{concurrency_mermaid}"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}

#[test]
fn recovers_inlined_spawn_sites_from_dwarf() {
    let Some(binary) = build_fixture_at("2") else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let tdg = analyze(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    tdg.ensure_valid().expect("TDG must validate");

    let thread_context = tdg
        .contexts
        .iter()
        .find(|context| context.kind == ContextKind::Thread)
        .expect("logical thread context");
    assert_eq!(
        thread_context
            .ext
            .get("elf2tdg.logical_task")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(thread_context.entry.as_str().starts_with("fn:task:"));
    let scoped_context = tdg
        .contexts
        .iter()
        .find(|context| context.kind == ContextKind::ScopedThread)
        .expect("logical scoped context");
    assert_eq!(
        scoped_context
            .ext
            .get("elf2tdg.logical_task")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    let spawns: Vec<&Edge> = tdg
        .edges
        .iter()
        .filter(|edge| matches!(edge, Edge::Spawn { .. }))
        .collect();
    assert_eq!(spawns.len(), 2, "inline spawn sites");
    for edge in &spawns {
        let Edge::Spawn {
            api,
            name,
            target: SpawnTarget::Context { entry, .. },
            ..
        } = edge
        else {
            panic!("expected inline spawn with a context, got {edge:?}");
        };
        assert!(matches!(api.as_str(), "thread::spawn" | "Scope::spawn"));
        assert!(
            name.as_deref()
                .is_some_and(|name| name.contains("{closure#"))
        );
        assert!(entry.as_str().starts_with("fn:task:"));
    }

    let join = tdg
        .edges
        .iter()
        .find_map(|edge| match edge {
            Edge::Join { target, .. } => Some(target),
            _ => None,
        })
        .expect("inline join edge");
    assert!(matches!(join, JoinTarget::Context { .. }));

    let scope = tdg.scopes.first().expect("inline scope");
    assert_eq!(scope.kind, ScopeKind::RustThreadScope);
    assert!(scope.exit_site.is_some());
    assert_eq!(scope.members.len(), 1);

    let logical_functions: Vec<&elf2tdg_schema::Function> = tdg
        .functions
        .iter()
        .filter(|function| function.kind == elf2tdg_schema::FunctionKind::TaskEntry)
        .collect();
    assert_eq!(logical_functions.len(), 2);
    assert!(logical_functions.iter().all(|function| {
        function
            .ext
            .get("elf2tdg.logical_task")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    }));

    let concurrency_dot = output::render_dot_with(&tdg, GraphOptions::concurrency_with_legend());
    assert!(
        concurrency_dot.contains("style=\"rounded,filled,dashed\""),
        "logical task functions should be dashed"
    );
    assert!(
        concurrency_dot.contains("style=\"filled,dashed\""),
        "logical task contexts should be dashed"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
