//! End-to-end coverage for the Cortex-M0 fixture.
//!
//! The fixture is built with arm-none-eabi-gcc. If neither the ELF nor the
//! cross-compiler is available the test reports a skip instead of failing on
//! machines without an embedded toolchain.

use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::cfg;
use elf2tdg::loader::{self, ArchKind};
use elf2tdg_schema::FunctionKind;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cortex_m0")
}

fn fixture_elf() -> Option<PathBuf> {
    let dir = fixture_dir();
    let elf = dir.join("firmware.elf");
    if elf.exists() {
        return Some(elf);
    }
    let status = Command::new("make").arg("-C").arg(&dir).status().ok()?;
    if status.success() && elf.exists() {
        Some(elf)
    } else {
        eprintln!(
            "skipping Cortex-M0 fixture test: build {} with `make` (requires arm-none-eabi-gcc)",
            elf.display()
        );
        None
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn analyzes_cortex_m0_fixture() {
    let Some(path) = fixture_elf() else {
        return;
    };
    let image = loader::load(&path).expect("fixture must load");
    assert_eq!(image.arch, ArchKind::Thumb);
    assert_eq!(image.arm_cpu.as_deref(), Some("Cortex-M0"));
    assert!(image.has_symbols);
    assert!(image.has_debug_info);
    assert!(image.vector_table.iter().any(|entry| entry.index == 53));

    let options = AnalysisOptions {
        frequency_hz: Some(48_000_000),
        ..AnalysisOptions::default()
    };
    let program = analyze(&image, &options).expect("fixture analysis must succeed");
    program.ensure_valid().expect("fixture CFG must validate");

    assert_eq!(
        program
            .timing
            .as_ref()
            .and_then(|timing| timing.models.first())
            .map(|model| model.id.as_str()),
        Some("cortex-m0")
    );
    assert!(
        program
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "timing-model-auto-detected")
    );

    let function_names: Vec<&str> = program
        .functions
        .iter()
        .map(|function| function.primary_name.as_str())
        .collect();
    for expected in [
        "Reset_Handler",
        "main",
        "sensor_task",
        "delay",
        "USART1_IRQHandler",
    ] {
        assert!(
            function_names.contains(&expected),
            "missing function {expected}; got {function_names:?}"
        );
    }
    assert!(program.functions.iter().any(|function| {
        function.primary_name == "Reset_Handler" && function.kind == FunctionKind::Entry
    }));
    assert!(program.functions.iter().any(|function| {
        function.primary_name == "USART1_IRQHandler" && function.kind == FunctionKind::Isr
    }));
    let main_function = program
        .functions
        .iter()
        .find(|function| function.primary_name == "main")
        .expect("main function");
    let source = main_function.source.as_ref().expect("DWARF source line");
    assert!(
        source.file.ends_with("main.c"),
        "unexpected source {source:?}"
    );
    assert!(source.line > 0);

    let by_name = |name: &str| {
        program
            .functions
            .iter()
            .find(|function| function.primary_name == name)
            .unwrap_or_else(|| panic!("missing function {name}"))
            .id
            .clone()
    };
    let main_root = program
        .roots
        .iter()
        .find(|root| root.kind == cfg::CfgRootKind::Main)
        .expect("main root");
    assert_eq!(main_root.function, by_name("main"));
    let isr_root = program
        .roots
        .iter()
        .find(|root| root.kind == cfg::CfgRootKind::Isr)
        .expect("ISR root");
    assert_eq!(isr_root.name.as_deref(), Some("USART1_IRQHandler"));
    assert_eq!(isr_root.vector, Some(53));
    assert_eq!(isr_root.irq, Some(37));
    assert!(
        !program
            .roots
            .iter()
            .filter_map(|root| root.name.as_deref())
            .any(|name| name.contains("Default_Handler"))
    );

    for (caller, callee) in [
        ("Reset_Handler", "main"),
        ("main", "sensor_task"),
        ("sensor_task", "delay"),
        ("main", "delay"),
    ] {
        let source_id = by_name(caller);
        let target_id = by_name(callee);
        assert!(
            program.calls.iter().any(|call| {
                call.caller == source_id && call.callee.as_ref() == Some(&target_id)
            })
        );
    }

    let timed_block = program
        .functions
        .iter()
        .flat_map(|function| {
            function
                .cfg
                .blocks_by_address
                .values()
                .map(move |node| &function.cfg.graph[*node])
        })
        .find(|block| block.cycles.is_some())
        .expect("Cortex-M0 timing");
    assert!(
        timed_block
            .cycles
            .is_some_and(elf2tdg_schema::CostRange::is_valid)
    );
    assert!(
        program
            .timing
            .as_ref()
            .is_some_and(|timing| !timing.frequency_domains.is_empty())
    );

    let json = cfg::render_json(&program, None, true).expect("CFG JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("rendered JSON must parse");
    assert_eq!(value["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);

    let dot = cfg::render_dot(&program, None, true).expect("CFG DOT");
    assert!(dot.contains("USART1_IRQHandler"));
    let mermaid = cfg::render_mermaid(&program, None, true).expect("CFG Mermaid");
    assert!(mermaid.contains("USART1_IRQHandler"));
}
