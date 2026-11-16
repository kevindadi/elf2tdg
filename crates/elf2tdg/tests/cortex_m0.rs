//! End-to-end coverage for the Cortex-M0 fixture.
//!
//! The fixture is built with arm-none-eabi-gcc. If neither the ELF nor the
//! cross-compiler is available the test reports a skip instead of failing on
//! machines without an embedded toolchain.

use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::loader::{self, ArchKind};
use elf2tdg::output;
use elf2tdg_schema::{ContextKind, Edge, FunctionKind, Tdg};

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
    let tdg = analyze(&image, &options).expect("fixture analysis must succeed");
    tdg.ensure_valid().expect("fixture TDG must validate");

    assert_eq!(
        tdg.timing.models.first().map(|model| model.id.as_str()),
        Some("cortex-m0")
    );
    assert!(
        tdg.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "timing-model-auto-detected")
    );

    let function_names: Vec<&str> = tdg
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
    assert!(tdg.functions.iter().any(|function| {
        function.primary_name == "Reset_Handler" && function.kind == FunctionKind::Entry
    }));
    assert!(tdg.functions.iter().any(|function| {
        function.primary_name == "USART1_IRQHandler" && function.kind == FunctionKind::Isr
    }));
    let main_function = tdg
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
        tdg.functions
            .iter()
            .find(|function| function.primary_name == name)
            .unwrap_or_else(|| panic!("missing function {name}"))
            .id
            .clone()
    };
    let main_context = tdg
        .contexts
        .iter()
        .find(|context| context.kind == ContextKind::Main)
        .expect("main context");
    assert_eq!(main_context.entry, by_name("main"));
    let isr_context = tdg
        .contexts
        .iter()
        .find(|context| context.kind == ContextKind::Isr)
        .expect("ISR context");
    assert_eq!(isr_context.name, "USART1_IRQHandler");
    assert!(
        !tdg.contexts
            .iter()
            .any(|context| context.name.contains("Default_Handler"))
    );

    assert!(tdg.edges.iter().any(|edge| matches!(
        edge,
        Edge::IsrActivate { vector, irq: Some(37), .. } if *vector == 53
    )));
    for (caller, callee) in [
        ("Reset_Handler", "main"),
        ("main", "sensor_task"),
        ("sensor_task", "delay"),
        ("main", "delay"),
    ] {
        let source_id = by_name(caller);
        let target_id = by_name(callee);
        assert!(tdg.edges.iter().any(|edge| matches!(
            edge,
            Edge::Call { caller: from, callee: to, .. }
                if from == &source_id && to == &target_id
        )));
    }

    let timed_block = tdg
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .find_map(|block| block.timing.as_ref())
        .expect("Cortex-M0 timing");
    assert!(timed_block.cycles.is_valid());
    assert!(timed_block.time_ns.is_some());

    let json = output::render_json(&tdg).expect("JSON render");
    let reparsed: Tdg = serde_json::from_str(&json).expect("rendered JSON must parse");
    assert_eq!(tdg, reparsed);

    let dot = output::render_dot(&tdg);
    assert!(dot.contains("USART1_IRQHandler"));
    assert!(dot.contains("IRQ 37"));
    let mermaid = output::render_mermaid(&tdg);
    assert!(mermaid.contains("USART1_IRQHandler"));
    assert!(mermaid.contains("IRQ 37"));
}
