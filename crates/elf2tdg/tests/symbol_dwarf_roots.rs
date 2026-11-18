//! Symbol and DWARF function roots.
//!
//! The fixture contains two functions that no code calls. One keeps its ELF
//! symbol; the other has that symbol stripped while its DWARF subprogram DIE
//! survives. Both must be discovered, named and treated as system roots, so
//! the default CFG includes unreferenced code and recovers stripped function
//! entries from debug information.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::loader;
use elf2tdg_schema::FunctionKind;

const SOURCE: &str = r"
__attribute__((noinline, used)) static int dwell_symbol_only(void) {
    return 11;
}

__attribute__((noinline, used)) static int dwell_dwarf_only(int value) {
    return value * 3 + 1;
}

int main(void) {
    return 0;
}
";

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn compile_fixture() -> Option<(PathBuf, PathBuf)> {
    if !cfg!(target_arch = "x86_64") {
        eprintln!("skipping symbol/DWARF root fixture: host-specific code generation");
        return None;
    }
    if !command_available("gcc") || !command_available("objcopy") {
        eprintln!("skipping symbol/DWARF root fixture: gcc or objcopy is not available");
        return None;
    }
    let directory =
        std::env::temp_dir().join(format!("elf2tdg-symbol-roots-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source = directory.join("roots.c");
    std::fs::write(&source, SOURCE).ok()?;
    let binary = directory.join("roots");
    let status = Command::new("gcc")
        .args([
            "-O0",
            "-g",
            "-fno-inline",
            "-fno-builtin",
            "-fno-pie",
            "-no-pie",
            "-o",
        ])
        .arg(&binary)
        .arg(&source)
        .status()
        .ok()?;
    if !status.success() || !binary.exists() {
        eprintln!("skipping symbol/DWARF root fixture: compilation failed");
        return None;
    }
    let stripped = directory.join("roots-stripped");
    let status = Command::new("objcopy")
        .arg("--strip-symbol=dwell_dwarf_only")
        .arg(&binary)
        .arg(&stripped)
        .status()
        .ok()?;
    if !status.success() || !stripped.exists() {
        eprintln!("skipping symbol/DWARF root fixture: objcopy failed");
        return None;
    }
    Some((binary, stripped))
}

fn cfg_function<'a>(
    program: &'a elf2tdg::cfg::ProgramCfg,
    name: &str,
) -> &'a elf2tdg::cfg::CfgFunction {
    program
        .functions
        .iter()
        .find(|function| function.primary_name == name)
        .unwrap_or_else(|| panic!("missing CFG function {name}"))
}

#[test]
#[allow(clippy::too_many_lines)]
fn recovers_symbol_and_dwarf_function_roots() {
    let Some((binary, stripped)) = compile_fixture() else {
        return;
    };

    let image = loader::load(&binary).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    analysis.cfg.ensure_valid().expect("CFG must validate");

    let symbol_function = cfg_function(&analysis.cfg, "dwell_symbol_only");
    let dwarf_function = cfg_function(&analysis.cfg, "dwell_dwarf_only");
    assert!(
        image
            .symbols
            .iter()
            .any(|symbol| symbol.name == "dwell_symbol_only"),
        "the fixture must retain the symbol-only function"
    );
    assert!(
        image
            .symbols
            .iter()
            .any(|symbol| symbol.name == "dwell_dwarf_only"),
        "the unstripped fixture keeps both function symbols"
    );
    assert_eq!(symbol_function.kind, FunctionKind::Normal);
    assert_eq!(dwarf_function.kind, FunctionKind::Normal);

    let stripped_image = loader::load(&stripped).expect("stripped fixture must load");
    assert!(
        stripped_image
            .symbols
            .iter()
            .all(|symbol| symbol.name != "dwell_dwarf_only"),
        "objcopy must remove the DWARF-only function symbol"
    );
    let dwarf = stripped_image
        .dwarf
        .as_ref()
        .expect("the fixture must retain DWARF");
    let dwarf_entry = dwarf
        .functions
        .iter()
        .find(|function| function.display_name().as_deref() == Some("dwell_dwarf_only"))
        .expect("DWARF subprogram for the stripped function");
    let (low, high) = dwarf_entry
        .primary_range()
        .expect("DWARF subprogram must have a concrete range");

    let stripped_analysis = analyze_with_cfg(&stripped_image, &AnalysisOptions::default())
        .expect("stripped analysis must succeed");
    stripped_analysis
        .cfg
        .ensure_valid()
        .expect("stripped CFG must validate");
    let stripped_symbol = cfg_function(&stripped_analysis.cfg, "dwell_symbol_only");
    let stripped_dwarf = cfg_function(&stripped_analysis.cfg, "dwell_dwarf_only");
    assert_eq!(
        stripped_dwarf.address,
        stripped_image.canonical_address(low)
    );
    assert_eq!(stripped_dwarf.size, high - low);
    assert_eq!(stripped_dwarf.kind, FunctionKind::Normal);

    // Neither function is called or stored in a pointer table; only the
    // symbol table and DWARF can explain why they are roots.
    for function in [stripped_symbol, stripped_dwarf] {
        assert!(
            !stripped_analysis
                .cfg
                .pointer_roots
                .contains(&function.address),
            "{} must not be a pointer root",
            function.primary_name
        );
        assert!(
            !stripped_analysis.cfg.calls.iter().any(|call| {
                call.callee.as_ref() == Some(&function.id) || call.candidates.contains(&function.id)
            }),
            "{} must not be referenced by a call edge",
            function.primary_name
        );
    }
    let roots = stripped_analysis.cfg.system_roots(&stripped_image);
    for function in [stripped_symbol, stripped_dwarf] {
        assert!(
            roots.contains(&function.id),
            "{} should be a system root",
            function.primary_name
        );
    }
    let reachable = stripped_analysis
        .cfg
        .reachable_from_system(&stripped_image, false);
    for function in [stripped_symbol, stripped_dwarf] {
        assert!(
            reachable
                .iter()
                .any(|candidate| candidate.id == function.id),
            "default CFG should include {}",
            function.primary_name
        );
    }

    // Discovery roots are deliberately not execution roots: pruning from
    // execution roots must not treat an uncalled symbol as live.
    let execution_roots = stripped_analysis.cfg.execution_roots(&stripped_image);
    let main = cfg_function(&stripped_analysis.cfg, "main");
    assert!(
        execution_roots.contains(&main.id),
        "main must remain an execution root"
    );
    for function in [stripped_symbol, stripped_dwarf] {
        assert!(
            !execution_roots.contains(&function.id),
            "{} must not be an execution root",
            function.primary_name
        );
    }
    let execution_reachable = stripped_analysis
        .cfg
        .reachable_from_execution_roots(&stripped_image, false);
    assert!(
        execution_reachable
            .iter()
            .any(|candidate| candidate.id == main.id),
        "execution reachability must include main"
    );
    for function in [stripped_symbol, stripped_dwarf] {
        assert!(
            !execution_reachable
                .iter()
                .any(|candidate| candidate.id == function.id),
            "execution reachability must exclude {}",
            function.primary_name
        );
    }

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
