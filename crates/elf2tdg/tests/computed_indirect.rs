//! Computed indirect-call targets: indexed dispatch tables, returned function
//! pointers and stack-slot function pointers.
//!
//! The same C fixture is compiled for the host and, when the toolchains are
//! available, for Thumb, `AArch64` and RISC-V. Every indirect call in `main`
//! must resolve to a concrete target or a bounded candidate set.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg::{CfgCallSite, ProgramCfg};
use elf2tdg::loader;
use elf2tdg_schema::{FunctionId, Tdg};

const SOURCE: &str = r"
#include <stddef.h>

volatile int selector;

static void cmd_a(void) { }
static void cmd_b(void) { }
static void cmd_c(void) { }
static void cmd_d(void) { }
static void (*const commands[])(void) = { cmd_a, cmd_b, cmd_c, cmd_d };

static void ret_a(void) { }
static void ret_b(void) { }
static void (*get_one(void))(void) { return ret_a; }
static void (*pick(int value))(void) { return value ? ret_a : ret_b; }

struct ops { void (*run)(void); int value; };
static void field_run(void) { }
static struct ops global_ops = { field_run, 1 };

int main(void) {
    commands[selector & 3]();
    get_one()();
    pick(selector)();
    global_ops.run();
    void (*local)(void) = field_run;
    local();
    return 0;
}
";

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn compile_host() -> Option<PathBuf> {
    compile_with_args(
        "gcc",
        "computed_indirect.c",
        &[
            "-O0",
            "-g",
            "-fno-inline",
            "-fno-builtin",
            "-fno-pie",
            "-no-pie",
        ],
    )
}

fn compile_thumb() -> Option<PathBuf> {
    compile_with_args(
        "arm-none-eabi-gcc",
        "computed_indirect_thumb.c",
        &[
            "-O0",
            "-g",
            "-mthumb",
            "-mcpu=cortex-m4",
            "-nostdlib",
            "-ffreestanding",
            "-Wl,-Ttext=0x8000000",
            "-Wl,-e,main",
        ],
    )
}

fn compile_clang_target(target: &str, source_name: &str, flags: &[&str]) -> Option<PathBuf> {
    if !tool_available("clang") {
        eprintln!("skipping {source_name}: clang is not available");
        return None;
    }
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let sysroot = String::from_utf8_lossy(&sysroot.stdout).trim().to_owned();
    let lld = std::fs::read_dir(Path::new(&sysroot).join("lib/rustlib"))
        .ok()?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path().join("bin/rust-lld"))
        .find(|path| path.exists())?;
    let directory =
        std::env::temp_dir().join(format!("elf2tdg-{source_name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source_path = directory.join(source_name);
    std::fs::write(&source_path, SOURCE).ok()?;
    let object = directory.join("fixture.o");
    let binary = directory.join("fixture");
    let compile = Command::new("clang")
        .args(["-target", target, "-O0", "-g", "-fno-inline"])
        .args(flags)
        .arg("-c")
        .arg(&source_path)
        .arg("-o")
        .arg(&object)
        .status()
        .ok()?;
    if !compile.success() {
        eprintln!("skipping {source_name}: cross compilation failed");
        return None;
    }
    let link = Command::new(lld)
        .args(["-flavor", "gnu", "-Ttext=0x400000", "-e", "main", "-o"])
        .arg(&binary)
        .arg(&object)
        .status()
        .ok()?;
    (link.success() && binary.exists()).then_some(binary)
}

fn compile_with_args(compiler: &str, source_name: &str, args: &[&str]) -> Option<PathBuf> {
    if !tool_available(compiler) {
        eprintln!("skipping {source_name}: {compiler} is not available");
        return None;
    }
    let directory =
        std::env::temp_dir().join(format!("elf2tdg-{source_name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source_path = directory.join(source_name);
    std::fs::write(&source_path, SOURCE).ok()?;
    let binary = directory.join("fixture");
    let status = Command::new(compiler)
        .args(args)
        .arg("-o")
        .arg(&binary)
        .arg(&source_path)
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping {source_name}: compilation failed");
        None
    }
}

fn function_id(cfg: &ProgramCfg, name: &str) -> FunctionId {
    cfg.functions
        .iter()
        .find(|function| function.primary_name == name)
        .unwrap_or_else(|| panic!("missing function {name}"))
        .id
        .clone()
}

fn call_target_names(cfg: &ProgramCfg, call: &CfgCallSite) -> BTreeSet<String> {
    let targets: Vec<u64> = if call.candidates.is_empty() {
        call.target.into_iter().collect()
    } else {
        call.candidates
            .iter()
            .map(|candidate| candidate.target)
            .collect()
    };
    targets
        .into_iter()
        .filter_map(|target| cfg.function_at(target))
        .map(|function| function.primary_name.clone())
        .collect()
}

fn indirect_calls<'a>(cfg: &'a ProgramCfg, caller: &str) -> Vec<&'a CfgCallSite> {
    let function = cfg
        .functions
        .iter()
        .find(|function| function.primary_name == caller)
        .unwrap_or_else(|| panic!("missing caller {caller}"));
    function
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| function.cfg.graph[*node].calls.iter())
        .chain(function.cfg.recovered_calls.iter())
        .filter(|call| !call.direct)
        .collect()
}

fn assert_computed_calls(binary: &Path) {
    let image = loader::load(binary).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let tdg: &Tdg = &analysis.tdg;
    tdg.ensure_valid().expect("TDG must validate");
    let calls = indirect_calls(&analysis.cfg, "main");

    let table: BTreeSet<String> = ["cmd_a", "cmd_b", "cmd_c", "cmd_d"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert!(
        calls
            .iter()
            .any(|call| !call.unresolved && call_target_names(&analysis.cfg, call) == table),
        "missing indexed call-table candidates: {calls:#?}"
    );

    let ret_a = function_id(&analysis.cfg, "ret_a");
    let ret_a_address = analysis
        .cfg
        .function(&ret_a)
        .expect("ret_a function")
        .address;
    assert!(
        calls.iter().any(|call| {
            !call.unresolved && call.candidates.is_empty() && call.target == Some(ret_a_address)
        }),
        "missing single returned function pointer"
    );
    assert!(
        calls.iter().any(|call| {
            !call.unresolved
                && call_target_names(&analysis.cfg, call)
                    == BTreeSet::from(["ret_a".to_owned(), "ret_b".to_owned()])
        }),
        "missing returned candidate set"
    );

    let field_run = function_id(&analysis.cfg, "field_run");
    let field_run_address = analysis
        .cfg
        .function(&field_run)
        .expect("field_run function")
        .address;
    let field_calls = calls
        .iter()
        .filter(|call| call.target == Some(field_run_address) && !call.unresolved)
        .count();
    assert!(
        field_calls >= 2,
        "global and local field calls must resolve, got {field_calls}"
    );

    assert!(
        calls.iter().all(|call| !call.unresolved),
        "main still has unresolved indirect calls: {calls:#?}"
    );
    for code in ["resolved-call-table", "resolved-returned-indirect-call"] {
        assert!(
            tdg.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "missing {code} diagnostic"
        );
    }

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}

#[test]
fn resolves_computed_indirect_calls_on_x86_64() {
    let Some(binary) = compile_host() else {
        return;
    };
    assert_computed_calls(&binary);
}

#[test]
fn resolves_computed_indirect_calls_on_thumb() {
    let Some(binary) = compile_thumb() else {
        return;
    };
    assert_computed_calls(&binary);
}

#[test]
fn resolves_computed_indirect_calls_on_aarch64() {
    let Some(binary) = compile_clang_target(
        "aarch64-none-elf",
        "computed_indirect_aarch64.c",
        &["-fno-pie"],
    ) else {
        return;
    };
    assert_computed_calls(&binary);
}

#[test]
fn resolves_computed_indirect_calls_on_riscv64() {
    let Some(binary) = compile_clang_target(
        "riscv64-unknown-elf",
        "computed_indirect_riscv64.c",
        &["-fno-pie"],
    ) else {
        return;
    };
    assert_computed_calls(&binary);
}
